"""G-7: build, verify and check the ML-BOM for the self-hosted model weights.

  python3 scripts/ml_bom.py hash-dir /srv/models/deepseek-v3.2 --model-id deepseek-v3.2 [--write-manifest sbom/models.yaml]
      SHA-256 of every file in a weights directory (safetensors only; pickle checkpoints are refused),
      printed as sha256sum lines or written into the manifest entry.
  python3 scripts/ml_bom.py registry-hashes --model-id deepseek-v3.2 [--revision main] [--write-manifest sbom/models.yaml]
      the same per-file SHA-256 list straight from the official Hugging Face repository (LFS object
      ids for the weights, small git-stored files fetched and hashed), pinned to the resolved commit;
      no weight download needed. Set HF_TOKEN for a gated repository. Refuses any non-huggingface.co
      source and any pickle checkpoint in the tree.
  python3 scripts/ml_bom.py build --manifest sbom/models.yaml --out sbom/ml-bom.cdx.json [--allow-pending]
      CycloneDX 1.6 ML-BOM from the manifest; exits 1 on a pending entry unless --allow-pending.
  python3 scripts/ml_bom.py validate --bom sbom/ml-bom.cdx.json [--manifest sbom/models.yaml]
      schema validation (vendored CycloneDX 1.6 schema) and, with --manifest, drift check.
  python3 scripts/ml_bom.py verify --bom sbom/ml-bom.cdx.json --model-id deepseek-v3.2 --weights /srv/models/deepseek-v3.2
      re-hash the directory and compare with the BOM (run on the inference host before serving).
  python3 scripts/ml_bom.py verify-signature --bom ... --bundle ... --certificate-identity ... --certificate-oidc-issuer ...
      cosign verify-blob with the locked cosign from tools/versions.lock.
  python3 scripts/ml_bom.py sign-command --bom sbom/ml-bom.cdx.json
      print the cosign sign-blob command (keyless signing is interactive; it is not run here).
  python3 scripts/ml_bom.py check [--config config/mara.yaml]
      BOM status of every self-hosted model in the config (what policy P7 and governance G-7 see).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import mlbom  # noqa: E402


def cmd_registry_hashes(a: argparse.Namespace) -> int:
    entry = next((e for e in mlbom.load_manifest(a.manifest) if e.model_id == a.model_id), None)
    if entry is None:
        print(f"ERROR: model_id {a.model_id!r} not in {a.manifest}", file=sys.stderr)
        return 2
    if str(entry.source.get("kind", "")).lower() != "huggingface":
        print(f"ERROR: {a.model_id}: source.kind is {entry.source.get('kind')!r}, not huggingface; registry-hashes reads the official "
              f"Hugging Face repository only (for NGC use the NGC checksum list or hash-dir on the download host)", file=sys.stderr)
        return 2
    repo = mlbom.hf_repo_from_url(str(entry.source.get("url", "")))
    revision = a.revision or str(entry.source.get("revision") or "main")
    print(f"# {a.model_id}: {repo} @ {revision} (token {'set' if os.environ.get(mlbom.HF_TOKEN_ENV) else 'not set'})", file=sys.stderr)
    commit, files = mlbom.registry_files(repo, revision)
    for f in files:
        print(f"{f.sha256}  {f.path}")
    print(f"# commit {commit}; {len(files)} file(s); component digest {mlbom.manifest_digest(files)}", file=sys.stderr)
    if a.write_manifest:
        mlbom.write_manifest_files(a.write_manifest, a.model_id, files)
        mlbom.write_manifest_source_revision(a.write_manifest, a.model_id, commit)
        print(f"# wrote {len(files)} hashes and source.revision {commit[:12]} into {a.write_manifest} for {a.model_id}", file=sys.stderr)
    return 0


def cmd_hash_dir(a: argparse.Namespace) -> int:
    files = mlbom.hash_dir(a.directory)
    for f in files:
        print(f"{f.sha256}  {f.path}")
    print(f"# {len(files)} file(s); component digest {mlbom.manifest_digest(files)}", file=sys.stderr)
    if a.write_manifest:
        if not a.model_id:
            print("ERROR: --write-manifest needs --model-id", file=sys.stderr)
            return 2
        mlbom.write_manifest_files(a.write_manifest, a.model_id, files)
        print(f"# wrote {len(files)} hashes into {a.write_manifest} for {a.model_id}", file=sys.stderr)
    return 0


def cmd_build(a: argparse.Namespace) -> int:
    entries = mlbom.load_manifest(a.manifest)
    bom = mlbom.build_bom(entries, allow_pending=a.allow_pending)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    pending = [e.model_id for e in entries if e.pending]
    print(f"wrote {a.out}: {len(entries)} model component(s)" + (f", pending: {pending}" if pending else ""))
    return 0


def cmd_validate(a: argparse.Namespace) -> int:
    bom = mlbom.load_bom(a.bom)
    errors = mlbom.validate_schema(bom)
    for e in errors:
        print(f"schema: {e}")
    rc = 1 if errors else 0
    if a.manifest:
        rebuilt = mlbom.build_bom(mlbom.load_manifest(a.manifest), allow_pending=True)
        if not mlbom.bom_equal_ignoring_volatile(bom, rebuilt):
            print(f"drift: {a.bom} does not match {a.manifest}; rebuild it with `ml_bom.py build`")
            rc = 1
        else:
            print(f"{a.bom} matches {a.manifest}")
    comps = mlbom.ml_components(bom)
    for mid, c in comps.items():
        pr = mlbom.component_problems(c)
        print(f"{mid}: {'complete' if not pr else 'incomplete: ' + '; '.join(pr)}")
    print("schema: valid (CycloneDX 1.6)" if not errors else f"schema: {len(errors)} error(s)")
    return rc


def cmd_verify(a: argparse.Namespace) -> int:
    problems = mlbom.verify_dir(mlbom.load_bom(a.bom), a.model_id, a.weights)
    for p in problems:
        print(f"MISMATCH {p}")
    print(f"{a.model_id}: {'weights match the BOM' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


def cmd_verify_signature(a: argparse.Namespace) -> int:
    cmd = mlbom.cosign_verify_blob_cmd(a.bom, a.bundle, a.certificate_identity, a.certificate_oidc_issuer)
    print("+ " + " ".join(cmd))
    r = subprocess.run(cmd, check=False)
    print("signature: " + ("verified" if r.returncode == 0 else f"FAILED (cosign exit {r.returncode})"))
    return r.returncode


def cmd_sign_command(a: argparse.Namespace) -> int:
    bundle = a.bundle or Path(str(a.bom) + ".sigstore.json")
    print(" ".join(mlbom.cosign_sign_blob_cmd(a.bom, bundle)))
    print("# keyless signing opens a browser for the OIDC flow; commit the bundle next to the BOM and set "
          "ml_bom.require_signature / bundle / certificate_identity / certificate_oidc_issuer in the config", file=sys.stderr)
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    from mara.config import load_config
    from mara.policy import p7_ml_bom

    cfg = load_config(a.config)
    for name, st in mlbom.status_for_config(cfg).items():
        line = f"{name} ({st.model_id}): {st.status}"
        if st.status == mlbom.STATUS_COMPLETE:
            line += f" {st.component_name}@{st.component_version} sha256 {st.digest[:12]}"
        elif st.problems:
            line += " — " + "; ".join(st.problems)
        print(line)
    r = p7_ml_bom(cfg)
    print(f"P7 ml-bom: {'PASS' if r.passed else 'FAIL'} — {r.reason}")
    return 0 if r.passed else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("hash-dir")
    s.add_argument("directory", type=Path)
    s.add_argument("--model-id")
    s.add_argument("--write-manifest", type=Path)
    s = sub.add_parser("registry-hashes")
    s.add_argument("--model-id", required=True)
    s.add_argument("--revision", help="branch, tag or commit; default the manifest's source.revision, else main")
    s.add_argument("--manifest", type=Path, default=ROOT / "sbom" / "models.yaml")
    s.add_argument("--write-manifest", type=Path)
    s = sub.add_parser("build")
    s.add_argument("--manifest", type=Path, default=ROOT / "sbom" / "models.yaml")
    s.add_argument("--out", type=Path, default=ROOT / "sbom" / "ml-bom.cdx.json")
    s.add_argument("--allow-pending", action="store_true")
    s = sub.add_parser("validate")
    s.add_argument("--bom", type=Path, default=ROOT / "sbom" / "ml-bom.cdx.json")
    s.add_argument("--manifest", type=Path)
    s = sub.add_parser("verify")
    s.add_argument("--bom", type=Path, required=True)
    s.add_argument("--model-id", required=True)
    s.add_argument("--weights", type=Path, required=True)
    s = sub.add_parser("verify-signature")
    s.add_argument("--bom", type=Path, required=True)
    s.add_argument("--bundle", type=Path, required=True)
    s.add_argument("--certificate-identity", required=True)
    s.add_argument("--certificate-oidc-issuer", required=True)
    s = sub.add_parser("sign-command")
    s.add_argument("--bom", type=Path, default=ROOT / "sbom" / "ml-bom.cdx.json")
    s.add_argument("--bundle", type=Path)
    s = sub.add_parser("check")
    s.add_argument("--config", type=Path, default=ROOT / "config" / "mara.yaml")
    a = ap.parse_args()
    try:
        return {"hash-dir": cmd_hash_dir, "registry-hashes": cmd_registry_hashes, "build": cmd_build, "validate": cmd_validate, "verify": cmd_verify,
                "verify-signature": cmd_verify_signature, "sign-command": cmd_sign_command, "check": cmd_check}[a.cmd](a)
    except (mlbom.PickleWeightsError, FileNotFoundError, ValueError, KeyError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
