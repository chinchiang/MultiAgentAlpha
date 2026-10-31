"""Offline trivy vulnerability database: fetch once, record what was fetched, carry it to isolated runners.

  python3 scripts/trivy_db.py download [--repository REF] [--pin-digest sha256:...] [--cache-dir DIR]
      `trivy image --download-db-only` from the first repository in tools/trivy-db.yaml that answers (or
      REF), then write <cache>/mara-trivy-db.json: repository, OCI manifest + layer digest (read from the
      registry before the download), trivy's metadata.json (UpdatedAt, NextUpdate), the SHA-256 of
      trivy.db and the trivy version. --pin-digest fetches REPO@sha256:... for a reproducible fetch, and only
      when the registry names exactly that manifest digest: a repository that answers with another one is
      refused (the next repository is tried), so the pin never rests on the registry's word.
  python3 scripts/trivy_db.py status [--max-age-hours N] [--cache-dir DIR]
      exit 1 when the database is missing, its trivy.db no longer matches the record, or UpdatedAt is
      older than N hours (default tools/trivy-db.yaml max_age_hours). What CI runs before any scan.
  python3 scripts/trivy_db.py export --out trivy-db-bundle.tar.gz [--cache-dir DIR]
  python3 scripts/trivy_db.py import --bundle trivy-db-bundle.tar.gz --bundle-sha256 <hex> [--cache-dir DIR]
      move the database to a runner without egress (report part VIII: the isolated pipelines). The
      bundle holds db/trivy.db, db/metadata.json and the record; import requires the bundle's SHA-256 as
      `export` printed it, obtained out of band (--trust-bundle skips that), and refuses a trivy.db whose
      SHA-256 differs from the record it travels with.

trivy comes only from MARA_TOOLS_DIR/bin and its manifest version must equal tools/versions.lock. The
database is NOT pinned in the lock (upstream refreshes it every six hours); the record is its provenance.
Upstream publishes no signature or attestation for the artifact (aquasecurity/trivy-db cron.yml).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools import pins  # noqa: E402
from mara.tools import trivy_db as tdb  # noqa: E402
from mara.tools.runner import installed_version, tool_path, tools_dir  # noqa: E402

CONFIG = ROOT / "tools" / "trivy-db.yaml"
BUNDLE_MEMBERS = ("db/trivy.db", "db/metadata.json", tdb.RECORD_NAME)
OCI_ACCEPT = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json"


def load_config(path: Path = CONFIG) -> dict:
    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    repos = [str(r) for r in d.get("repositories") or []]
    if not repos:
        raise SystemExit(f"ERROR: {path} lists no repositories")
    return {"repositories": repos, "max_age_hours": float(d.get("max_age_hours", 48))}


def locked_version(lock: Path = ROOT / pins.LOCK) -> str:
    return pins.locked_version("trivy", lock)


class PinError(RuntimeError):
    """trivy is missing from the tools directory or its version is not the locked one."""


def pinned_trivy() -> Path:
    exe = tool_path("trivy")
    if exe is None:
        raise PinError(f"trivy is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)")
    want, have = locked_version(), installed_version("trivy")
    not_pinned = pins.mismatch("trivy", want, have)
    if not_pinned:
        raise PinError(not_pinned)
    return exe


def split_ref(ref: str) -> tuple[str, str, str]:
    """'host/path:tag' or 'host/path@sha256:...' -> (host, path, reference)."""
    host, _, rest = ref.partition("/")
    if "@" in rest:
        path, _, reference = rest.partition("@")
    else:
        path, _, reference = rest.rpartition(":") if ":" in rest else (rest, "", "latest")
    return host, path, reference


def head_manifest(ref: str, timeout: int = 20) -> dict:
    """OCI manifest digest, layer digest and created annotation from the registry; 'unknown' when unreachable.
    Anonymous on mirror.gcr.io; ghcr.io hands out a pull token without credentials."""
    host, path, reference = split_ref(ref)
    out = {"manifest_digest": "unknown", "layer_digest": "unknown", "created": "unknown"}
    headers = {"Accept": OCI_ACCEPT, "User-Agent": "mara-trivy-db/1"}
    try:
        if host == "ghcr.io":
            with urllib.request.urlopen(urllib.request.Request(f"https://ghcr.io/token?scope=repository:{path}:pull", headers=headers), timeout=timeout) as r:
                headers["Authorization"] = "Bearer " + json.loads(r.read().decode())["token"]
        req = urllib.request.Request(f"https://{host}/v2/{path}/manifests/{reference}", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out["manifest_digest"] = r.headers.get("Docker-Content-Digest", "unknown")
            body = json.loads(r.read().decode())
        layers = body.get("layers") or []
        if layers:
            out["layer_digest"] = layers[0].get("digest", "unknown")
        out["created"] = (body.get("annotations") or {}).get("org.opencontainers.image.created", "unknown")
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        out["error"] = str(e)[:200]
    return out


def cmd_download(a: argparse.Namespace) -> int:
    cfg = load_config()
    exe = pinned_trivy()
    cache = a.cache_dir.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    repos = [a.repository] if a.repository else cfg["repositories"]
    pin = (a.pin_digest or "").strip().lower()
    if a.pin_digest:
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", pin):
            print("ERROR: --pin-digest must be sha256: followed by 64 hex digits", file=sys.stderr)
            return 2
        repos = [f"{split_ref(r)[0]}/{split_ref(r)[1]}@{pin}" for r in repos]
    last = ""
    for ref in repos:
        info = head_manifest(ref)
        print(f"registry {ref}: manifest {info['manifest_digest']} layer {info['layer_digest']} created {info['created']}"
              + (f" (registry query failed: {info['error']})" if "error" in info else ""))
        digest = info["manifest_digest"]
        if pin and digest.startswith("sha256:") and digest.lower() != pin:
            # the download below would fetch the digest the registry named, not the pin: refuse it
            last = f"{ref}: the registry answered with manifest {digest}, not the pinned {pin}; refusing it"
            print(f"  {last}; trying the next repository" if ref != repos[-1] else f"  {last}")
            continue
        if not digest.startswith("sha256:"):
            if not a.allow_unknown_provenance:
                last = (f"{ref}: the registry did not name the manifest digest, so the record could not say what was "
                        "downloaded (pass --allow-unknown-provenance to accept that)")
                print(f"  {last}; trying the next repository" if ref != repos[-1] else f"  {last}")
                continue
            fetch_ref = ref
        else:
            # download exactly the manifest the registry just named: by tag, the artifact could move between the
            # query and the download (upstream refreshes it every six hours) and the record would name another one
            host, path, _ = split_ref(ref)
            fetch_ref = f"{host}/{path}@{digest}"
        argv = [str(exe), "--cache-dir", str(cache), "image", "--download-db-only", "--db-repository", fetch_ref]
        print("+ " + " ".join(argv))
        r = subprocess.run(argv, capture_output=True, text=True)
        last = "\n".join(line for line in (r.stderr + r.stdout).splitlines() if "MiB /" not in line)[-1200:]
        if r.returncode == 0 and tdb.db_path(cache).is_file():
            meta = tdb.read_metadata(cache) or {}
            ver = subprocess.run([str(exe), "--version"], capture_output=True, text=True).stdout
            trivy_version = next((line.split()[-1] for line in ver.splitlines() if line.startswith("Version:")), installed_version("trivy"))
            rec = {"repository": ref, "downloaded_ref": fetch_ref, "provenance": "digest" if digest.startswith("sha256:") else "unverified",
                   **({"pinned_digest": pin} if pin else {}),
                   "manifest_digest": info["manifest_digest"], "layer_digest": info["layer_digest"], "created": info["created"],
                   "metadata": meta, "trivy_db_sha256": tdb.sha256_file(tdb.db_path(cache)), "trivy_db_bytes": tdb.db_path(cache).stat().st_size,
                   "trivy_version": trivy_version, "downloaded_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds")}
            tdb.record_path(cache).write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
            print(f"database UpdatedAt {meta.get('UpdatedAt')} NextUpdate {meta.get('NextUpdate')}; trivy.db sha256 {rec['trivy_db_sha256'][:16]}… "
                  f"({rec['trivy_db_bytes']} bytes); record {tdb.record_path(cache)}")
            return 0
        print(f"  download from {ref} failed (exit {r.returncode}); trying the next repository" if ref != repos[-1] else f"  exit {r.returncode}")
    print(f"ERROR: could not download the database from {repos}\n{last}", file=sys.stderr)
    return 1


def cmd_status(a: argparse.Namespace) -> int:
    max_age = a.max_age_hours if a.max_age_hours is not None else load_config()["max_age_hours"]
    ok, lines = tdb.check(a.cache_dir.resolve(), max_age)
    for line in lines:
        print(("  " if ok else "ERROR: ") + line)
    print("offline database " + ("OK" if ok else "NOT usable"))
    return 0 if ok else 1


def cmd_export(a: argparse.Namespace) -> int:
    cache = a.cache_dir.resolve()
    ok, lines = tdb.check(cache, float("inf"))
    if not ok:
        for line in lines:
            print("ERROR: " + line, file=sys.stderr)
        return 1
    out = a.out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tf:
        for m in BUNDLE_MEMBERS:
            tf.add(cache / m, arcname=m)
    digest = tdb.sha256_file(out)
    out.with_name(out.name + ".sha256").write_text(f"{digest}  {out.name}\n", encoding="utf-8")
    rec = tdb.read_record(cache) or {}
    print(f"wrote {out} ({out.stat().st_size} bytes) sha256 {digest}\n  database UpdatedAt {rec.get('metadata', {}).get('UpdatedAt')} from {rec.get('repository')}"
          f"\n  carry the bundle to the isolated runner, send this digest separately (ticket, chat, signed note), and run:"
          f"\n  scripts/trivy_db.py import --bundle {out.name} --bundle-sha256 {digest}")
    return 0


def cmd_import(a: argparse.Namespace) -> int:
    bundle = a.bundle.resolve()
    if not bundle.is_file():
        print(f"ERROR: bundle {bundle} not found", file=sys.stderr)
        return 2
    # The expected digest must come from somewhere other than the bundle: the .sha256 file travels with it, and
    # whoever can alter the bundle in transit can rewrite a self-consistent database, record and sidecar together.
    # Without --bundle-sha256 the import is refused unless --trust-bundle accepts that risk explicitly.
    if not a.bundle_sha256 and not a.trust_bundle:
        print("ERROR: --bundle-sha256 is required: pass the digest `export` printed, obtained through a channel other than "
              "the one that carried the bundle (or --trust-bundle to accept the bundle's own consistency)", file=sys.stderr)
        return 2
    if a.bundle_sha256:
        got = tdb.sha256_file(bundle)
        if got != a.bundle_sha256.strip().lower():
            print(f"ERROR: bundle sha256 {got} does not match the expected {a.bundle_sha256}", file=sys.stderr)
            return 1
    cache = a.cache_dir.resolve()
    staging = cache.parent / (cache.name + ".importing")
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)
    try:
        with tarfile.open(bundle, "r:gz") as tf:
            names = {m.name for m in tf.getmembers()}
            missing = [m for m in BUNDLE_MEMBERS if m not in names]
            if missing or names - set(BUNDLE_MEMBERS):
                print(f"ERROR: bundle members {sorted(names)} are not exactly {list(BUNDLE_MEMBERS)}", file=sys.stderr)
                return 1
            for m in tf.getmembers():
                if not m.isfile() or ".." in Path(m.name).parts or Path(m.name).is_absolute():
                    print(f"ERROR: refusing unsafe bundle member {m.name}", file=sys.stderr)
                    return 1
                dest = staging / m.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                src = tf.extractfile(m)
                assert src is not None
                with dest.open("wb") as out:
                    shutil.copyfileobj(src, out)
        rec = tdb.read_record(staging) or {}
        digest = tdb.sha256_file(tdb.db_path(staging))
        if digest != rec.get("trivy_db_sha256"):
            print(f"ERROR: trivy.db sha256 {digest} does not match the record in the bundle ({rec.get('trivy_db_sha256')}); refusing to import", file=sys.stderr)
            return 1
        cache.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(cache / "db", ignore_errors=True)
        shutil.move(str(staging / "db"), str(cache / "db"))
        shutil.move(str(staging / tdb.RECORD_NAME), str(tdb.record_path(cache)))
        print(f"imported database UpdatedAt {rec.get('metadata', {}).get('UpdatedAt')} (sha256 {digest[:16]}…) from {rec.get('repository')} into {cache}")
        return 0
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cache-dir", type=Path, default=tdb.cache_dir(), help="default MARA_TRIVY_CACHE_DIR or MARA_TOOLS_DIR/trivy-cache")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("download")
    s.add_argument("--repository", help="OCI reference to use instead of tools/trivy-db.yaml")
    s.add_argument("--pin-digest", help="sha256:<hex> manifest digest to fetch instead of the tag")
    s.add_argument("--allow-unknown-provenance", action="store_true",
                   help="download by tag even when the registry does not name the manifest digest; the record then says "
                        "provenance: unverified (never in CI)")
    s = sub.add_parser("status")
    s.add_argument("--max-age-hours", type=float)
    s = sub.add_parser("export")
    s.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("import")
    s.add_argument("--bundle", type=Path, required=True)
    s.add_argument("--bundle-sha256", help="expected sha256 of the bundle file, as `export` printed it, obtained out of band "
                   "(not from the .sha256 file that travels with the bundle); required unless --trust-bundle")
    s.add_argument("--trust-bundle", action="store_true",
                   help="import without --bundle-sha256, relying only on the bundle's own record (never in CI)")
    a = ap.parse_args(argv)
    try:
        return {"download": cmd_download, "status": cmd_status, "export": cmd_export, "import": cmd_import}[a.cmd](a)
    except PinError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    except (OSError, tarfile.TarError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
