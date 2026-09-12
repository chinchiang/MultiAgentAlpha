"""Install the L0 tools pinned in tools/versions.lock into .mara-tools/ (Appendix E prompt 7).

For every tool: download the asset (or wheels), check its SHA-256 against the lock, run the
publisher-side verification named in the lock (cosign keyless bundle, SLSA provenance, GitHub
attestation, publisher checksum file, or pip --require-hashes), then install into
<install_dir>/bin. Any hash mismatch or failed verification aborts with a message and nothing of
that tool is installed. The SHA-256 check can never be skipped; --no-signature-check skips only
the publisher-side step (for networks that block Sigstore's TUF root) and is recorded in the
manifest as signature_verified: false.

Usage:
  python scripts/install_tools.py                 # everything in the lock
  python scripts/install_tools.py --only zizmor trivy
  python scripts/install_tools.py --relock-semgrep <dir of wheels>   # rewrite the hash-pinned requirements
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "tools" / "versions.lock"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_METHODS = {"cosign-keyless", "slsa-provenance", "github-attestation"}


class InstallError(RuntimeError):
    """Raised on any verification failure; the message says which tool and why."""


# ----------------------------------------------------------------------------- helpers


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path, *, retries: int = 3, timeout: int = 600) -> Path:
    """Fetch url to dest (file:// allowed for tests). Writes to a temp file then renames."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if url.startswith("file://"):
        shutil.copyfile(url[len("file://"):], dest)
        return dest
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "mara-install-tools/1"})
            with urllib.request.urlopen(req, timeout=timeout) as r, tmp.open("wb") as out:
                shutil.copyfileobj(r, out, length=1 << 20)
            tmp.replace(dest)
            return dest
        except (urllib.error.URLError, OSError) as e:  # noqa: PERF203
            last = e
            tmp.unlink(missing_ok=True)
            print(f"  download attempt {attempt}/{retries} failed: {e}")
    raise InstallError(f"could not download {url}: {last}")


def run(cmd: list[str], *, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def load_lock(path: Path) -> dict:
    lock = yaml.safe_load(path.read_text(encoding="utf-8"))
    if lock.get("schema") != 1 or "tools" not in lock:
        raise InstallError(f"{path}: unsupported lock schema")
    for name, t in lock["tools"].items():
        if t.get("kind") in ("binary", "archive"):
            for key in ("version", "url", "sha256", "verify"):
                if key not in t:
                    raise InstallError(f"{path}: tool {name} lacks '{key}'")
            if not SHA_RE.match(str(t["sha256"])):
                raise InstallError(f"{path}: tool {name} has a malformed sha256")
        elif t.get("kind") == "pip":
            for key in ("version", "requirements", "verify"):
                if key not in t:
                    raise InstallError(f"{path}: tool {name} lacks '{key}'")
        else:
            raise InstallError(f"{path}: tool {name} has unknown kind {t.get('kind')!r}")
    return lock


# ----------------------------------------------------------------------------- verification


def check_sha256(name: str, path: Path, expected: str) -> str:
    actual = sha256_file(path)
    if actual != expected:
        raise InstallError(f"{name}: SHA-256 mismatch for {path.name}\n  expected {expected}\n  actual   {actual}\n  The lock or the download is wrong; nothing was installed.")
    return actual


def check_publisher_checksums(name: str, asset_name: str, expected: str, checksums_url: str, cache: Path) -> None:
    """The publisher's checksum file must list exactly the pinned SHA-256 for this asset."""
    path = download(checksums_url, cache / f"{name}.publisher-checksums.txt")
    listed = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == asset_name and SHA_RE.match(parts[0]):
            listed = parts[0]
            break  # first match wins: for SHA256SUM.md-style files the newest section comes first
    if listed is None:
        raise InstallError(f"{name}: publisher checksum file {checksums_url} does not list {asset_name}")
    if listed != expected:
        raise InstallError(f"{name}: publisher checksum {listed} differs from the pinned {expected} for {asset_name}")


def need_tool(bin_dir: Path, tool: str, method: str, name: str, self_artifact: Path | None = None) -> Path:
    """Locate the verifier binary. A verifier verifying its own release (cosign checking cosign's bundle,
    slsa-verifier checking its own provenance) uses the freshly downloaded, SHA-256-checked artifact,
    because it is not installed yet at that point."""
    if self_artifact is not None and name == tool:
        self_artifact.chmod(self_artifact.stat().st_mode | stat.S_IXUSR)
        return self_artifact
    p = bin_dir / tool
    if p.is_file() and os.access(p, os.X_OK):
        return p
    found = shutil.which(tool) if tool == "gh" else None  # gh is the only verifier we accept from PATH
    if found:
        return Path(found)
    raise InstallError(f"{name}: verification method {method} needs '{tool}' but it is not installed "
                       f"({p} missing). Install verifiers first or pass --no-signature-check (never in CI).")


def verify_signature(name: str, spec: dict, artifact: Path, bin_dir: Path, cache: Path) -> str:
    v = spec["verify"]
    method = v["method"]
    if method == "cosign-keyless":
        cosign = need_tool(bin_dir, "cosign", method, name, self_artifact=artifact)
        bundle = download(v["bundle_url"], cache / f"{name}.sigstore.json")
        cp = run([str(cosign), "verify-blob", "--bundle", str(bundle), "--certificate-oidc-issuer", v["oidc_issuer"],
                  "--certificate-identity-regexp", v["certificate_identity_regexp"], str(artifact)])
        if cp.returncode != 0:
            raise InstallError(f"{name}: cosign keyless verification FAILED\n{cp.stderr.strip()[-1500:]}")
        return f"cosign-keyless identity~{v['certificate_identity_regexp']} issuer={v['oidc_issuer']}"
    if method == "slsa-provenance":
        verifier = need_tool(bin_dir, "slsa-verifier", method, name, self_artifact=artifact)
        prov = download(v["provenance_url"], cache / f"{name}.intoto.jsonl")
        cp = run([str(verifier), "verify-artifact", str(artifact), "--provenance-path", str(prov),
                  "--source-uri", v["source_uri"], "--source-tag", v["source_tag"]])
        if cp.returncode != 0:
            raise InstallError(f"{name}: SLSA provenance verification FAILED\n{(cp.stderr or cp.stdout).strip()[-1500:]}")
        return f"slsa-provenance source={v['source_uri']}@{v['source_tag']}"
    if method == "github-attestation":
        gh = need_tool(bin_dir, "gh", method, name)
        env = dict(os.environ)
        if "GH_TOKEN" not in env and env.get("GITHUB_TOKEN"):
            env["GH_TOKEN"] = env["GITHUB_TOKEN"]
        cp = run([str(gh), "attestation", "verify", str(artifact), "--repo", v["repo"]], env=env)
        if cp.returncode != 0:
            raise InstallError(f"{name}: GitHub attestation verification FAILED\n{(cp.stderr or cp.stdout).strip()[-1500:]}")
        return f"github-attestation repo={v['repo']}"
    if method == "checksums-file":
        return "checksums-file (publisher checksum matched; no signature published)"
    raise InstallError(f"{name}: unknown verify method {method!r}")


# ----------------------------------------------------------------------------- install


def extract_member(name: str, archive: Path, member: str, dest: Path) -> None:
    with tarfile.open(archive, "r:*") as tf:
        hit = None
        for m in tf.getmembers():
            if m.isfile() and (m.name == member or m.name.endswith("/" + member)):
                hit = m
                break
        if hit is None:
            raise InstallError(f"{name}: archive {archive.name} has no member named {member}")
        if hit.issym() or hit.islnk() or ".." in Path(hit.name).parts:
            raise InstallError(f"{name}: refusing unsafe archive member {hit.name}")
        src = tf.extractfile(hit)
        assert src is not None
        with dest.open("wb") as out:
            shutil.copyfileobj(src, out)


def install_binary_or_archive(name: str, spec: dict, *, bin_dir: Path, cache: Path, no_signature_check: bool) -> dict:
    url = spec["url"]
    asset_name = url.rsplit("/", 1)[-1]
    print(f"[{name}] {spec['version']}: downloading {asset_name}")
    asset = download(url, cache / asset_name)
    digest = check_sha256(name, asset, spec["sha256"])
    print(f"[{name}] sha256 ok {digest[:16]}…")
    if spec.get("publisher_checksums_url"):
        check_publisher_checksums(name, asset_name, spec["sha256"], spec["publisher_checksums_url"], cache)
        print(f"[{name}] publisher checksum file agrees")
    method = spec["verify"]["method"]
    if method in SIGNATURE_METHODS and no_signature_check:
        verified_by = f"{method} SKIPPED (--no-signature-check)"
        signature_verified = False
        print(f"[{name}] WARNING: {method} skipped by --no-signature-check")
    else:
        verified_by = verify_signature(name, spec, asset, bin_dir, cache)
        signature_verified = method in SIGNATURE_METHODS
        print(f"[{name}] {verified_by}")
    target = bin_dir / name
    tmp = target.with_suffix(".installing")
    if spec["kind"] == "archive":
        extract_member(name, asset, spec["extract"], tmp)
    else:
        shutil.copyfile(asset, tmp)
    tmp.chmod(tmp.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp.replace(target)
    return {"version": str(spec["version"]), "kind": spec["kind"], "url": url, "sha256": digest,
            "verified_by": verified_by, "signature_verified": signature_verified, "path": str(target)}


def python_for_pip(lock: dict) -> Path:
    """The interpreter the wheel hashes were locked for (lock platform.python). Wheels are ABI-specific,
    so pip under any other CPython would resolve different files and the hash check would fail."""
    want = str(lock.get("platform", {}).get("python", "3.11"))
    if f"{sys.version_info.major}.{sys.version_info.minor}" == want:
        return Path(sys.executable)
    found = shutil.which(f"python{want}")
    if found:
        return Path(found)
    raise InstallError(f"the pip-locked tools need CPython {want} (lock platform.python) but only "
                       f"{sys.version.split()[0]} is available and python{want} is not on PATH; "
                       "install it (CI: actions/setup-python) or relock for the interpreter you run")


def install_pip(name: str, spec: dict, *, install_dir: Path, bin_dir: Path, python: Path) -> dict:
    req = (ROOT / spec["requirements"]).resolve()
    if not req.is_file():
        raise InstallError(f"{name}: requirements file {req} missing")
    text = req.read_text(encoding="utf-8")
    if "--hash=sha256:" not in text:
        raise InstallError(f"{name}: {req.name} carries no hashes; refusing to install")
    pin = re.search(rf"^{re.escape(name)}=={re.escape(str(spec['version']))}\b", text, re.M)
    if not pin:
        raise InstallError(f"{name}: {req.name} does not pin {name}=={spec['version']}")
    venv_dir = install_dir / f"{name}-venv"
    print(f"[{name}] {spec['version']}: creating venv {venv_dir} with {python} and installing with --require-hashes")
    cp = run([str(python), "-m", "venv", "--clear", str(venv_dir)])
    if cp.returncode != 0:
        raise InstallError(f"{name}: could not create venv with {python}\n{cp.stderr.strip()[-800:]}")
    pip = [str(venv_dir / "bin" / "python"), "-m", "pip"]
    cp = run(pip + ["install", "--quiet", "--disable-pip-version-check", "--require-hashes", "--only-binary=:all:", "-r", str(req)])
    if cp.returncode != 0:
        shutil.rmtree(venv_dir, ignore_errors=True)
        raise InstallError(f"{name}: pip --require-hashes install FAILED\n{(cp.stderr or cp.stdout).strip()[-2000:]}")
    exe = venv_dir / "bin" / name
    if not exe.is_file():
        raise InstallError(f"{name}: venv has no {exe}")
    link = bin_dir / name
    link.unlink(missing_ok=True)
    link.symlink_to(exe)
    return {"version": str(spec["version"]), "kind": "pip", "requirements": spec["requirements"],
            "sha256": hashlib.sha256(text.encode()).hexdigest(), "verified_by": "pip-hashes (every wheel hash-pinned)",
            "signature_verified": False, "path": str(link)}


def install(lock: dict, *, install_dir: Path, only: list[str] | None = None, no_signature_check: bool = False) -> dict:
    bin_dir = install_dir / "bin"
    cache = install_dir / "cache"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    tools = lock["tools"]
    names = [n for n in tools if not only or n in only]
    unknown = [n for n in (only or []) if n not in tools]
    if unknown:
        raise InstallError(f"unknown tool(s) {unknown}; lock has {list(tools)}")
    # verifiers first, then everything else, so cosign/slsa-verifier exist before they are needed
    names.sort(key=lambda n: (tools[n].get("role") != "verifier", list(tools).index(n)))
    manifest_path = install_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {"tools": {}}
    python = python_for_pip(lock) if any(tools[n]["kind"] == "pip" for n in names) else None
    for n in names:
        spec = tools[n]
        if spec["kind"] == "pip":
            assert python is not None
            entry = install_pip(n, spec, install_dir=install_dir, bin_dir=bin_dir, python=python)
        else:
            entry = install_binary_or_archive(n, spec, bin_dir=bin_dir, cache=cache, no_signature_check=no_signature_check)
        entry["installed_at"] = dt.datetime.now(dt.UTC).isoformat(timespec="seconds")
        manifest["tools"][n] = entry
        manifest["lock_sha256"] = lock.get("_sha256")
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"[{n}] installed -> {entry['path']}")
    return manifest


def relock_semgrep(wheel_dir: Path, req_path: Path, version: str) -> int:
    rows = []
    for p in sorted(wheel_dir.glob("*.whl"), key=lambda q: q.name.lower()):
        dist, ver = p.name.split("-")[0], p.name.split("-")[1]
        rows.append((dist.replace("_", "-"), ver, sha256_file(p)))
    if not any(n == "semgrep" and v == version for n, v, _ in rows):
        raise InstallError(f"{wheel_dir} has no semgrep-{version} wheel")
    req_path.write_text(
        "# semgrep and its full dependency closure, hash-pinned for CPython 3.11 / manylinux x86_64.\n"
        "# Regenerate with scripts/install_tools.py --relock-semgrep (see docs/tools-provenance.md).\n"
        + "".join(f"{n}=={v} \\\n    --hash=sha256:{h}\n" for n, v, h in rows), encoding="utf-8")
    print(f"wrote {req_path} ({len(rows)} wheels)")
    return len(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    ap.add_argument("--dest", type=Path, help="install dir (default: lock's install_dir, relative to the repo root)")
    ap.add_argument("--only", nargs="+", metavar="TOOL")
    ap.add_argument("--no-signature-check", action="store_true", help="skip publisher signature/provenance checks (SHA-256 still enforced); never in CI")
    ap.add_argument("--relock-semgrep", type=Path, metavar="WHEEL_DIR", help="rewrite tools/semgrep-requirements.txt from a directory of wheels")
    args = ap.parse_args()
    try:
        lock = load_lock(args.lock)
        lock["_sha256"] = sha256_file(args.lock)
        if args.relock_semgrep:
            spec = lock["tools"]["semgrep"]
            relock_semgrep(args.relock_semgrep, ROOT / spec["requirements"], str(spec["version"]))
            return 0
        install_dir = (args.dest or (ROOT / lock.get("install_dir", ".mara-tools"))).resolve()
        manifest = install(lock, install_dir=install_dir, only=args.only, no_signature_check=args.no_signature_check)
        unsigned = [n for n, e in manifest["tools"].items() if not e["signature_verified"]]
        print(f"\ninstalled {len(manifest['tools'])} tool(s) into {install_dir}/bin; manifest: {install_dir / 'manifest.json'}")
        if unsigned:
            print(f"signature/provenance NOT verified for: {', '.join(unsigned)} (see manifest and docs/tools-provenance.md)")
        return 0
    except InstallError as e:
        print(f"\nINSTALL ABORTED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
