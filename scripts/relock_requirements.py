"""Write a hash-pinned requirements file (a full dependency closure) from a pip resolution.

  python3 scripts/relock_requirements.py --from-pyproject dev --out tools/dev-requirements.txt
  python3 scripts/relock_requirements.py --in tools/model-eval-requirements.in --out tools/model-eval-requirements.txt --allow-sdist

pip resolves the closure with `pip install --dry-run --report` (nothing is installed) and reports, for
every distribution it picked, the exact file it would download and that file's SHA-256 as published
by the index. The output lists every distribution as `name==version --hash=sha256:...`, sorted, so
that `pip install --require-hashes -r <file>` refuses anything that differs from what was resolved
here. The closure is specific to the interpreter and platform it was resolved on (CPython 3.11 /
Linux x86_64, the CI and L0 hosts); the script refuses to run elsewhere unless --any-platform is
given, and the header records what it was resolved on.

--only-binary=:all: is the default: every entry must be a wheel, so an install needs no build step.
--allow-sdist admits source distributions for projects that publish no wheel (their hash is pinned
just the same); installing them builds in an isolated environment whose build tools pip fetches
without hash checking, which is why the header names every sdist and why the wheel-only closures
keep the default.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import sysconfig
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (3, 11)
EXPECTED_PLATFORM_PREFIX = "linux-x86_64"


class RelockError(Exception):
    pass


def requirements_from_pyproject(path: Path, extras: list[str]) -> list[str]:
    doc = tomllib.loads(path.read_text(encoding="utf-8"))
    project = doc.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    optional = project.get("optional-dependencies") or {}
    for extra in extras:
        if extra not in optional:
            raise RelockError(f"{path}: no optional-dependencies group {extra!r} (have {sorted(optional)})")
        reqs.extend(optional[extra])
    return reqs


def requirements_from_file(path: Path) -> list[str]:
    reqs = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            reqs.append(line)
    if not reqs:
        raise RelockError(f"{path}: no requirements")
    return reqs


def check_host(any_platform: bool) -> str:
    plat = sysconfig.get_platform()
    py = ".".join(str(v) for v in sys.version_info[:3])
    if not any_platform:
        if sys.version_info[:2] != EXPECTED_PYTHON:
            raise RelockError(f"resolve on CPython {EXPECTED_PYTHON[0]}.{EXPECTED_PYTHON[1]} (this is {py}); the closure is interpreter-specific")
        if not plat.startswith(EXPECTED_PLATFORM_PREFIX):
            raise RelockError(f"resolve on {EXPECTED_PLATFORM_PREFIX} (this is {plat}); the closure is platform-specific")
    return f"CPython {py} / {plat}"


def resolve(reqs: list[str], allow_sdist: bool, workdir: Path) -> dict:
    req_file = workdir / "requirements.in"
    req_file.write_text("".join(r + "\n" for r in reqs), encoding="utf-8")
    report = workdir / "report.json"
    argv = [sys.executable, "-m", "pip", "install", "--dry-run", "--ignore-installed", "--disable-pip-version-check", "--quiet",
            "--report", str(report)]
    if not allow_sdist:
        argv.append("--only-binary=:all:")
    argv += ["-r", str(req_file)]
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    if r.returncode != 0 or not report.is_file():
        raise RelockError(f"pip could not resolve the closure (exit {r.returncode}):\n{(r.stderr or r.stdout).strip()[-2000:]}")
    return json.loads(report.read_text(encoding="utf-8"))


def entries_from_report(report: dict) -> list[dict]:
    """[{name, version, sha256, filename, sdist}] sorted by name; every entry must carry a sha256."""
    out, missing = [], []
    for item in report.get("install", []):
        meta = item.get("metadata") or {}
        info = item.get("download_info") or {}
        url = str(info.get("url", ""))
        sha = ((info.get("archive_info") or {}).get("hashes") or {}).get("sha256")
        name, version = str(meta.get("name", "")), str(meta.get("version", ""))
        if not name or not version:
            raise RelockError(f"report entry without name/version: {item}")
        if not sha:
            missing.append(f"{name}=={version}")
            continue
        out.append({"name": name, "version": version, "sha256": sha, "filename": url.rsplit("/", 1)[-1],
                    "sdist": not url.endswith(".whl")})
    if missing:
        raise RelockError("no sha256 in the index for: " + ", ".join(missing) + " (refusing to write an unpinned entry)")
    if not out:
        raise RelockError("pip resolved nothing")
    out.sort(key=lambda e: (e["name"].lower(), e["version"]))
    return out


def render(entries: list[dict], *, title: str, source: str, host: str, pip_version: str, regenerate: str, allow_sdist: bool) -> str:
    sdists = [e for e in entries if e["sdist"]]
    lines = [
        f"# {title}: hash-pinned dependency closure, {len(entries)} distribution(s), resolved {dt.date.today().isoformat()}",
        f"# on {host} with pip {pip_version} from {source}. Do not edit by hand; regenerate with",
        f"#   {regenerate}",
        "# Install: python3 -m pip install --require-hashes " + ("" if allow_sdist else "--only-binary=:all: ") + "-r <this file>",
    ]
    if sdists:
        lines.append("# Source distributions (no wheel published; built at install time, see scripts/relock_requirements.py): "
                     + ", ".join(f"{e['name']}=={e['version']}" for e in sdists))
    body = "".join(f"{e['name']}=={e['version']} \\\n    --hash=sha256:{e['sha256']}\n" for e in entries)
    return "\n".join(lines) + "\n" + body


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--from-pyproject", nargs="*", metavar="EXTRA", help="pyproject.toml dependencies plus these optional groups")
    src.add_argument("--in", dest="infile", type=Path, metavar="FILE", help="a requirements.in with the top-level requirements")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--title", default="", help="first words of the header (default: derived from --out)")
    ap.add_argument("--allow-sdist", action="store_true", help="admit source distributions (default: wheels only)")
    ap.add_argument("--any-platform", action="store_true", help="skip the CPython 3.11 / linux-x86_64 host check")
    ap.add_argument("--report", type=Path, help="use this pip --report JSON instead of resolving (tests)")
    a = ap.parse_args()

    try:
        host = check_host(a.any_platform)
        if a.infile is not None:
            reqs = requirements_from_file(a.infile)
            source = a.infile.as_posix()
            regenerate = f"python3 scripts/relock_requirements.py --in {source} --out {a.out.as_posix()}" + (" --allow-sdist" if a.allow_sdist else "")
        else:
            reqs = requirements_from_pyproject(ROOT / "pyproject.toml", a.from_pyproject)
            source = "pyproject.toml" + (f" [{', '.join(a.from_pyproject)}]" if a.from_pyproject else "")
            regenerate = f"python3 scripts/relock_requirements.py --from-pyproject {' '.join(a.from_pyproject)} --out {a.out.as_posix()}".rstrip() + (" --allow-sdist" if a.allow_sdist else "")
        if a.report is not None:
            report = json.loads(a.report.read_text(encoding="utf-8"))
        else:
            with tempfile.TemporaryDirectory(prefix="relock-") as tmp:
                report = resolve(reqs, a.allow_sdist, Path(tmp))
        entries = entries_from_report(report)
        if not a.allow_sdist and any(e["sdist"] for e in entries):
            raise RelockError("the report contains source distributions; pass --allow-sdist to admit them")
        title = a.title or a.out.name.replace("-requirements.txt", "").replace("-", " ")
        text = render(entries, title=title, source=source, host=host, pip_version=str(report.get("pip_version", "?")),
                      regenerate=regenerate, allow_sdist=a.allow_sdist)
        a.out.write_text(text, encoding="utf-8")
    except RelockError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    sd = sum(1 for e in entries if e["sdist"])
    print(f"wrote {a.out} ({len(entries)} distributions, {sd} sdist) from {source} on {host}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
