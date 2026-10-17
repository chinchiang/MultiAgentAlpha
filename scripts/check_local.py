"""Before a push, four of the checks CI runs on a pull request, run here with every output kept.

  .venv/bin/python scripts/check_local.py                     # ruff, mypy, the whole suite, gitleaks on the branch
  .venv/bin/python scripts/check_local.py --only ruff mypy    # some of them
  .venv/bin/python scripts/check_local.py --base origin/main  # the base gitleaks scans from (default origin/main)

Run it with the dev environment's interpreter: ruff and pytest come from it. Each check writes its whole output to
out/check-local/<UTC time>/<check>.log and the summary names the log of every check that failed, so a failure is
always there to read afterwards. The checks, as .github/workflows/mara-review.yml runs them:
  ruff      ruff check src tests scripts
  mypy      python -m mypy from .venv-typecheck: CPython 3.12 with the hash-pinned closure CI installs (the 3.12 dev
            requirements, the build requirements, this package without its dependencies, the typecheck requirements),
            built on first use and again whenever one of those requirement files changes
  pytest    GITHUB_ACTIONS=true pytest -q -rs (CI colours CLI output), after clearing src/ and tests/ of compiled
            bytecode, which can keep a same-size edit made within a second from taking effect
  gitleaks  scripts/gitleaks_ci.py --event pull_request over the commits since the merge base with --base
Not run here: the whole suite on CPython 3.12, the repository scanners (semgrep, osv-scanner, trivy, zizmor,
csp-evaluator), the two mock reviews and the ML-BOM check of mara-review.yml, and docs-check.yml.
When a check that reads the branch's commits (gitleaks) ran and the working tree has changes git status lists, the
summary warns that it did not see them. Exit 0 when every check passed, 1 otherwise; the warning changes neither.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TYPECHECK_VENV = ROOT / ".venv-typecheck"
# the 3.12 closure the CI type-check job installs, in its order (the package itself goes in after the first two)
TYPECHECK_REQUIREMENTS = ("tools/dev-requirements-py312.txt", "tools/build-requirements.txt", "tools/typecheck-requirements.txt")
RUFF_PATHS = ("src", "tests", "scripts")


def _pip(python: Path, *args: str) -> None:
    subprocess.run([str(python), "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *args], cwd=ROOT, check=True)


def typecheck_python(python312: str) -> Path:
    """The interpreter of .venv-typecheck, built (or rebuilt, when a requirement file changed) from `python312`."""
    stamp = TYPECHECK_VENV / "requirements.sha256"
    digest = hashlib.sha256(b"".join((ROOT / r).read_bytes() for r in TYPECHECK_REQUIREMENTS)).hexdigest()
    python = TYPECHECK_VENV / "bin" / "python"
    if python.exists() and stamp.is_file() and stamp.read_text(encoding="utf-8").strip() == digest:
        return python
    shutil.rmtree(TYPECHECK_VENV, ignore_errors=True)
    subprocess.run([python312, "-m", "venv", str(TYPECHECK_VENV)], check=True)
    pinned = ("--require-hashes", "--only-binary=:all:")
    _pip(python, *pinned, "-r", TYPECHECK_REQUIREMENTS[0])
    _pip(python, *pinned, "-r", TYPECHECK_REQUIREMENTS[1])
    _pip(python, "--no-deps", "--no-build-isolation", "-e", ".")
    _pip(python, *pinned, "-r", TYPECHECK_REQUIREMENTS[2])
    stamp.write_text(digest + "\n", encoding="utf-8")
    return python


def _clear_bytecode() -> None:
    for top in ("src", "tests"):
        for pyc in (ROOT / top).rglob("*.pyc"):
            pyc.unlink(missing_ok=True)


# each check: (argv, extra environment, what to do first)
Check = Callable[[argparse.Namespace], tuple[list[str], dict[str, str], Callable[[], None] | None]]
CHECKS: dict[str, Check] = {
    "ruff": lambda a: ([sys.executable, "-m", "ruff", "check", *RUFF_PATHS], {}, None),
    "mypy": lambda a: ([str(typecheck_python(a.python312)), "-m", "mypy"], {}, None),
    "pytest": lambda a: ([sys.executable, "-m", "pytest", "-q", "-rs"], {"GITHUB_ACTIONS": "true"},
                         _clear_bytecode),
    "gitleaks": lambda a: ([sys.executable, str(ROOT / "scripts" / "gitleaks_ci.py"), "--base", a.base, "--head", "HEAD",
                            "--event", "pull_request", "--report", str(a.logs / "gitleaks.sarif")], {}, None),
}


COMMIT_CHECKS = ("gitleaks",)  # the checks that read the branch's commits, not the working tree


def uncommitted(root: Path) -> list[str]:
    """The changes `git status --porcelain` lists under `root`, tracked and untracked; why git could not tell, if so."""
    cp = subprocess.run(["git", "-C", str(root), "status", "--porcelain"], capture_output=True, text=True)
    return cp.stdout.splitlines() if cp.returncode == 0 else [f"git status failed: {cp.stderr.strip()}"]


def run_check(name: str, check: Check, a: argparse.Namespace) -> int:
    """Run one check with its whole output (stdout and stderr) in <logs>/<name>.log; its exit code."""
    log = a.logs / f"{name}.log"
    with log.open("w", encoding="utf-8") as out:
        try:
            argv, env, first = check(a)
            if first is not None:
                first()
        except (OSError, subprocess.CalledProcessError) as e:
            out.write(f"could not set up {name}: {e}\n")
            return 1
        out.write("$ " + " ".join(argv) + "\n")
        out.flush()
        return subprocess.run(argv, cwd=ROOT, env={**os.environ, **env}, stdout=out, stderr=subprocess.STDOUT).returncode


def _last_line(log: Path) -> str:
    lines = [line for line in log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
    return lines[-1].strip() if lines else ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", nargs="+", choices=list(CHECKS), default=list(CHECKS))
    ap.add_argument("--base", default="origin/main", help="gitleaks scans the commits since the merge base with this")
    ap.add_argument("--python312", default=shutil.which("python3.12") or "python3.12", help="builds .venv-typecheck")
    ap.add_argument("--logs", type=Path, default=None, help="default: out/check-local/<UTC time>")
    a = ap.parse_args(argv)
    a.logs = a.logs or ROOT / "out" / "check-local" / dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    a.logs.mkdir(parents=True, exist_ok=True)
    failed = []
    for name in a.only:
        code = run_check(name, CHECKS[name], a)
        log = a.logs / f"{name}.log"
        print(f"{'ok  ' if code == 0 else 'FAIL'} {name:8} {_last_line(log)}")
        if code != 0:
            failed.append(log)
    for log in failed:
        print(f"failed: {log}")
    blind = [name for name in a.only if name in COMMIT_CHECKS]
    changes = uncommitted(ROOT) if blind else []
    if changes:
        reads = "it reads" if len(blind) == 1 else "they read"
        print(f"WARNING: {len(changes)} uncommitted change(s), which {', '.join(blind)} did not see: {reads} the branch's "
              f"commits. Commit them and run --only {' '.join(blind)} to check them.")
    print(f"logs: {a.logs}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
