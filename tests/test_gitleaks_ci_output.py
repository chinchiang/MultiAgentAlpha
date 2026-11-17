"""What scripts/gitleaks_ci.py prints of what gitleaks said: every line when gitleaks fails, its last lines when it
completes (no leaks, or leaks found: exit 2 is a result). A stand-in gitleaks, so these run without the locked one that
test_gitleaks_ci.py needs."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gitleaks_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))

from gitleaks_ci import locked_version  # noqa: E402

from tests.test_gitleaks_ci import _repo  # noqa: E402

SAID = tuple(f"gitleaks said {n:02}" for n in range(1, 21))  # more lines than a completed scan shows (its last 6)


def _fake_gitleaks(tools: Path, exit_code: int) -> None:
    """A gitleaks whose `version` answers the locked version, and whose scan writes each line of SAID to stderr, an empty
    SARIF to its --report-path and exits `exit_code`."""
    (tools / "bin").mkdir(parents=True)
    (tools / "said.txt").write_text("".join(line + "\n" for line in SAID), encoding="utf-8")
    (tools / "canned.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{"results": []}]}), encoding="utf-8")
    py_script = tools / "bin" / "fake_gitleaks.py"
    py_script.write_text(f"""import shutil, sys
from pathlib import Path
args = sys.argv[1:]
if args[:1] == ['version']:
    print({locked_version()!r})
    sys.exit(0)
sys.stderr.write(Path({str(tools / 'said.txt')!r}).read_text(encoding='utf-8'))
for a in args:
    if a.startswith('--report-path='):
        shutil.copyfile(Path({str(tools / 'canned.sarif')!r}), a.split('=', 1)[1])
sys.exit({exit_code})
""", encoding="utf-8")
    if sys.platform == "win32":
        (tools / "bin" / "gitleaks.cmd").write_text(f'@"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
    else:
        exe = tools / "bin" / "gitleaks"
        exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{py_script}" "$@"\n', encoding="utf-8")
        exe.chmod(0o755)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"gitleaks": {"version": locked_version()}}}), encoding="utf-8")


def _run(tmp_path: Path, exit_code: int) -> subprocess.CompletedProcess:
    repo = _repo(tmp_path)
    tools = tmp_path / "tools"
    _fake_gitleaks(tools, exit_code)
    return subprocess.run([sys.executable, str(SCRIPT), "--source", str(repo), "--report", str(tmp_path / "out.sarif"),
                           "--base", "", "--head", "HEAD"],
                          capture_output=True, text=True, env={**os.environ, "MARA_TOOLS_DIR": str(tools)})


def _said(r: subprocess.CompletedProcess) -> list[str]:
    return [line.strip() for line in r.stdout.splitlines() if line.strip().startswith("gitleaks said")]


def test_a_crash_prints_every_line_gitleaks_said(tmp_path):
    """The line that says why gitleaks crashed is rarely among its last: a failure shows every line it said."""
    r = _run(tmp_path, 1)
    assert r.returncode == 1 and "gitleaks exited 1" in r.stderr, r.stdout + r.stderr
    assert _said(r) == list(SAID)


@pytest.mark.parametrize("exit_code", [0, 2], ids=["no-leaks", "leaks"])
def test_a_completed_scan_still_shows_only_the_last_six_lines(tmp_path, exit_code):
    r = _run(tmp_path, exit_code)
    assert r.returncode == exit_code, r.stdout + r.stderr
    assert _said(r) == list(SAID[-6:])
