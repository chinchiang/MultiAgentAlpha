"""scripts/zizmor_ci.py replaces zizmor-action: binary only from MARA_TOOLS_DIR (never PATH), version must
match tools/versions.lock, the verdict comes from the SARIF (zizmor exits 0 with --format sarif even when
it has findings): any result exit 2, clean exit 0, crash exit 1. Fake zizmor, no network."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "zizmor_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))

from zizmor_ci import locked_version  # noqa: E402

FINDING = {"ruleId": "zizmor/template-injection", "level": "error", "message": {"text": "code injection via template expansion"},
           "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/deploy.yml"}, "region": {"startLine": 15}}}]}


def _sarif(*results: dict) -> str:
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor", "version": "1.30.1"}}, "results": list(results)}]})


def _fake_zizmor(tools: Path, version: str, sarif: str | None, crash: bool = False, said: tuple[str, ...] = ()) -> None:
    """A zizmor that records its argv, writes each line of `said` to stderr, and prints the canned SARIF to stdout (exit 0),
    or crashes: what it was given as the SARIF on stdout (nothing by default), then `crash` on stderr, exit 3."""
    (tools / "bin").mkdir(parents=True, exist_ok=True)
    (tools / "canned.sarif").write_text(sarif or "", encoding="utf-8")
    (tools / "said.txt").write_text("".join(line + "\n" for line in said), encoding="utf-8")
    if sys.platform == "win32":
        py_script = tools / "bin" / "fake_zizmor.py"
        py_code = f"""import sys, os
from pathlib import Path
args = sys.argv[1:]
argv_path = Path({str(tools / 'argv.txt')!r})
with open(argv_path, 'w', encoding='utf-8') as f:
    f.write('\\n'.join(args) + '\\n')
sys.stderr.write(Path({str(tools / 'said.txt')!r}).read_text(encoding='utf-8'))
canned = Path({str(tools / 'canned.sarif')!r}).read_text(encoding='utf-8')
sys.stdout.write(canned)
if {crash}:
    sys.stderr.write('crash\\n')
    sys.exit(3)
sys.exit(0)
"""
        py_script.write_text(py_code, encoding="utf-8")
        cmd_script = tools / "bin" / "zizmor.cmd"
        cmd_script.write_text(f'@"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
    else:
        body = "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$(dirname \"$0\")/../argv.txt\"\n"
        body += "cat \"$(dirname \"$0\")/../said.txt\" >&2\ncat \"$(dirname \"$0\")/../canned.sarif\"\n"
        body += "echo 'crash' >&2; exit 3\n" if crash else ""
        exe = tools / "bin" / "zizmor"
        exe.write_text(body, encoding="utf-8")
        exe.chmod(0o755)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"zizmor": {"version": version}}}), encoding="utf-8")


def _run(tools: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools)}
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


def test_clean_audit_writes_sarif_and_exits_zero(tmp_path):
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), _sarif())
    report = tmp_path / "zizmor.sarif"
    r = _run(tools, "--target", ".github/workflows", "--report", str(report), "--offline")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "clean" in r.stdout and json.loads(report.read_text())["runs"][0]["results"] == []
    argv = (tools / "argv.txt").read_text().split()
    assert argv[:5] == ["--no-progress", "--format", "sarif", "--persona", "regular"] and "--offline" in argv and argv[-1].replace("\\", "/") == ".github/workflows"


def test_any_finding_exits_two_and_is_listed(tmp_path):
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), _sarif(FINDING))
    r = _run(tools, "--target", ".github/workflows", "--report", str(tmp_path / "z.sarif"), "--persona", "auditor")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "FINDINGS: 1" in r.stdout and "zizmor/template-injection  error  .github/workflows/deploy.yml:15" in r.stdout
    argv = (tools / "argv.txt").read_text().split()
    assert "--persona" in argv and "auditor" in argv and "--offline" not in argv, "online audits stay on unless --offline"


def test_crash_or_empty_output_exits_one(tmp_path):
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), None, crash=True)
    r = _run(tools, "--target", ".github/workflows", "--report", str(tmp_path / "z.sarif"))
    assert r.returncode == 1 and "without a SARIF" in r.stderr


SAID = tuple(f"zizmor said {n:02}" for n in range(1, 21))  # more lines than a passing audit shows (its last 8)


def test_a_crash_prints_every_line_zizmor_said_on_either_stream(tmp_path):
    """The line that says why zizmor crashed is rarely among its last: a failure shows all of stderr, and stdout too."""
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), "partial output 1\npartial output 2\n", crash=True, said=SAID)
    r = _run(tools, "--target", ".github/workflows", "--report", str(tmp_path / "z.sarif"))
    assert r.returncode == 1 and "without a SARIF" in r.stderr
    shown = [line.strip() for line in r.stdout.splitlines()]
    assert [line for line in shown if line.startswith(("zizmor said", "partial output", "crash"))] == [
        *SAID, "crash", "partial output 1", "partial output 2"]


def test_output_that_is_not_json_prints_every_line_zizmor_said(tmp_path):
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), "thread 'main' panicked\nnot a SARIF document\n", said=SAID)
    r = _run(tools, "--target", ".github/workflows", "--report", str(tmp_path / "z.sarif"))
    assert r.returncode == 1 and "is not JSON" in r.stderr
    shown = [line.strip() for line in r.stdout.splitlines()]
    assert [line for line in shown if line.startswith(("zizmor said", "thread", "not a SARIF"))] == [
        *SAID, "thread 'main' panicked", "not a SARIF document"]


def test_a_clean_audit_still_shows_only_the_last_eight_lines_zizmor_said(tmp_path):
    tools = tmp_path / "tools"
    _fake_zizmor(tools, locked_version(), _sarif(), said=SAID)
    r = _run(tools, "--target", ".github/workflows", "--report", str(tmp_path / "z.sarif"), "--offline")
    assert r.returncode == 0, r.stdout + r.stderr
    assert [line.strip() for line in r.stdout.splitlines() if line.strip().startswith("zizmor said")] == list(SAID[-8:])


def test_missing_or_mismatched_tool_exits_two(tmp_path):
    r = _run(tmp_path / "empty", "--target", ".github/workflows")
    assert r.returncode == 2 and "not installed" in r.stderr
    tools = tmp_path / "tools"
    _fake_zizmor(tools, "0.0.1", _sarif())
    r = _run(tools, "--target", ".github/workflows")
    assert r.returncode == 2 and "does not match tools/versions.lock" in r.stderr
