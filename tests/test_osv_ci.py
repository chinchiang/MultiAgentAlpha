"""osv-scanner wiring, without network: a fake osv-scanner under a temporary MARA_TOOLS_DIR writes a canned
SARIF and exits like the real one, so the script's version pin, exit-code mapping, package parsing,
--expect-package and IgnoredVulns (suppressions) handling are exercised deterministically."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "osv_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))

from osv_ci import packages_in, summarize  # noqa: E402

# exactly what osv-scanner 2.5.1 writes (internal/output/sarif.go): the package sits in the result message, the
# "Affected Packages" table in the rule's help markdown
MSG = "Package 'requests@2.19.0' is vulnerable to 'CVE-2018-18074' (also known as 'GHSA-x84v-xcm2-53pg')."
HELP = ("**Your dependency is vulnerable to [CVE-2018-18074](https://osv.dev/CVE-2018-18074)**\n## [CVE-2018-18074]\n"
        "### Affected Packages\n\n| Source | Package Name | Package Version |\n| --- | --- | --- |\n| lockfile:/x/requirements.txt | requests | 2.19.0 |\n\n## Remediation\n")


def _sarif(*results: dict) -> dict:
    rules = [{"id": r["ruleId"], "name": r["ruleId"], "help": {"markdown": HELP.replace("requests", r["_pkg"]).replace("2.19.0", r["_ver"])}} for r in results]
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "osv-scanner", "rules": rules}},
                                          "results": [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]}]}


def _result(vid: str, pkg: str, ver: str, suppressed: bool = False, table_only: bool = False) -> dict:
    text = "See the rule help." if table_only else MSG.replace("requests", pkg).replace("2.19.0", ver).replace("CVE-2018-18074", vid)
    r = {"ruleId": vid, "level": "warning", "message": {"text": text}, "_pkg": pkg, "_ver": ver,
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///w/fixtures/vuln-sample/requirements.txt"}}}]}
    if suppressed:
        r["suppressions"] = [{"kind": "external", "status": "accepted"}]
    return r


def _tools(tmp_path: Path, sarif: dict, exit_code: int, version: str = "2.5.1") -> Path:
    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    (tools / "canned.sarif").write_text(json.dumps(sarif))
    fake = tools / "bin" / "osv-scanner"
    fake.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'osv-scanner version: 2.5.1'; exit 0; fi\n"
                    f"echo \"$@\" > {tools}/argv.txt\n"
                    "out=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --output-file ]; then out=$2; fi; shift; done\n"
                    f"[ -n \"$out\" ] && cp {tools}/canned.sarif \"$out\"\nexit {exit_code}\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"osv-scanner": {"version": version}}}))
    return tools


def _run(tools: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env={**os.environ, "MARA_TOOLS_DIR": str(tools)}, cwd=ROOT)


def test_packages_are_parsed_from_the_message_or_the_rule_help_table():
    assert packages_in(_result("CVE-1", "requests", "2.19.0")) == [("requests", "2.19.0")]
    assert packages_in({"message": {"text": "Package 'github.com/x/y@abc1234' is vulnerable to 'GO-1'."}}) == [("github.com/x/y", "abc1234")]
    assert packages_in({"message": {"text": "nothing here"}}) == []
    rows = summarize(_sarif(_result("CVE-1", "requests", "2.19.0"), _result("GHSA-2", "pyyaml", "3.0", suppressed=True, table_only=True)))
    assert [(r["id"], r["packages"], r["suppressed"]) for r in rows] == [("CVE-1", [("requests", "2.19.0")], False), ("GHSA-2", [("pyyaml", "3.0")], True)]


def test_fixture_mode_requires_the_expected_package(tmp_path):
    tools = _tools(tmp_path, _sarif(_result("CVE-2018-18074", "requests", "2.19.0")), exit_code=1)
    r = _run(tools, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "f.sarif"), "--expect-package", "requests")
    assert r.returncode == 0 and "expected package requests reported vulnerable in 1" in r.stdout, r.stdout + r.stderr
    assert "osv-scanner version: 2.5.1" in r.stdout and "(lock 2.5.1)" in r.stdout
    argv = (tools / "argv.txt").read_text()
    assert "scan source" in argv and "--no-resolve" in argv and "-r" in argv and "--format sarif" in argv
    r = _run(tools, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "g.sarif"), "--expect-package", "urllib3")
    assert r.returncode == 2 and "expected urllib3 to be reported vulnerable" in r.stderr


def test_lockfile_mode_fails_on_unignored_advisories_and_passes_when_all_ignored(tmp_path):
    tools = _tools(tmp_path, _sarif(_result("GHSA-1", "certifi", "2020.1"), _result("GHSA-2", "idna", "2.8", suppressed=True)), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--config", "tools/osv-scanner.toml", "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2 and "VULNERABILITIES: 1 un-ignored" in r.stdout and "ignored GHSA-2" in r.stdout and "VULN    GHSA-1  certifi@2020.1" in r.stdout
    argv = (tools / "argv.txt").read_text()
    assert "--lockfile" in argv and "osv-scanner.toml" in argv and "--no-resolve" in argv
    tools = _tools(tmp_path / "b", _sarif(_result("GHSA-2", "idna", "2.8", suppressed=True)), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "p.sarif"))
    assert r.returncode == 0 and "no un-ignored known vulnerabilities (1 ignored)" in r.stdout
    tools = _tools(tmp_path / "c", _sarif(), exit_code=0)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "q.sarif"))
    assert r.returncode == 0 and "no un-ignored known vulnerabilities (0 ignored)" in r.stdout


def test_crashes_no_packages_and_version_drift_are_never_green(tmp_path):
    tools = _tools(tmp_path / "a", _sarif(), exit_code=127)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "a.sarif"))
    assert r.returncode == 1 and "no package sources" in r.stderr
    tools = _tools(tmp_path / "b", _sarif(), exit_code=128)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "b.sarif"))
    assert r.returncode == 1 and "exited 128" in r.stderr
    tools = _tools(tmp_path / "c", _sarif(), exit_code=0, version="2.0.0")
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "c.sarif"))
    assert r.returncode == 2 and "does not match tools/versions.lock" in r.stderr
    empty = tmp_path / "none"
    empty.mkdir()
    r = _run(empty, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "d.sarif"))
    assert r.returncode == 2 and "not installed" in r.stderr and "PATH is never used" in r.stderr
    tools = _tools(tmp_path / "d", _sarif(), exit_code=0)
    r = _run(tools, "--lockfile", "tools/nonexistent.txt", "--report", str(tmp_path / "e.sarif"))
    assert r.returncode == 2 and "not found" in r.stderr


def test_runner_does_not_count_a_failed_osv_scan_as_a_clean_one(tmp_path, monkeypatch):
    from mara.tools import runner

    tools = _tools(tmp_path, _sarif(), exit_code=128)  # writes an empty SARIF and exits 128, as when api.osv.dev is unreachable
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    target = tmp_path / "t"
    target.mkdir()
    (run,) = runner.run_all(target, tmp_path / "out", enabled=["osv-scanner"])
    assert not run.ran and "exit 128" in run.note
    tools = _tools(tmp_path / "ok", _sarif(_result("CVE-1", "requests", "2.19.0")), exit_code=1)
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    (run,) = runner.run_all(target, tmp_path / "out2", enabled=["osv-scanner"])
    assert run.ran and run.results[0].rule_id == "CVE-1" and "scan source" in (tools / "argv.txt").read_text()
