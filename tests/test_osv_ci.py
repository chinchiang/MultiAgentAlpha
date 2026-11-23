"""osv-scanner wiring, without network: a fake osv-scanner under a temporary MARA_TOOLS_DIR writes a canned
SARIF and exits like the real one, so the script's version pin, exit-code mapping, package parsing,
--expect-package and IgnoredVulns handling are exercised deterministically. The SARIF each test gives the stand-in leaves
out each vulnerability the config ignores, as osv-scanner 2.5.1's does; the stand-in reads no config."""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "osv_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))

from osv_ci import packages_in, summarize  # noqa: E402

from tests import tool_installs  # noqa: E402

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


def _tools(tmp_path: Path, sarif: dict | str | None, exit_code: int, version: str = "2.5.1", said: tuple[str, ...] = ()) -> Path:
    """A fake osv-scanner that writes each line of `said` to stderr, copies `sarif` to its --output-file (as JSON, a
    string as it is, an empty file when it is None) and exits `exit_code`."""
    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    (tools / "canned.sarif").write_text("" if sarif is None else sarif if isinstance(sarif, str) else json.dumps(sarif))
    (tools / "said.txt").write_text("".join(line + "\n" for line in said), encoding="utf-8")
    if sys.platform == "win32":
        py_script = tools / "bin" / "fake_osv.py"
        py_code = f"""import sys, os, shutil
from pathlib import Path
args = sys.argv[1:]
if args and args[0] == '--version':
    print('osv-scanner version: 2.5.1')
    sys.exit(0)
argv_path = Path({str(tools / 'argv.txt')!r})
with open(argv_path, 'w', encoding='utf-8') as f:
    f.write(' '.join(args) + '\\n')
sys.stderr.write(Path({str(tools / 'said.txt')!r}).read_text(encoding='utf-8'))
out = ''
i = 0
while i < len(args):
    if args[i] == '--output-file' and i + 1 < len(args):
        out = args[i+1]
        i += 2
    else:
        i += 1
if out:
    shutil.copyfile(Path({str(tools / 'canned.sarif')!r}), out)
sys.exit({exit_code})
"""
        py_script.write_text(py_code, encoding="utf-8")
        cmd_script = tools / "bin" / "osv-scanner.cmd"
        cmd_script.write_text(f'@"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
    else:
        fake = tools / "bin" / "osv-scanner"
        fake.write_text("#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'osv-scanner version: 2.5.1'; exit 0; fi\n"
                        f"echo \"$@\" > {tools}/argv.txt\ncat {tools}/said.txt >&2\n"
                        "out=''\nwhile [ $# -gt 0 ]; do if [ \"$1\" = --output-file ]; then out=$2; fi; shift; done\n"
                        f"[ -n \"$out\" ] && cp {tools}/canned.sarif \"$out\"\nexit {exit_code}\n")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"osv-scanner": {"version": version}}}))
    tool_installs.record_installed(tools, "osv-scanner")
    return tools


def _run(tools: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env={**os.environ, "MARA_TOOLS_DIR": str(tools)}, cwd=ROOT)


def test_packages_are_parsed_from_the_message_or_the_rule_help_table():
    assert packages_in(_result("CVE-1", "requests", "2.19.0")) == [("requests", "2.19.0")]
    assert packages_in({"message": {"text": "Package 'github.com/x/y@abc1234' is vulnerable to 'GO-1'."}}) == [("github.com/x/y", "abc1234")]
    assert packages_in({"message": {"text": "nothing here"}}) == []
    rows = summarize(_sarif(_result("CVE-1", "requests", "2.19.0"), _result("GHSA-2", "pyyaml", "3.0", table_only=True)))
    uri = "file:///w/fixtures/vuln-sample/requirements.txt"
    assert rows == [{"id": "CVE-1", "uri": uri, "packages": [("requests", "2.19.0")]}, {"id": "GHSA-2", "uri": uri, "packages": [("pyyaml", "3.0")]}]


def test_fixture_mode_requires_the_expected_package(tmp_path):
    tools = _tools(tmp_path, _sarif(_result("CVE-2018-18074", "requests", "2.19.0")), exit_code=1)
    r = _run(tools, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "f.sarif"), "--expect-package", "requests")
    assert r.returncode == 0 and "expected package requests reported vulnerable in 1" in r.stdout, r.stdout + r.stderr
    assert "osv-scanner version: 2.5.1" in r.stdout and "(lock 2.5.1)" in r.stdout
    argv = (tools / "argv.txt").read_text()
    assert "scan source" in argv and "--no-resolve" in argv and "-r" in argv and "--format sarif" in argv
    r = _run(tools, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "g.sarif"), "--expect-package", "urllib3")
    assert r.returncode == 2 and "expected urllib3 to be reported vulnerable" in r.stderr


def _config(tmp_path: Path, *ids: str) -> Path:
    """An osv-scanner config with one IgnoredVulns entry per id, each far from its expiry."""
    path = tmp_path / "osv.toml"
    path.write_text("".join(f'[[IgnoredVulns]]\nid = "{vid}"\nignoreUntil = 2099-01-01\nreason = "r"\n\n' for vid in ids))
    return path


def test_lockfile_mode_fails_on_unignored_advisories_and_passes_when_all_ignored(tmp_path):
    """osv-scanner 2.5.1 leaves a vulnerability its config ignores out of the SARIF, so a clean scan counts the
    config's IgnoredVulns entries, not ignored results (#410)."""
    config = _config(tmp_path, "GHSA-2", "GHSA-3")
    tools = _tools(tmp_path / "a", _sarif(_result("GHSA-1", "certifi", "2020.1")), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--config", str(config), "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2 and "VULNERABILITIES: 1 un-ignored" in r.stdout and "VULN    GHSA-1  certifi@2020.1" in r.stdout
    argv = (tools / "argv.txt").read_text()
    assert "--lockfile" in argv and f"--config {config}" in argv and "--no-resolve" in argv
    tools = _tools(tmp_path / "b", _sarif(), exit_code=0)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--config", str(config), "--report", str(tmp_path / "p.sarif"))
    assert r.returncode == 0, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == f"no un-ignored known vulnerabilities (2 IgnoredVulns entries in {config.as_posix()})"
    tools = _tools(tmp_path / "c", _sarif(), exit_code=0)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "q.sarif"))
    assert r.returncode == 0 and r.stdout.splitlines()[-1] == "no un-ignored known vulnerabilities (no --config)"


def test_a_result_osv_scanner_marks_suppressed_still_fails_the_scan(tmp_path):
    """osv-scanner 2.5.1 writes no suppressions; a result is a vulnerability the config does not ignore, whatever a later
    version marks on it, so the scan fails closed."""
    tools = _tools(tmp_path, _sarif(_result("GHSA-2", "idna", "2.8", suppressed=True)), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2 and "VULNERABILITIES: 1 un-ignored" in r.stdout and "VULN    GHSA-2  idna@2.8" in r.stdout


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


SAID = tuple(f"osv-scanner said {n:02}" for n in range(1, 21))  # more lines than a scan that does not fail shows (its last 8)
# an error notification osv-scanner records when a scan of a package source fails
NOTE = {"level": "error", "message": {"text": "could not read the lockfile"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "tools/bootstrap-requirements.txt"}}}]}


def _incomplete(sarif: dict) -> dict:
    sarif["runs"][0]["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": [NOTE]}]
    return sarif


@pytest.mark.parametrize("sarif, exit_code, error", [
    (_incomplete(_sarif()), 127, "no package sources"),
    (_incomplete(_sarif()), 128, "exited 128"),
    (None, 0, "wrote no SARIF"),
    (_incomplete(_sarif()), 0, "incomplete scan"),
    (_incomplete(_sarif(_result("GHSA-1", "certifi", "2020.1"))), 1, "incomplete scan"),
    ("{not a SARIF document", 0, "is not JSON"),
    (json.dumps({"runs": [1]}), 128, "exited 128"),  # a SARIF not shaped as SARIF has no errors to read (#344)
], ids=["no-packages", "crash", "no-sarif", "incomplete", "incomplete-with-findings", "not-json", "crash-not-shaped"])
def test_a_failed_scan_prints_every_line_osv_scanner_said_and_the_sarif_errors(tmp_path, sarif, exit_code, error):
    """The line that says why osv-scanner failed is rarely among its last: a failure shows every line, then each error
    notification of the SARIF it wrote."""
    tools = _tools(tmp_path, sarif, exit_code=exit_code, said=SAID)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 1 and error in r.stderr, r.stdout + r.stderr
    shown = [line.strip() for line in r.stdout.splitlines()]
    assert [line for line in shown if line.startswith("osv-scanner said")] == list(SAID)
    notes = [line for line in shown if line.startswith("osv-scanner error:")]
    assert notes == ([] if not isinstance(sarif, dict) else ["osv-scanner error: could not read the lockfile (tools/bootstrap-requirements.txt)"])


@pytest.mark.parametrize("sarif, exit_code", [(_sarif(), 0), (_sarif(_result("GHSA-1", "certifi", "2020.1")), 1)], ids=["clean", "findings"])
def test_a_scan_that_does_not_fail_still_shows_only_the_last_eight_lines(tmp_path, sarif, exit_code):
    """Exit 1 is osv-scanner's result (advisories found), not a failure of the scan."""
    tools = _tools(tmp_path, sarif, exit_code=exit_code, said=SAID)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2 * exit_code, r.stdout + r.stderr
    assert [line.strip() for line in r.stdout.splitlines() if line.strip().startswith("osv-scanner said")] == list(SAID[-8:])


def test_runner_does_not_count_a_failed_osv_scan_as_a_clean_one(tmp_path):
    from mara.tools import runner

    tools = _tools(tmp_path, _sarif(), exit_code=128)  # writes an empty SARIF and exits 128, as when api.osv.dev is unreachable
    target = tmp_path / "t"
    target.mkdir()
    (run,) = runner.run_all(target, tmp_path / "out", enabled=["osv-scanner"], workspace=tool_installs.workspace(tools))
    assert not run.ran and "exit 128" in run.note
    tools = _tools(tmp_path / "ok", _sarif(_result("CVE-1", "requests", "2.19.0")), exit_code=1)
    (run,) = runner.run_all(target, tmp_path / "out2", enabled=["osv-scanner"], workspace=tool_installs.workspace(tools))
    assert run.ran and run.results[0].rule_id == "CVE-1" and "scan source" in (tools / "argv.txt").read_text()


def test_a_failing_lockfile_scan_names_the_command_that_gathers_the_facts(tmp_path):
    """The un-ignored advisories' packages, with the lockfile scanned, in the scripts/advisory_facts.py command line that
    gathers what a relock or a dated exception needs."""
    tools = _tools(tmp_path, _sarif(_result("GHSA-1", "certifi", "2020.1"), _result("GHSA-3", "idna", "2.8")), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "python3 scripts/advisory_facts.py --lockfile tools/bootstrap-requirements.txt certifi idna\n" in r.stdout


def test_with_several_lockfiles_each_command_names_only_the_packages_found_in_it(tmp_path):
    """L0 scans several closures in one run; each finding's path tells which lockfile's command it belongs to."""
    in_dev = _result("GHSA-4", "certifi", "2020.1")
    in_dev["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "file:///w/tools/dev-requirements.txt"
    tools = _tools(tmp_path, _sarif(in_dev), exit_code=1)
    r = _run(tools, "--lockfile", "tools/bootstrap-requirements.txt", "--lockfile", "tools/dev-requirements.txt",
             "--report", str(tmp_path / "o.sarif"))
    assert r.returncode == 2, r.stdout + r.stderr
    assert "python3 scripts/advisory_facts.py --lockfile tools/dev-requirements.txt certifi" in r.stdout
    assert "--lockfile tools/bootstrap-requirements.txt certifi" not in r.stdout
