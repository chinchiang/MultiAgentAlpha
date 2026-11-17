"""semgrep wiring: rule ids are normalised to the registry form whatever the install path, the SARIF reader
takes the CWE id out of semgrep's tags, the triage file decides what may pass, and (when the locked semgrep
and the pinned rules are installed under .mara-tools) the seeded fixture reproduces its recording."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "semgrep_ci.py"
TOOLS = ROOT / ".mara-tools"
sys.path.insert(0, str(ROOT / "scripts"))

from semgrep_ci import apply_triage, load_triage, locked, match_triage  # noqa: E402

from mara.tools.sarif import read_sarif  # noqa: E402
from mara.tools.semgrep_rules import canonical_rule_id, normalize_sarif, result_keys, timeouts  # noqa: E402

needs_tools = pytest.mark.skipif(not (TOOLS / "bin" / "semgrep").exists() or not (TOOLS / "semgrep-rules").is_dir(),
                                 reason="locked semgrep + semgrep-rules not installed under .mara-tools (run scripts/install_tools.py)")


def _doc(rule_prefix: str) -> dict:
    rid = rule_prefix + "python.flask.security.injection.tainted-sql-string"
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
        {"id": rid, "name": rid, "defaultConfiguration": {"level": "error"},
         "properties": {"tags": ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "security"]}},
        {"id": rule_prefix + "python.flask.security.audit.unused-rule", "properties": {"tags": ["CWE-1: x"]}}]}},
        "results": [{"ruleId": rid, "message": {"text": "sql"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 32}}}]}],
        "invocations": [{"toolExecutionNotifications": [{"message": {"text": f"Syntax error in rule '{rule_prefix}yaml.github-actions.security.curl-eval'"}}]}]}]}


@pytest.mark.parametrize("prefix", ["mara-tools.semgrep-rules.", "tmp.claude-0.-home-user-x.scratch.semgrep-rules.", "home.runner.work.r.r..mara-tools.semgrep-rules.", ""])
def test_rule_ids_lose_the_install_path_prefix(prefix):
    assert canonical_rule_id(prefix + "python.flask.security.injection.tainted-sql-string") == "python.flask.security.injection.tainted-sql-string"


def test_normalize_sarif_rewrites_ids_prunes_rules_and_keeps_results(tmp_path):
    p = tmp_path / "s.sarif"
    p.write_text(json.dumps(_doc("tmp.x.semgrep-rules.")))
    doc = normalize_sarif(p)
    run = doc["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == ["python.flask.security.injection.tainted-sql-string"], "unreferenced descriptors dropped"
    assert result_keys(doc) == [("python.flask.security.injection.tainted-sql-string", "app.py", 32)]
    assert "semgrep-rules" not in run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    assert json.loads(p.read_text()) == doc, "rewritten in place"


def test_sarif_reader_extracts_cwe_id_and_default_level(tmp_path):
    p = tmp_path / "s.sarif"
    p.write_text(json.dumps(_doc("")))
    (r,) = read_sarif(p)
    assert r.cwe == "CWE-89" and r.cwes == ["CWE-89"] and r.level == "error" and r.rule_id.endswith("tainted-sql-string")
    real = read_sarif(ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif")
    by_rule = {x.rule_id: x for x in real}
    # upstream tags tainted-sql-string with CWE-704 only; the SQLi at app.py:32 is corroborated as CWE-89 through
    # sqlalchemy-execute-raw-query on the same line (see test_pipeline_mock.test_tool_corroboration_yields_tier_a)
    sqli = by_rule["python.flask.security.injection.tainted-sql-string"]
    assert sqli.cwes == ["CWE-704"] and sqli.level == "error" and sqli.line == 32 and sqli.file == "app.py"
    assert by_rule["python.sqlalchemy.security.sqlalchemy-execute-raw-query"].cwes == ["CWE-89"]
    assert all(x.level in ("error", "warning", "note") and x.cwes for x in real)


def test_recorded_fixture_sarif_is_the_normalised_real_thing():
    doc = json.loads((ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif").read_text())
    run = doc["runs"][0]
    assert run["tool"]["driver"]["semanticVersion"] == "1.179.0"
    keys = result_keys(doc)
    assert ("python.flask.security.injection.tainted-sql-string", "app.py", 32) in keys
    assert ("python.flask.security.audit.render-template-string", "app.py", 26) in keys
    assert ("python.flask.security.audit.debug-enabled", "app.py", 74) in keys
    assert ("yaml.github-actions.security.run-shell-injection", ".github/workflows/deploy.yml", 14) in keys
    assert not any("semgrep-rules" in k[0] for k in keys) and len(keys) >= 12
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {k[0] for k in keys}


def test_triage_matching_and_suppressions(tmp_path):
    t = tmp_path / "triage.yaml"
    t.write_text("exclude: [fixtures]\naccepted:\n  - rule: a.b\n    paths: ['scripts/*.py']\n    reason: fine\n  - rule: c.d\n    paths: [x.py]\n    reason: stale\n")
    entries, excludes = load_triage(t)
    assert excludes == ["fixtures"] and match_triage("a.b", "scripts/x.py", entries) and not match_triage("a.b", "src/x.py", entries)
    doc = {"runs": [{"results": [
        {"ruleId": "a.b", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "scripts/x.py"}, "region": {"startLine": 3}}}]},
        {"ruleId": "a.b", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/y.py"}, "region": {"startLine": 4}}}]}]}]}
    accepted, untriaged, stale = apply_triage(doc, entries)
    assert accepted == ["a.b  scripts/x.py:3"] and untriaged == ["a.b  src/y.py:4"] and [e["rule"] for e in stale] == ["c.d"]
    assert doc["runs"][0]["results"][0]["suppressions"][0] == {"kind": "external", "status": "accepted", "justification": "fine"}
    assert "suppressions" not in doc["runs"][0]["results"][1]
    t.write_text("accepted:\n  - rule: a.b\n    paths: [x]\n    reason: ''\n")
    with pytest.raises(SystemExit, match="reason"):
        load_triage(t)


def test_shipped_triage_file_is_well_formed():
    entries, excludes = load_triage(ROOT / "tools" / "semgrep-triage.yaml")
    assert excludes == ["fixtures", "calib/samples"]
    assert all(len(" ".join(str(e["reason"]).split())) > 40 for e in entries), "every accepted rule carries a real reason"
    assert all("." in e["rule"] and "semgrep-rules" not in e["rule"] for e in entries)


def _run(*args: str, tools: Path = TOOLS) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools)}
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


@needs_tools
def test_fixture_scan_matches_the_recording(tmp_path):
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "fx.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "semgrep 1.179.0" in r.stdout and "matches the recording" in r.stdout and "--metrics=off --disable-version-check" in r.stdout
    doc = json.loads((tmp_path / "fx.sarif").read_text())
    assert result_keys(doc) == result_keys(json.loads((ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif").read_text()))


def _tool_dir_with_a_fake_semgrep(tmp_path, exit_code: int, sarif: dict) -> Path:
    """A tool directory whose semgrep answers --version with the locked version and, for a scan, prints six numbered lines to
    stderr, writes `sarif` where --output says and exits `exit_code`; the rules are the locked checkout, linked."""
    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    (tools / "semgrep-rules").symlink_to(TOOLS / "semgrep-rules")
    manifest = json.loads((TOOLS / "manifest.json").read_text(encoding="utf-8"))
    (tools / "manifest.json").write_text(json.dumps({"tools": {k: manifest["tools"][k] for k in ("semgrep", "semgrep-rules")}}))
    body = (
        "import json, sys\n"
        "if '--version' in sys.argv:\n"
        f"    print({locked()[0]!r}); sys.exit(0)\n"
        "for i in range(1, 7):\n"
        "    print(f'fake semgrep stderr line {i}', file=sys.stderr)\n"
        f"open(sys.argv[sys.argv.index('--output') + 1], 'w').write(json.dumps({sarif!r}))\n"
        f"sys.exit({exit_code})\n")
    script = tools / "bin" / "semgrep"
    script.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    script.chmod(0o755)
    return tools


@needs_tools
def test_a_scan_fails_when_semgrep_exits_non_zero_even_with_a_complete_report(tmp_path):
    # the recording itself, which passes when semgrep exits 0: exit 2 alone must fail the scan
    recorded = json.loads((ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif").read_text(encoding="utf-8"))
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 2, recorded)
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "c.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif",
             tools=tools)
    assert r.returncode == 1 and "ERROR: semgrep exited 2; partial results cannot pass" in r.stderr, r.stdout + r.stderr


@needs_tools
def test_a_failed_scan_whose_sarif_is_not_shaped_as_sarif_still_says_why_it_failed(tmp_path):
    """Its SARIF errors cannot be read from such a file (#344): the ERROR line comes all the same, with no traceback."""
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 2, {"runs": [1]})
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "c.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif",
             tools=tools)
    assert r.returncode == 1 and "ERROR: semgrep exited 2; partial results cannot pass" in r.stderr, r.stdout + r.stderr
    assert "Traceback" not in r.stderr and "fake semgrep stderr line 1" in r.stdout


@needs_tools
def test_a_completed_scan_whose_sarif_is_not_shaped_as_sarif_is_incomplete(tmp_path):
    """semgrep exits 0 but writes a file not shaped as SARIF (#344): it is not normalized, and the scan is reported
    incomplete, with no traceback."""
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 0, {"runs": [1]})
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "c.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif",
             tools=tools)
    assert r.returncode == 1 and "ERROR: semgrep SARIF reports an incomplete scan" in r.stderr, r.stdout + r.stderr
    assert "Traceback" not in r.stderr


@needs_tools
def test_a_scan_semgrep_fails_prints_every_error_semgrep_reported(tmp_path):
    # the last lines of semgrep's stderr are its summary table and its warnings: the error that made it exit 2 is earlier,
    # or in the SARIF's notifications
    execution = [{"level": "error", "message": {"text": "Timeout when running rule-x"},
                  "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}]},
                 {"level": "warning", "message": {"text": "Skipped a minified file"}}]  # not an error: not printed
    configuration = [{"level": "error", "message": {"text": "Invalid rule rule-y"}}]
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [], "invocations": [
        {"executionSuccessful": False, "toolExecutionNotifications": execution, "toolConfigurationNotifications": configuration}]}]}
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 2, sarif)
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "f.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif",
             tools=tools)
    assert r.returncode == 1, r.stdout + r.stderr
    out = r.stdout + r.stderr
    assert [n for n in range(1, 7) if f"fake semgrep stderr line {n}" not in out] == [], out
    assert "semgrep error: Timeout when running rule-x (app.py)" in out and "semgrep error: Invalid rule rule-y" in out, out
    assert "Skipped a minified file" not in out, out
    assert "ERROR: semgrep exited 2; partial results cannot pass" in r.stderr


@needs_tools
def test_a_scan_semgrep_completes_prints_only_the_last_lines_semgrep_said(tmp_path):
    recorded = json.loads((ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif").read_text(encoding="utf-8"))
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 0, recorded)
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "ok.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif",
             tools=tools)
    assert r.returncode == 0 and "matches the recording" in r.stdout, r.stdout + r.stderr
    printed = [n for n in range(1, 7) if f"fake semgrep stderr line {n}" in r.stdout + r.stderr]
    assert printed == [3, 4, 5, 6], r.stdout


@needs_tools
def test_repo_style_scan_fails_on_untriaged_findings_and_passes_with_a_reason(tmp_path):
    target = tmp_path / "t"
    target.mkdir()
    (target / "run.py").write_text("import subprocess\n\ndef go(cmd):\n    subprocess.run(cmd)\n")
    (target / "fixtures").mkdir()
    (target / "fixtures" / "seed.py").write_text("import subprocess\n\ndef go(cmd):\n    subprocess.run(cmd)\n")
    triage = tmp_path / "triage.yaml"
    triage.write_text("exclude: [fixtures]\naccepted: []\n")
    r = _run("--target", str(target), "--report", str(tmp_path / "a.sarif"), "--triage", str(triage))
    assert r.returncode == 2 and "UNTRIAGED: 1" in r.stdout and "dangerous-subprocess-use-audit  run.py:4" in r.stdout, r.stdout + r.stderr
    assert "seed.py" not in r.stdout, "the exclude list keeps seeded material out of the repository scan"
    triage.write_text("exclude: [fixtures]\naccepted:\n  - rule: python.lang.security.audit.dangerous-subprocess-use-audit\n    paths: ['*.py']\n    reason: argv list, no shell\n"
                      "  - rule: python.lang.security.audit.never-fires\n    paths: ['*.py']\n    reason: stale on purpose\n")
    r = _run("--target", str(target), "--report", str(tmp_path / "b.sarif"), "--triage", str(triage))
    assert r.returncode == 0 and "clean: 1 accepted" in r.stdout and "STALE triage entry" in r.stdout, r.stdout + r.stderr
    doc = json.loads((tmp_path / "b.sarif").read_text())
    (res,) = doc["runs"][0]["results"]
    assert res["ruleId"] == "python.lang.security.audit.dangerous-subprocess-use-audit" and res["suppressions"][0]["justification"] == "argv list, no shell"


@needs_tools
def test_binary_and_rules_only_from_the_tools_dir(tmp_path):
    empty = tmp_path / "none"
    empty.mkdir()
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "x.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif", tools=empty)
    assert r.returncode == 2 and "not installed" in r.stderr and "PATH is never used" in r.stderr
    fake = tmp_path / "tools"
    (fake / "bin").mkdir(parents=True)
    (fake / "bin" / "semgrep").symlink_to(TOOLS / "bin" / "semgrep")
    (fake / "manifest.json").write_text(json.dumps({"tools": {"semgrep": {"version": "1.179.0"}}}))
    r = _run("--target", "fixtures/vuln-sample", "--report", str(tmp_path / "y.sarif"), "--expect", "fixtures/vuln-sample-sarif/semgrep.sarif", tools=fake)
    assert r.returncode == 2 and "semgrep-rules is not installed" in r.stderr


def test_exact_secret_triage_does_not_accept_changed_or_missing_snippet():
    import hashlib

    from semgrep_ci import match_triage
    source = "known synthetic allowlist entry"
    entry = {"rule": "test.secret", "paths": [".gitleaks.toml"], "reason": "synthetic",
             "snippet_sha256": hashlib.sha256(source.encode()).hexdigest()}
    assert match_triage("test.secret", ".gitleaks.toml", [entry], source) is entry
    assert match_triage("test.secret", ".gitleaks.toml", [entry], source+"modified") is None
    assert match_triage("test.secret", ".gitleaks.toml", [entry]) is None
    assert match_triage("test.secret", "other.py", [entry], source) is None


# a timeout as semgrep records it in its SARIF: the rule and the file are in the text alone, the rule with the
# prefix of where the rules are installed
TAINT = "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args"


def _timeout(rule: str, file: str) -> dict:
    return {"descriptor": {"id": "Timeout"}, "level": "warning",
            "message": {"text": f"Timeout when running mara-tools.semgrep-rules.{rule} on {file}:\n "}}


def _complete(*notes: dict) -> dict:
    """A SARIF of a scan that completed with no result and these notifications."""
    return {"runs": [{"results": [], "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": list(notes)}]}]}


def _notified(tmp_path: Path, *notes: dict) -> Path:
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(_complete(*notes)))
    return path


def test_each_timeout_is_read_as_its_rule_without_the_install_prefix_and_its_file(tmp_path):
    other = {"descriptor": {"id": "Other syntax error"}, "level": "warning",
             "message": {"text": "Other syntax error at line scripts/count_words.py:1:\n Failure: int_of_string"}}
    path = _notified(tmp_path, _timeout(TAINT, "tests/test_model_eval.py"), other, _timeout("python.x.y", "tests/test_model_eval.py"))
    assert timeouts(path) == [(TAINT, "tests/test_model_eval.py"), ("python.x.y", "tests/test_model_eval.py")]


@pytest.mark.parametrize("content", ["not JSON", json.dumps({"runs": [1]})], ids=["not-json", "not-shaped"])
def test_a_report_that_cannot_be_read_has_no_timeouts(tmp_path, content):
    path = tmp_path / "semgrep.sarif"
    path.write_text(content)
    assert timeouts(path) == [] and timeouts(tmp_path / "none.sarif") == []


@needs_tools
@pytest.mark.parametrize("notes, said, last", [
    ([], [], "clean: 0 accepted finding(s), 0 untriaged"),
    ([_timeout(TAINT, "tests/test_model_eval.py")], [f"timed out  {TAINT}  tests/test_model_eval.py"],
     "clean: 0 accepted finding(s), 0 untriaged; 1 timeout(s) (tests/test_model_eval.py)"),
    ([_timeout(TAINT, "a.py"), _timeout("python.x.y", "a.py"), _timeout(TAINT, "b.py")],
     [f"timed out  {TAINT}  a.py", "timed out  python.x.y  a.py", f"timed out  {TAINT}  b.py"],
     "clean: 0 accepted finding(s), 0 untriaged; 3 timeout(s) (a.py, b.py)"),
], ids=["none", "one", "three-on-two-files"])
def test_a_clean_scan_says_which_rules_timed_out_on_which_files(tmp_path, notes, said, last):
    """A rule semgrep gave up on drops its findings in that file, so the accepted count moves: the last line says
    how many timeouts there were and on which files, a line above it names each, and the scan still passes."""
    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 0, _complete(*notes))
    target = tmp_path / "t"
    target.mkdir()
    triage = tmp_path / "triage.yaml"
    triage.write_text("exclude: []\naccepted: []\n")
    r = _run("--target", str(target), "--report", str(tmp_path / "c.sarif"), "--triage", str(triage), tools=tools)
    lines = r.stdout.splitlines()
    assert r.returncode == 0 and lines[-1] == last, r.stdout + r.stderr
    assert [line.strip() for line in lines if line.strip().startswith("timed out")] == said
