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

from semgrep_ci import apply_triage, load_triage, match_triage  # noqa: E402

from mara.tools.sarif import read_sarif  # noqa: E402
from mara.tools.semgrep_rules import canonical_rule_id, normalize_sarif, result_keys  # noqa: E402

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
    assert run["tool"]["driver"]["semanticVersion"] == "1.177.0"
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
    assert "semgrep 1.177.0" in r.stdout and "matches the recording" in r.stdout and "--metrics=off --disable-version-check" in r.stdout
    doc = json.loads((tmp_path / "fx.sarif").read_text())
    assert result_keys(doc) == result_keys(json.loads((ROOT / "fixtures" / "vuln-sample-sarif" / "semgrep.sarif").read_text()))


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
    (fake / "manifest.json").write_text(json.dumps({"tools": {"semgrep": {"version": "1.177.0"}}}))
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
