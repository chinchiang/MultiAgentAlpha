"""tests for the L0 csp-evaluator integration: policy extraction, the driver protocol, SARIF
emission and the runner branch. The evaluator package is faked in JS (real node, no network);
the opt-in test at the end runs the real pinned package when it is installed."""

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools import csp_eval, runner  # noqa: E402
from mara.tools.sarif import scan_complete  # noqa: E402
from tests import tool_installs  # noqa: E402

DRIVER_SRC = ROOT / "src" / "mara" / "tools" / "csp_driver.js"

FAKE_DIST = {
    "dist/parser.js": """
"use strict";
class CspParser {
  parse(p) { if (String(p).indexOf("UNPARSEABLE") >= 0) throw new Error("bad policy"); return { directives: {} }; }
}
module.exports = { CspParser: CspParser };
""",
    "dist/finding.js": """
"use strict";
module.exports = {
  Severity: { HIGH: 10, INFO: 60, NONE: 100 },
  Type: { SCRIPT_UNSAFE_INLINE: 301, FAKE_INFO: 999 }
};
""",
    "dist/evaluator.js": """
"use strict";
class CspEvaluator {
  constructor(parsed) { this.csp = parsed; }
  evaluate() {
    return [
      { type: 301, severity: 10, directive: "script-src", description: "unsafe inline", value: "'unsafe-inline'" },
      { type: 999, severity: 60, directive: "object-src", description: "informational" },
      { type: 999, severity: 100, directive: "misc", description: "NONE severity must be dropped" }
    ];
  }
}
module.exports = { CspEvaluator: CspEvaluator };
""",
}


@pytest.fixture
def csp_install(tmp_path, monkeypatch):
    """A fake csp-evaluator install: the repository's real driver plus a minimal package, driven
    by the real node interpreter (a platform runtime, never installed by MARA)."""
    if shutil.which("node") is None:
        pytest.skip("node is not available")
    mt = tmp_path / "mt"
    pkg = mt / "csp-evaluator"
    (pkg / "dist").mkdir(parents=True)
    shutil.copyfile(DRIVER_SRC, pkg / "mara_driver.js")
    for rel, js in FAKE_DIST.items():
        (pkg / rel).write_text(js, encoding="utf-8")
    shim = mt / "bin" / "csp-evaluator"
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text("#!/bin/sh\nexec node \"$0/../csp-evaluator/mara_driver.js\"\n", encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    (mt / "bin" / "csp-evaluator.cmd").write_text("@echo off\nnode \"%~dp0..\\csp-evaluator\\mara_driver.js\"\n", encoding="ascii")
    tool_installs.manifest(mt, "csp-evaluator")  # at its locked version
    monkeypatch.setenv("MARA_TOOLS_DIR", str(mt))
    return mt


def _write(tmp_path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ----------------------------------------------------------------------------- extraction


def test_extracts_policies_from_every_supported_pattern(tmp_path):
    _write(tmp_path, "static/index.html", '<html><head>\n<meta HTTP-EQUIV="Content-Security-Policy" content="default-src \'self\'; script-src \'none\'">\n</head></html>\n')
    _write(tmp_path, "app.py", 'headers = {"Content-Security-Policy": "script-src \'unsafe-eval\' http://x"}\n')
    _write(tmp_path, "server.js", "res.set_header('content-security-policy', \"default-src 'none'\");\n")
    _write(tmp_path, "site.conf", "server {\n  add_header Content-Security-Policy \"frame-ancestors 'none'; base-uri 'none'\";\n}\n")
    _write(tmp_path, ".htaccess", "Header always set Content-Security-Policy \"default-src 'self'\"\n")
    got = csp_eval.extract_policies(tmp_path)[0]
    by_file = {p.file: p for p in got}
    assert by_file["static/index.html"].line == 2
    assert by_file["static/index.html"].policy == "default-src 'self'; script-src 'none'"
    assert by_file["app.py"].policy == "script-src 'unsafe-eval' http://x"
    assert by_file["server.js"].policy == "default-src 'none'"
    assert by_file["site.conf"].policy == "frame-ancestors 'none'; base-uri 'none'"
    assert by_file[".htaccess"].policy == "default-src 'self'"


def test_ignores_non_policies_and_report_only_and_dedupes(tmp_path):
    _write(tmp_path, "a.py", "h = {'Content-Security-Policy-Report-Only': 'default-src *'}\n"
                             "not_a_policy = 'just a random string'\n"
                             "h2 = {'Content-Security-Policy': \"default-src 'self'\"}; "
                             "h3 = {'Content-Security-Policy': \"default-src 'self'\"}\n")
    got = csp_eval.extract_policies(tmp_path)[0]
    assert [p.line for p in got] == [3], f"report-only, non-CSP strings and same-line duplicates must be skipped, got {got}"


def test_extraction_cap_is_reported(tmp_path):
    metas = "\n".join(f'<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src s{i}">' for i in range(csp_eval.MAX_POLICIES + 5))
    _write(tmp_path, "many.html", metas)
    policies, truncated = csp_eval.extract_policies(tmp_path)
    assert truncated and len(policies) == csp_eval.MAX_POLICIES


def test_skips_oversized_and_hidden_files(tmp_path):
    _write(tmp_path, "big.html", '<meta http-equiv="Content-Security-Policy" content="default-src x">' + " " * (csp_eval.MAX_FILE_BYTES + 1))
    _write(tmp_path, "node_modules/lib.js", "h = {'Content-Security-Policy': \"default-src 'self'\"}")
    assert csp_eval.extract_policies(tmp_path) == ([], False)


# ----------------------------------------------------------------------------- driver + SARIF


def test_run_csp_eval_end_to_end(tmp_path, csp_install):
    _write(tmp_path, "index.html", '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">')
    _write(tmp_path, "weird.html", '<meta http-equiv="Content-Security-Policy" content="script-src UNPARSEABLE">')
    out = tmp_path / "sarif" / "csp-evaluator.sarif"
    cp = csp_eval.run_csp_eval(tmp_path, out, version="9.9.9")
    assert cp.returncode == 0, cp.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "csp-evaluator" and run["tool"]["driver"]["version"] == "9.9.9"
    assert scan_complete(doc)
    inv = run["invocations"][0]
    assert inv["executionSuccessful"] is True and inv["properties"]["policies"] == 2
    results = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                r["locations"][0]["physicalLocation"]["region"]["startLine"], r["level"]) for r in run["results"]}
    assert results == {("SCRIPT_UNSAFE_INLINE", "index.html", 1, "error"),
                       ("FAKE_INFO", "index.html", 1, "note")}, results
    notes = [n for n in inv["toolExecutionNotifications"] if n["descriptor"]["id"] == "CSP_PARSE_ERROR"]
    assert len(notes) == 1 and "weird.html:1" in notes[0]["message"]["text"]


def test_run_csp_eval_with_no_policies_still_reports_a_complete_scan(tmp_path, csp_install):
    _write(tmp_path, "plain.py", "print('no csp here')\n")
    out = tmp_path / "csp-evaluator.sarif"
    cp = csp_eval.run_csp_eval(tmp_path, out)
    assert cp.returncode == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert scan_complete(doc) and doc["runs"][0]["results"] == []
    assert doc["runs"][0]["invocations"][0]["properties"]["note"]


def test_run_csp_eval_refuses_missing_package_or_node(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "empty"))
    assert csp_eval.run_csp_eval(tmp_path, tmp_path / "o.sarif").returncode == 66
    mt = tmp_path / "mt"
    (mt / "csp-evaluator").mkdir(parents=True)
    shutil.copyfile(DRIVER_SRC, mt / "csp-evaluator" / "mara_driver.js")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(mt))
    monkeypatch.setattr(csp_eval, "node_exe", lambda: None)
    assert csp_eval.run_csp_eval(tmp_path, tmp_path / "o.sarif").returncode == 127


def test_runner_branch_runs_and_reports_the_tool(tmp_path, csp_install):
    _write(tmp_path, "index.html", '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">')
    runs = {r.tool: r for r in runner.run_all(tmp_path, tmp_path / "out", enabled=["csp-evaluator"])}
    r = runs["csp-evaluator"]
    assert r.ran and r.note == f"pinned {tool_installs.locked('csp-evaluator')}"
    assert [x.rule_id for x in r.results] == ["SCRIPT_UNSAFE_INLINE", "FAKE_INFO"]


def test_runner_branch_reports_a_missing_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "empty"))
    runs = runner.run_all(tmp_path, tmp_path / "out", enabled=["csp-evaluator"])
    assert not runs[0].ran and "install_tools.py" in runs[0].note


def test_severity_mapping_and_message_shape():
    policies = [csp_eval.CspPolicy(file="a.html", line=3, policy="default-src *")]
    driver_results = {0: {"parse_ok": True, "findings": [
        {"type": "PLAIN_WILDCARD", "severity": "HIGH", "directive": "default-src", "description": "wildcard", "value": "*"},
        {"type": "MYSTERY", "severity": "WAT", "directive": "x", "description": "unknown severity"},
        {"type": "STYLE_UNSAFE_INLINE", "severity": "MEDIUM", "directive": "style-src", "description": "inline styles"},
        {"type": "GONE", "severity": "NONE", "directive": "x", "description": "dropped upstream, but mapped if it appears"},
    ]}}
    res = {r.rule_id: r for r in csp_eval.to_results(policies, driver_results)}
    assert res["PLAIN_WILDCARD"].level == "error" and res["PLAIN_WILDCARD"].cwe is None and res["PLAIN_WILDCARD"].cwes == []
    assert "wildcard" in res["PLAIN_WILDCARD"].message and "(value: *)" in res["PLAIN_WILDCARD"].message
    assert res["MYSTERY"].level == "note" and res["STYLE_UNSAFE_INLINE"].level == "warning"
    assert res["GONE"].level == "note"
    assert csp_eval.SEVERITY_LEVELS["HIGH"] == "error" and csp_eval.SEVERITY_LEVELS["INFO"] == "note"


def test_build_sarif_is_deterministic_and_complete():
    policies = [csp_eval.CspPolicy(file="a.html", line=1, policy="default-src *")]
    res = [csp_eval.ToolResult(tool="csp-evaluator", rule_id="PLAIN_WILDCARD", level="error", message="m",
                               file="a.html", line=1, cwe=None, cwes=[])]
    docs = [json.dumps(csp_eval.build_sarif(policies, res, version="1.1.8"), sort_keys=True) for _ in range(2)]
    assert docs[0] == docs[1]
    assert scan_complete(json.loads(docs[0]))


# ----------------------------------------------------------------------------- real pinned package (opt-in)

REAL_INSTALL = ROOT / ".mara-tools"


@pytest.mark.skipif(not os.path.isdir(REAL_INSTALL / "csp-evaluator"), reason="real csp-evaluator not installed")
def test_real_pinned_package_matches_the_recording(tmp_path):
    """The same check the L0 job runs: the pinned package on the seeded fixture must equal the
    pre-recorded SARIF exactly (drift here means the lock, the fixture or the driver changed)."""
    env = {**os.environ, "MARA_TOOLS_DIR": str(REAL_INSTALL)}
    cp = subprocess.run([sys.executable, str(ROOT / "scripts" / "csp_ci.py"),
                         "--target", str(ROOT / "fixtures" / "vuln-sample"),
                         "--report", str(tmp_path / "fixture-csp-check.sarif"),
                         "--expect", str(ROOT / "fixtures" / "vuln-sample-sarif" / "csp-evaluator.sarif")],
                        capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=300)
    assert cp.returncode == 0, f"{cp.stdout}\n{cp.stderr}"
