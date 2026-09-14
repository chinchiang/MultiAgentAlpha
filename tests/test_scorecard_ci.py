"""scripts/scorecard_ci.py: the locked scorecard CLI (never PATH, version = lock, token only from
GITHUB_AUTH_TOKEN) produces JSON that is converted to SARIF (rule per check, note for -1, warning below 10,
error below the policy minimum, location from the check's details) and gated by tools/scorecard-policy.yaml.
Fake scorecard, no network."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scorecard_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))

import scorecard_ci as sc  # noqa: E402

DOC = {
    "date": "2026-09-14T03:30:59Z", "repo": {"name": "github.com/o/r", "commit": "abc"},
    "scorecard": {"version": "v5.5.0", "commit": "c395761"}, "score": 6.0,
    "checks": [
        {"name": "Token-Permissions", "score": 10, "reason": "least privilege", "details": ["Info: jobLevel 'contents' permission set to 'read': .github/workflows/mara-review.yml:47"],
         "documentation": {"url": "https://x/checks.md#token-permissions", "short": "tokens"}},
        {"name": "Dangerous-Workflow", "score": 10, "reason": "none", "details": None, "documentation": {"url": "https://x/#dw", "short": "dw"}},
        {"name": "Binary-Artifacts", "score": 10, "reason": "no binaries", "details": None, "documentation": {"url": "https://x/#ba", "short": "ba"}},
        {"name": "Branch-Protection", "score": -1, "reason": "internal error: admin token needed", "details": None, "documentation": {"url": "https://x/#bp", "short": "bp"}},
        {"name": "License", "score": 0, "reason": "license file not detected", "details": ["Warn: project does not have a license file"],
         "documentation": {"url": "https://x/#lic", "short": "license"}},
        {"name": "Pinned-Dependencies", "score": 7, "reason": "dependency not pinned by hash detected", "details": ["Warn: pipCommand not pinned by hash: .github/workflows/mara-review.yml:143"],
         "documentation": {"url": "https://x/#pin", "short": "pinned"}},
    ],
}


def _fake_scorecard(tools: Path, version: str, doc: dict | None, crash: bool = False) -> Path:
    (tools / "bin").mkdir(parents=True, exist_ok=True)
    exe = tools / "bin" / "scorecard"
    lines = ["#!/bin/sh", "printf '%s\\n' \"$@\" > \"$(dirname \"$0\")/../argv.txt\""]
    if crash:
        lines.append("echo 'boom' >&2; exit 1")
    else:
        (tools / "canned.json").write_text(json.dumps(doc), encoding="utf-8")
        lines += ["for a in \"$@\"; do case \"$a\" in --output=*) out=\"${a#--output=}\";; esac; done",
                  "cp \"$(dirname \"$0\")/../canned.json\" \"$out\""]
    exe.write_text("\n".join(lines) + "\n", encoding="utf-8")
    exe.chmod(0o755)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"scorecard": {"version": version}}}), encoding="utf-8")
    return exe


def _policy(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def _run(tools: Path, *args: str, token: str | None = "t") -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != sc.TOKEN_ENV}
    env["MARA_TOOLS_DIR"] = str(tools)
    if token is not None:
        env[sc.TOKEN_ENV] = token
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


def test_repository_policy_file_is_valid_and_enforces_the_three_self_evident_checks():
    pol = sc.load_policy(ROOT / "tools" / "scorecard-policy.yaml")
    assert pol == {"Dangerous-Workflow": 10, "Token-Permissions": 10, "Binary-Artifacts": 10}


def test_policy_rejects_unknown_checks_and_bad_minimums(tmp_path):
    with pytest.raises(ValueError, match="unknown Scorecard check"):
        sc.load_policy(_policy(tmp_path, "enforce: {Tokn-Permissions: 10}\n"))
    with pytest.raises(ValueError, match="0..10"):
        sc.load_policy(_policy(tmp_path, "enforce: {License: 11}\n"))


def test_sarif_levels_locations_and_categories():
    rows, failures = sc.evaluate(DOC, {"Token-Permissions": 10, "Pinned-Dependencies": 9})
    assert failures == ["Pinned-Dependencies: 7 < 9: dependency not pinned by hash detected"]
    sarif = sc.to_sarif(DOC, rows, None)
    run = sarif["runs"][0]
    assert run["automationDetails"] == {"id": "scorecard/"} and run["tool"]["driver"]["name"] == "OpenSSF Scorecard"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {f"scorecard/{c['name']}" for c in DOC["checks"]}
    by = {r["ruleId"]: r for r in run["results"]}
    assert set(by) == {"scorecard/Branch-Protection", "scorecard/License", "scorecard/Pinned-Dependencies"}, "checks at 10 produce no result"
    assert by["scorecard/Branch-Protection"]["level"] == "note"
    assert by["scorecard/License"]["level"] == "warning"
    lic = by["scorecard/License"]["locations"][0]["physicalLocation"]
    assert lic["artifactLocation"]["uri"] == "README.md" and "attached to README.md:1" in by["scorecard/License"]["message"]["text"]
    pin = by["scorecard/Pinned-Dependencies"]
    assert pin["level"] == "error" and "Policy minimum: 9" in pin["message"]["text"]
    assert pin["locations"][0]["physicalLocation"] == {"artifactLocation": {"uri": ".github/workflows/mara-review.yml"}, "region": {"startLine": 143}}


def test_enforced_check_that_could_not_be_evaluated_fails():
    _, failures = sc.evaluate(DOC, {"Branch-Protection": 5})
    assert failures and "not evaluated" in failures[0]
    _, failures = sc.evaluate(DOC, {"SAST": 1})
    assert failures == ["SAST: enforced by policy but absent from Scorecard's output"]


def test_cli_runs_the_locked_binary_and_gates_on_policy(tmp_path):
    tools = tmp_path / "tools"
    _fake_scorecard(tools, sc.locked_version(), DOC)
    pol = _policy(tmp_path, "enforce: {Token-Permissions: 10, Dangerous-Workflow: 10}\n")
    r = _run(tools, "--repo", "github.com/o/r", "--commit", "abc", "--json", str(tmp_path / "s.json"), "--sarif", str(tmp_path / "s.sarif"), "--policy", str(pol))
    assert r.returncode == 0, r.stdout + r.stderr
    argv = (tools / "argv.txt").read_text().split()
    assert argv[:4] == ["--repo=github.com/o/r", "--commit=abc", "--format=json", "--show-details"] and argv[4].startswith("--output=")
    assert "policy met" in r.stdout and "SARIF: 3 result(s)" in r.stdout
    assert json.loads((tmp_path / "s.sarif").read_text())["runs"][0]["automationDetails"]["id"] == "scorecard/"
    # the same output fails once the policy asks for something the repository does not reach
    pol = _policy(tmp_path, "enforce: {License: 10}\n")
    r = _run(tools, "--repo", "github.com/o/r", "--json", str(tmp_path / "s.json"), "--sarif", str(tmp_path / "s.sarif"), "--policy", str(pol))
    assert r.returncode == 2 and "POLICY: 1 enforced check(s) not met" in r.stdout and "License: 0 < 10" in r.stdout


def test_cli_refuses_missing_token_bad_repo_wrong_version_and_crash(tmp_path):
    tools = tmp_path / "tools"
    _fake_scorecard(tools, sc.locked_version(), DOC)
    pol = _policy(tmp_path, "enforce: {}\n")
    r = _run(tools, "--repo", "github.com/o/r", "--policy", str(pol), token=None)
    assert r.returncode == 2 and sc.TOKEN_ENV in r.stderr
    r = _run(tools, "--repo", "https://github.com/o/r", "--policy", str(pol))
    assert r.returncode == 2 and "github.com/<owner>/<repo>" in r.stderr
    r = _run(tmp_path / "empty", "--repo", "github.com/o/r", "--policy", str(pol))
    assert r.returncode == 2 and "not installed" in r.stderr
    _fake_scorecard(tools, "0.0.1", DOC)
    r = _run(tools, "--repo", "github.com/o/r", "--policy", str(pol))
    assert r.returncode == 2 and "does not match tools/versions.lock" in r.stderr
    _fake_scorecard(tools, sc.locked_version(), None, crash=True)
    r = _run(tools, "--repo", "github.com/o/r", "--json", str(tmp_path / "none.json"), "--policy", str(pol))
    assert r.returncode == 1 and "wrote no" in r.stderr
