"""Tool subprocesses get an allowlisted environment, never the review's secrets (tools review item 11), and a
semgrep run whose rules come from MARA_SEMGREP_CONFIG is labelled unpinned and warned about (item 12)."""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

from mara.tools import csp_eval, runner, semgrep_rules
from tests import tool_installs

EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]})
SECRETS = {
    "ANTHROPIC_API_KEY": "sk-ant-secret", "GEMINI_API_KEY": "AIza-secret", "GLM_LOCAL_KEY": "glm-secret",
    "AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "aws-secret", "AWS_SESSION_TOKEN": "aws-session",
    "GH_TOKEN": "ghp_secret", "GITHUB_TOKEN": "ghs_secret", "HF_TOKEN": "hf_secret", "PSIRT_WEBHOOK_TOKEN": "psirt-secret",
}
# settings that would change what an explicitly configured scan does
OVERRIDES = {"TRIVY_SKIP_DIRS": "src", "GITLEAKS_CONFIG": "/tmp/allow-all.toml", "SEMGREP_RULES": "p/default",
             "NODE_OPTIONS": "--require /tmp/x.js", "PYTHONPATH": "/tmp/evil"}
NEEDED = {"PATH": "/usr/bin:/bin", "HOME": "/home/reviewer", "HTTPS_PROXY": "http://proxy.example.internal:3128",
          "NO_PROXY": "localhost", "SSL_CERT_FILE": "/etc/ssl/org-ca.pem", "LANG": "C.UTF-8"}


@pytest.fixture
def parent_env(monkeypatch):
    for k, v in {**SECRETS, **OVERRIDES, **NEEDED}.items():
        monkeypatch.setenv(k, v)


def _clean(env: dict, *allowed_secret: str) -> None:
    leaked = {k for k in SECRETS if k in env} - set(allowed_secret)
    assert not leaked, f"secrets reached a tool: {sorted(leaked)}"
    assert not set(OVERRIDES) & set(env), "a parent setting may not change the configured scan"
    assert all(env.get(k) == v for k, v in NEEDED.items()), "path, home, proxy, CA and locale still reach the tool"


def test_tool_env_keeps_only_the_allowlist(parent_env):
    _clean(runner.tool_env())
    env = runner.tool_env("GH_TOKEN", EXTRA="1")
    assert env["GH_TOKEN"] == "ghp_secret" and env["EXTRA"] == "1"
    _clean(env, "GH_TOKEN")


def test_semgrep_scan_env_is_the_allowlist_plus_its_own_switches(parent_env):
    env = semgrep_rules.scan_env()
    _clean(env)
    assert env["SEMGREP_ENABLE_VERSION_CHECK"] == "0" and env["SEMGREP_SEND_METRICS"] == "off"


@pytest.fixture
def every_tool(tmp_path, monkeypatch, parent_env):
    """run_all with every tool 'installed'; subprocess.run is captured, each call writes an empty SARIF."""
    calls: list[tuple[str, dict]] = []

    def fake_subprocess_run(cmd, *a, **kw):
        calls.append((Path(cmd[0]).name, kw.get("env")))
        for flag in ("--output", "--output-file", "--report-path", "--sarif-output"):
            if flag in cmd:
                Path(cmd[cmd.index(flag) + 1]).write_text(EMPTY_SARIF, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout=EMPTY_SARIF if Path(cmd[0]).name == "zizmor" else "", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(runner, "tool_path", lambda tool: tmp_path / "bin" / tool)
    tool_installs.manifest(tmp_path / "tools", *runner.TOOL_DIMENSIONS)  # each at its locked version
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))
    rules = tmp_path / "rules"
    rules.mkdir()
    monkeypatch.setattr(semgrep_rules, "installed_rule_paths", lambda: [rules])
    monkeypatch.delenv("MARA_SEMGREP_CONFIG", raising=False)
    target = tmp_path / "target"
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    return target, tmp_path / "out", calls


def test_no_tool_subprocess_sees_the_reviews_secrets(every_tool, monkeypatch):
    target, out, calls = every_tool
    monkeypatch.delenv("MARA_ZIZMOR_ONLINE", raising=False)
    runner.run_all(target, out, enabled=["semgrep", "gitleaks", "osv-scanner", "zizmor"])
    assert {name for name, _ in calls} == {"semgrep", "gitleaks", "osv-scanner", "zizmor"}
    for name, env in calls:
        assert env is not None, f"{name} inherited the full parent environment"
        _clean(env)


def test_zizmor_gets_the_token_only_for_its_online_audits(every_tool, monkeypatch):
    target, out, calls = every_tool
    monkeypatch.setenv("MARA_ZIZMOR_ONLINE", "1")
    runner.run_all(target, out, enabled=["zizmor", "osv-scanner"])
    envs = dict(calls)
    assert envs["zizmor"]["GH_TOKEN"] == "ghp_secret"
    _clean(envs["zizmor"], "GH_TOKEN", "GITHUB_TOKEN")
    _clean(envs["osv-scanner"])


def test_csp_evaluator_driver_runs_with_the_allowlist(parent_env, tmp_path, monkeypatch):
    seen = {}

    def fake(cmd, *a, **kw):
        seen["env"] = kw.get("env")
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")

    monkeypatch.setattr(csp_eval.subprocess, "run", fake)
    csp_eval.evaluate([], driver=tmp_path / "driver.js", node="node")
    assert seen["env"] is not None
    _clean(seen["env"])


# ------------------------------------------------------------------ MARA_SEMGREP_CONFIG is never "pinned"

def test_pinned_rules_are_labelled_pinned(every_tool):
    target, out, _ = every_tool
    [run] = runner.run_all(target, out, enabled=["semgrep"])
    assert run.ran and run.note == f"pinned {tool_installs.locked('semgrep')}" and "UNPINNED" not in run.note


@pytest.mark.parametrize("config, registry", [("/opt/rules/custom.yml", False), ("p/default", True), ("auto", True),
                                              ("/opt/a.yml,r/python.lang.security", True)])
def test_override_rules_are_labelled_unpinned_with_a_warning(every_tool, monkeypatch, caplog, config, registry):
    target, out, calls = every_tool
    monkeypatch.setenv("MARA_SEMGREP_CONFIG", config)
    with caplog.at_level(logging.WARNING, logger="mara.tools"):
        [run] = runner.run_all(target, out, enabled=["semgrep"])
    assert run.ran and "UNPINNED rules from MARA_SEMGREP_CONFIG" in run.note
    assert ("semgrep.dev" in run.note) == registry
    assert any("UNPINNED" in r.getMessage() for r in caplog.records if r.levelno == logging.WARNING)
    argv_configs = [c.strip() for c in config.split(",")]
    assert semgrep_rules.default_configs() == argv_configs == semgrep_rules.override_configs()


def test_blank_override_falls_back_to_the_pinned_rules(every_tool, monkeypatch):
    target, out, _ = every_tool
    monkeypatch.setenv("MARA_SEMGREP_CONFIG", " , ")
    assert semgrep_rules.override_configs() == []
    [run] = runner.run_all(target, out, enabled=["semgrep"])
    assert run.note == f"pinned {tool_installs.locked('semgrep')}"


# ---------------------------------------------------------------- the tool directory of the workspace the runner is given

def _fake_tool(tools: Path, name: str) -> Path:
    """An executable `name` in <tools>/bin, as tool_path finds one (a .cmd on Windows)."""
    binary = tools / "bin" / (f"{name}.cmd" if sys.platform == "win32" else name)
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    return binary


def test_the_tool_directory_and_a_tool_are_those_of_the_workspace_given_not_of_MARA_TOOLS_DIR(tmp_path, monkeypatch):
    from mara.workspace import Workspace

    environment = tmp_path / "environment-tools"
    in_environment = _fake_tool(environment, "gitleaks")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(environment))
    ws = Workspace(tmp_path / "ws")
    assert runner.tools_dir(workspace=ws) == ws.tools_dir
    assert runner.tool_path("gitleaks", workspace=ws) is None  # the environment's copy is not the workspace's
    in_workspace = _fake_tool(ws.tools_dir, "gitleaks")
    assert runner.tool_path("gitleaks", workspace=ws) == in_workspace != in_environment
    assert runner.tool_path("gitleaks") == in_environment  # without a workspace, as before


def _manifest(tools: Path, tool: str, version: str) -> None:
    tools.mkdir(parents=True, exist_ok=True)
    (tools / "manifest.json").write_text(json.dumps({"tools": {tool: {"version": version, "signature_verified": True}}}),
                                         encoding="utf-8")


def test_the_manifest_entry_and_version_of_a_tool_are_those_of_the_workspace_given_not_of_MARA_TOOLS_DIR(tmp_path, monkeypatch):
    from mara.workspace import Workspace

    environment = tmp_path / "environment-tools"
    _manifest(environment, "gitleaks", "1.0.0")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(environment))
    ws = Workspace(tmp_path / "ws")
    assert runner.installed_manifest_entry("gitleaks", workspace=ws) is None  # the environment's manifest is not the workspace's
    assert runner.installed_version("gitleaks", workspace=ws) is None
    _manifest(ws.tools_dir, "gitleaks", "2.0.0")
    assert runner.installed_manifest_entry("gitleaks", workspace=ws) == {"version": "2.0.0", "signature_verified": True}
    assert runner.installed_version("gitleaks", workspace=ws) == "2.0.0"
    assert runner.installed_version("gitleaks") == "1.0.0"  # without a workspace, as before


def test_the_csp_driver_is_that_of_the_workspace_given_not_of_MARA_TOOLS_DIR(tmp_path, monkeypatch):
    from mara.workspace import Workspace

    def put_driver(tools: Path) -> Path:
        driver = tools / csp_eval.PACKAGE_DIR / csp_eval.DRIVER_NAME
        driver.parent.mkdir(parents=True)
        driver.write_text("// driver\n", encoding="utf-8")
        return driver

    environment = tmp_path / "environment-tools"
    in_environment = put_driver(environment)
    monkeypatch.setenv("MARA_TOOLS_DIR", str(environment))
    ws = Workspace(tmp_path / "ws")
    assert csp_eval.driver_path(workspace=ws) is None  # the environment's driver is not the workspace's
    in_workspace = put_driver(ws.tools_dir)
    assert csp_eval.driver_path(workspace=ws) == in_workspace != in_environment
    assert csp_eval.driver_path() == in_environment  # without a workspace, as before


def test_the_semgrep_rules_directory_is_below_the_tool_directory_of_the_workspace_given_not_of_MARA_TOOLS_DIR(tmp_path, monkeypatch):
    from mara.workspace import Workspace

    environment = tmp_path / "environment-tools"
    monkeypatch.setenv("MARA_TOOLS_DIR", str(environment))
    ws = Workspace(tmp_path / "ws")
    assert semgrep_rules.rules_dir(workspace=ws) == tmp_path / "ws" / ".mara-tools" / "semgrep-rules"
    assert semgrep_rules.rules_dir() == environment / "semgrep-rules"  # without a workspace, as before
