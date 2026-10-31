"""Tool pins (mara.tools.pins): the version tools/versions.lock pins each deterministic tool at, and whether the tool
installed under MARA_TOOLS_DIR is that one. A review runs a required tool only at its locked version, as CI does: a tool
installed at another version is not run, so the review is incomplete (GLOSSARY.md: required tool)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mara.tools import pins, runner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
LOCK_TEXT = "schema: 1\ntools:\n  gitleaks:\n    version: 8.24.3\n  zizmor:\n    version: '1.30.1'\n"
EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]})


def test_the_lock_gives_each_tools_version_and_nothing_for_a_tool_it_does_not_name(tmp_path):
    lock = tmp_path / "versions.lock"
    lock.write_text(LOCK_TEXT, encoding="utf-8")
    assert pins.locked_version("gitleaks", lock) == "8.24.3" and pins.locked_version("zizmor", lock) == "1.30.1"
    assert pins.locked_version("trivy", lock) == ""


@pytest.mark.parametrize("text", [None, "tools: [unclosed\n", "- a list\n", "tools: [gitleaks]\n", "tools:\n  gitleaks: 8.24.3\n"])
def test_a_missing_unreadable_or_misshapen_lock_pins_nothing(tmp_path, text):
    lock = tmp_path / "versions.lock"
    if text is not None:
        lock.write_text(text, encoding="utf-8")
    assert pins.locked_version("gitleaks", lock) == ""


def test_an_installed_tool_is_the_pinned_one_only_at_the_locked_version():
    assert pins.mismatch("gitleaks", "8.24.3", "8.24.3") is None
    for installed in ("8.24.2", None, ""):
        why = pins.mismatch("gitleaks", "8.24.3", installed)
        assert why is not None and "8.24.3" in why and "scripts/install_tools.py" in why
    assert pins.mismatch("gitleaks", "", "8.24.3") is not None, "a tool the lock does not pin is not the pinned one"


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """A MARA workspace whose lock pins gitleaks 8.24.3 and a tool directory holding a gitleaks; subprocess.run is
    captured and writes an empty SARIF. Returns (target, out, the tool directory's manifest, the commands run)."""
    home, tools = tmp_path / "home", tmp_path / "home" / ".mara-tools"
    (home / "tools").mkdir(parents=True)
    (home / "tools" / "versions.lock").write_text(LOCK_TEXT, encoding="utf-8")
    (tools / "bin").mkdir(parents=True)
    exe = tools / "bin" / "gitleaks"
    exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    exe.chmod(0o755)
    monkeypatch.setenv("MARA_HOME", str(home))
    monkeypatch.delenv("MARA_TOOLS_DIR", raising=False)
    calls: list[str] = []

    def fake_run(cmd, *a, **kw):
        calls.append(Path(cmd[0]).name)
        Path(cmd[cmd.index("--report-path") + 1]).write_text(EMPTY_SARIF, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    target = tmp_path / "target"
    target.mkdir()
    return target, tmp_path / "out", tools / "manifest.json", calls


def _manifest(path: Path, version: str) -> None:
    path.write_text(json.dumps({"tools": {"gitleaks": {"version": version, "signature_verified": True}}}), encoding="utf-8")


def test_a_review_does_not_run_a_tool_installed_at_another_version_than_the_lock(workspace):
    target, out, manifest, calls = workspace
    _manifest(manifest, "8.24.2")
    (run,) = runner.run_all(target, out, enabled=["gitleaks"])
    assert not run.ran and calls == []
    assert "8.24.2" in run.note and "8.24.3" in run.note and "scripts/install_tools.py" in run.note


def test_a_review_runs_a_tool_installed_at_its_locked_version_and_says_which(workspace):
    target, out, manifest, calls = workspace
    _manifest(manifest, "8.24.3")
    (run,) = runner.run_all(target, out, enabled=["gitleaks"])
    assert run.ran and calls == ["gitleaks"] and run.note == "pinned 8.24.3"


def test_a_review_runs_no_tool_without_a_lock_or_a_record_of_the_install(workspace):
    target, out, manifest, calls = workspace
    (run,) = runner.run_all(target, out, enabled=["gitleaks"])
    assert not run.ran and calls == [], "no manifest: the installed version is unknown"
    _manifest(manifest, "8.24.3")
    (manifest.parents[1] / "tools" / "versions.lock").unlink()
    (run,) = runner.run_all(target, out, enabled=["gitleaks"])
    assert not run.ran and calls == [], "no lock: nothing is pinned"


def _ci_scripts() -> dict[str, object]:
    import csp_ci
    import gitleaks_ci
    import osv_ci
    import scorecard_ci
    import trivy_db
    import zizmor_ci

    return {"gitleaks": gitleaks_ci, "osv-scanner": osv_ci, "zizmor": zizmor_ci, "scorecard": scorecard_ci, "trivy": trivy_db,
            "csp-evaluator": csp_ci}


@pytest.mark.parametrize("tool", ["gitleaks", "osv-scanner", "zizmor", "scorecard", "trivy", "csp-evaluator"])
def test_each_ci_script_reads_its_tools_version_from_the_repositorys_lock(tool):
    module = _ci_scripts()[tool]
    want = pins.locked_version(tool, ROOT / "tools" / "versions.lock")
    assert want and module.locked_version() == want


def test_the_workbench_names_each_tools_install_status_as_the_runner_judges_it():
    assert pins.install_status("8.24.3", None, installed=False) == "missing"
    assert pins.install_status("8.24.3", {"version": "8.24.3"}, installed=False) == "missing"
    assert pins.install_status("8.24.3", {"version": "8.24.2", "signature_verified": True}, installed=True) == "version_mismatch"
    assert pins.install_status("8.24.3", {"version": "8.24.3", "signature_verified": False}, installed=True) == "unverified"
    assert pins.install_status("8.24.3", {"version": "8.24.3", "signature_verified": True}, installed=True) == "ok"


def test_g5_reads_the_install_record_from_the_tool_directory(tmp_path, monkeypatch):
    """MARA_TOOLS_DIR moves the tool directory for the runner, so G-5 reads the manifest there too."""
    import governance_check as gc

    tools = tmp_path / "elsewhere"
    tools.mkdir()
    (tools / "manifest.json").write_text(json.dumps({"tools": {"probe-tool": {"version": "1", "signature_verified": True}}}),
                                         encoding="utf-8")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    assert "probe-tool=signed" in gc.check_g5(ROOT).evidence


@pytest.mark.parametrize("text", ["tools: [unclosed\n", "schema: 1\n", "tools: {}\n"])
def test_g5_fails_on_a_lock_it_cannot_read_or_that_lists_no_tool(tmp_path, text):
    import governance_check as gc

    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "versions.lock").write_text(text, encoding="utf-8")
    assert gc.check_g5(tmp_path).status == gc.FAIL


def test_a_relative_tool_directory_lies_below_the_workspace_it_is_asked_for(tmp_path, monkeypatch):
    monkeypatch.delenv("MARA_TOOLS_DIR", raising=False)
    assert runner.tools_dir(tmp_path) == (tmp_path / ".mara-tools").resolve()
    monkeypatch.setenv("MARA_TOOLS_DIR", "elsewhere")
    assert runner.tools_dir(tmp_path) == (tmp_path / "elsewhere").resolve()
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "abs"))
    assert runner.tools_dir(tmp_path / "ignored") == (tmp_path / "abs").resolve()


def test_the_workbench_shows_a_tool_installed_at_another_version_as_a_version_mismatch(tmp_path, monkeypatch):
    from mara.web import env
    from tests import tool_installs

    home, tools = tmp_path / "home", tmp_path / "tools"
    tool_installs.lock_into(home)
    tool_installs.manifest(tools, "gitleaks")
    (tools / "bin").mkdir()
    (tools / "bin" / "gitleaks").write_text("#!/bin/sh\n", encoding="utf-8")
    (tools / "bin" / "gitleaks").chmod(0o755)
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    assert {r["name"]: r["status"] for r in env.tools(home)["rows"]}["gitleaks"] == "ok"
    (tools / "manifest.json").write_text(json.dumps({"tools": {"gitleaks": {"version": "0.0.1", "signature_verified": True}}}),
                                         encoding="utf-8")
    assert {r["name"]: r["status"] for r in env.tools(home)["rows"]}["gitleaks"] == "version_mismatch"
