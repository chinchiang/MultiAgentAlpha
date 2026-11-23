"""What scripts/install_tools.py leaves for the review's tool runner: the workspace's tools/versions.lock and the tool
directory's manifest.json, which records each tool installed at the version the lock pins. A test that fakes a tool's
binary gives the runner these with the repository's own lock, so the runner's pin check (mara.tools.pins) runs as it
does in a review, rather than being patched away."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from mara.tools import pins
from mara.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]
REPO_LOCK = ROOT / pins.LOCK


def locked(tool: str) -> str:
    """The version the repository's lock pins `tool` at."""
    version = pins.locked_version(tool, REPO_LOCK)
    assert version, f"tools/versions.lock pins no {tool}"
    return version


def workspace(tools_dir: Path, trivy_cache: Path | None = None) -> Workspace:
    """The repository's own root as a MARA workspace whose tool directory (and trivy cache) is the one given."""
    return Workspace(ROOT, tools_dir=tools_dir, trivy_cache=trivy_cache)


def lock_into(workspace: Path) -> None:
    """The repository's lock as the lock of the MARA workspace `workspace`."""
    (workspace / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_LOCK, workspace / pins.LOCK)


def manifest(tools_dir: Path, *tools: str) -> None:
    """A manifest in `tools_dir` recording each of `tools` installed at its locked version, its signature verified, and,
    as the installer records it, the SHA-256 of its binary under `tools_dir`/bin when a test has put one there (call
    this after the binary is written, as the installer writes the manifest after it installs)."""
    tools_dir.mkdir(parents=True, exist_ok=True)
    entries: dict[str, dict] = {}
    for t in tools:
        entries[t] = {"version": locked(t), "signature_verified": True}
        binary = tools_dir / "bin" / t
        if binary.is_file():
            entries[t]["installed_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    (tools_dir / "manifest.json").write_text(json.dumps({"tools": entries}), encoding="utf-8")


def stand_in_binaries(monkeypatch) -> None:
    """For a test that fakes where a tool's binary is (it patches `runner.tool_path` to a file that is not there, and
    `runner._run` so that nothing is executed): the runner's check of the installed file against the manifest
    (`runner.installed_file_problem`) finds nothing wrong, as its pin check is given a manifest. tests/test_tool_installed_file.py
    tests that check itself, on a binary that is there."""
    from mara.tools import runner

    monkeypatch.setattr(runner, "installed_file_problem", lambda tool, exe, entry, kind: None)


def record_installed(tools_dir: Path, *tools: str) -> None:
    """Add to the manifest of `tools_dir`, as the installer does for a single-file tool, the SHA-256 of each of `tools`'
    stand-in binary under its bin/ (the .cmd launcher on Windows): the runner runs such a tool only as the file its
    manifest records (`runner.installed_file_problem`). The manifest is made when there is none."""
    path = tools_dir / "manifest.json"
    doc = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"tools": {}}
    for t in tools:
        binary = next(p for p in (tools_dir / "bin" / f"{t}.cmd", tools_dir / "bin" / f"{t}.exe", tools_dir / "bin" / t) if p.is_file())
        doc["tools"].setdefault(t, {})["installed_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    path.write_text(json.dumps(doc), encoding="utf-8")

