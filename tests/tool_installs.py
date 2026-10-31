"""What scripts/install_tools.py leaves for the review's tool runner: the workspace's tools/versions.lock and the tool
directory's manifest.json, which records each tool installed at the version the lock pins. A test that fakes a tool's
binary gives the runner these with the repository's own lock, so the runner's pin check (mara.tools.pins) runs as it
does in a review, rather than being patched away."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from mara.tools import pins

ROOT = Path(__file__).resolve().parents[1]
REPO_LOCK = ROOT / pins.LOCK


def locked(tool: str) -> str:
    """The version the repository's lock pins `tool` at."""
    version = pins.locked_version(tool, REPO_LOCK)
    assert version, f"tools/versions.lock pins no {tool}"
    return version


def lock_into(workspace: Path) -> None:
    """The repository's lock as the lock of the MARA workspace `workspace`."""
    (workspace / "tools").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(REPO_LOCK, workspace / pins.LOCK)


def manifest(tools_dir: Path, *tools: str) -> None:
    """A manifest in `tools_dir` recording each of `tools` installed at its locked version, its signature verified."""
    tools_dir.mkdir(parents=True, exist_ok=True)
    entries = {t: {"version": locked(t), "signature_verified": True} for t in tools}
    (tools_dir / "manifest.json").write_text(json.dumps({"tools": entries}), encoding="utf-8")
