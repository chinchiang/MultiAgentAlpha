"""Tool pins (GLOSSARY.md: required tool, tool evidence): the version tools/versions.lock pins each deterministic tool
at, and whether a tool installed under MARA_TOOLS_DIR is the pinned one. The review's tool runner, the CI scripts, the
workbench's environment view and governance check G-5 read the lock here, and judge an install by one rule: a tool is
the pinned one only at the version the lock pins, as scripts/install_tools.py recorded it in the tool directory's
manifest. Pure, except that read_lock, and through it locked_versions and locked_version, read the lock file they are
given.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

LOCK = Path("tools") / "versions.lock"  # below the MARA workspace, or the repository for the CI scripts

# The kinds of install whose tool is one file, the binary that is executed; the installer records its SHA-256 for them
# (scripts/install_tools.py, `installed_sha256`). semgrep is a virtual environment, its rules a checkout and
# csp-evaluator a package directory: their files are checked when they are installed, not each time they run.
SINGLE_FILE_KINDS = ("archive", "binary")


def read_lock(path: Path) -> dict[str, Any]:
    """The lock at `path` as a mapping, or {} when it is missing, unreadable or not a mapping."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    return doc if isinstance(doc, dict) else {}


def locked_tools(lock: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Each tool the lock's `tools` block names with a mapping of its own, by name."""
    tools = lock.get("tools")
    return {name: spec for name, spec in tools.items() if isinstance(spec, dict)} if isinstance(tools, dict) else {}


def locked_versions(lock: Path) -> dict[str, str]:
    """The version the lock at `lock` pins each tool at, by name; a tool it names without a version is left out."""
    return {name: str(spec["version"]) for name, spec in locked_tools(read_lock(lock)).items() if spec.get("version") is not None}


def locked_kinds(lock: Path) -> dict[str, str]:
    """The kind of install the lock at `lock` gives each tool, by name ("" for a tool it gives none)."""
    return {name: str(spec.get("kind", "")) for name, spec in locked_tools(read_lock(lock)).items()}


def locked_version(tool: str, lock: Path) -> str:
    """The version the lock at `lock` pins `tool` at, or "" when it pins none."""
    return locked_versions(lock).get(tool, "")


def mismatch(tool: str, locked: str, installed: str | None) -> str | None:
    """Why `tool`, installed at `installed` (None: no record of the install), is not the one the lock pins at `locked`
    ("": the lock pins no version), or None when it is."""
    if locked and installed == locked:
        return None
    return f"installed {tool} {installed!r} does not match tools/versions.lock {locked!r}; re-run scripts/install_tools.py"


def install_status(locked: str, entry: dict[str, Any] | None, *, installed: bool, kind: str = "") -> str:
    """The workbench's status of a tool locked at `locked` as an install of `kind`, whose install record is `entry` and
    whose binary (or checkout) is `installed`: missing, version_mismatch (not the pinned one, which a review does not
    run), no_file_hash (a single-file tool whose record holds no SHA-256 of the installed binary, which a review does
    not run either: it was installed before that was recorded), unverified (the pinned one, its publisher signature
    not verified) or ok. Whether the binary still is the recorded one is the runner's to read, each time it runs it."""
    if not installed or entry is None:
        return "missing"
    have = entry.get("version")
    if mismatch("", locked, None if have is None else str(have)) is not None:
        return "version_mismatch"
    if kind in SINGLE_FILE_KINDS and not entry.get("installed_sha256"):
        return "no_file_hash"
    return "ok" if entry.get("signature_verified") else "unverified"
