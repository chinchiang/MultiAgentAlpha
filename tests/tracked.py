"""The repository's tracked files, for tests that check the repository itself.

Walking the working tree also finds what git does not track - a `docs/.claude/worktrees/` checkout, the fetched
calibration corpora under `calib/corpora/`, `.venv` - so such a test passed or failed with whatever happened to be
lying around. What CI checks out is what git tracks.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def tracked_files(root: Path) -> list[str]:
    """Every tracked file below `root`, repository-relative with forward slashes, sorted."""
    out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, encoding="utf-8", check=True).stdout
    return sorted(p for p in out.split("\0") if p)
