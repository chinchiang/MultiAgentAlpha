"""The MARA workspace: where MARA's own trust anchors live, never inside the code under review.

Relative paths for MARA's own state - calib/latest.json (policy P8's evidence), the human-queue
backlog, the ML-BOM, the PSIRT ledger, and the default tool directory .mara-tools (the pinned,
verified binaries) - resolve against the workspace root: MARA_HOME when set, the working directory
otherwise; so do the defaults of `mara review --config/--out`. A review whose workspace, tool directory,
trivy database, config file or output directory lies inside the review target is refused: run as
`cd target && mara review .` (or a CI job reviewing its own checkout), the reviewed repository would
supply the binaries the runner executes, the evidence the policies trust and the config itself.
"""

from __future__ import annotations

import os
from pathlib import Path


class WorkspaceInsideTarget(ValueError):
    """A MARA trust anchor resolves inside the repository under review."""


def root() -> Path:
    return Path(os.environ.get("MARA_HOME") or ".").resolve()


def resolve(path: str | Path) -> Path:
    """An absolute path as given; a relative one below the workspace root."""
    p = Path(path)
    return p if p.is_absolute() else root() / p


def _inside(anchor: Path, target: Path) -> bool:
    return anchor == target or target in anchor.parents


def check_outside(target: Path, extra: dict[str, Path] | None = None) -> None:
    """Raise WorkspaceInsideTarget when the workspace root, the tool directory or the trivy cache
    lies inside `target` (or is it). `extra` names further anchors to check (the CLI's config file
    and output directory)."""
    from .tools.runner import tools_dir
    from .tools.trivy_db import cache_dir

    target = Path(target).resolve()
    anchors = {"the MARA workspace (MARA_HOME or the working directory)": root(),
               "the tool directory (MARA_TOOLS_DIR or <workspace>/.mara-tools)": tools_dir(),
               "the trivy database (MARA_TRIVY_CACHE_DIR)": cache_dir(), **(extra or {})}
    inside = [f"{name} {path}" for name, path in anchors.items() if _inside(path.resolve(), target)]
    if inside:
        raise WorkspaceInsideTarget(
            f"refusing to review {target}: {'; '.join(inside)} lies inside the review target, so the reviewed "
            "repository would supply the tools the runner executes, the evidence the policies trust or the configuration "
            "itself, or would have the reports bundled into the next review. "
            "Run mara from the MARA workspace (`mara review path/to/target`) or set MARA_HOME outside the target, "
            "and keep --config and --out outside it."
        )
