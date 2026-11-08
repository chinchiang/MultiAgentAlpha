"""The MARA workspace: where MARA's own trust anchors live, never inside the code under review.

Relative paths for MARA's own state - calib/latest.json (the Evidence record policy P8 reads), the human-queue
backlog, the ML-BOM, the PSIRT ledger, and the default tool directory .mara-tools (the pinned,
verified binaries) - resolve against the workspace root: MARA_HOME when set, the working directory
otherwise; so do the defaults of `mara review --config/--out`. A review whose workspace, tool directory,
trivy database, config file or output directory lies inside the review target is refused: run as
`cd target && mara review .` (or a CI job reviewing its own checkout), the reviewed repository would
supply the binaries the runner executes, the evidence the policies trust and the config itself.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, init=False)
class Workspace:
    """The MARA workspace a reader is given: its relative paths resolve below `root`, never against the environment.
    The tool directory is `tools_dir` and the trivy cache `trivy_cache`; when not given they are <root>/.mara-tools and
    <tool directory>/trivy-cache. Building a workspace reads no environment variable."""

    root: Path
    tools_dir: Path
    trivy_cache: Path

    def __init__(self, root: Path, tools_dir: Path | None = None, trivy_cache: Path | None = None) -> None:
        tools = tools_dir if tools_dir is not None else root / ".mara-tools"
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "tools_dir", tools)
        object.__setattr__(self, "trivy_cache", trivy_cache if trivy_cache is not None else tools / "trivy-cache")

    @classmethod
    def from_env(cls, root: Path | None = None) -> Workspace:
        """The workspace the environment names: `root` when given, else MARA_HOME or the working directory; the tool
        directory MARA_TOOLS_DIR and the trivy cache MARA_TRIVY_CACHE_DIR (a relative one of either below the root), each
        derived from the root when its variable is not set. It reads these three variables; no reader of the tool directory
        or the trivy cache reads them any other way."""
        base = Path(root).resolve() if root is not None else Path(os.environ.get("MARA_HOME") or ".").resolve()
        tools = (base / (os.environ.get("MARA_TOOLS_DIR") or ".mara-tools")).resolve()
        cache = os.environ.get("MARA_TRIVY_CACHE_DIR")
        return cls(base, tools, (base / cache).resolve() if cache else None)


class WorkspaceInsideTarget(ValueError):
    """A MARA trust anchor resolves inside the repository under review."""


def root() -> Path:
    return Path(os.environ.get("MARA_HOME") or ".").resolve()


def resolve(path: str | Path, base: Path) -> Path:
    """An absolute path as given; a relative one below `base`, the root of a workspace."""
    p = Path(path)
    return p if p.is_absolute() else base / p


def _inside(anchor: Path, target: Path) -> bool:
    return anchor == target or target in anchor.parents


def check_outside(target: Path, extra: dict[str, Path] | None = None, *, workspace: Workspace) -> None:
    """Raise WorkspaceInsideTarget when the root, the tool directory or the trivy cache of `workspace` lies inside
    `target` (or is it). `extra` names further anchors to check (the CLI's config file and output directory)."""
    target = Path(target).resolve()
    anchors = {"the MARA workspace": workspace.root, "the tool directory": workspace.tools_dir,
               "the trivy database": workspace.trivy_cache, **(extra or {})}
    inside = [f"{name} {path}" for name, path in anchors.items() if _inside(path.resolve(), target)]
    if inside:
        raise WorkspaceInsideTarget(
            f"refusing to review {target}: {'; '.join(inside)} lies inside the review target, so the reviewed "
            "repository would supply the tools the runner executes, the evidence the policies trust or the configuration "
            "itself, or would have the reports bundled into the next review. "
            "Run mara from the MARA workspace (`mara review path/to/target`) or set MARA_HOME (and MARA_TOOLS_DIR, "
            "MARA_TRIVY_CACHE_DIR) outside the target, and keep --config and --out outside it."
        )
