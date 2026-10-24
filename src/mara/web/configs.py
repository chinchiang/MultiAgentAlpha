"""The configs a workbench launch may name (GLOSSARY.md: workbench; docs/adr/0006-local-web-workbench.md): a file
whose resolved path has a YAML suffix and lies directly in `config/` or `config/examples/` of the workspace. The
工具與執行環境 page lists these (`env.configs`), and a review or a check_config job starts with one of these only
(`runs.resolve_config`), so the page offers exactly the configs a launch accepts.

Not pure: it reads the workspace's two config directories and resolves the symlinks in them.
"""

from __future__ import annotations

from pathlib import Path

SUFFIXES = (".yaml", ".yml")


def config_dirs(workspace: Path) -> tuple[Path, Path]:
    return (workspace / "config").resolve(), (workspace / "config" / "examples").resolve()


def allowed(workspace: Path, path: Path) -> bool:
    """`path`, once its symlinks are resolved, is a file with a YAML suffix directly in config/ or config/examples/ of
    `workspace`."""
    try:
        real = path.resolve()
    except (OSError, RuntimeError):  # a symlink loop
        return False
    return real.parent in config_dirs(workspace) and real.suffix in SUFFIXES and real.is_file()


def config_files(workspace: Path) -> list[Path]:
    """Every entry of config/ and then of config/examples/ that allowed() accepts, each directory's sorted by name."""
    base = workspace / "config"
    return [p for d in (base, base / "examples") if d.is_dir() for p in sorted(d.iterdir()) if allowed(workspace, p)]
