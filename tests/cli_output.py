"""CLI output as a reader sees it, for tests that check what `mara` prints.

rich colours its output whenever FORCE_COLOR or GITHUB_ACTIONS is set (CI sets both), so a phrase it styles part of
("(exit 2)", a [bold] phase) is not a substring of the raw output; and it wraps long lines at the terminal width."""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def plain(output: str) -> str:
    """`output` without ANSI escape sequences, its whitespace (line breaks from wrapping included) as single spaces."""
    return " ".join(_ANSI.sub("", output).split())
