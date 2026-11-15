"""The lines a change adds to Python files, each within the 150 columns CODING_STANDARDS.md wraps code in.

  python3 scripts/line_width.py --base origin/main              # the lines added since the merge base with origin/main
  python3 scripts/line_width.py --base origin/main --worktree   # and what the working tree adds, before it is committed

ruff checks line length in src/ only (pyproject.toml ignores E501 for tests/ and scripts/, which hold lines wider than
that); this checks every Python file, but only the lines a change adds, read as scripts/change_lines.py reads a change
(the commits since the merge base of --base and --head, or with --worktree the working tree), so the lines already
there are left alone. A line is as wide as its characters. Each wider line is printed as path:line: width, then each
file whose added lines are not UTF-8 as path: not UTF-8. Exit 0 when there is neither, 1 when there is one, 2 when git
cannot tell the change.
"""

from __future__ import annotations

import subprocess
import sys

from change_lines import git_error, parse_args, read_change, report

LIMIT = 150


def main(argv: list[str] | None = None) -> int:
    a = parse_args(__doc__.splitlines()[0], argv)
    try:
        change = read_change(a, "*.py")
    except subprocess.CalledProcessError as e:
        return git_error(e, a)
    wide = sorted((path, n, len(text)) for path, n, text in change.lines if len(text) > LIMIT)
    return report([f"{path}:{n}: {width} columns" for path, n, width in wide], change.not_utf8,
                  f"{len(wide)} added line(s) wider than {LIMIT} columns", f"no added line is wider than {LIMIT} columns")


if __name__ == "__main__":
    sys.exit(main())
