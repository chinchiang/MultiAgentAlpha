"""The lines a change adds to Python files, each within the 150 columns CODING_STANDARDS.md wraps code in.

  python3 scripts/line_width.py --base origin/main   # the lines added since the merge base with origin/main

ruff checks line length in src/ only (pyproject.toml ignores E501 for tests/ and scripts/, which hold lines wider than
that); this checks every Python file, but only the lines the commits since the merge base of --base and --head add,
so the lines already there are left alone. A line is as wide as its characters. Each wider line is printed as
path:line: width. Exit 0 when none is wider, 1 when one is, 2 when git cannot tell the change.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

LIMIT = 150
HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,\d+)? @@")


def added_lines(diff: str) -> list[tuple[str, int, str]]:
    """(path, line number, text) of every line a `git diff --unified=0` adds."""
    lines, path, number = [], None, 0
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[len("+++ b/"):] if line.startswith("+++ b/") else None  # +++ /dev/null: a deleted file
        elif m := HUNK.match(line):
            number = int(m[1])
        elif line.startswith("+") and path is not None:
            lines.append((path, number, line[1:]))
            number += 1
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, help="the change is what the commits since the merge base with this add")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--repo", type=Path, default=Path("."), help=argparse.SUPPRESS)  # a repository other than this one (tests)
    a = ap.parse_args(argv)
    git = ["git", "-C", str(a.repo)]
    try:
        base = subprocess.run([*git, "merge-base", a.base, a.head], capture_output=True, text=True, check=True).stdout.strip()
        diff = subprocess.run([*git, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
                               f"{base}..{a.head}", "--", "*.py"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git {' '.join(e.cmd[3:5])} failed for --base {a.base}: {e.stderr.strip()}", file=sys.stderr)
        return 2
    wide = [(path, n, len(text)) for path, n, text in added_lines(diff) if len(text) > LIMIT]
    for path, n, width in sorted(wide):
        print(f"{path}:{n}: {width} columns")
    print(f"{len(wide)} added line(s) wider than {LIMIT} columns" if wide else f"no added line is wider than {LIMIT} columns")
    return 1 if wide else 0


if __name__ == "__main__":
    sys.exit(main())
