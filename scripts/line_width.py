"""The lines a change adds to Python files, each within the 150 columns CODING_STANDARDS.md wraps code in.

  python3 scripts/line_width.py --base origin/main              # the lines added since the merge base with origin/main
  python3 scripts/line_width.py --base origin/main --worktree   # and what the working tree adds, before it is committed

ruff checks line length in src/ only (pyproject.toml ignores E501 for tests/ and scripts/, which hold lines wider than
that); this checks every Python file, but only the lines the commits since the merge base of --base and --head add,
so the lines already there are left alone. With --worktree it reads the working tree, not the commits up to --head: what the
tracked files hold over the merge base, committed or not, and every line of an untracked file git does not ignore. A
line is as wide as its characters. The diff is read as UTF-8 whatever the locale's encoding, with paths as they are
(core.quotepath=false), and split at newlines only, as git ends its lines. Each wider line is printed as path:line:
width. Exit 0 when none is wider, 1 when one is, 2 when git cannot tell the change.
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
    for line in diff.split("\n"):  # git ends a line at a newline only; splitlines() also splits at FF, FS, NEL, LS, PS
        if line.startswith("+++ "):
            path = line[len("+++ b/"):] if line.startswith("+++ b/") else None  # +++ /dev/null: a deleted file
        elif m := HUNK.match(line):
            number = int(m[1])
        elif line.startswith("+") and path is not None:
            lines.append((path, number, line[1:]))
            number += 1
    return lines


def untracked_lines(git: list[str], repo: Path, *pathspec: str) -> list[tuple[str, int, str]]:
    """(path, line number, text) of every line of each untracked file git does not ignore, as all of it is added; a file
    that holds a NUL anywhere or is not UTF-8 has none (git diff reads such a file by its own rules, see its docs)."""
    names = subprocess.run([*git, "ls-files", "--others", "--exclude-standard", "-z", "--", *pathspec], capture_output=True,
                           encoding="utf-8", check=True).stdout
    lines = []
    for name in filter(None, names.split("\0")):
        data = (repo / name).read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if "\0" not in text:
            lines += [(name, n, line) for n, line in enumerate(text.split("\n"), 1)]
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True,
                    help="the change is what the commits since the merge base with this add, or with --worktree the working tree")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--worktree", action="store_true",
                    help="read the working tree over the merge base, untracked files included, not the commits up to --head")
    ap.add_argument("--repo", type=Path, default=Path("."), help=argparse.SUPPRESS)  # a repository other than this one (tests)
    a = ap.parse_args(argv)
    git = ["git", "-c", "core.quotepath=false", "-C", str(a.repo)]  # paths as they are, not quoted octal escapes
    try:
        base = subprocess.run([*git, "merge-base", a.base, a.head], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", check=True).stdout.strip()
        diff = subprocess.run([*git, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
                               base if a.worktree else f"{base}..{a.head}", "--", "*.py"], capture_output=True, encoding="utf-8",
                              check=True).stdout
        untracked = untracked_lines(git, a.repo, "*.py") if a.worktree else []
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git {' '.join(e.cmd[len(git):len(git) + 2])} failed for --base {a.base}: {e.stderr.strip()}", file=sys.stderr)
        return 2
    wide = [(path, n, len(text)) for path, n, text in added_lines(diff) + untracked if len(text) > LIMIT]
    for path, n, width in sorted(wide):
        print(f"{path}:{n}: {width} columns")
    print(f"{len(wide)} added line(s) wider than {LIMIT} columns" if wide else f"no added line is wider than {LIMIT} columns")
    return 1 if wide else 0


if __name__ == "__main__":
    sys.exit(main())
