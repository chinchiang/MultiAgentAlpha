"""The lines a change adds to Python files, each within the 150 columns CODING_STANDARDS.md wraps code in.

  python3 scripts/line_width.py --base origin/main              # the lines added since the merge base with origin/main
  python3 scripts/line_width.py --base origin/main --worktree   # and what the working tree adds, before it is committed

ruff checks line length in src/ only (pyproject.toml ignores E501 for tests/ and scripts/, which hold lines wider than
that); this checks every Python file, but only the lines the commits since the merge base of --base and --head add,
so the lines already there are left alone. With --worktree it reads the working tree, not the commits up to --head: what the
tracked files hold over the merge base, committed or not, and every untracked file git does not ignore, read as git
diff reads it once added (untracked_lines). A line is as wide as its characters. Each added line is read as UTF-8
whatever the locale's encoding and split at newlines only, as git ends its lines, with paths as the files are named
(core.quotepath=false, header_path). Each wider line is printed as path:line: width, then each file whose added lines are not UTF-8 as path: not
UTF-8 (diff_lines). Exit 0 when there is neither, 1 when there is one, 2 when git cannot tell the change.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

LIMIT = 150
HUNK = re.compile(rb"^@@ -\S+ \+(\d+)(?:,\d+)? @@")


def git_bytes(cmd: list[str], *, ok: tuple[int, ...] = (0,)) -> bytes:
    """What git writes to stdout, as it is; any exit not in `ok` raises CalledProcessError with git's stderr as text."""
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode not in ok:
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr.decode("utf-8", "replace"))
    return r.stdout


ESCAPES = {b"a": 7, b"b": 8, b"t": 9, b"n": 10, b"v": 11, b"f": 12, b"r": 13, b'"': 34, b"\\": 92}


def header_path(name: bytes) -> str | None:
    """The path a +++ line of a diff names, None for /dev/null (a deleted file). git quotes a path that holds a tab, a
    quote, a backslash or a newline, C-style; one that holds a space it leaves bare and ends the line with a tab. A
    name that is not UTF-8 shows U+FFFD where it is not."""
    if name.startswith(b'"'):
        out, i = bytearray(), 1
        while i < len(name) and name[i:i + 1] != b'"':
            if name[i:i + 1] == b"\\" and name[i + 1:i + 2] in ESCAPES:
                out.append(ESCAPES[name[i + 1:i + 2]])
                i += 2
            elif name[i:i + 1] == b"\\":  # \ooo: a byte in octal
                out.append(int(name[i + 1:i + 4], 8))
                i += 4
            else:
                out += name[i:i + 1]
                i += 1
        name = bytes(out)
    else:
        name = name.split(b"\t")[0]  # a bare path holds no tab: the one there is git's
    return name[len(b"b/"):].decode("utf-8", "replace") if name.startswith(b"b/") else None


def diff_lines(diff: bytes) -> tuple[list[tuple[str, int, str]], list[str]]:
    """(path, line number, text) of every line a `git diff --unified=0` adds, and the paths of the files whose added
    lines are not UTF-8: such a file is named once and the rest of its lines skipped, and every other file is still
    read. Only what is added must be UTF-8: a line removed, a deleted file or a hunk header's context is not read as it.
    A binary file has no lines in it."""
    lines, not_utf8, path, number = [], [], None, 0
    for line in diff.split(b"\n"):  # git ends a line at a newline only; splitlines() also splits at FF, FS, NEL, LS, PS
        if line.startswith(b"+++ "):
            path = header_path(line[len(b"+++ "):])
        elif m := HUNK.match(line):
            number = int(m[1])
        elif line.startswith(b"+") and path is not None and path not in not_utf8:
            try:
                lines.append((path, number, line[1:].decode("utf-8")))
            except UnicodeDecodeError:
                not_utf8.append(path)
            number += 1
    return lines, not_utf8


def untracked_lines(git: list[str], repo: Path, *pathspec: str) -> tuple[list[tuple[str, int, str]], list[str]]:
    """(path, line number, text) of every line git diff adds for each untracked file git does not ignore, as it would
    once the file is added (git add -N): git decides what is binary, .gitattributes included, and a symlink is the text
    of its link. A directory (a nested repository, a symlink to a directory) has none; a file that is not UTF-8 is named
    instead (diff_lines). A git error raises CalledProcessError, with git's stderr when git exits 2 or more, and with
    "no diff of <name>" when it exits 1 and writes nothing (it cannot read the file)."""
    names = subprocess.run([*git, "ls-files", "--others", "--exclude-standard", "-z", "--", *pathspec], capture_output=True,
                           encoding="utf-8", check=True).stdout
    lines, not_utf8 = [], []
    for name in filter(None, names.split("\0")):
        if (repo / name).is_dir():  # a nested repository (sub/) or a symlink to a directory: one entry, no lines
            continue
        cmd = [*git, "diff", "--no-index", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
               "--", "/dev/null", name]
        out = git_bytes(cmd, ok=(1,))  # it exits 1 when the files differ, as a new one always does, and on an error
        if not out:
            raise subprocess.CalledProcessError(1, cmd, out, f"no diff of {name}")
        file_lines, file_not_utf8 = diff_lines(out)
        lines += file_lines
        not_utf8 += file_not_utf8
    return lines, not_utf8


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
        lines, not_utf8 = diff_lines(git_bytes([*git, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/",
                                                "--dst-prefix=b/", base if a.worktree else f"{base}..{a.head}", "--", "*.py"]))
        untracked, untracked_not_utf8 = untracked_lines(git, a.repo, "*.py") if a.worktree else ([], [])
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git {' '.join(e.cmd[len(git):len(git) + 2])} failed for --base {a.base}: {e.stderr.strip()}", file=sys.stderr)
        return 2
    not_utf8 += untracked_not_utf8
    wide = [(path, n, len(text)) for path, n, text in lines + untracked if len(text) > LIMIT]
    for path, n, width in sorted(wide):
        print(f"{path}:{n}: {width} columns")
    for path in not_utf8:
        print(f"{path}: not UTF-8")
    summary = ([f"{len(wide)} added line(s) wider than {LIMIT} columns"] if wide else []) + \
        ([f"{len(not_utf8)} file(s) not UTF-8"] if not_utf8 else [])
    print("; ".join(summary) or f"no added line is wider than {LIMIT} columns")
    return 1 if summary else 0


if __name__ == "__main__":
    sys.exit(main())
