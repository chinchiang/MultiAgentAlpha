"""What a change adds, read once for the two checks of it: scripts/line_width.py and scripts/control_chars.py.

A change is what the commits since the merge base of --base and --head add, or with --worktree what the working tree
adds over that merge base: the tracked files, committed or not, and every untracked file git does not ignore, read as
git diff reads it once added (untracked_lines). Only what is added is read, so the lines already there are left alone.
Each added line is read as UTF-8 whatever the locale's encoding and split at newlines only, as git ends its lines,
with paths as the files are named (core.quotepath=false, header_path); a binary file has no lines in it, and a file
whose added lines are not UTF-8 is named instead (diff_lines). Each check keeps what it looks for in the lines and how
it says so; the arguments (parse_args), the error a git failure prints (git_error) and the ending, each not-UTF-8 file
and the summary (report), are shared.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HUNK = re.compile(rb"^@@ -\S+ \+(\d+)(?:,\d+)? @@")
DIFF_FLAGS = ("--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/")
ESCAPES = {b"a": 7, b"b": 8, b"t": 9, b"n": 10, b"v": 11, b"f": 12, b"r": 13, b'"': 34, b"\\": 92}


@dataclass
class AddedLines:
    """What a diff adds: (path, line number, text) of every added line, and the paths of the files whose added lines
    are not UTF-8."""

    lines: list[tuple[str, int, str]] = field(default_factory=list)
    not_utf8: list[str] = field(default_factory=list)

    def extend(self, other: AddedLines) -> None:
        self.lines += other.lines
        self.not_utf8 += other.not_utf8


@dataclass(kw_only=True)
class Change(AddedLines):
    """What a change adds, with the merge base it was read from (control_chars reads the commits' messages from it)."""

    base: str


def git_prefix(repo: Path) -> list[str]:
    return ["git", "-c", "core.quotepath=false", "-C", str(repo)]  # paths as they are, not quoted octal escapes


def git_bytes(cmd: list[str], *, ok: tuple[int, ...] = (0,)) -> bytes:
    """What git writes to stdout, as it is; any exit not in `ok` raises CalledProcessError with git's stderr as text."""
    r = subprocess.run(cmd, capture_output=True)
    if r.returncode not in ok:
        raise subprocess.CalledProcessError(r.returncode, cmd, r.stdout, r.stderr.decode("utf-8", "replace"))
    return r.stdout


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


def diff_lines(diff: bytes) -> AddedLines:
    """What a `git diff --unified=0` adds. A file whose added lines are not UTF-8 is named once and the rest of its
    lines skipped, and every other file is still read. Only what is added must be UTF-8: a line removed, a deleted file
    or a hunk header's context is not read as it. A binary file has no lines in it."""
    added, path, number = AddedLines(), None, 0
    for line in diff.split(b"\n"):  # git ends a line at a newline only; splitlines() also splits at FF, FS, NEL, LS, PS
        if line.startswith(b"+++ "):
            path = header_path(line[len(b"+++ "):])
        elif m := HUNK.match(line):
            number = int(m[1])
        elif line.startswith(b"+") and path is not None and path not in added.not_utf8:
            try:
                added.lines.append((path, number, line[1:].decode("utf-8")))
            except UnicodeDecodeError:
                added.not_utf8.append(path)
            number += 1
    return added


def untracked_lines(git: list[str], repo: Path, *pathspec: str) -> AddedLines:
    """What git diff adds for each untracked file git does not ignore, as it would once the file is added (git add -N):
    git decides what is binary, .gitattributes included, and a symlink is the text of its link. A directory (a nested
    repository, a symlink to a directory) has no lines; a file that is not UTF-8 is named instead (diff_lines). A git
    error raises CalledProcessError, with git's stderr when git exits 2 or more, and with "no diff of <name>" when it
    exits 1 and writes nothing (it cannot read the file)."""
    names = subprocess.run([*git, "ls-files", "--others", "--exclude-standard", "-z", "--", *pathspec], capture_output=True,
                           encoding="utf-8", check=True).stdout
    added = AddedLines()
    for name in filter(None, names.split("\0")):
        if (repo / name).is_dir():  # a nested repository (sub/) or a symlink to a directory: one entry, no lines
            continue
        cmd = [*git, "diff", "--no-index", *DIFF_FLAGS, "--", "/dev/null", name]
        out = git_bytes(cmd, ok=(1,))  # it exits 1 when the files differ, as a new one always does, and on an error
        if not out:
            raise subprocess.CalledProcessError(1, cmd, out, f"no diff of {name}")
        added.extend(diff_lines(out))
    return added


def parse_args(description: str, argv: list[str] | None) -> argparse.Namespace:
    """The arguments both checks take: --base, --head, --worktree and, for the tests, --repo."""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--base", required=True,
                    help="the change is what the commits since the merge base with this add, or with --worktree the working tree")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--worktree", action="store_true",
                    help="read the working tree over the merge base, untracked files included, not the commits up to --head")
    ap.add_argument("--repo", type=Path, default=Path("."), help=argparse.SUPPRESS)  # a repository other than this one (tests)
    return ap.parse_args(argv)


def read_change(a: argparse.Namespace, *pathspec: str) -> Change:
    """What the change `a` names adds to the files `pathspec` matches (every file when it is empty). A git error raises
    CalledProcessError (git_error says it)."""
    git = git_prefix(a.repo)
    base = subprocess.run([*git, "merge-base", a.base, a.head], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", check=True).stdout.strip()
    change = Change(base=base)
    change.extend(diff_lines(git_bytes([*git, "diff", *DIFF_FLAGS, base if a.worktree else f"{base}..{a.head}",
                                        *(("--", *pathspec) if pathspec else ())])))
    if a.worktree:
        change.extend(untracked_lines(git, a.repo, *pathspec))
    return change


def git_error(e: subprocess.CalledProcessError, a: argparse.Namespace) -> int:
    """Say which git command failed, and with what, on stderr; 2, the exit of a change git cannot tell."""
    n = len(git_prefix(a.repo))
    print(f"ERROR: git {' '.join(e.cmd[n:n + 2])} failed for --base {a.base}: {e.stderr.strip()}", file=sys.stderr)
    return 2


def report(hits: list[str], not_utf8: list[str], found: str, clean: str) -> int:
    """Print each hit, then each file that is not UTF-8, then the summary: `found` (what the check says of its hits)
    when there is a hit, and the number of files not UTF-8, or `clean` when there is neither. 1 when there is one,
    else 0."""
    for hit in hits:
        print(hit)
    for path in not_utf8:
        print(f"{path}: not UTF-8")
    summary = ([found] if hits else []) + ([f"{len(not_utf8)} file(s) not UTF-8"] if not_utf8 else [])
    print("; ".join(summary) or clean)
    return 1 if summary else 0
