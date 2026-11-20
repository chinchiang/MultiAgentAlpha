"""What a change adds holds no control character: the lines it adds to any text file, and its commit messages; or a file.

  python3 scripts/control_chars.py --base origin/main              # what the commits since the merge base with origin/main add
  python3 scripts/control_chars.py --base origin/main --worktree   # what the working tree adds, before it is committed
  python3 scripts/control_chars.py --file scratch/pr-body-x.md     # every line of a file, read whole (check_files)

A control character is any C0 character other than the newline (a tab and a carriage return among them), NEL
(U+0085), and the line and paragraph separators (U+2028, U+2029). No text file this repository tracks holds one, so
one that a change adds came from a heredoc, sed or a tool input that wrote an escape as the character itself. The lines
a change adds are read as scripts/change_lines.py reads a change, so the lines already there are left alone; the
commits' messages are read too, except with --worktree, where there are none. Each character found is printed as
path:line: U+XXXX, or for a commit message as "commit <its first 12 hex digits>, message line N: U+XXXX", then each file
whose added lines are not UTF-8 as path: not UTF-8. No text file this repository tracks is in another encoding, so such
a file fails the check too. Exit 0 when there is none, 1 when there is one, 2 when git cannot tell the change.
With --file, which excludes --base and is refused with --worktree or a --head other than HEAD, each file given is
read whole and every line of it is checked the same way, its characters printed as path:line: U+XXXX and the file as
path: not UTF-8 when it is not; the exit is the same, and 2 when a file cannot be read.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

from change_lines import git_error, git_prefix, parse_args, read_change, report

CONTROL = frozenset(chr(c) for c in range(0x20) if c != 0x0A) | {chr(0x85), chr(0x2028), chr(0x2029)}


def found(text: str) -> list[str]:
    """The control characters of `text`, each once, in the order they first appear."""
    return list(dict.fromkeys(c for c in text if c in CONTROL))


def _hits(lines: Iterable[tuple[str, int, str]]) -> list[str]:
    """`path:line: U+XXXX` for each control character of each (path, line number, text) of `lines`."""
    return [f"{path}:{n}: U+{ord(c):04X}" for path, n, text in lines for c in found(text)]


def check_files(paths: list[Path]) -> int:
    """Check every line of each file of `paths`, read whole as UTF-8, and print what main prints for a change's added
    lines (report): 1 when a file holds a control character or is not UTF-8, else 0. When a file cannot be read, nothing
    but the error, on stderr, is printed, and 2 is returned: each file is read before anything is printed."""
    hits, not_utf8 = [], []
    for path in paths:
        try:
            text = path.read_bytes().decode("utf-8")
        except OSError as e:
            print(f"ERROR: {path}: {e.strerror}", file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            not_utf8.append(str(path))
            continue
        hits += _hits((str(path), n, line) for n, line in enumerate(text.split("\n"), 1))
    return report(hits, not_utf8, f"{len(hits)} control character(s) in the files given", "no control character in the files given")


def main(argv: list[str] | None = None) -> int:
    a = parse_args(__doc__.splitlines()[0], argv, files=True)
    if a.file:
        return check_files(a.file)
    try:
        change = read_change(a)
        log = "" if a.worktree else subprocess.run([*git_prefix(a.repo), "log", "-z", "--format=%H%n%B", f"{change.base}..{a.head}"],
                                                   capture_output=True, encoding="utf-8", check=True).stdout
    except subprocess.CalledProcessError as e:
        return git_error(e, a)
    hits = _hits(change.lines)
    for commit in filter(None, log.split("\0")):  # -z ends each commit with a NUL; a message cannot hold one
        sha, _, message = commit.partition("\n")
        hits += [f"commit {sha[:12]}, message line {n}: U+{ord(c):04X}" for n, line in enumerate(message.split("\n"), 1)
                 for c in found(line)]
    return report(hits, change.not_utf8, f"{len(hits)} control character(s) in what the change adds",
                  "no control character in what the change adds")


if __name__ == "__main__":
    sys.exit(main())
