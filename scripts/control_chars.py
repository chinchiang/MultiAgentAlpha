"""What a change adds holds no control character: the lines it adds to any text file, and its commit messages.

  python3 scripts/control_chars.py --base origin/main              # what the commits since the merge base with origin/main add
  python3 scripts/control_chars.py --base origin/main --worktree   # what the working tree adds, before it is committed

A control character is any C0 character other than the newline (a tab and a carriage return among them), NEL
(U+0085), and the line and paragraph separators (U+2028, U+2029). No text file this repository tracks holds one, so
one that a change adds came from a heredoc, sed or a tool input that wrote an escape as the character itself. The lines
a change adds are read as scripts/change_lines.py reads a change, so the lines already there are left alone; the
commits' messages are read too, except with --worktree, where there are none. Each character found is printed as
path:line: U+XXXX, or for a commit message as "commit <its first 12 hex digits>, message line N: U+XXXX", then each file
whose added lines are not UTF-8 as path: not UTF-8. No text file this repository tracks is in another encoding, so such
a file fails the check too. Exit 0 when there is none, 1 when there is one, 2 when git cannot tell the change.
"""

from __future__ import annotations

import subprocess
import sys

from change_lines import git_error, git_prefix, parse_args, read_change, report

CONTROL = frozenset(chr(c) for c in range(0x20) if c != 0x0A) | {chr(0x85), chr(0x2028), chr(0x2029)}


def found(text: str) -> list[str]:
    """The control characters of `text`, each once, in the order they first appear."""
    return list(dict.fromkeys(c for c in text if c in CONTROL))


def main(argv: list[str] | None = None) -> int:
    a = parse_args(__doc__.splitlines()[0], argv)
    try:
        change = read_change(a)
        log = "" if a.worktree else subprocess.run([*git_prefix(a.repo), "log", "-z", "--format=%H%n%B", f"{change.base}..{a.head}"],
                                                   capture_output=True, encoding="utf-8", check=True).stdout
    except subprocess.CalledProcessError as e:
        return git_error(e, a)
    hits = [f"{path}:{n}: U+{ord(c):04X}" for path, n, text in change.lines for c in found(text)]
    for commit in filter(None, log.split("\0")):  # -z ends each commit with a NUL; a message cannot hold one
        sha, _, message = commit.partition("\n")
        hits += [f"commit {sha[:12]}, message line {n}: U+{ord(c):04X}" for n, line in enumerate(message.split("\n"), 1)
                 for c in found(line)]
    return report(hits, change.not_utf8, f"{len(hits)} control character(s) in what the change adds",
                  "no control character in what the change adds")


if __name__ == "__main__":
    sys.exit(main())
