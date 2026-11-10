"""What a change adds holds no control character: the lines it adds to any text file, and its commit messages.

  python3 scripts/control_chars.py --base origin/main   # what the commits since the merge base with origin/main add

A control character is any C0 character other than the newline (a tab and a carriage return among them), NEL
(U+0085), and the line and paragraph separators (U+2028, U+2029). No text file this repository tracks holds one, so
one that a change adds came from a heredoc, sed or a tool input that wrote an escape as the character itself. Only
what the commits since the merge base of --base and --head add is read, so the lines already there are left alone.
The diff is read as UTF-8 with paths as they are, and split at newlines only (line_width.added_lines); a binary file
has no lines in it. Each character found is printed as path:line: U+XXXX, or for a commit message as
"commit <its first 12 hex digits>, message line N: U+XXXX". Exit 0 when there is none, 1 when there is one, 2 when git
cannot tell the change.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from line_width import added_lines

CONTROL = frozenset(chr(c) for c in range(0x20) if c != 0x0A) | {chr(0x85), chr(0x2028), chr(0x2029)}


def found(text: str) -> list[str]:
    """The control characters of `text`, each once, in the order they first appear."""
    return list(dict.fromkeys(c for c in text if c in CONTROL))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, help="the change is what the commits since the merge base with this add")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--repo", type=Path, default=Path("."), help=argparse.SUPPRESS)  # a repository other than this one (tests)
    a = ap.parse_args(argv)
    git = ["git", "-c", "core.quotepath=false", "-C", str(a.repo)]  # paths as they are, not quoted octal escapes
    try:
        base = subprocess.run([*git, "merge-base", a.base, a.head], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", check=True).stdout.strip()
        diff = subprocess.run([*git, "diff", "--unified=0", "--no-color", "--no-ext-diff", "--src-prefix=a/", "--dst-prefix=b/",
                               f"{base}..{a.head}"], capture_output=True, encoding="utf-8", check=True).stdout
        log = subprocess.run([*git, "log", "-z", "--format=%H%n%B", f"{base}..{a.head}"], capture_output=True, encoding="utf-8",
                             check=True).stdout
    except subprocess.CalledProcessError as e:
        print(f"ERROR: git {' '.join(e.cmd[len(git):len(git) + 2])} failed for --base {a.base}: {e.stderr.strip()}", file=sys.stderr)
        return 2
    hits = [f"{path}:{n}: U+{ord(c):04X}" for path, n, text in added_lines(diff) for c in found(text)]
    for commit in filter(None, log.split("\0")):  # -z ends each commit with a NUL; a message cannot hold one
        sha, _, message = commit.partition("\n")
        hits += [f"commit {sha[:12]}, message line {n}: U+{ord(c):04X}" for n, line in enumerate(message.split("\n"), 1)
                 for c in found(line)]
    for hit in hits:
        print(hit)
    print(f"{len(hits)} control character(s) in what the change adds" if hits else "no control character in what the change adds")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
