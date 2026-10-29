"""Renumber the commit a rebase stopped on, when another PR took its version first (docs/CHANGELOG.md, "## 版本規則").

  git rebase origin/main            # stops on the CHANGELOG's first row (and the version and the demo)
  .venv/bin/python scripts/renumber.py            # takes the next version after main's
  .venv/bin/python scripts/renumber.py --to 0.13.40

It resolves the conflicts the version alone causes: the CHANGELOG keeps both sides' rows, the branch's on top with the
new version; src/mara/__init__.py is main's with the new version; the demo is main's, re-assembled by
scripts/build_workbench_demo.py, which reads mara from this working tree (run it here, not in another worktree). Then it
finishes the rebase and makes the first sentence's closing ", v<old>" in the commit message ", v<new>"; other mentions of
the old version are left for a human.

It refuses, changing nothing, outside a rebase (git leaves REBASE_HEAD behind when one ends, so the rebase's state
directory decides), with more commits still to apply, with a conflict in any other file, without a CHANGELOG conflict,
and when any other file would change otherwise than the branch's commit did (main already holding part of it, say).
Exit 0 once the rebase is finished, 2 when it refuses.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

CHANGELOG = "docs/CHANGELOG.md"
VERSION_FILE = "src/mara/__init__.py"
DEMO = "docs/workbench/index.html"
VERSION_RE = re.compile(r'^__version__ = "(\d+\.\d+\.\d+)"$', re.M)
ROW_RE = re.compile(r"^(\| \d{4}-\d{2}-\d{2} \| v)(\d+\.\d+\.\d+)( \|)", re.M)
CONFLICT_RE = re.compile(r"^<<<<<<< [^\n]*\n(.*?)^=======\n(.*?)^>>>>>>> [^\n]*\n", re.M | re.S)


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], capture_output=True, text=True, check=check)


class Refusal(Exception):
    """A state renumber.py does not handle; nothing has been changed."""


def _version(text: str) -> str:
    m = VERSION_RE.search(text)
    if m is None:
        raise Refusal(f"no __version__ in {VERSION_FILE}")
    return m.group(1)


def _next(version: str) -> str:
    major, minor, patch = (int(n) for n in version.split("."))
    return f"{major}.{minor}.{patch + 1}"


def _changelog(text: str, target: str) -> str:
    """The CHANGELOG with its one conflict resolved: the branch's row, renumbered, above main's rows."""
    blocks = list(CONFLICT_RE.finditer(text))
    if len(blocks) != 1:
        raise Refusal(f"{CHANGELOG}: expected one conflict at its first row, found {len(blocks)}")
    main_rows, branch_rows = blocks[0].group(1), blocks[0].group(2)
    if len(ROW_RE.findall(branch_rows)) != 1 or branch_rows.count("\n") != 1:
        raise Refusal(f"{CHANGELOG}: the branch's side of the conflict is not one row")
    branch_row = ROW_RE.sub(lambda m: m.group(1) + target + m.group(3), branch_rows, count=1)
    return text[:blocks[0].start()] + branch_row + main_rows + text[blocks[0].end():]


def _changed_lines(*diff_args: str) -> list[str]:
    out = _git("diff", "--no-color", "--no-ext-diff", *diff_args).stdout.splitlines()
    return sorted(line for line in out if line[:1] in "+-" and not line.startswith(("+++", "---")))


def _drifted() -> list[str]:
    """The files, other than the version's three, whose changes after the rebase are not the branch commit's own."""
    own = {CHANGELOG, VERSION_FILE, DEMO}
    names = (set(_git("diff", "--name-only", "REBASE_HEAD~1", "REBASE_HEAD").stdout.split())
             | set(_git("diff", "--name-only", "--cached", "HEAD").stdout.split())) - own
    return sorted(f for f in names
                  if _changed_lines("REBASE_HEAD~1", "REBASE_HEAD", "--", f) != _changed_lines("--cached", "HEAD", "--", f))


def _subject(message: str, old: str, new: str) -> str:
    """The commit message with its first sentence's closing ", v<old>" made ", v<new>"."""
    first, sep, rest = message.partition("\n")
    return re.sub(rf", v{re.escape(old)}(?=\.|$)", f", v{new}", first, count=1) + sep + rest


def _rebasing() -> bool:
    """Whether a rebase is in progress; REBASE_HEAD alone cannot tell, since git leaves it behind when a rebase ends."""
    return any(Path(_git("rev-parse", "--git-path", d).stdout.strip()).is_dir() for d in ("rebase-merge", "rebase-apply"))


def _commits_left() -> int:
    """How many commits the rebase still has to apply after the one it stopped on."""
    for state, done, total in (("rebase-merge", "msgnum", "end"), ("rebase-apply", "next", "last")):
        d = Path(_git("rev-parse", "--git-path", state).stdout.strip())
        if d.is_dir():
            return int((d / total).read_text()) - int((d / done).read_text())
    return 0


def renumber(target: str | None) -> None:
    root = Path(_git("rev-parse", "--show-toplevel").stdout.strip())
    os.chdir(root)
    if not _rebasing():
        raise Refusal("no rebase in progress: run it where `git rebase origin/main` stopped")
    if left := _commits_left():
        raise Refusal(f"the rebase has {left} more commit(s) to apply; renumber.py handles a branch of one commit")
    conflicted = set(_git("diff", "--name-only", "--diff-filter=U").stdout.split())
    if others := sorted(conflicted - {CHANGELOG, VERSION_FILE, DEMO}):
        raise Refusal(f"conflicts outside the version's files, resolve them by hand first: {', '.join(others)}")
    if CHANGELOG not in conflicted:
        raise Refusal(f"{CHANGELOG} has no conflict: nothing to renumber")
    if drifted := _drifted():
        raise Refusal(f"these files change otherwise than the branch's commit did, check them by hand: {', '.join(drifted)}")
    old = _version(_git("show", f"REBASE_HEAD:{VERSION_FILE}").stdout)
    main_version_file = _git("show", f"HEAD:{VERSION_FILE}").stdout
    target = target or _next(_version(main_version_file))

    (root / CHANGELOG).write_text(_changelog((root / CHANGELOG).read_text(encoding="utf-8"), target), encoding="utf-8")
    (root / VERSION_FILE).write_text(VERSION_RE.sub(f'__version__ = "{target}"', main_version_file), encoding="utf-8")
    if DEMO in conflicted:  # the builder re-assembles the page it reads: give it main's (in a rebase, "ours")
        _git("checkout", "--ours", DEMO)
    subprocess.run([sys.executable, str(root / "scripts" / "build_workbench_demo.py")], check=True)
    _git("add", CHANGELOG, VERSION_FILE, DEMO)

    message = _git("log", "-1", "--format=%B", "REBASE_HEAD").stdout
    _git("-c", "core.editor=true", "rebase", "--continue")
    renamed = _subject(message, old, target)
    if renamed != message:
        subprocess.run(["git", "commit", "-q", "--amend", "-F", "-"], input=renamed, text=True, check=True)
    print(f"renumber: v{old} -> v{target}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--to", help="the version to take (default: main's version plus one)")
    args = ap.parse_args(argv)
    try:
        renumber(args.to)
    except Refusal as e:
        print(f"renumber: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
