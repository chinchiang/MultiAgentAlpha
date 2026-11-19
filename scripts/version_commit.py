"""Make a branch's version commit (GLOSSARY.md), the last commit of a branch (docs/agents/pr-flow.md, step 3), as one
command.

  .venv/bin/python scripts/version_commit.py --row scratch/row.txt --for "mutate.py --realign" \\
      --trailer "Co-Authored-By: <name> <address>"
  .venv/bin/python scripts/version_commit.py --row scratch/row.txt --for "..." --to 0.14.0

--row names a file of one line, `<變更摘要> | <變更者>`, the two cells of the CHANGELOG row a human writes; the last
` | ` parts them. It then, in this order:
1. takes the version: the next patch version after origin/main's __version__ (version_files.next_version), or --to;
2. sets __version__ in src/mara/__init__.py;
3. inserts the row above the newest row of docs/CHANGELOG.md, with today's date, the version, and its 查證狀態 cell
   from what scripts/check_citations.py and scripts/count_words.py print, run now (status);
4. rebuilds the demo page (version_files.rebuild_demo);
5. runs tests/test_version.py and tests/test_workbench_demo.py: a row that breaks the rule tests/test_version.py
   states for the newest row fails here, and is not checked before;
6. commits those three files, and no other, with the message `v<version>: CHANGELOG row and demo page for <--for>`
   and each --trailer, as written, on a line of its own after a blank line. It writes no attribution of its own. A
   --trailer is meant to be a git trailer, `Key: value` (`Co-Authored-By: <name> <address>`): a line of another shape
   in the block, such as `Refs #330`, can keep git from reading the others as trailers.

A step that fails stops it, exit 1, naming the step: a script, the tests or git that exits otherwise than 0, a count
that cannot be read from what the counting scripts print, a file that cannot be written. The files changed so far are
left as they are, and nothing is committed; when the commit step fails, git add may have staged them, and the message
ends with the command that brings them back to HEAD (git restore --staged --worktree --source=HEAD -- <the three>). It
refuses, changing nothing, exit 2: a --row file that cannot be read, or is not one line holding ` | `; git with no
committer identity in the repository (git var GIT_COMMITTER_IDENT fails, as with a HOME that holds no git config), with
the last line of what git said that is not blank (`no message` when there is none); a working tree that changes, or
holds an untracked file in, anything but the three files; an origin/main whose src/mara/__init__.py gives no
__version__; and a newest CHANGELOG row that already holds the version it would take. scripts/renumber.py takes a new
version for this commit when another pull request took its version first, its subject's opening version included.

GLOSSARY.md terms: Version commit. Not pure: it edits the three files, runs the scripts, the tests and git in the
repository it is run in, and commits.
"""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import re
import subprocess
import sys
from pathlib import Path

from version_files import CHANGELOG, DEMO, ROW_RE, VERSION_FILE, next_version, rebuild_demo, version_of, with_version

VERSION_COMMIT_FILES = (CHANGELOG, DEMO, VERSION_FILE)
TESTS = ("tests/test_version.py", "tests/test_workbench_demo.py")
CITATIONS = re.compile(r"附錄A 條目: (\d+)；正文引用的不同編號: (\d+)")
WORDS = re.compile(r"^合計（不含附錄A）\s+([\d,]+)$", re.M)
MARKERS = re.compile(r"^證據標記: (\{.*\}) 合計", re.M)
LEVELS = ("已證實", "廠商主張", "第三方評論", "尚未證實")


class Refusal(Exception):
    """A state version_commit.py does not start in; nothing has been changed."""


class StepFailed(Exception):
    """A step that failed; the files changed before it are left as they are."""


def _git(root: Path, *args: str, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, encoding="utf-8", input=input)


def _run(root: Path, *args: str) -> str:
    """The output of a Python script or module run in `root`; StepFailed, with what it printed, when it fails."""
    cp = subprocess.run([sys.executable, *args], cwd=root, capture_output=True, encoding="utf-8", errors="replace")
    if cp.returncode != 0:
        raise StepFailed(f"{' '.join(args)} exit {cp.returncode}: {(cp.stdout + cp.stderr).strip()}")
    return cp.stdout


def status(root: Path) -> str:
    """The 查證狀態 cell of a row: the 附錄A entries and the distinct ids cited, as scripts/check_citations.py prints them,
    then the evidence markers and the word count, as scripts/count_words.py does; StepFailed when either fails or
    prints none of them."""
    citations, words = _run(root, "scripts/check_citations.py"), _run(root, "scripts/count_words.py")
    cited, total, markers = CITATIONS.search(citations), WORDS.search(words), MARKERS.search(words)
    if not (cited and total and markers):
        raise StepFailed("check_citations.py or count_words.py printed no count to read")
    try:
        levels = ast.literal_eval(markers.group(1))
    except (ValueError, SyntaxError) as e:
        raise StepFailed("check_citations.py or count_words.py printed no count to read") from e
    return (f"附錄A {cited.group(1)} 條，引用 {cited.group(2)} 個編號；證據標記 "
            + "／".join(f"{level} {levels.get(level, 0)}" for level in LEVELS) + f"；{total.group(1)} 字")


def _row(path: Path) -> tuple[str, str]:
    """The 變更摘要 and the 變更者 of the --row file; Refusal when it cannot be read or is not one line holding ` | `."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        raise Refusal(f"{path}: cannot be read: {getattr(e, 'strerror', None) or e}") from e
    if len(lines) != 1 or " | " not in lines[0]:
        raise Refusal(f"{path}: not one line of `<變更摘要> | <變更者>`")
    summary, _, author = lines[0].rpartition(" | ")
    return summary.strip(), author.strip()


def _committed(cp: subprocess.CompletedProcess) -> None:
    """StepFailed, with what git said, when the git command of the commit step failed."""
    if cp.returncode != 0:
        raise StepFailed(f"git {cp.args[1]}: {(cp.stdout + cp.stderr).strip()}")


def version_commit(row_file: Path, what: str, to: str | None, trailers: list[str]) -> str:
    """Make the version commit (the module's docstring says how); the version it took."""
    root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip())
    summary, author = _row(row_file)
    ident = _git(root, "var", "GIT_COMMITTER_IDENT")
    if ident.returncode != 0:  # git commit, the last step, would fail after every other step had changed the files
        said = [line for line in ident.stderr.splitlines() if line.strip()]
        raise Refusal(f"git has no committer identity in {root} (is HOME the real one?): {said[-1] if said else 'no message'}")
    others = sorted(line[3:] for line in _git(root, "status", "--porcelain", "--untracked-files=all", "--no-renames").stdout.splitlines()
                    if line[3:] not in VERSION_COMMIT_FILES)
    if others:
        raise Refusal(f"the working tree changes more than the version commit's files: {', '.join(others)}")
    main_version = version_of(_git(root, "show", f"origin/main:{VERSION_FILE}").stdout)
    if main_version is None:
        raise Refusal(f"origin/main's {VERSION_FILE} gives no __version__")
    target = to or next_version(main_version)
    changelog = (root / CHANGELOG).read_text(encoding="utf-8")
    newest = ROW_RE.search(changelog)
    if newest and newest.group(2) == target:
        raise Refusal(f"{CHANGELOG}'s newest row already holds v{target}")

    step = "setting __version__"
    try:
        (root / VERSION_FILE).write_text(with_version((root / VERSION_FILE).read_text(encoding="utf-8"), target), encoding="utf-8")
        step = "the CHANGELOG row"
        row = f"| {dt.date.today().isoformat()} | v{target} | {summary} | {author} | {status(root)} |\n"
        at = newest.start() if newest else len(changelog)
        (root / CHANGELOG).write_text(changelog[:at] + row + changelog[at:], encoding="utf-8")
        step = "the demo page"
        try:
            rebuild_demo(root)
        except subprocess.CalledProcessError as e:
            raise StepFailed(f"scripts/build_workbench_demo.py exit {e.returncode}") from e
        step = "the version and demo tests"
        _run(root, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS)
        step = "the commit"
        message = f"v{target}: CHANGELOG row and demo page for {what}\n" + ("\n" + "\n".join(trailers) + "\n" if trailers else "")
        _committed(_git(root, "add", "--", *VERSION_COMMIT_FILES))
        _committed(_git(root, "commit", "-q", "-F", "-", input=message))
    except OSError as e:
        raise StepFailed(f"{step} failed, and the files changed so far are left as they are: {e}") from e
    except StepFailed as e:
        restore_hint = (f"; to bring them back to HEAD: git restore --staged --worktree --source=HEAD -- {' '.join(VERSION_COMMIT_FILES)}"
                        if step == "the commit" else "")  # git add may have staged them
        raise StepFailed(f"{step} failed, and the files changed so far are left as they are: {e}{restore_hint}") from e
    return target


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--row", type=Path, required=True, help="a file of one line, `<變更摘要> | <變更者>`")
    ap.add_argument("--for", dest="what", required=True, help="what the version is for, the end of the commit message")
    ap.add_argument("--to", help="the version to take (default: origin/main's version plus one)")
    ap.add_argument("--trailer", action="append", default=[], help="a line after the message, as written; repeats")
    args = ap.parse_args(argv)
    try:
        target = version_commit(args.row, args.what, args.to, args.trailer)
    except (Refusal, StepFailed) as e:
        print(f"version_commit: {e}", file=sys.stderr)
        return 2 if isinstance(e, Refusal) else 1
    print(f"version_commit: v{target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
