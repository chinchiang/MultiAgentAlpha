"""Run the working tree's tests against the base's code (docs/agents/pr-flow.md, step 2) and say, for each test, how it
ended there: for a test written after the fix, or green the moment it was written, whose red has to be shown on the base.

  .venv/bin/python scripts/red_on_base.py tests/test_x.py [tests/test_y.py ...] [-k <expr>] [--base origin/main]

It makes a git worktree of the merge base of --base and HEAD in a new directory under scratch/, replaces the worktree's
tests/ with the working tree's whole tests/, committed or not (so a helper or a conftest comes along without being
named; nothing else is copied), and links the checkout's .mara-tools into it when the checkout has one: git ignores it,
so the worktree has none, and a test that needs a tool skips without it. It runs pytest there on the test files given
(and -k), with this interpreter, PYTHONPATH at the worktree's src/, HOME at an empty directory, the collection
errors continued and the traceback --tb=auto whatever the environment or the base's config asks (outcomes reads its
frames), and reads the JUnit XML pytest writes (outcomes). It prints, in that order, a line for each test,
its status and its node id, the lines it gives indented below it, then the counts:
- RED: the first `>` line and the first `E` line of its failure (or error);
- GREEN;
- SKIPPED: pytest's reason (an expected failure, xfail, is one, its reason often empty);
- UNREACHED: a test file pytest could not collect on the base, or a test whose failure's first `E` line begins with a
  ModuleNotFoundError or an ImportError, with that line and UNREACHED_NOTE: what the base lacks is the module or the
  name the test imports (what that shows, and what does instead: pr-flow step 2); or a test whose failure's first `E`
  line is a TypeError for an unexpected keyword argument raised in the one frame its failure holds, the test's own
  call (or a fixture's), with that line and KEYWORD_NOTE: what the base lacks is the keyword (what then: pr-flow step
  2). The same TypeError raised in a frame further down, in a helper or code the test's call reaches, is RED.
Neither a skipped nor an unreached test is counted red or green. A test that runs a script the base lacks as a child
process, and imports nothing of it, fails at one of its own assertions with `No such file or directory` inside its
message, or on the FileNotFoundError its run raises: it is RED, as nothing here tells that failure from another.
The worktree and its directory are removed afterwards, also when pytest fails or the run is interrupted, and the
checkout's .mara-tools is left as it was. Exit 0 when pytest ran the tests, whatever their statuses; 2 when a test file
is not one under the working tree's tests/, git cannot tell the merge base or make the worktree, or pytest did not run
them (its exit code other than 0, 1 and 5, its output on stderr); 130 when interrupted.

GLOSSARY.md terms: none. Not pure: main runs git and pytest and writes under scratch/; outcomes is pure.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import NamedTuple

UNREACHED_ERRORS = ("ModuleNotFoundError", "ImportError")  # a first `E` line naming one: the base cannot reach the test
UNREACHED_NOTE = "shown sensitive by its mutations instead (pr-flow step 2)"
KEYWORD_ERROR = re.compile(r"^E\s+TypeError: \S+ got an unexpected keyword argument ")  # a call the base's function refuses
FRAME_SEPARATOR = "_ _ _"  # a line --tb=auto writes in a failure of two frames or more, after its first and before its last
KEYWORD_NOTE = "the base's function lacks the keyword: how to see the red the test is about is in pr-flow step 2"
STATUSES = ("RED", "GREEN", "SKIPPED", "UNREACHED")  # in the order the counts are printed
RAN = (0, 1, 5)  # pytest's exit codes when it ran the tests: all passed, some failed, none collected
TOOLS = ".mara-tools"  # where a test that needs a tool looks for it, below the repository it sits in


class Outcome(NamedTuple):
    status: str  # one of STATUSES
    node: str  # pytest's node id, <file>::<class>::<test>; a file pytest could not collect, its path alone
    detail: list[str]  # the lines printed under it


def _file_and_rest(dotted: str, files: list[str]) -> tuple[str, str] | None:
    """The file of `files` whose dotted path `dotted` is or begins with, and what follows it, or None."""
    for f in files:
        prefix = f.removesuffix(".py").replace("/", ".")
        if dotted == prefix or dotted.startswith(prefix + "."):
            return f, dotted[len(prefix) + 1:]
    return None


def _node(classname: str, name: str, files: list[str]) -> str:
    """The node id of a JUnit testcase: a collection error's name is its file's dotted path, and a test's classname is
    its file's then its classes'."""
    if not classname and (found := _file_and_rest(name, files)) and not found[1]:
        return found[0]
    if (found := _file_and_rest(classname, files)) is None:
        return f"{classname}::{name}"
    return "::".join([found[0], *filter(None, found[1].split(".")), name])


def outcomes(junit: str, files: list[str]) -> list[Outcome]:
    """Each testcase of pytest's JUnit XML `junit`, in its order, for the test files `files` (paths from the root pytest
    ran in), by the first `failure` or `error` it holds, if any:
    - UNREACHED when its first `E` line begins with a ModuleNotFoundError or an ImportError, or it is a file pytest could
      not collect, with that `E` line (`E` and the message pytest gives, for one with none) and UNREACHED_NOTE;
    - UNREACHED when its first `E` line is a TypeError for an unexpected keyword argument and its text holds one frame
      (no FRAME_SEPARATOR line, as --tb=auto writes it), the test's own or a fixture's, with that `E` line and
      KEYWORD_NOTE;
    - RED otherwise, with the first `>` line and the first `E` line of its text;
    - SKIPPED, with the message pytest gives (empty for an expected failure), when it holds none but a `skipped`;
    - GREEN when it holds none of them."""
    found = []
    for case in ET.fromstring(junit).iter("testcase"):
        node = _node(case.get("classname", ""), case.get("name", ""), files)
        failed = next((e for e in case if e.tag in ("failure", "error")), None)
        if failed is None and (skipped := case.find("skipped")) is not None:
            found.append(Outcome("SKIPPED", node, [skipped.get("message", "")]))
            continue
        if failed is None:
            found.append(Outcome("GREEN", node, []))
            continue
        lines = (failed.text or "").splitlines()
        arrow, error = (next((line for line in lines if line.startswith(mark)), None) for mark in (">", "E "))
        unreached = not case.get("classname") or (error is not None and error[1:].lstrip().startswith(UNREACHED_ERRORS))
        keyword_at_own_call = error is not None and bool(KEYWORD_ERROR.match(error)) and not any(
            line.startswith(FRAME_SEPARATOR) for line in lines)  # one frame: the test's own
        if unreached:
            found.append(Outcome("UNREACHED", node, [error or f"E   {failed.get('message', '')}", UNREACHED_NOTE]))
        elif keyword_at_own_call:
            found.append(Outcome("UNREACHED", node, [error, KEYWORD_NOTE]))
        else:
            found.append(Outcome("RED", node, [line for line in (arrow, error) if line is not None]))
    return found


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("files", nargs="+", help="test files of the working tree")
    p.add_argument("-k", help="pytest's -k expression")
    p.add_argument("--base", default="origin/main", help="the base whose merge base with HEAD the tests run on")
    a = p.parse_args(argv)
    root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").stdout.strip())
    tests = root / "tests"
    if missing := [f for f in a.files if not (Path(f).is_file() and Path(f).resolve().is_relative_to(tests))]:
        for f in missing:
            print(f"ERROR: {f}: no such test file under the working tree's tests/", file=sys.stderr)
        return 2
    files = [Path(f).resolve().relative_to(root).as_posix() for f in a.files]
    base = _git(root, "merge-base", a.base, "HEAD")
    if base.returncode != 0:
        print(f"ERROR: git merge-base {a.base} HEAD: {base.stderr.strip()}", file=sys.stderr)
        return 2
    (root / "scratch").mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="red-on-base-", dir=root / "scratch"))
    tree = work / "tree"
    try:
        made = _git(root, "worktree", "add", "-q", "--detach", str(tree), base.stdout.strip())
        if made.returncode != 0:
            print(f"ERROR: git worktree add: {made.stderr.strip()}", file=sys.stderr)
            return 2
        shutil.rmtree(tree / "tests")
        shutil.copytree(tests, tree / "tests", ignore=shutil.ignore_patterns("__pycache__"))
        if (root / TOOLS).exists():  # git ignores it, so the worktree has none: the checkout's, linked, not copied
            (tree / TOOLS).symlink_to(root / TOOLS)
        (work / "home").mkdir()
        env = {**os.environ, "PYTHONPATH": str(tree / "src"), "HOME": str(work / "home"), "PYTHONDONTWRITEBYTECODE": "1"}
        junit = work / "junit.xml"
        ran = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "--continue-on-collection-errors",
                              "--tb=auto", f"--junitxml={junit}", *files, *(["-k", a.k] if a.k else [])],
                             cwd=tree, env=env, capture_output=True, encoding="utf-8")
        if ran.returncode not in RAN:
            print(f"ERROR: pytest exited {ran.returncode} on the base:\n{ran.stdout}{ran.stderr}", end="", file=sys.stderr)
            return 2
        found = outcomes(junit.read_text(encoding="utf-8"), files)
    except KeyboardInterrupt:
        print("interrupted: the worktree is removed", file=sys.stderr)
        return 130
    finally:
        _git(root, "worktree", "remove", "--force", str(tree))
        shutil.rmtree(work, ignore_errors=True)
    for v in found:
        print(f"{v.status:<10} {v.node}")
        for line in v.detail:
            print(f"    {line}")
    counts = {s: sum(v.status == s for v in found) for s in STATUSES}
    print(", ".join(f"{n} {s.lower()}" for s, n in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
