"""Mutation checks: apply each mutation of a list to the source, run the tests that should catch it, and restore it; or
name the lists a change touches (--lists-for), or run each of them and sum them up (--base); or move the stale mutations
of a list to where their `old` now is (--realign).

  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml                  # every mutation of the list
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --only "a name" --only "another"  # some of them, by name
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --focused-only   # the focused tests alone, never the whole suite
  .venv/bin/python scripts/mutate.py --lists-for origin/main   # the lists the change touches, one per line; runs nothing
  .venv/bin/python scripts/mutate.py --base origin/main        # run each of them, focused, and sum them up
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --realign   # move each stale mutation's file; runs nothing

A mutation list (GLOSSARY.md) is a YAML file in tests/mutations/, where tests/test_mutation_lists.py checks that each
one loads, that each of its mutations has a caught_by, and that no two lists make the same mutant (mutant):

  focused: [tests/test_tool_evidence.py, ...]   # run first; the whole suite runs only for a mutation they miss
  mutations:
    - name: a note counts as an alert
      file: src/mara/tools/evidence.py
      caught_by: tests/test_tool_evidence.py::test_an_error_or_a_warning_is_a_tool_alert_and_a_note_is_not   # meant to catch it
      old: 'ALERT_LEVELS = ("error", "warning")'
      new: 'ALERT_LEVELS = ("error", "warning", "note")'

A list whose mutations only a later Python catches says the Python it needs, a specifier as pyproject.toml's
requires-python is: `requires-python: ">=3.13"`. Run alone under an interpreter the specifier does not take (the one
that runs mutate.py, which runs pytest), the list is refused, `ERROR: <list> needs Python <specifier>, this is
<version>`, exit 2, before any file is touched; run it with one it takes (for >=3.13, a venv of
tools/dev-requirements-py313.txt, as CI's 3.13 job installs). A pre-release is compared as PEP 440 orders it:
3.14.0rc1 is taken by >=3.13, and not by >=3.14.

Quote every value with a ` #` in it: YAML ends an unquoted value at ` #` and reads the rest as a comment, so
`name: the PR #141 rule` loads as "the PR".
Write a value of several lines in double quotes: in single quotes YAML keeps `\\n` as a backslash and an `n`, so the
`old` never matches, and load says so (_quoted_newline).

Every `old` must occur exactly once in its file and differ from its `new`, no two mutations of a file may make the same
mutant (one of them is a mis-aligned copy of the other), and every focused path must exist; the list is checked before
any file is touched. A `caught_by`, where a mutation has one, names a test as pytest takes it: a test file, or a test of
it (`file::test`, `file::Class::test`, with its parameters `[...]` or without); each part must be defined in the file
(_names_a_test). It is optional here, so a list outside tests/mutations/ loads without it; every mutation of this
repository's lists carries one, which tests/test_mutation_lists.py checks, as it checks that no mutant is made by two
lists. A mutation may name the exception its catch is meant to end in (`error: FileNotFoundError`), when that is not an
AssertionError: such a catch is then not marked for it (below). Then the focused tests and the whole suite run once
without a mutation, and must pass; and no `caught_by`, run alone, may fail (exit 1) there, as one that does would catch
every mutant. A mutation is caught when a test fails on it (pytest exits 1): its `caught_by` first, when it has one, run
alone as pytest takes it (its alone run), and no other test when it fails; then the focused tests (all of them, or until
one fails); then, if they pass, the whole suite. An alone run that exits otherwise than 1 leaves the mutation to the
focused tests. Any other exit of the focused tests, such as a mutant that does not import (2), is an error: nothing
caught the mutation, and the whole suite does not run after them. Tests run with GITHUB_ACTIONS=true and without writing
bytecode, after src/, tests/ and scripts/ are cleared of it: a mutant of the same size written within a second of the
original would otherwise run as the original's cached bytecode. The file is restored after each mutation, and checked to
be byte for byte what it was.
For each mutation it prints CAUGHT, MISSED or ERROR and its name; a catch also names the test that caught it (`<-
<test>`) and, from that run's output, where it failed (`at:` and the source line pytest marks with `>`), the first
failure being the only one, since pytest stops there (-x), then, when that failure compares two sequences that differ at
an index, the first item that differs as pytest gives it (the text of its first `E` line from `At index <n> diff:` to
the line's end, which pytest may shorten after the index; two that differ only in length give none), and, when the
exception that ended it is not an AssertionError, where that exception was raised as the repository sees it (`raised:`
and the path:line, relative to the root, of the traceback's deepest frame under the root and not in an installed
package's site-packages: an exception the standard library or a package raises is placed at the line of the repository
that called into it). A catch is marked with the exception that ended the failure, read from its traceback's last line,
when it is not the one the mutation names (`error: FileNotFoundError`, above), or, when it names none, when it is not an
AssertionError: `(KeyError)`, and `(KeyError, not FileNotFoundError)` or `(no exception, not FileNotFoundError)` when it
names one. A failure with no such line, as an ExceptionGroup's, has no exception, and no `at:` either; with no `error`
named, it has no mark. A catch is marked with `(expected <caught_by>, alone: …)` when a run other than its alone run
caught it (the focused tests or the whole suite): the mark ends with what the alone run gave, `passes`, or `pytest exit
<n>` for any other exit; what each asks is in docs/agents/pr-flow.md, step 4. A marked catch is still a catch: whether
it is the fault the name says is for the reader to judge.
It reads git status (untracked files one by one) before the runs without a mutation, after them, and after each run
with one; every path it lists that it did not list before, outside the run's own directory, is a left path, printed
after the last mutation as `LEFT <path>  (<the mutation, or baseline>)`, and neither removed nor counted against the
run. In a root that is not a git repository it says so on stderr, and does not look; once git status fails during a
run, it says so and looks no more.
Each run writes out/mutations/<UTC time>/results.json (one entry per mutation: caught, by which test, where (its alone
run `alone`, the focused tests `focused` or the whole suite `suite`), pytest's exit code, the logs it wrote, at,
first_diff and error (null when the output holds none, as for a failure with pytrace=False, or for a mutation not
caught), raised (null as well, and for an AssertionError), expected (the caught_by of a catch its alone run did not
make, else null), expected_alone (for such a catch, the exit of the alone run, else null), declared_error (the
mutation's `error`, else null) and left (the paths it left, null when git status was not read)), the output of the runs
without a mutation (baseline.focused.log, baseline.suite.log, and baseline.alone.log for a caught_by that failed alone),
the output of the focused tests with each mutation in <slug>.focused.log, the output of each run of the whole suite with
a mutation in <slug>.suite.log, that of an alone run in <slug>.alone.log (<slug> is the mutation's name with whitespace,
/ \\ : * ? " < > | turned into _, at most 80 characters), a copy of the list and its pid; a later run never overwrites
an earlier one.
Before it mutates a file, a run keeps the file and its mutant under original/ and mutant/ in its directory, and removes
them once the file is restored. A run killed in between (SIGKILL, SIGTERM, the end of a session) never restores it, so
every run first looks for such copies: a file still holding the mutant is restored from original/, one holding the
original again needs nothing, and one holding neither (edited since) is left as it is, and no run starts until it is
sorted out by hand; nor while the run whose copies they are is still going.
With --lists-for BASE it runs nothing and prints, one per line, each list of tests/mutations/ the change since BASE
touches (lists_for): the change (GLOSSARY.md) is every path the working tree changes, adds or deletes over the merge
base of BASE and HEAD, committed or not, and each untracked file git does not ignore (changed_paths); a list is touched
when the change holds the list itself, the file of one of its mutations or one of its focused test files.
With --base BASE it runs each of those lists, one after the other, as --focused-only runs one (run_mutation_list: its own run
directory, results.json and lines, after a `== <list>` line), every one loaded first, so a list that does not load, or
names no focused tests, stops the run before any mutation is applied. A list whose requires-python this interpreter does
not take is not run. Then it prints `summary`: each list's last line after its name (`SKIP <list>: needs Python
<specifier>, this is <version>` for one not run), and, across all of them, the marked catches, the catches with no `at:`
and the LEFT lines, each after its list, then, last of every summary, the line of totals: `<k> lists, <s> skipped,
<caught> of <total> caught, <m> marked, <u> with no at:, <l> left`, the lists run, those skipped, the mutations caught
and run over the lists run, and the lines of those three, a list whose baseline failed counted among the lists and
adding no mutation (run_base). It exits 0 when every list caught all, 1 when a mutation was missed or an error, 2 when a
list was refused (none runs) or a baseline failed (the other lists still run), whatever the lists it skipped; a change
that touches no list is said so, exit 0.
With --realign it runs no mutation. It first restores what a killed run left (restore_left, as every run does), then,
for each stale mutation (GLOSSARY.md; stale) of the list, or of those --only names, it searches every file git tracks,
or that is untracked and not ignored, apart from tests/mutations/. When the `old` occurs exactly once in exactly one
other file, it rewrites that mutation's `file:` value, plain or in the quotes it was written in, and no other byte of
the list, and prints `<name>: <old file> -> <new file>`; unless the value is a block, or the moved mutation would make
the same mutant as another of this list or of a list under tests/mutations/, which it names. Each other stale mutation
(found nowhere, more than once in one file, or in several files), and such a move, is printed as
`<name>: left: <why it is stale>; <what it found>` and left as it is (realign). The list is read as YAML, not loaded:
its other problems are not --realign's. It takes a list, and no --base, --lists-for, --focused-only or --runs; it exits
0 when no stale mutation is left, 1 when one is, 2 when --only names a mutation the list does not have, the list is not
YAML or gives a key twice, git fails, or restore_left refuses (a run still going, a file edited since).
With --focused-only the whole suite never runs, for checking the tests of one module: the baseline is the focused
tests, and a mutation they miss is missed.
Exit 0 when every mutation was caught, 1 when one was missed or was an error, 2 when the list is wrong (or names no
focused tests for --focused-only), needs another Python, or the tests fail without a mutation.

GLOSSARY.md terms: Mutation list, Stale mutation, Left path, Marked catch, Change. Not pure: it edits the files it
mutates, and the list --realign re-aligns, and runs pytest and git in the root.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet

ROOT = Path(__file__).resolve().parents[1]
BANNER = re.compile(r"^=+ (?:FAILURES|ERRORS) =+$")  # where pytest's output starts telling its failures
# the head of one failure, ____ test_x ____ (one _ a side for a long name); not the line between two frames of its
# traceback, `_ _ _ _ `, which ends in a space
FAILURE_HEAD = re.compile(r"^_+ .*\S.* _+$")
EXCEPTION_NAME = r"[A-Za-z_][\w.]*"  # an exception's name as a traceback's last line gives it, dotted or not
EXCEPTION_LINE = re.compile(rf"^\S.*:\d+: ({EXCEPTION_NAME})$")  # the last line of a traceback: path:line: ExceptionName
# a frame's path and line in a traceback, its last line's included; an `E` line that happens to match comes before
# that last line, so it is never the deepest
FRAME_LINE = re.compile(r"^(\S.*?):(\d+): ")
CAPTURED = re.compile(r"^-+ Captured .* -+$")  # where a failure's traceback ends and the output of its test begins
FIRST_DIFF = re.compile(r"^E\s+(At index \d+ diff: .*)$")  # the first item that differs of two sequences pytest compares


def _names_a_test(root: Path, test: object) -> bool:
    """Whether `test` names a test of `root` as pytest takes one: a test file, then the classes and the test of it after
    `::`, each defined in the file (`def` or `class`), a test's parameters (`[...]`) left out."""
    if not isinstance(test, str):
        return False
    file, *parts = test.split("[")[0].split("::")  # parameters may hold :: themselves
    if not (root / file).is_file():
        return False
    text = (root / file).read_text(encoding="utf-8")
    return all(re.search(rf"^\s*(?:async\s+)?(?:def|class)\s+{re.escape(part)}\b", text, re.M) for part in parts)


def mutant(root: Path, m: dict) -> tuple[str, str]:
    """The mutant `m` makes, as two mutations are compared: its file and the file's text with `old` replaced once by
    `new`. Two mutations make the same mutant when these are equal, whatever their `old` and `new` say. It is read for a
    mutation whose `old` occurs once in its file (load checks that first); for any other the text is not a mutant."""
    return m["file"], (root / m["file"]).read_text(encoding="utf-8").replace(m["old"], m["new"], 1)


def _quoted_newline(old: str, text: str | None) -> str:
    """The hint for an `old` that occurs nowhere in `text` only because it holds a backslash and an `n` that YAML kept
    as written (single quotes), and occurs once with each read as a newline; empty for any other."""
    if text is None or "\\n" not in old or text.count(old) or text.count(old.replace("\\n", "\n")) != 1:
        return ""
    return " (YAML keeps \\n as written in single quotes: write the value in double quotes)"


def stale(root: Path, m: dict) -> str:
    """Why `m`, a mutation with a `file` and an `old`, is a stale mutation (GLOSSARY.md): `` `old` occurs <n> times in
    <file> `` when its `old` does not occur exactly once in its file, with _quoted_newline's hint when it gives one, or
    `no file <file>` when the file is gone; empty when it is not stale. load and --realign both ask it."""
    text = (root / m["file"]).read_text(encoding="utf-8") if (root / m["file"]).is_file() else None
    if text is None:
        return f"no file {m['file']}"
    n = text.count(m["old"])
    return f"`old` occurs {n} times in {m['file']}{_quoted_newline(m['old'], text)}" if n != 1 else ""


def _is_specifier(value: object) -> bool:
    """Whether `value` is a version specifier as pyproject.toml's requires-python is (`>=3.13`, `>=3.11,<3.14`)."""
    if not isinstance(value, str):
        return False
    try:
        SpecifierSet(value)
    except InvalidSpecifier:
        return False
    return True


def load(path: Path, root: Path) -> tuple[list[str], list[dict], str | None]:
    """(the focused tests, the mutations, its requires-python or None) of a list, every focused path checked to exist, a
    requires-python to be a specifier (_is_specifier), no mutation to be stale (stale), every `new` to differ from its
    `old`, no two mutations of a file to make the same mutant, every `caught_by` to name a test (_names_a_test), and
    every `error` to be an exception's name other than AssertionError; ValueError otherwise."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    focused = list(data.get("focused") or [])
    mutations = data.get("mutations") or []
    requires_python = data.get("requires-python")
    problems = [f"focused: no {t}" for t in focused if not isinstance(t, str) or not (root / t.split("::")[0]).exists()]
    if requires_python is not None and not _is_specifier(requires_python):
        problems.append(f"requires-python: {requires_python!r} is not a version specifier (`>=3.13`)")
    mutants: dict[tuple[str, str], list[str]] = {}  # (file, its text once mutated): the mutations that make it
    for m in mutations:
        missing = [k for k in ("name", "file", "old", "new") if not isinstance(m.get(k), str)]
        if missing:
            problems.append(f"{m.get('name', m)}: no {', '.join(missing)}")
            continue
        if why := stale(root, m):
            problems.append(f"{m['name']}: {why}")
        elif m["new"] == m["old"]:
            problems.append(f"{m['name']}: new is old, so the file is unchanged")
        else:
            mutants.setdefault(mutant(root, m), []).append(m["name"])
        if "caught_by" in m and not _names_a_test(root, m["caught_by"]):
            problems.append(f"{m['name']}: caught_by: no {m['caught_by']}")
        if "error" in m and not (isinstance(m["error"], str) and re.fullmatch(EXCEPTION_NAME, m["error"])):
            problems.append(f"{m['name']}: error: {m['error']!r} is not an exception's name")
        elif "error" in m and m["error"] == "AssertionError":
            problems.append(f"{m['name']}: error: AssertionError is what a catch ends in when error is not given")
    problems += [f"{', '.join(same)}: the same mutant of {file}" for (file, _), same in mutants.items() if len(same) > 1]
    names = [m.get("name") for m in mutations]
    problems += [f"{n}: named twice" for n in sorted({n for n in names if names.count(n) > 1})]
    if problems:
        raise ValueError("; ".join(problems))
    return focused, mutations, requires_python


def needs_python(requires_python: str | None) -> str:
    """Why this interpreter cannot run a list that needs `requires_python`, a specifier as pyproject.toml's
    (`>=3.13`); empty when it can, or when the list needs none. A pre-release is compared as PEP 440 orders it: 3.14.0rc1
    is taken by >=3.13, and not by >=3.14."""
    version = platform.python_version()
    if requires_python is None or SpecifierSet(requires_python).contains(version, prereleases=True):
        return ""
    return f"needs Python {requires_python}, this is {version}"


def _clear_bytecode(root: Path) -> None:
    for top in ("src", "tests", "scripts"):
        for pyc in (root / top).rglob("*.pyc") if (root / top).is_dir() else ():
            pyc.unlink(missing_ok=True)


def _slug(name: str) -> str:
    """A mutation's name as the start of a file name: whitespace and what a file name cannot hold on Windows or Linux (`/`,
    `\\`, `:`, `*`, `?`, `"`, `<`, `>`, `|`) become `_`; at most 80 characters."""
    return re.sub(r'[\s/\\:*?"<>|]', "_", name)[:80]


def _pytest(root: Path, tests: list[str]) -> tuple[int, str, str]:
    """(pytest's exit code, the first failing test, the whole output) of one pytest run that stops at a failure."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "GITHUB_ACTIONS": "true"}
    cp = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-rf", "-p", "no:cacheprovider", *tests], cwd=root, env=env,
                        capture_output=True, text=True, encoding="utf-8", errors="replace")
    failed = [line.removeprefix("FAILED ").split(" - ")[0] for line in cp.stdout.splitlines() if line.startswith("FAILED ")]
    return cp.returncode, failed[0] if failed else "", cp.stdout + cp.stderr


def _in_root(path: str, root: Path) -> str | None:
    """`path`, as pytest prints a frame's (relative to the directory it ran in, `root`, or absolute once a test changed
    directory), relative to `root`; None when it is outside `root` or in an installed package (site-packages)."""
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(root.resolve())
        except ValueError:
            return None
    if p.parts[:1] == ("..",) or "site-packages" in p.parts:
        return None
    return p.as_posix()


class Failure(NamedTuple):
    """What _failure reads of the first failure of a pytest run's output: None for each part the output does not hold,
    so Failure() holds none of them (an output with no failure, or one whose failure shows none of them)."""

    at: str | None = None  # the source line pytest marks with `>`, stripped
    error: str | None = None  # the name of the exception that ended it, from the traceback's last line
    raised: str | None = None  # when there is that exception, the path:line of its deepest frame in the repository (_in_root)
    first_diff: str | None = None  # the text of its first `E` line from `At index <n> diff:` to the line's end


def _failure(out: str, root: Path) -> Failure:
    """The Failure of the first failure of `out`, its frames placed in the repository `root` (_in_root); Failure() when
    `out` holds none."""
    lines = out.splitlines()
    start = next((i for i, line in enumerate(lines) if BANNER.match(line)), None)
    if start is None:
        return Failure()
    section = []
    for line in lines[start + 2:]:  # after the banner and the head of the first failure
        if line.startswith("=") or FAILURE_HEAD.match(line) or CAPTURED.match(line):
            break
        section.append(line)
    at = next((line[1:].strip() for line in section if line.startswith(">")), None)
    error = next((m[1] for line in reversed(section) if (m := EXCEPTION_LINE.match(line))), None)
    frames = [f"{path}:{m[2]}" for line in section if (m := FRAME_LINE.match(line)) and (path := _in_root(m[1], root))]
    first_diff = next((m[1] for line in section if (m := FIRST_DIFF.match(line))), None)
    return Failure(at=at, error=error, raised=frames[-1] if error and frames else None, first_diff=first_diff)


def changed_paths(base: str, root: Path) -> set[str]:
    """The paths of the change since the merge base of `base` and HEAD in `root`, relative to it: each file the working
    tree changes, adds or deletes over that merge base, committed or not (a rename as the path it deleted and the one it
    added, --no-renames), and each untracked file git does not ignore. ValueError, naming the git command and what it
    said, when git fails."""
    def git(*args: str) -> str:
        cp = subprocess.run(["git", *args], cwd=root, capture_output=True)  # -z: each path as it is named, unquoted
        if cp.returncode != 0:
            raise ValueError(f"git {' '.join(args)}: {cp.stderr.decode('utf-8', 'replace').strip()}")
        return cp.stdout.decode("utf-8", "replace")

    merge_base = git("merge-base", base, "HEAD").strip()
    names = git("diff", "--name-only", "--no-renames", "-z", merge_base) + git("ls-files", "--others", "--exclude-standard", "-z")
    return {name for name in names.split("\0") if name}


def lists_for(base: str, root: Path) -> list[str]:
    """The mutation lists of tests/mutations/ in `root` the change since `base` touches (changed_paths), sorted, each as
    its path relative to `root`: a list is touched when the change holds the list itself, the file of one of its mutations, or one of its
    focused test files (the part of the entry before `::`). A list is read as YAML and not loaded (load), so one whose
    `old` the change made stale is still named; one that is not YAML is named, for its run to say what is wrong."""
    changed = changed_paths(base, root)
    touched = []
    for path in sorted((root / "tests" / "mutations").glob("*.yaml")):
        name = path.relative_to(root).as_posix()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            touched.append(name)
            continue
        data = data if isinstance(data, dict) else {}
        mutations, focused = data.get("mutations") or [], data.get("focused") or []
        reads = {name, *(m["file"] for m in mutations if isinstance(m, dict) and isinstance(m.get("file"), str)),
                 *(t.split("::")[0] for t in focused if isinstance(t, str))}
        if reads & changed:
            touched.append(name)
    return touched


def git_status(root: Path) -> set[str] | None:
    """The paths git status lists in `root`, relative to it: each untracked file by itself, and a rename as the path it
    deleted and the one it added (--no-renames); None when `root` is not a git repository or git fails."""
    cp = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all", "--no-renames", "-z"], cwd=root,
                        capture_output=True)
    if cp.returncode != 0:
        return None
    return {entry[3:] for entry in cp.stdout.decode("utf-8", "replace").split("\0") if entry}


def left_since(before: set[str] | None, root: Path, run_dir: Path) -> tuple[set[str] | None, list[str] | None]:
    """(what git status lists now, the paths it lists that it did not before, those in the run's own directory left out);
    both None when `before` is (no git repository, or a read that failed before) or git status fails now."""
    now = git_status(root) if before is not None else None
    if before is None or now is None:
        return None, None
    own = run_dir.resolve().relative_to(root).as_posix() + "/" if run_dir.resolve().is_relative_to(root) else None
    return now, sorted(path for path in now - before if not (own and path.startswith(own)))


def baseline(focused: list[str], root: Path, run_dir: Path, *, whole_suite: bool = True, caught_by: list[str] = ()) -> str:
    """Why the focused tests or the whole suite fail without a mutation, each run's output kept, or why a caught_by run
    alone fails without one (exit 1: its alone run would catch every mutant), that run's output kept; empty when none
    does. Another exit of a caught_by run alone (4, a test pytest cannot run) is left to the mark of its catches."""
    _clear_bytecode(root)
    runs = ([("focused tests", focused, "focused")] if focused else []) + ([("whole suite", [], "suite")] if whole_suite else [])
    for name, tests, where in runs:
        code, by, out = _pytest(root, tests)
        log = run_dir / f"baseline.{where}.log"
        log.write_text(out, encoding="utf-8")
        if code != 0:
            return f"the {name} exit {code} without a mutation" + (f" ({by})" if by else "") + f"; {log}"
    for test in dict.fromkeys(caught_by):
        code, by, out = _pytest(root, [test])
        if code == 1:
            log = run_dir / "baseline.alone.log"
            log.write_text(out, encoding="utf-8")
            return f"the caught_by {test} fails run alone without a mutation ({by}); {log}"
    return ""


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        return True  # os.kill() ends a process there, whatever the signal; its copies are then removed by hand
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _drop_copies(run_dir: Path) -> None:
    for kind in ("original", "mutant"):
        shutil.rmtree(run_dir / kind, ignore_errors=True)


def restore_left(root: Path, runs: Path) -> str:
    """Restore every file a killed run left mutated, from the copies it kept; why no run can start, empty when one can."""
    for kept in sorted(runs.glob("*/original")) if runs.is_dir() else ():
        run_dir = kept.parent
        pid = (run_dir / "pid").read_text(encoding="utf-8").strip() if (run_dir / "pid").is_file() else ""
        if pid.isdigit() and _alive(int(pid)):
            return f"the run {run_dir} is still going (pid {pid})"
        for copy in sorted(p for p in kept.rglob("*") if p.is_file()):
            rel = copy.relative_to(kept)
            target, mutant = root / rel, run_dir / "mutant" / rel
            now = target.read_bytes() if target.is_file() else None
            if now == copy.read_bytes():
                continue
            if mutant.is_file() and now == mutant.read_bytes():
                target.write_bytes(copy.read_bytes())
                print(f"restored {rel.as_posix()}, left mutated by the run {run_dir}", flush=True)
                continue
            return (f"{rel.as_posix()} is neither the original nor the mutant the run {run_dir} left: compare it with {copy} "
                    f"and {mutant}, then remove {kept} and {run_dir / 'mutant'}")
        _drop_copies(run_dir)
    return ""


def check(m: dict, focused: list[str], root: Path, run_dir: Path, *, whole_suite: bool = True) -> dict:
    """Apply `m`, find whether a test catches it: its caught_by first, alone (the alone run), then, when that does not
    catch it, the focused tests and the whole suite; restore the file; its result. The file and its mutant are kept in
    `run_dir` while it is mutated (restore_left)."""
    path = root / m["file"]
    original = path.read_bytes()
    text = original.decode("utf-8")
    old, new = m["old"], m["new"]
    if "\r\n" in text:  # a list is read with its newlines as \n, as load reads the file (a Windows checkout has CRLF)
        old, new = old.replace("\n", "\r\n"), new.replace("\n", "\r\n")
    mutant = text.replace(old, new).encode("utf-8")
    for kind, data in (("original", original), ("mutant", mutant)):
        (run_dir / kind / m["file"]).parent.mkdir(parents=True, exist_ok=True)
        (run_dir / kind / m["file"]).write_bytes(data)
    try:
        path.write_bytes(mutant)
        _clear_bytecode(root)
        code, by, where, logs, slug, out = 0, "", "focused", [], _slug(m["name"]), ""
        alone = None
        if "caught_by" in m:  # the alone run: the caught_by alone, against the mutant, before any other test
            alone_code, alone_by, alone_out = _pytest(root, [m["caught_by"]])
            (run_dir / f"{slug}.alone.log").write_text(alone_out, encoding="utf-8")
            logs.append(f"{slug}.alone.log")
            alone = {"exit": alone_code}
            if alone_code == 1:
                code, by, where, out = 1, alone_by, "alone", alone_out
        if code == 0 and focused:
            code, by, out = _pytest(root, focused)
            (run_dir / f"{slug}.focused.log").write_text(out, encoding="utf-8")
            logs.append(f"{slug}.focused.log")
        if code == 0 and whole_suite:
            where = "suite"
            code, by, out = _pytest(root, [])
            (run_dir / f"{slug}.suite.log").write_text(out, encoding="utf-8")
            logs.append(f"{slug}.suite.log")
    finally:
        path.write_bytes(original)
        _clear_bytecode(root)
    if path.read_bytes() != original:
        raise RuntimeError(f"{m['file']} was not restored")
    _drop_copies(run_dir)
    failure = _failure(out, root) if code == 1 else Failure()
    expected = m["caught_by"] if code == 1 and "caught_by" in m and where != "alone" else None  # its alone run caught nothing
    return {"mutation": m["name"], "file": m["file"], "caught": code == 1, "by": by, "where": where, "exit": code, "logs": logs,
            "at": failure.at, "first_diff": failure.first_diff, "error": failure.error,
            "raised": failure.raised if failure.error != "AssertionError" else None,
            "expected": expected, "expected_alone": alone if expected else None, "declared_error": m.get("error")}


def expected_mark(r: dict) -> str:
    """The mark a catch's line carries when its alone run did not make it (`r` is check's result, `expected` set):
    `expected <caught_by>, alone: ` and what the alone run gave, `passes` or `pytest exit <n>`; empty when `expected` is
    None."""
    if not r["expected"]:
        return ""
    exit_code = r["expected_alone"]["exit"]
    return f"expected {r['expected']}, alone: " + ("passes" if exit_code == 0 else f"pytest exit {exit_code}")


def error_mark(r: dict) -> str:
    """The mark a catch's line carries for the exception it ended in (`r` is check's result): empty when that is the
    exception its mutation names (`error`), or, when it names none, AssertionError or no exception read; else the
    exception, and, when the mutation names one, `, not <it>` (`no exception` for none read). Empty for a miss."""
    error, declared = r["error"], r["declared_error"]
    if not r["caught"] or error == declared or (declared is None and error in (None, "AssertionError")):
        return ""
    return f"{error or 'no exception'}, not {declared}" if declared is not None else error


@dataclass
class MutationListRun:
    """What a run of one list gives a run of many (--base): its exit code (0 every mutation caught, 1 one missed or an
    error, 2 its baseline failed), its last line (`<caught> of <total> caught; <results.json>`, or the error that stopped
    it), and its marked catches, its catches with no `at:` and its LEFT lines, each as it printed them; and the counts of
    its last line, its caught and its total (both 0 for a baseline that failed)."""
    code: int
    last: str
    marked: list[str] = field(default_factory=list)
    unplaced: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)
    caught: int = 0
    total: int = 0


def run_mutation_list(path: Path, focused: list[str], mutations: list[dict], root: Path, runs: Path, *, whole_suite: bool) -> MutationListRun:
    """Run the mutations of the list at `path` (load gave `focused` and `mutations`) in a run directory of its own under
    `runs`, printing a line per mutation, its LEFT lines and its last line, and writing its results.json; the run a
    list given alone and each list of --base both make."""
    run_dir = runs / dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir.mkdir(parents=True)
    (run_dir / "pid").write_text(str(os.getpid()), encoding="utf-8")
    shutil.copyfile(path, run_dir / path.name)
    status = git_status(root)
    if status is None:
        print(f"left paths not checked: {root} is not a git repository", file=sys.stderr)
    why = baseline(focused, root, run_dir, whole_suite=whole_suite, caught_by=[m["caught_by"] for m in mutations if "caught_by" in m])
    if why:
        print(f"ERROR: {why}", file=sys.stderr)
        return MutationListRun(2, f"ERROR: {why}")
    left_lines: list[str] = []

    def look(after: str) -> list[str] | None:
        """The paths left since git status was last read, each named on a LEFT line `after` the run that left it."""
        nonlocal status
        looked = status is not None
        status, left = left_since(status, root, run_dir)
        if looked and status is None:
            print(f"left paths no longer checked: git status failed after {after}", file=sys.stderr)
        left_lines.extend(f"LEFT {path}  ({after})" for path in left or [])
        return left

    look("baseline")
    results = []
    marked: list[str] = []
    unplaced: list[str] = []
    for m in mutations:
        r = check(m, focused, root, run_dir, whole_suite=whole_suite)
        r["left"] = look(r["mutation"])
        results.append(r)
        if r["exit"] not in (0, 1):
            print(f"ERROR {r['mutation']}  (pytest exit {r['exit']}, {r['where']})", flush=True)
        else:
            line = (("CAUGHT " if r["caught"] else "MISSED ") + r["mutation"] + (f"  <- {r['by']}" if r["by"] else f"  ({r['where']})")
                    + (f"  at: {r['at']}" if r["at"] else "") + (f"  {r['first_diff']}" if r["first_diff"] else "")
                    + (f"  raised: {r['raised']}" if r["raised"] else "")
                    + (f"  ({mark})" if (mark := error_mark(r)) else "")
                    + (f"  ({expected_text})" if (expected_text := expected_mark(r)) else ""))
            print(line, flush=True)
            if r["caught"] and (mark or r["expected"]):
                marked.append(line)
            if r["caught"] and not r["at"]:
                unplaced.append(line)
        (run_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    for line in left_lines:
        print(line)
    caught = sum(r["caught"] for r in results)
    last = f"{caught} of {len(results)} caught; {run_dir / 'results.json'}"
    print(last)
    return MutationListRun(0 if caught == len(results) else 1, last, marked, unplaced, left_lines, caught=caught, total=len(results))


def run_base(base: str, root: Path, runs: Path) -> int:
    """Restore what a killed run left (restore_left), then run, focused and one after the other, each list
    lists_for(base, root) names, every one loaded before any runs; a list whose requires-python this interpreter does
    not take (needs_python) is loaded too, and not run. Then print a summary: each list's last line or why it was
    skipped, the marked catches, the catches with no `at:` and the LEFT lines of all of them, each after its list, and
    the line of their totals the module's docstring gives. 0 every list caught all; 1 one missed or an error; 2
    restore_left or git refused, or a list does not load or names no focused tests (none runs), or a baseline failed
    (the others still run). A skipped list does not change it."""
    if why := restore_left(root, runs):  # first: a mutant a killed run left would read as part of the change
        print(f"ERROR: {why}", file=sys.stderr)
        return 2
    try:
        names = lists_for(base, root)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not names:
        print(f"the change since {base} touches no mutation list")
        return 0
    loaded, refused = [], []
    for name in names:
        try:
            focused, mutations, requires_python = load(root / name, root)
        except ValueError as e:
            refused.append(f"ERROR: {name}: {e}")
            continue
        if not focused:
            refused.append(f"ERROR: {name}: --base runs the focused tests alone, and the list names none")
            continue
        loaded.append((name, focused, mutations, needs_python(requires_python)))
    if refused:
        print("\n".join(refused), file=sys.stderr)
        return 2
    done: list[tuple[str, MutationListRun | None, str]] = []  # (the list, its run or None when skipped, why it was skipped)
    for name, focused, mutations, why in loaded:
        if why:
            done.append((name, None, why))
            continue
        print(f"== {name}", flush=True)
        done.append((name, run_mutation_list(root / name, focused, mutations, root, runs, whole_suite=False), ""))
    ran = [(name, run) for name, run, _ in done if run is not None]
    print("\nsummary")
    for name, run, why in done:
        print(f"{name}: {run.last}" if run is not None else f"SKIP {name}: {why}")
    sections = (("marked:", lambda run: run.marked), ("caught with no at:", lambda run: run.unplaced), ("left:", lambda run: run.left))
    for title, part in sections:
        lines = [f"{name}: {line}" for name, run in ran for line in part(run)]
        if lines:
            print(title, *lines, sep="\n")
    print(f"{len(ran)} lists, {len(done) - len(ran)} skipped, {sum(run.caught for _, run in ran)} of {sum(run.total for _, run in ran)}"
          f" caught, {sum(len(run.marked) for _, run in ran)} marked, {sum(len(run.unplaced) for _, run in ran)} with no at:,"
          f" {sum(len(run.left) for _, run in ran)} left")
    codes = {run.code for _, run in ran}
    return 2 if 2 in codes else 1 if 1 in codes else 0


def _searched(root: Path) -> dict[str, str]:
    """The text of each file --realign looks for an `old` in: each file git tracks in `root` or that is untracked and
    not ignored, that is on the disk and is UTF-8, apart from tests/mutations/; by its path relative to `root`."""
    cp = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root, capture_output=True)
    if cp.returncode != 0:
        raise ValueError(f"git ls-files: {cp.stderr.decode('utf-8', 'replace').strip()}")
    texts = {}
    for name in sorted(set(cp.stdout.decode("utf-8", "replace").split("\0")) - {""}):
        if name.startswith("tests/mutations/") or not (root / name).is_file():
            continue
        try:
            texts[name] = (root / name).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
    return texts


def _relative(path: Path, root: Path) -> str:
    """`path` relative to `root`, as a list is named; as given when it is outside `root`."""
    return path.resolve().relative_to(root).as_posix() if path.resolve().is_relative_to(root) else str(path)


def _has_text(m: object, *keys: str) -> bool:
    """Whether `m` is a mapping whose value under each of `keys` is a text."""
    return isinstance(m, dict) and all(isinstance(m.get(k), str) for k in keys)


def _once(path: Path, node: yaml.MappingNode) -> None:
    """ValueError, naming the key and its two lines, when `node` gives a key twice: YAML takes the last, and the place
    of the value to rewrite would be read from the first."""
    seen: dict[object, int] = {}
    for k, _ in node.value:
        if k.value in seen:
            raise ValueError(f"{path}: `{k.value}` is given twice, on lines {seen[k.value]} and {k.start_mark.line + 1}")
        seen[k.value] = k.start_mark.line + 1


def _file_nodes(path: Path, text: str) -> list[yaml.Node | None]:
    """The node of each mutation's `file` value in the text of the list at `path`, where its place in the text is read
    from, in the order of its mutations: one per entry of `mutations`, None for an entry that is not a mapping or has no
    `file`; none when the list has no sequence of mutations. ValueError when the list, or one of its entries, gives a key
    twice (_once)."""
    node = yaml.compose(text)
    if not isinstance(node, yaml.MappingNode):
        return []
    _once(path, node)
    entries = next((v for k, v in node.value if k.value == "mutations"), None)
    if not isinstance(entries, yaml.SequenceNode):
        return []
    nodes: list[yaml.Node | None] = []
    for e in entries.value:
        if isinstance(e, yaml.MappingNode):
            _once(path, e)
        nodes.append(next((v for k, v in e.value if k.value == "file"), None) if isinstance(e, yaml.MappingNode) else None)
    return nodes


def _as_written(path: str, style: str | None) -> str:
    """`path` as a plain YAML value (`style` None or empty), or in single (`'`) or double (`"`) quotes."""
    return {"'": "'" + path.replace("'", "''") + "'", '"': json.dumps(path)}.get(style or "", path)


def _made_mutants(path: Path, mutations: list, root: Path) -> dict[tuple[str, str], str]:
    """The mutant (mutant) of each mutation that is not stale and has a text `name`, `file`, `old` and `new`, of
    `mutations`, the list at `path`, then of every other list under tests/mutations/, read as YAML, in the order of
    their names; each as `<list>: <name>`, the list relative to `root`, the first mutation that makes it named. A list
    that is not YAML, or holds no mapping, gives none."""
    lists = [(_relative(path, root), mutations)]
    for other in sorted((root / "tests" / "mutations").glob("*.yaml")):
        if other.resolve() == path.resolve():
            continue
        try:
            data = yaml.safe_load(other.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        lists.append((_relative(other, root), (data.get("mutations") or []) if isinstance(data, dict) else []))
    made: dict[tuple[str, str], str] = {}
    for name, ms in lists:
        for m in ms:
            if _has_text(m, "name", "file", "old", "new") and not stale(root, m):
                made.setdefault(mutant(root, m), f"{name}: {m['name']}")
    return made


def realign(path: Path, root: Path, only: list[str] | None) -> int:
    """Move each stale mutation (stale) of the list at `path`, or of those `only` names, whose `old` occurs exactly once
    in exactly one other file _searched gives, to that file, rewriting its `file` value, plain or in the quotes it was
    written in, and no other byte of the list, and print `<name>: <old file> -> <new file>`; unless its `file` value is
    a block, or the moved mutation makes the same mutant as one _made_mutants gives or one moved before it. Print
    `<name>: left: <why it is stale>; <what the search found>` for each other stale mutation, and leave it. A mutation
    with no text `name`, `file` or `old` is passed over. The list is read as YAML, not loaded (load), which refuses a
    stale `old`; its other problems are not looked at. 0 when none is left, 1 when one is, 2 when `only` names a
    mutation the list does not have (nothing moves); ValueError when git fails, or the list is not YAML or gives a key
    twice (_file_nodes)."""
    text = path.read_bytes().decode("utf-8")  # newlines as written, so a CRLF list keeps them
    try:
        data = yaml.safe_load(text) or {}
        nodes = _file_nodes(path, text)
    except yaml.YAMLError as e:
        raise ValueError(f"{path} is not YAML: {' '.join(str(e).split())}") from e
    mutations = data.get("mutations") if isinstance(data, dict) and isinstance(data.get("mutations"), list) else []
    if only is not None:
        unknown = sorted(set(only) - {m.get("name") for m in mutations if isinstance(m, dict)})
        if unknown:
            print(f"ERROR: no mutation named {', '.join(unknown)}", file=sys.stderr)
            return 2
    searched = _searched(root)
    made = _made_mutants(path, mutations, root)
    own = _relative(path, root)
    edits: list[tuple[int, int, str]] = []
    left = 0
    for m, node in zip(mutations, nodes, strict=True):  # one node per mutation, read from the same text
        if not _has_text(m, "name", "file", "old"):
            continue
        if only is not None and m["name"] not in only or not (why := stale(root, m)):
            continue
        found = {name: n for name, t in searched.items() if (n := t.count(m["old"]))}
        if len(found) == 1 and list(found.values()) == [1]:
            (to,) = found
            assert isinstance(node, yaml.ScalarNode)  # its value is a text
            made_by_move = mutant(root, {**m, "file": to}) if isinstance(m.get("new"), str) else None
            if node.style in ("|", ">"):
                print(f"{m['name']}: left: {why}; found in {to}, but its file: is a block, not plain or in quotes")
            elif made_by_move is not None and (same := made.get(made_by_move)):
                print(f"{m['name']}: left: {why}; moved to {to} it makes the same mutant as {same}")
            else:
                if made_by_move is not None:
                    made[made_by_move] = f"{own}: {m['name']}"
                edits.append((node.start_mark.index, node.end_mark.index, _as_written(to, node.style)))
                print(f"{m['name']}: {m['file']} -> {to}")
                continue
        elif not found:
            print(f"{m['name']}: left: {why}; found nowhere")
        elif len(found) == 1:
            ((name, n),) = found.items()
            print(f"{m['name']}: left: {why}; found {n} times in {name}")
        else:
            print(f"{m['name']}: left: {why}; found in {', '.join(found)}")
        left += 1
    for start, end, written in sorted(edits, reverse=True):
        text = text[:start] + written + text[end:]
    if edits:
        path.write_bytes(text.encode("utf-8"))
    return 1 if left else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mutations", type=Path, nargs="?", help="the YAML list")
    ap.add_argument("--lists-for", metavar="BASE", help="print the lists the change since BASE touches, and run nothing")
    ap.add_argument("--base", metavar="BASE", help="run, focused, every list the change since BASE touches, and sum them up")
    ap.add_argument("--only", action="extend", nargs="+", default=None, help="the names of the mutations to run; repeats")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)  # a repository other than this one (tests)
    ap.add_argument("--runs", type=Path, default=None, help="default: <root>/out/mutations")
    ap.add_argument("--focused-only", action="store_true", help="run the focused tests alone, never the whole suite")
    ap.add_argument("--realign", action="store_true", help="move each stale mutation's file to where its old now is; runs nothing")
    a = ap.parse_args(argv)
    if a.realign and (a.base is not None or a.lists_for is not None or a.focused_only or a.runs is not None):
        ap.error("--realign runs no mutation: --base, --lists-for, --focused-only and --runs do not apply")
    if a.realign and a.mutations is None:
        ap.error("--realign needs a list")
    if a.base is not None and (a.mutations is not None or a.lists_for is not None or a.only or a.focused_only):
        ap.error("--base runs every list the change touches, focused: give no list, --lists-for, --only or --focused-only")
    if a.base is not None:
        root = a.root.resolve()
        return run_base(a.base, root, a.runs or root / "out" / "mutations")
    if (a.mutations is None) == (a.lists_for is None):
        ap.error("give a list, --lists-for BASE or --base BASE")
    if a.lists_for is not None and (a.only or a.focused_only):
        ap.error("--lists-for runs no mutation: --only and --focused-only do not apply")
    root = a.root.resolve()
    if a.realign:
        if why := restore_left(root, root / "out" / "mutations"):
            print(f"ERROR: {why}", file=sys.stderr)
            return 2
        try:
            return realign(a.mutations, root, a.only)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
    if a.lists_for is not None:
        try:
            touched = lists_for(a.lists_for, root)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        for name in touched:
            print(name)
        return 0
    runs = a.runs or root / "out" / "mutations"
    if why := restore_left(root, runs):
        print(f"ERROR: {why}", file=sys.stderr)
        return 2
    try:
        focused, mutations, requires_python = load(a.mutations, root)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if why := needs_python(requires_python):
        print(f"ERROR: {a.mutations} {why}", file=sys.stderr)
        return 2
    if a.focused_only and not focused:
        print("ERROR: --focused-only needs focused tests, and the list names none", file=sys.stderr)
        return 2
    if a.only:
        unknown = sorted(set(a.only) - {m["name"] for m in mutations})
        if unknown:
            print(f"ERROR: no mutation named {', '.join(unknown)}", file=sys.stderr)
            return 2
        mutations = [m for m in mutations if m["name"] in a.only]
    return run_mutation_list(a.mutations, focused, mutations, root, runs, whole_suite=not a.focused_only).code


if __name__ == "__main__":
    sys.exit(main())
