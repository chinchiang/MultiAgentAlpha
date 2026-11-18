"""Mutation checks: apply each mutation of a list to the source, run the tests that should catch it, and restore it; or
name the lists a change touches (--lists-for), or run each of them and sum them up (--base).

  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml                  # every mutation of the list
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --only "a name" --only "another"  # some of them, by name
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --focused-only   # the focused tests alone, never the whole suite
  .venv/bin/python scripts/mutate.py --lists-for origin/main   # the lists the change touches, one per line; runs nothing
  .venv/bin/python scripts/mutate.py --base origin/main        # run each of them, focused, and sum them up

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
lists. A mutation may name the exception its catch is meant to end in (`error: FileNotFoundError`), when that is not
an AssertionError: such a catch is then not marked for it (below). Then the focused tests and the whole suite
run once without a mutation, and must pass. A mutation is caught when a test fails on it (pytest exits 1): the focused
tests first (all of them, or until one fails), then, if they pass, the whole suite. Any other exit, such as a mutant
that does not import (2), is an error: nothing caught the mutation, and the whole suite does not run after the focused
tests. Tests run with GITHUB_ACTIONS=true and without writing bytecode, after src/, tests/ and scripts/ are cleared of
it: a mutant of the same size written within a second of the original would otherwise run as the original's cached
bytecode. The file is restored after each mutation, and checked to be byte for byte what it was.
For each mutation it prints CAUGHT, MISSED or ERROR and its name; a catch also names the test that caught it
(`<- <test>`) and, from that run's output, where it failed (`at:` and the source line pytest marks with `>`), the first
failure being the only one, since pytest stops there (-x). A catch is marked with the exception that ended the failure,
read from its traceback's last line, when it is not the one the mutation names (`error: FileNotFoundError`, above), or,
when it names none, when it is not an AssertionError:
`(KeyError)`, and `(KeyError, not FileNotFoundError)` or `(no exception, not FileNotFoundError)` when it names one. A
failure with no such line, as an ExceptionGroup's, has no exception, and no `at:` either; with no `error` named, it has
no mark. A catch is marked with `(expected <caught_by>)` when a test other than the one its
`caught_by` names caught it (a test file named alone names each of its tests; a test named without its parameters,
each of them). A marked catch is still a catch: whether it is the fault the name says is for the reader to judge.
It reads git status (untracked files one by one) before the runs without a mutation, after them, and after each run
with one; every path it lists that it did not list before, outside the run's own directory, is a left path, printed
after the last mutation as `LEFT <path>  (<the mutation, or baseline>)`, and neither removed nor counted against the
run. In a root that is not a git repository it says so on stderr, and does not look; once git status fails during a
run, it says so and looks no more.
Each run writes out/mutations/<UTC time>/results.json (one entry per mutation: caught, by which test, by the focused
tests or the whole suite, pytest's exit code, the logs it wrote, at and error (null when the output holds none, as for
a failure with pytrace=False, or for a mutation not caught), expected (the caught_by a catch did not match, else null),
declared_error (the mutation's `error`, else null) and left (the paths it left, null when git status was not read)),
the output of the runs without a mutation (baseline.focused.log, baseline.suite.log), the output of the focused tests
with each mutation in <slug>.focused.log, the output of each run of the whole suite with a mutation in <slug>.suite.log
(<slug> is the mutation's name with whitespace, / \\ : * ? " < > | turned into _, at most 80 characters), a copy of the
list and its pid; a later run never overwrites an earlier one.
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
<specifier>, this is <version>` for one not run), and, across all of them, the marked catches, the catches with no
`at:` and the LEFT lines, each after its list (run_base). It exits 0 when every list caught all, 1 when a mutation was
missed or an error, 2 when a list was refused (none runs) or a baseline failed (the other lists still run), whatever
the lists it skipped; a change that touches no list is said so, exit 0.
With --focused-only the whole suite never runs, for checking the tests of one module: the baseline is the focused
tests, and a mutation they miss is missed.
Exit 0 when every mutation was caught, 1 when one was missed or was an error, 2 when the list is wrong (or names no
focused tests for --focused-only), needs another Python, or the tests fail without a mutation.

GLOSSARY.md terms: Mutation list, Left path, Marked catch, Change. Not pure: it edits the files it mutates and runs pytest and
git in the root.
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

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet

ROOT = Path(__file__).resolve().parents[1]
BANNER = re.compile(r"^=+ (?:FAILURES|ERRORS) =+$")  # where pytest's output starts telling its failures
# the head of one failure, ____ test_x ____ (one _ a side for a long name); not the line between two frames of its
# traceback, `_ _ _ _ `, which ends in a space
FAILURE_HEAD = re.compile(r"^_+ .*\S.* _+$")
EXCEPTION_NAME = r"[A-Za-z_][\w.]*"  # an exception's name as a traceback's last line gives it, dotted or not
EXCEPTION_LINE = re.compile(rf"^\S.*:\d+: ({EXCEPTION_NAME})$")  # the last line of a traceback: path:line: ExceptionName
CAPTURED = re.compile(r"^-+ Captured .* -+$")  # where a failure's traceback ends and the output of its test begins


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
    requires-python to be a specifier (_is_specifier), every `old` to occur exactly once and to differ from its `new`, no
    two mutations of a file to make the same mutant, every `caught_by` to name a test (_names_a_test), and every
    `error` to be an exception's name other than AssertionError; ValueError otherwise."""
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
        text = (root / m["file"]).read_text(encoding="utf-8") if (root / m["file"]).is_file() else None
        n = text.count(m["old"]) if text is not None else -1
        if n != 1:
            problems.append(f"{m['name']}: `old` occurs {n} times in {m['file']}{_quoted_newline(m['old'], text)}" if n >= 0
                            else f"{m['name']}: no file {m['file']}")
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


def _failure(out: str) -> tuple[str | None, str | None]:
    """(the source line pytest marks with `>` in the first failure of `out`, stripped; the name of the exception that
    ended it, from the traceback's last line); None for what the output does not hold."""
    lines = out.splitlines()
    start = next((i for i, line in enumerate(lines) if BANNER.match(line)), None)
    if start is None:
        return None, None
    section = []
    for line in lines[start + 2:]:  # after the banner and the head of the first failure
        if line.startswith("=") or FAILURE_HEAD.match(line) or CAPTURED.match(line):
            break
        section.append(line)
    at = next((line[1:].strip() for line in section if line.startswith(">")), None)
    error = next((m[1] for line in reversed(section) if (m := EXCEPTION_LINE.match(line))), None)
    return at, error


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


def baseline(focused: list[str], root: Path, run_dir: Path, *, whole_suite: bool = True) -> str:
    """Why the focused tests or the whole suite fail without a mutation, each run's output kept; empty when they pass."""
    _clear_bytecode(root)
    runs = ([("focused tests", focused, "focused")] if focused else []) + ([("whole suite", [], "suite")] if whole_suite else [])
    for name, tests, where in runs:
        code, by, out = _pytest(root, tests)
        log = run_dir / f"baseline.{where}.log"
        log.write_text(out, encoding="utf-8")
        if code != 0:
            return f"the {name} exit {code} without a mutation" + (f" ({by})" if by else "") + f"; {log}"
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


def is_named_by(test: str, caught_by: str) -> bool:
    """Whether `test`, a test id as pytest reports it, is one `caught_by` names: the same id, a test of the file it
    names alone, or the test it names without its parameters."""
    return test == caught_by or test.startswith(caught_by + "::") or ("[" not in caught_by and test.split("[")[0] == caught_by)


def check(m: dict, focused: list[str], root: Path, run_dir: Path, *, whole_suite: bool = True) -> dict:
    """Apply `m`, find whether a test catches it, restore the file; its result. The file and its mutant are kept in
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
        if focused:
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
    at, error = _failure(out) if code == 1 else (None, None)
    expected = m["caught_by"] if code == 1 and "caught_by" in m and not is_named_by(by, m["caught_by"]) else None
    return {"mutation": m["name"], "file": m["file"], "caught": code == 1, "by": by, "where": where, "exit": code, "logs": logs,
            "at": at, "error": error, "expected": expected, "declared_error": m.get("error")}


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
    it), and its marked catches, its catches with no `at:` and its LEFT lines, each as it printed them."""
    code: int
    last: str
    marked: list[str] = field(default_factory=list)
    unplaced: list[str] = field(default_factory=list)
    left: list[str] = field(default_factory=list)


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
    why = baseline(focused, root, run_dir, whole_suite=whole_suite)
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
                    + (f"  at: {r['at']}" if r["at"] else "") + (f"  ({mark})" if (mark := error_mark(r)) else "")
                    + (f"  (expected {r['expected']})" if r["expected"] else ""))
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
    return MutationListRun(0 if caught == len(results) else 1, last, marked, unplaced, left_lines)


def run_base(base: str, root: Path, runs: Path) -> int:
    """Restore what a killed run left (restore_left), then run, focused and one after the other, each list lists_for(base,
    root) names, every one loaded before any runs; a list whose requires-python this interpreter does not take
    (needs_python) is loaded too, and not run. Then print a summary: each list's last line or why it was skipped, and the marked catches,
    the catches with no `at:` and the LEFT lines of all of them, each after its list. 0 every list caught all; 1 one
    missed or an error; 2 restore_left or git refused, or a list does not load or names no focused tests (none runs),
    or a baseline failed (the others still run). A skipped list does not change it."""
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
    codes = {run.code for _, run in ran}
    return 2 if 2 in codes else 1 if 1 in codes else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mutations", type=Path, nargs="?", help="the YAML list")
    ap.add_argument("--lists-for", metavar="BASE", help="print the lists the change since BASE touches, and run nothing")
    ap.add_argument("--base", metavar="BASE", help="run, focused, every list the change since BASE touches, and sum them up")
    ap.add_argument("--only", action="extend", nargs="+", default=None, help="the names of the mutations to run; repeats")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)  # a repository other than this one (tests)
    ap.add_argument("--runs", type=Path, default=None, help="default: <root>/out/mutations")
    ap.add_argument("--focused-only", action="store_true", help="run the focused tests alone, never the whole suite")
    a = ap.parse_args(argv)
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
