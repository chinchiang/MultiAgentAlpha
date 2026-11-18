"""Mutation checks: apply each mutation of a list to the source, run the tests that should catch it, and restore it.

  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml                  # every mutation of the list
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --only "a name" --only "another"  # some of them, by name
  .venv/bin/python scripts/mutate.py tests/mutations/web-children.yaml --focused-only   # the focused tests alone, never the whole suite

A mutation list (GLOSSARY.md) is a YAML file in tests/mutations/, where tests/test_mutation_lists.py checks that each
one loads, that each of its mutations has a caught_by, and that no two lists make the same mutant (mutant):

  focused: [tests/test_tool_evidence.py, ...]   # run first; the whole suite runs only for a mutation they miss
  mutations:
    - name: a note counts as an alert
      file: src/mara/tools/evidence.py
      caught_by: tests/test_tool_evidence.py::test_an_error_or_a_warning_is_a_tool_alert_and_a_note_is_not   # meant to catch it
      old: 'ALERT_LEVELS = ("error", "warning")'
      new: 'ALERT_LEVELS = ("error", "warning", "note")'

Quote every value with a ` #` in it: YAML ends an unquoted value at ` #` and reads the rest as a comment, so
`name: the PR #141 rule` loads as "the PR".

Every `old` must occur exactly once in its file and differ from its `new`, no two mutations of a file may make the same
mutant (one of them is a mis-aligned copy of the other), and every focused path must exist; the list is checked before
any file is touched. A `caught_by`, where a mutation has one, names a test as pytest takes it: a test file, or a test of
it (`file::test`, `file::Class::test`, with its parameters `[...]` or without); each part must be defined in the file
(_names_a_test). It is optional here, so a list outside tests/mutations/ loads without it; every mutation of this
repository's lists carries one, which tests/test_mutation_lists.py checks, as it checks that no mutant is made by two
lists. Then the focused tests and the whole suite
run once without a mutation, and must pass. A mutation is caught when a test fails on it (pytest exits 1): the focused
tests first (all of them, or until one fails), then, if they pass, the whole suite. Any other exit, such as a mutant
that does not import (2), is an error: nothing caught the mutation, and the whole suite does not run after the focused
tests. Tests run with GITHUB_ACTIONS=true and without writing bytecode, after src/, tests/ and scripts/ are cleared of
it: a mutant of the same size written within a second of the original would otherwise run as the original's cached
bytecode. The file is restored after each mutation, and checked to be byte for byte what it was.
For each mutation it prints CAUGHT, MISSED or ERROR and its name; a catch also names the test that caught it
(`<- <test>`) and, from that run's output, where it failed (`at:` and the source line pytest marks with `>`), the first
failure being the only one, since pytest stops there (-x). A catch is marked with the exception that ended the failure,
read from its traceback's last line, when it is not an AssertionError (`(KeyError)`; a failure with no such line, as an
ExceptionGroup's, has no exception and no mark, but has no `at:` either), and with `(expected <caught_by>)` when a test other than the one its
`caught_by` names caught it (a test file named alone names each of its tests; a test named without its parameters,
each of them). A marked catch is still a catch: whether it is the fault the name says is for the reader to judge.
It reads git status (untracked files one by one) before the runs without a mutation, after them, and after each run
with one; every path it lists that it did not list before, outside the run's own directory, is a left path, printed
after the last mutation as `LEFT <path>  (<the mutation, or baseline>)`, and neither removed nor counted against the
run. In a root that is not a git repository it says so on stderr, and does not look; once git status fails during a
run, it says so and looks no more.
Each run writes out/mutations/<UTC time>/results.json (one entry per mutation: caught, by which test, by the focused
tests or the whole suite, pytest's exit code, the logs it wrote, at and error (null when the output holds none, as for
a failure with pytrace=False, or for a mutation not caught), expected (the caught_by a catch did not match, else null)
and left (the paths it left, null when git status was not read)), the output of the runs without a mutation
(baseline.focused.log, baseline.suite.log), the output of the focused tests with each mutation in <slug>.focused.log,
the output of each run of the whole suite with a mutation in <slug>.suite.log (<slug> is the mutation's name with
whitespace, / \\ : * ? " < > | turned into _, at most 80 characters), a copy of the list and its pid; a later run never
overwrites an earlier one.
Before it mutates a file, a run keeps the file and its mutant under original/ and mutant/ in its directory, and removes
them once the file is restored. A run killed in between (SIGKILL, SIGTERM, the end of a session) never restores it, so
every run first looks for such copies: a file still holding the mutant is restored from original/, one holding the
original again needs nothing, and one holding neither (edited since) is left as it is, and no run starts until it is
sorted out by hand; nor while the run whose copies they are is still going.
With --focused-only the whole suite never runs, for checking the tests of one module: the baseline is the focused
tests, and a mutation they miss is missed.
Exit 0 when every mutation was caught, 1 when one was missed or was an error, 2 when the list is wrong (or names no
focused tests for --focused-only) or the tests fail without a mutation.

GLOSSARY.md terms: Mutation list, Left path, Marked catch. Not pure: it edits the files it mutates and runs pytest and
git in the root.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BANNER = re.compile(r"^=+ (?:FAILURES|ERRORS) =+$")  # where pytest's output starts telling its failures
# the head of one failure, ____ test_x ____ (one _ a side for a long name); not the line between two frames of its
# traceback, `_ _ _ _ `, which ends in a space
FAILURE_HEAD = re.compile(r"^_+ .*\S.* _+$")
EXCEPTION_LINE = re.compile(r"^\S.*:\d+: ([A-Za-z_][\w.]*)$")  # the last line of a traceback: path:line: ExceptionName
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


def load(path: Path, root: Path) -> tuple[list[str], list[dict]]:
    """(the focused tests, the mutations) of a list, every focused path checked to exist, every `old` to occur exactly
    once and to differ from its `new`, no two mutations of a file to make the same mutant, and every `caught_by` to name
    a test (_names_a_test); ValueError otherwise."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    focused = list(data.get("focused") or [])
    mutations = data.get("mutations") or []
    problems = [f"focused: no {t}" for t in focused if not isinstance(t, str) or not (root / t.split("::")[0]).exists()]
    mutants: dict[tuple[str, str], list[str]] = {}  # (file, its text once mutated): the mutations that make it
    for m in mutations:
        missing = [k for k in ("name", "file", "old", "new") if not isinstance(m.get(k), str)]
        if missing:
            problems.append(f"{m.get('name', m)}: no {', '.join(missing)}")
            continue
        text = (root / m["file"]).read_text(encoding="utf-8") if (root / m["file"]).is_file() else None
        n = text.count(m["old"]) if text is not None else -1
        if n != 1:
            problems.append(f"{m['name']}: `old` occurs {n} times in {m['file']}" if n >= 0 else f"{m['name']}: no file {m['file']}")
        elif m["new"] == m["old"]:
            problems.append(f"{m['name']}: new is old, so the file is unchanged")
        else:
            mutants.setdefault(mutant(root, m), []).append(m["name"])
        if "caught_by" in m and not _names_a_test(root, m["caught_by"]):
            problems.append(f"{m['name']}: caught_by: no {m['caught_by']}")
    problems += [f"{', '.join(same)}: the same mutant of {file}" for (file, _), same in mutants.items() if len(same) > 1]
    names = [m.get("name") for m in mutations]
    problems += [f"{n}: named twice" for n in sorted({n for n in names if names.count(n) > 1})]
    if problems:
        raise ValueError("; ".join(problems))
    return focused, mutations


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
            "at": at, "error": error, "expected": expected}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mutations", type=Path, help="the YAML list")
    ap.add_argument("--only", action="extend", nargs="+", default=None, help="the names of the mutations to run; repeats")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)  # a repository other than this one (tests)
    ap.add_argument("--runs", type=Path, default=None, help="default: <root>/out/mutations")
    ap.add_argument("--focused-only", action="store_true", help="run the focused tests alone, never the whole suite")
    a = ap.parse_args(argv)
    root = a.root.resolve()
    runs = a.runs or root / "out" / "mutations"
    if why := restore_left(root, runs):
        print(f"ERROR: {why}", file=sys.stderr)
        return 2
    try:
        focused, mutations = load(a.mutations, root)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
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
    run_dir = runs / dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir.mkdir(parents=True)
    (run_dir / "pid").write_text(str(os.getpid()), encoding="utf-8")
    shutil.copyfile(a.mutations, run_dir / a.mutations.name)
    status = git_status(root)
    if status is None:
        print(f"left paths not checked: {root} is not a git repository", file=sys.stderr)
    why = baseline(focused, root, run_dir, whole_suite=not a.focused_only)
    if why:
        print(f"ERROR: {why}", file=sys.stderr)
        return 2
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
    for m in mutations:
        r = check(m, focused, root, run_dir, whole_suite=not a.focused_only)
        r["left"] = look(r["mutation"])
        results.append(r)
        if r["exit"] not in (0, 1):
            print(f"ERROR {r['mutation']}  (pytest exit {r['exit']}, {r['where']})", flush=True)
        else:
            print(("CAUGHT " if r["caught"] else "MISSED ") + r["mutation"] + (f"  <- {r['by']}" if r["by"] else f"  ({r['where']})")
                  + (f"  at: {r['at']}" if r["at"] else "") + (f"  ({r['error']})" if r["error"] not in (None, "AssertionError") else "")
                  + (f"  (expected {r['expected']})" if r["expected"] else ""), flush=True)
        (run_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    for line in left_lines:
        print(line)
    caught = sum(r["caught"] for r in results)
    print(f"{caught} of {len(results)} caught; {run_dir / 'results.json'}")
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
