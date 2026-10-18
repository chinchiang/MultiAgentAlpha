"""Mutation checks: apply each mutation of a list to the source, run the tests that should catch it, and restore it.

  .venv/bin/python scripts/mutate.py mutations.yaml                  # every mutation of the list
  .venv/bin/python scripts/mutate.py mutations.yaml --only "a name"  # some of them, by name
  .venv/bin/python scripts/mutate.py mutations.yaml --focused-only   # the focused tests alone, never the whole suite

The list is a YAML file:

  focused: [tests/test_tool_evidence.py, ...]   # run first; the whole suite runs only for a mutation they miss
  mutations:
    - name: a note counts as an alert
      file: src/mara/tools/evidence.py
      old: 'ALERT_LEVELS = ("error", "warning")'
      new: 'ALERT_LEVELS = ("error", "warning", "note")'

Quote every value with a ` #` in it: YAML ends an unquoted value at ` #` and reads the rest as a comment, so
`name: the PR #141 rule` loads as "the PR".

Every `old` must occur exactly once in its file and every focused path must exist; the list is checked before any file
is touched. Then the focused tests and the whole suite run once without a mutation, and must pass. A mutation is caught
when a test fails on it (pytest exits 1): the focused tests first (all of them, or until one fails), then, if they
pass, the whole suite. Any other exit, such as a mutant that does not import (2), is an error: nothing caught the
mutation, and the whole suite does not run after the focused tests. Tests run with GITHUB_ACTIONS=true and without
writing bytecode, after src/ and tests/ are cleared of it: a mutant of the same size written within a second of the
original would otherwise run as the original's cached bytecode. The file is restored after each mutation, and checked
to be byte for byte what it was. Each run writes out/mutations/<UTC time>/results.json (one entry per mutation: caught,
by which test, by the focused tests or the whole suite, pytest's exit code), the output of the runs without a mutation
and of every run of the whole suite; a later run never overwrites an earlier one.
With --focused-only the whole suite never runs, for checking the tests of one module: the baseline is the focused
tests, and a mutation they miss is missed.
Exit 0 when every mutation was caught, 1 when one was missed or was an error, 2 when the list is wrong (or names no
focused tests for --focused-only) or the tests fail without a mutation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path: Path, root: Path) -> tuple[list[str], list[dict]]:
    """(the focused tests, the mutations) of a list, every focused path checked to exist and every `old` to occur exactly
    once; ValueError otherwise."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    focused = list(data.get("focused") or [])
    mutations = data.get("mutations") or []
    problems = [f"focused: no {t}" for t in focused if not isinstance(t, str) or not (root / t.split("::")[0]).exists()]
    for m in mutations:
        missing = [k for k in ("name", "file", "old", "new") if not isinstance(m.get(k), str)]
        if missing:
            problems.append(f"{m.get('name', m)}: no {', '.join(missing)}")
            continue
        n = (root / m["file"]).read_text(encoding="utf-8").count(m["old"]) if (root / m["file"]).is_file() else -1
        if n != 1:
            problems.append(f"{m['name']}: `old` occurs {n} times in {m['file']}" if n >= 0 else f"{m['name']}: no file {m['file']}")
    names = [m.get("name") for m in mutations]
    problems += [f"{n}: named twice" for n in sorted({n for n in names if names.count(n) > 1})]
    if problems:
        raise ValueError("; ".join(problems))
    return focused, mutations


def _clear_bytecode(root: Path) -> None:
    for top in ("src", "tests"):
        for pyc in (root / top).rglob("*.pyc") if (root / top).is_dir() else ():
            pyc.unlink(missing_ok=True)


def _pytest(root: Path, tests: list[str]) -> tuple[int, str, str]:
    """(pytest's exit code, the first failing test, the whole output) of one pytest run that stops at a failure."""
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "GITHUB_ACTIONS": "true"}
    cp = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-rf", "-p", "no:cacheprovider", *tests], cwd=root, env=env,
                        capture_output=True, text=True)
    failed = [line.removeprefix("FAILED ").split(" - ")[0] for line in cp.stdout.splitlines() if line.startswith("FAILED ")]
    return cp.returncode, failed[0] if failed else "", cp.stdout + cp.stderr


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


def check(m: dict, focused: list[str], root: Path, run_dir: Path, *, whole_suite: bool = True) -> dict:
    """Apply `m`, find whether a test catches it, restore the file; its result."""
    path = root / m["file"]
    original = path.read_bytes()
    try:
        path.write_bytes(original.decode("utf-8").replace(m["old"], m["new"]).encode("utf-8"))
        _clear_bytecode(root)
        code, by, where = 0, "", "focused"
        if focused:
            code, by, _ = _pytest(root, focused)
        if code == 0 and whole_suite:
            where = "suite"
            code, by, out = _pytest(root, [])
            (run_dir / (m["name"].replace("/", "_").replace(" ", "_")[:80] + ".suite.log")).write_text(out, encoding="utf-8")
    finally:
        path.write_bytes(original)
        _clear_bytecode(root)
    if path.read_bytes() != original:
        raise RuntimeError(f"{m['file']} was not restored")
    return {"mutation": m["name"], "file": m["file"], "caught": code == 1, "by": by, "where": where, "exit": code}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("mutations", type=Path, help="the YAML list")
    ap.add_argument("--only", nargs="+", default=None, help="the names of the mutations to run")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)  # a repository other than this one (tests)
    ap.add_argument("--runs", type=Path, default=None, help="default: <root>/out/mutations")
    ap.add_argument("--focused-only", action="store_true", help="run the focused tests alone, never the whole suite")
    a = ap.parse_args(argv)
    root = a.root.resolve()
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
    run_dir = (a.runs or root / "out" / "mutations") / dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir.mkdir(parents=True)
    why = baseline(focused, root, run_dir, whole_suite=not a.focused_only)
    if why:
        print(f"ERROR: {why}", file=sys.stderr)
        return 2
    results = []
    for m in mutations:
        r = check(m, focused, root, run_dir, whole_suite=not a.focused_only)
        results.append(r)
        if r["exit"] not in (0, 1):
            print(f"ERROR {r['mutation']}  (pytest exit {r['exit']}, {r['where']})", flush=True)
        else:
            print(("CAUGHT " if r["caught"] else "MISSED ") + r["mutation"] + (f"  <- {r['by']}" if r["by"] else f"  ({r['where']})"),
                  flush=True)
        (run_dir / "results.json").write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")
    caught = sum(r["caught"] for r in results)
    print(f"{caught} of {len(results)} caught; {run_dir / 'results.json'}")
    return 0 if caught == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
