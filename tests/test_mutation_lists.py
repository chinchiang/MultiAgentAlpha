"""tests/mutations/: every mutation list loads and names, for each mutation, the test meant to catch it (`caught_by`), and
no two lists make the same mutant (shared_mutants), so a change that makes an `old` stale, adds a mutation without its
test, or copies a mutant another list holds, goes red in the commit that makes it."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mutate  # noqa: E402

LISTS = sorted((ROOT / "tests" / "mutations").glob("*.yaml"))


def test_mutation_lists_are_found():
    assert LISTS, "no mutation list in tests/mutations/"


def list_problems(path: Path, root: Path) -> str:
    """What is wrong with a mutation list: what `mutate.load` refuses, then each mutation with no `caught_by`, which
    `mutate.py` leaves optional and this repository requires; empty when nothing is."""
    try:
        mutate.load(path, root)
        problems = []
    except ValueError as e:
        problems = [str(e)]
    mutations = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("mutations") or []
    problems += [f"{m.get('name', m)}: no caught_by" for m in mutations if "caught_by" not in m]
    return "; ".join(problems)


def shared_mutants(paths: list[Path], root: Path) -> str:
    """Each mutant that two of `paths` make (`mutate.mutant`, the comparison `mutate.load` makes within one list),
    naming each list and mutation that makes it; empty when no two lists share one. A list that does not load is left to
    test_a_mutation_list_loads."""
    makers: dict[tuple[str, str], list[str]] = {}
    for path in paths:
        try:
            _, mutations = mutate.load(path, root)
        except ValueError:
            continue
        for m in mutations:
            makers.setdefault(mutate.mutant(root, m), []).append(f"{path.relative_to(root).as_posix()}: {m['name']}")
    return "; ".join(f"{' and '.join(names)} make the same mutant of {file}" for (file, _), names in makers.items() if len(names) > 1)


@pytest.mark.parametrize("path", LISTS, ids=[p.stem for p in LISTS])
def test_a_mutation_list_loads(path):
    problems = list_problems(path, ROOT)
    if problems:
        pytest.fail(f"{path.relative_to(ROOT)} is not a valid mutation list: {problems}. Re-align each `old` to the code it "
                    f"mutates, or drop a mutation that no longer means anything; give a mutation with no caught_by the test "
                    f"you mean to catch it (the CAUGHT line of `scripts/mutate.py {path.relative_to(ROOT)} --focused-only` "
                    f"shows which test catches it now, to compare with)", pytrace=False)


def test_a_mutation_without_caught_by_is_named_and_one_with_it_is_not(tmp_path):
    """Every mutation of this repository's lists names the test meant to catch it; what `mutate.load` refuses is still
    said, beside it."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "window.py").write_text("LIMIT = 3\nWIDTH = 2\n", encoding="utf-8")
    (tmp_path / "tests" / "test_window.py").write_text("def test_limit():\n    pass\n", encoding="utf-8")
    named = {"name": "a wider window", "file": "src/window.py", "old": "LIMIT = 3", "new": "LIMIT = 4",
             "caught_by": "tests/test_window.py::test_limit"}
    unnamed = [{"name": "a narrower window", "file": "src/window.py", "old": "WIDTH = 2", "new": "WIDTH = 1"},
               {"name": "no width", "file": "src/window.py", "old": "WIDTH = 2", "new": "WIDTH = 0"}]
    path = tmp_path / "window.yaml"
    path.write_text(json.dumps({"focused": ["tests/test_window.py"], "mutations": [named, *unnamed]}), encoding="utf-8")
    assert list_problems(path, tmp_path) == "a narrower window: no caught_by; no width: no caught_by"
    path.write_text(json.dumps({"focused": ["tests/test_window.py"], "mutations": [named]}), encoding="utf-8")
    assert list_problems(path, tmp_path) == ""
    stale = {**named, "old": "LIMIT = 9"}
    path.write_text(json.dumps({"focused": ["tests/test_window.py"], "mutations": [stale, unnamed[0]]}), encoding="utf-8")
    assert list_problems(path, tmp_path) == "a wider window: `old` occurs 0 times in src/window.py; a narrower window: no caught_by"


def test_no_two_mutation_lists_make_the_same_mutant():
    shared = shared_mutants(LISTS, ROOT)
    if shared:
        pytest.fail(f"{shared}. Keep each mutant in one list: drop it from the list that added it later", pytrace=False)


def test_two_lists_that_make_one_mutant_are_named_and_two_that_differ_are_not(tmp_path):
    """Two mutations make one mutant when the file they make is the same, however their `old` and `new` are written."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "window.py").write_text("LIMIT = 3\nWIDTH = 2\n", encoding="utf-8")
    (tmp_path / "tests" / "test_window.py").write_text("def test_limit():\n    pass\n", encoding="utf-8")

    def write(name: str, *mutations: dict) -> Path:
        path = tmp_path / name
        made = [{"file": "src/window.py", "caught_by": "tests/test_window.py::test_limit", **m} for m in mutations]
        path.write_text(json.dumps({"focused": ["tests/test_window.py"], "mutations": made}), encoding="utf-8")
        return path

    wider = write("wider.yaml", {"name": "a wider window", "old": "LIMIT = 3", "new": "LIMIT = 4"})
    four = write("four.yaml", {"name": "a limit of four", "old": "= 3\n", "new": "= 4\n"})
    narrower = write("narrower.yaml", {"name": "a narrower window", "old": "WIDTH = 2", "new": "WIDTH = 1"})
    stale = write("stale.yaml", {"name": "a wider window again", "old": "LIMIT = 3", "new": "LIMIT = 4"},
                  {"name": "a stale one", "old": "LIMIT = 9", "new": "LIMIT = 4"})
    assert shared_mutants([wider, four, narrower], tmp_path) == \
        "wider.yaml: a wider window and four.yaml: a limit of four make the same mutant of src/window.py"
    assert shared_mutants([wider, narrower], tmp_path) == ""
    assert shared_mutants([wider, stale], tmp_path) == ""  # stale.yaml does not load: test_a_mutation_list_loads says so
