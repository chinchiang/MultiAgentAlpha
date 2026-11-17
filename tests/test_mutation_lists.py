"""tests/mutations/: every mutation list loads and names, for each mutation, the test meant to catch it (`caught_by`), so
a change that makes an `old` stale, or adds a mutation without its test, goes red in the commit that makes it."""

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
