"""tests/mutations/: every mutation list loads, so a change that makes an `old` stale goes red in the commit that makes it."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mutate  # noqa: E402

LISTS = sorted((ROOT / "tests" / "mutations").glob("*.yaml"))


def test_mutation_lists_are_found():
    assert LISTS, "no mutation list in tests/mutations/"


@pytest.mark.parametrize("path", LISTS, ids=[p.stem for p in LISTS])
def test_a_mutation_list_loads(path):
    try:
        mutate.load(path, ROOT)
        problems = ""
    except ValueError as e:
        problems = str(e)
    if problems:
        pytest.fail(f"{path.relative_to(ROOT)} does not load: {problems}. Re-align each `old` to the code it mutates, or "
                    f"drop a mutation that no longer means anything", pytrace=False)
