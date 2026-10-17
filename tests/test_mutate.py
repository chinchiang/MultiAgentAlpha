"""scripts/mutate.py: a mutation is applied, the tests that should catch it run, and the source is restored."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import mutate  # noqa: E402

SOURCE = "def limit():\n    return 3  # the window\n"


def _repo(tmp_path: Path) -> Path:
    """A repository of one module and its test."""
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src" / "window.py").write_text(SOURCE, encoding="utf-8")
    (root / "tests" / "test_window.py").write_text("from window import limit\n\n\ndef test_limit():\n    assert limit() == 3\n",
                                                   encoding="utf-8")
    (root / "pyproject.toml").write_text('[tool.pytest.ini_options]\npythonpath = ["src"]\n', encoding="utf-8")
    return root


def _list(tmp_path: Path, mutations: list[dict], focused: list[str] | None = None) -> Path:
    path = tmp_path / "mutations.yaml"
    path.write_text(json.dumps({"focused": focused or [], "mutations": mutations}), encoding="utf-8")  # JSON is YAML
    return path


def test_a_mutation_a_test_catches_and_one_none_does_are_told_apart_and_the_source_is_restored(tmp_path, capsys):
    root = _repo(tmp_path)
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"},
                 {"name": "another comment", "file": "src/window.py", "old": "# the window", "new": "# a window"}]
    code = mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs")])
    assert code == 1, "one mutation was missed"
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [(r["mutation"], r["caught"], r["where"]) for r in results] == [("a wider window", True, "focused"),
                                                                          ("another comment", False, "suite")]
    assert results[0]["by"] == "tests/test_window.py::test_limit"
    assert (run / "another_comment.suite.log").is_file(), "the whole suite's output is kept for a missed mutation"
    assert "1 of 2 caught" in capsys.readouterr().out


def test_every_run_keeps_its_own_results(tmp_path):
    root = _repo(tmp_path)
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}])
    for _ in range(2):
        assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 0
    assert len(list((tmp_path / "runs").iterdir())) == 2


def test_a_wrong_list_is_refused_before_any_file_is_touched(tmp_path, capsys):
    root = _repo(tmp_path)
    (root / "src" / "window.py").write_text(SOURCE + "# return 3\n", encoding="utf-8")
    wrong = [{"name": "ambiguous", "file": "src/window.py", "old": "return 3", "new": "return 4"},
             {"name": "nowhere", "file": "src/gone.py", "old": "x", "new": "y"},
             {"name": "half", "file": "src/window.py"}]
    assert mutate.main([str(_list(tmp_path, wrong)), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    err = capsys.readouterr().err
    assert "ambiguous: `old` occurs 2 times" in err and "nowhere: no file src/gone.py" in err and "half: no old, new" in err
    assert not (tmp_path / "runs").exists()
    assert mutate.main([str(_list(tmp_path, wrong[:0])), "--root", str(root), "--only", "nothing"]) == 2


def test_a_focused_test_that_does_not_exist_is_refused_before_any_file_is_touched(tmp_path, capsys):
    """pytest exits 4 on a path it cannot find, which a failed test's exit 1 must not be mistaken for."""
    root = _repo(tmp_path)
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}],
                 ["tests/test_window.py::test_limit", "tests/test_gone.py"])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    assert "focused: no tests/test_gone.py" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


def test_tests_that_fail_without_a_mutation_stop_the_run_before_any_mutation(tmp_path, capsys):
    """Otherwise every mutation would count as caught by a test that fails anyway."""
    root = _repo(tmp_path)
    (root / "tests" / "test_window.py").write_text("from window import limit\n\n\ndef test_limit():\n    assert limit() == 4\n",
                                                   encoding="utf-8")
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 5"}],
                 ["tests/test_window.py"])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    assert "the focused tests exit 1 without a mutation (tests/test_window.py::test_limit)" in capsys.readouterr().err
    (run,) = (tmp_path / "runs").iterdir()
    assert not (run / "results.json").exists() and (run / "baseline.focused.log").is_file()
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE


def test_a_mutant_the_tests_cannot_run_against_is_an_error_not_a_catch(tmp_path, capsys):
    """A mutant that does not import stops pytest at collection (exit 2): no test failed on it, so nothing caught it."""
    root = _repo(tmp_path)
    broken = [{"name": "a broken module", "file": "src/window.py", "old": "return 3", "new": "return ("}]
    for focused in (["tests/test_window.py"], []):
        runs = tmp_path / f"runs-{len(focused)}"
        assert mutate.main([str(_list(tmp_path, broken, focused)), "--root", str(root), "--runs", str(runs)]) == 1
        (run,) = runs.iterdir()
        (r,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
        assert (r["caught"], r["exit"], r["where"]) == (False, 2, "focused" if focused else "suite")
        assert "ERROR a broken module  (pytest exit 2" in capsys.readouterr().out
        assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE
