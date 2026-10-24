"""scripts/mutate.py: a mutation is applied, the tests that should catch it run, and the source is restored."""

from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

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
    assert (run / "mutations.yaml").read_text(encoding="utf-8") == (tmp_path / "mutations.yaml").read_text(encoding="utf-8")
    assert not (run / "original").exists() and not (run / "mutant").exists(), "the copies go once every file is restored"
    assert "1 of 2 caught" in capsys.readouterr().out


def test_every_run_keeps_its_own_results(tmp_path):
    root = _repo(tmp_path)
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}])
    for _ in range(2):
        assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 0
    assert len(list((tmp_path / "runs").iterdir())) == 2


def test_a_repeated_only_runs_every_name_it_gives(tmp_path):
    """`--only A --only B` once ran B alone; it runs what `--only A B` runs, in the list's order."""
    root = _repo(tmp_path)
    path = _list(tmp_path, [{"name": n, "file": "src/window.py", "old": "return 3", "new": f"return {k}"}
                            for n, k in (("four", 4), ("five", 5), ("six", 6))], ["tests/test_window.py"])
    ran = []
    for only in (["--only", "six", "--only", "four"], ["--only", "six", "four"]):
        runs = tmp_path / f"runs{len(ran)}"
        assert mutate.main([str(path), "--root", str(root), "--runs", str(runs), "--focused-only", *only]) == 0
        (run,) = runs.iterdir()
        ran.append([r["mutation"] for r in json.loads((run / "results.json").read_text(encoding="utf-8"))])
    assert ran == [["four", "six"], ["four", "six"]]


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


def test_a_list_with_a_mutation_that_changes_nothing_or_two_that_make_the_same_mutant_is_refused(tmp_path, capsys):
    """A mutation that leaves its file as it was, or one that makes the same file as another of the list (a mis-aligned
    copy of it), is refused. Two of the same `new` that make different files are not, nor the same text made of two
    files."""
    root = _repo(tmp_path)
    (root / "src" / "door.py").write_text(SOURCE, encoding="utf-8")
    mutations = [{"name": "unchanged", "file": "src/window.py", "old": "return 3", "new": "return 3"},
                 {"name": "four", "file": "src/window.py", "old": "return 3", "new": "return 4"},
                 {"name": "four again", "file": "src/window.py", "old": "3  # the", "new": "4  # the"},
                 {"name": "renamed", "file": "src/window.py", "old": "limit", "new": "lim"},
                 {"name": "comment renamed", "file": "src/window.py", "old": "window", "new": "lim"},
                 {"name": "a wider door", "file": "src/door.py", "old": "return 3", "new": "return 4"}]
    assert mutate.main([str(_list(tmp_path, mutations)), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    err = capsys.readouterr().err
    assert "unchanged: new is old, so the file is unchanged" in err and "four, four again: the same mutant of src/window.py" in err
    assert "renamed" not in err and "door" not in err
    assert not (tmp_path / "runs").exists()


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


def test_focused_only_runs_the_focused_tests_alone_and_a_mutation_they_miss_is_missed(tmp_path, capsys):
    """A failing test outside the focused ones stops a run that reads the whole suite; with --focused-only it is never run."""
    root = _repo(tmp_path)
    (root / "tests" / "test_elsewhere.py").write_text("def test_elsewhere():\n    assert False\n", encoding="utf-8")
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"},
                 {"name": "another comment", "file": "src/window.py", "old": "# the window", "new": "# a window"}]
    path = _list(tmp_path, mutations, ["tests/test_window.py"])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "whole")]) == 2
    assert "the whole suite exit 1 without a mutation" in capsys.readouterr().err
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs"), "--focused-only"]) == 1
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [(r["mutation"], r["caught"], r["where"]) for r in results] == [("a wider window", True, "focused"),
                                                                          ("another comment", False, "focused")]
    assert sorted(p.name for p in run.iterdir()) == ["baseline.focused.log", "mutations.yaml", "pid", "results.json"], \
        "no run of the whole suite"
    assert "MISSED another comment  (focused)" in capsys.readouterr().out
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE


def test_a_mutation_in_scripts_runs_as_its_source_not_as_bytecode_cached_before_it(tmp_path):
    """Bytecode Python never checks against its source stands in for a mutant written within a second of the original."""
    root = _repo(tmp_path)
    (root / "scripts").mkdir()
    (root / "scripts" / "window.py").write_text(SOURCE, encoding="utf-8")
    (root / "pyproject.toml").write_text('[tool.pytest.ini_options]\npythonpath = ["scripts"]\n', encoding="utf-8")
    source = str(root / "scripts" / "window.py")
    py_compile.compile(source, cfile=importlib.util.cache_from_source(source), invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    path = _list(tmp_path, [{"name": "a wider window", "file": "scripts/window.py", "old": "return 3", "new": "return 4"}],
                 ["tests/test_window.py"])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 0
    assert (root / "scripts" / "window.py").read_text(encoding="utf-8") == SOURCE


def test_focused_only_without_focused_tests_is_refused(tmp_path, capsys):
    root = _repo(tmp_path)
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs"), "--focused-only"]) == 2
    assert "--focused-only needs focused tests" in capsys.readouterr().err
    assert not (tmp_path / "runs").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL to a process group")
def test_a_mutant_left_by_a_killed_run_is_restored_before_the_next_run(tmp_path, capsys):
    """Killed, a run never reaches the finally that restores the file: the next one restores it from the run's copy."""
    root = _repo(tmp_path)
    test = (root / "tests" / "test_window.py").read_text(encoding="utf-8")
    running = tmp_path / "mutant-running"
    (root / "tests" / "test_window.py").write_text(
        "import time\nfrom pathlib import Path\nfrom window import limit\n\n\ndef test_limit():\n    if limit() != 3:\n"
        f"        Path({str(running)!r}).touch()\n        time.sleep(60)\n    assert limit() == 3\n", encoding="utf-8")
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}],
                 ["tests/test_window.py"])
    args = [str(path), "--root", str(root), "--runs", str(tmp_path / "runs"), "--focused-only"]
    proc = subprocess.Popen([sys.executable, str(ROOT / "scripts" / "mutate.py"), *args], start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 60
        while not running.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert running.exists(), "the focused test ran on the mutant"
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(30)
    (killed,) = (tmp_path / "runs").iterdir()
    assert "return 4" in (root / "src" / "window.py").read_text(encoding="utf-8"), "the mutant is left in place"
    assert (killed / "original" / "src" / "window.py").read_text(encoding="utf-8") == SOURCE
    (root / "tests" / "test_window.py").write_text(test, encoding="utf-8")
    assert mutate.main(args) == 0
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE
    assert f"restored src/window.py, left mutated by the run {killed}" in capsys.readouterr().out
    assert not (killed / "original").exists() and not (killed / "mutant").exists()


def _left(tmp_path: Path, root: Path, current: str, pid: int) -> Path:
    """A run that left src/window.py mutated, its copies kept, run by `pid`; the file now holding `current`."""
    run = tmp_path / "runs" / "20261022T000000000000Z"
    for kind, text in (("original", SOURCE), ("mutant", SOURCE.replace("return 3", "return 4"))):
        (run / kind / "src").mkdir(parents=True)
        (run / kind / "src" / "window.py").write_text(text, encoding="utf-8")
    (run / "pid").write_text(str(pid), encoding="utf-8")
    (root / "src" / "window.py").write_text(current, encoding="utf-8")
    return run


def _gone_pid() -> int:
    done = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True, check=True)
    return int(done.stdout)


def test_a_file_changed_since_a_killed_run_left_it_is_not_restored_and_no_run_starts(tmp_path, capsys):
    """Neither the original nor the mutant: someone edited it since, and restoring it would lose that edit."""
    root = _repo(tmp_path)
    edited = SOURCE.replace("return 3", "return 5")
    run = _left(tmp_path, root, edited, _gone_pid())
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 5", "new": "return 6"}])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    err = capsys.readouterr().err
    assert f"src/window.py is neither the original nor the mutant the run {run} left" in err
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == edited
    assert (run / "original" / "src" / "window.py").is_file(), "the copies stay until the file is sorted out"
    assert [p.name for p in (tmp_path / "runs").iterdir()] == [run.name], "no run starts"


def test_the_copies_of_a_run_still_going_are_left_to_it_and_no_run_starts(tmp_path, capsys):
    """Its copies are not a leftover: restoring the file under it would end its mutation for it."""
    root = _repo(tmp_path)
    mutant = SOURCE.replace("return 3", "return 4")
    run = _left(tmp_path, root, mutant, os.getpid())
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 4", "new": "return 5"}])
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    assert f"the run {run} is still going (pid {os.getpid()})" in capsys.readouterr().err
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == mutant
