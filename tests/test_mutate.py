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


def test_the_output_of_the_focused_tests_is_kept_for_each_mutation_and_listed_in_the_results(tmp_path):
    """Where the test that caught a mutation fails says whether it was caught for the reason the mutation's name gives; the
    output of the focused tests with a mutation used to be dropped, and a review had to apply the mutant by hand."""
    root = _repo(tmp_path)
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"},
                 {"name": "another comment", "file": "src/window.py", "old": "# the window", "new": "# a window"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs")])
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [r["logs"] for r in results] == [["a_wider_window.focused.log"],
                                            ["another_comment.focused.log", "another_comment.suite.log"]], "the logs it wrote"
    caught = (run / "a_wider_window.focused.log").read_text(encoding="utf-8")
    assert "test_limit" in caught and "4 == 3" in caught, "the failure of the test that caught it"
    assert "1 passed" in (run / "another_comment.focused.log").read_text(encoding="utf-8"), "a missed mutation keeps its run too"


def test_a_mutation_caught_at_an_assertion_says_the_line_it_failed_at(tmp_path, capsys):
    root = _repo(tmp_path)
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs")])
    (run,) = (tmp_path / "runs").iterdir()
    (result,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert (result["at"], result["error"]) == ("assert limit() == 3", "AssertionError")
    assert capsys.readouterr().out.splitlines()[0] == "CAUGHT a wider window  <- tests/test_window.py::test_limit  at: assert limit() == 3"


def test_a_catch_by_a_test_whose_name_fills_the_failure_head_says_the_line_it_failed_at(tmp_path):
    """pytest pads a failure's head with underscores to its line width, and a long name leaves room for one on each
    side; its traceback's frames are parted by a line of `_ _ _`."""
    root = _repo(tmp_path)
    long = "test_the_window_limit_is_three_when_the_window_is_read_from_its_module_and_nothing_else_changed"
    (root / "tests" / "test_window.py").write_text(
        f"from window import limit\n\n\ndef check():\n    assert limit() == 3\n\n\ndef {long}():\n    check()\n", encoding="utf-8")
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs"),
                 "--focused-only"])
    (run,) = (tmp_path / "runs").iterdir()
    (result,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert f"_ {long} _" in (run / "a_wider_window.focused.log").read_text(encoding="utf-8").splitlines()
    assert (result["at"], result["error"]) == ("check()", "AssertionError")


def test_what_the_failing_test_printed_is_not_read_as_its_exception(tmp_path, capsys):
    """pytest shows a failed test's output after its traceback, under ---- Captured stdout call ----."""
    root = _repo(tmp_path)
    (root / "tests" / "test_window.py").write_text(
        "from window import limit\n\n\ndef test_limit():\n    print('tests/test_door.py:12: KeyError')\n    assert limit() == 3\n",
        encoding="utf-8")
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs"),
                 "--focused-only"])
    (run,) = (tmp_path / "runs").iterdir()
    (result,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert "Captured stdout call" in (run / "a_wider_window.focused.log").read_text(encoding="utf-8")
    assert (result["at"], result["error"]) == ("assert limit() == 3", "AssertionError")


def test_a_mutation_caught_by_an_error_of_the_code_under_test_is_marked_with_the_error(tmp_path, capsys):
    """Still a catch: whether a KeyError is the fault the name says is for the reader of the line to judge."""
    root = _repo(tmp_path)
    (root / "src" / "window.py").write_text('SIZES = {"window": 3}\n\n\ndef limit():\n    return SIZES["window"]\n', encoding="utf-8")
    mutations = [{"name": "the door's size", "file": "src/window.py", "old": 'SIZES["window"]', "new": 'SIZES["door"]'}]
    code = mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs"),
                        "--focused-only"])
    (run,) = (tmp_path / "runs").iterdir()
    (result,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert (code, result["caught"], result["at"], result["error"]) == (0, True, "assert limit() == 3", "KeyError")
    assert capsys.readouterr().out.splitlines()[0] == ("CAUGHT the door's size  <- tests/test_window.py::test_limit  "
                                                       "at: assert limit() == 3  (KeyError)")


def test_a_catch_by_the_whole_suite_says_where_from_its_log_and_a_failure_with_no_traceback_says_nothing(tmp_path, capsys):
    """pytest.fail(..., pytrace=False), as tests/test_mutation_lists.py fails, prints no source line and no exception."""
    root = _repo(tmp_path)
    (root / "src" / "door.py").write_text("def width():\n    return 2\n\n\ndef height():\n    return 5\n", encoding="utf-8")
    (root / "tests" / "test_door.py").write_text(
        "import pytest\nfrom door import height, width\n\n\ndef test_width():\n    assert width() == 2\n\n\n"
        "def test_height():\n    if height() != 5:\n        pytest.fail('the door is too high', pytrace=False)\n", encoding="utf-8")
    mutations = [{"name": "a wider door", "file": "src/door.py", "old": "return 2", "new": "return 3"},
                 {"name": "a higher door", "file": "src/door.py", "old": "return 5", "new": "return 6"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs")])
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [(r["where"], r["caught"], r["at"], r["error"]) for r in results] == [
        ("suite", True, "assert width() == 2", "AssertionError"), ("suite", True, None, None)]
    assert capsys.readouterr().out.splitlines()[:2] == ["CAUGHT a wider door  <- tests/test_door.py::test_width  at: assert width() == 2",
                                                        "CAUGHT a higher door  <- tests/test_door.py::test_height"]


def test_a_catch_by_another_test_than_the_one_caught_by_names_is_marked_and_still_a_catch(tmp_path, capsys):
    """A test file named alone matches any of its tests, and a test named without its parameters each of them."""
    root = _repo(tmp_path)
    (root / "tests" / "test_window.py").write_text(
        "import pytest\nfrom window import limit\n\n\n@pytest.mark.parametrize('n', [3])\ndef test_limit(n):\n    assert limit() == n\n",
        encoding="utf-8")
    (root / "tests" / "test_door.py").write_text("def test_width():\n    pass\n", encoding="utf-8")
    named = {"its file": "tests/test_window.py", "its test": "tests/test_window.py::test_limit",
             "its parameters": "tests/test_window.py::test_limit[3]", "other parameters": "tests/test_window.py::test_limit[4]",
             "another test": "tests/test_door.py::test_width"}
    mutations = [{"name": name, "file": "src/window.py", "old": "return 3", "new": f"return {k}", "caught_by": test}
                 for k, (name, test) in enumerate(named.items(), start=4)]
    code = mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs"),
                        "--focused-only"])
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [r["expected"] for r in results] == [None, None, None, "tests/test_window.py::test_limit[4]", "tests/test_door.py::test_width"]
    caught = "  <- tests/test_window.py::test_limit[3]  at: assert limit() == n"
    assert capsys.readouterr().out.splitlines()[:5] == [
        f"CAUGHT its file{caught}", f"CAUGHT its test{caught}", f"CAUGHT its parameters{caught}",
        f"CAUGHT other parameters{caught}  (expected tests/test_window.py::test_limit[4])",
        f"CAUGHT another test{caught}  (expected tests/test_door.py::test_width)"]
    assert code == 0


def _git_repo(tmp_path: Path) -> Path:
    """_repo, as a git repository with its files committed."""
    root = _repo(tmp_path)
    for args in (["init", "-q"], ["add", "."], ["commit", "-qm", "base"]):
        _git(root, *args)
    return root


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=root, check=True, capture_output=True)


def test_a_path_a_mutation_leaves_in_the_repository_is_named_with_the_mutation(tmp_path, capsys):
    """A file in a new directory is named as itself, once, after the run that left it: a test that writes one every run
    leaves it in the runs without a mutation. The run's own directory is not a left path."""
    root = _git_repo(tmp_path)
    (root / "tests" / "test_log.py").write_text(
        "import os\n\n\ndef test_log():\n    os.makedirs('logs', exist_ok=True)\n    open('logs/run.txt', 'w').close()\n",
        encoding="utf-8")
    leaves = 'import os; os.makedirs("stray", exist_ok=True); open("stray/file", "w").close(); return 4'
    mutations = [{"name": "a window that leaves a file", "file": "src/window.py", "old": "return 3", "new": leaves},
                 {"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 5"}]
    code = mutate.main([str(_list(tmp_path, mutations, ["tests/test_log.py", "tests/test_window.py"])), "--root", str(root),
                        "--focused-only"])
    (run,) = (root / "out" / "mutations").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [r["left"] for r in results] == [["stray/file"], []]
    out = capsys.readouterr().out.splitlines()
    assert [line for line in out if line.startswith("LEFT")] == ["LEFT logs/run.txt  (baseline)",
                                                                 "LEFT stray/file  (a window that leaves a file)"]
    assert code == 0, "a left path is reported, not counted against the run"
    assert (root / "stray" / "file").is_file(), "and it is not removed"


def test_once_git_status_fails_during_a_run_no_path_is_named_left_after_it(tmp_path, capsys):
    """A failed read is no empty one: compared with it, every path already there would be named left."""
    root = _git_repo(tmp_path)
    (root / "notes.txt").write_text("already here\n", encoding="utf-8")
    mutations = [{"name": "a window that hides .git", "file": "src/window.py", "old": "return 3",
                  "new": 'import os; os.rename(".git", ".git-away"); return 4'},
                 {"name": "a window that brings .git back", "file": "src/window.py", "old": "return 3",
                  "new": 'import os; os.rename(".git-away", ".git"); return 5'}]
    assert mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--focused-only"]) == 0
    captured = capsys.readouterr()
    assert [line for line in captured.out.splitlines() if line.startswith("LEFT")] == []
    assert captured.err.splitlines() == ["left paths no longer checked: git status failed after a window that hides .git"]
    (run,) = (root / "out" / "mutations").iterdir()
    assert [r["left"] for r in json.loads((run / "results.json").read_text(encoding="utf-8"))] == [None, None]


def test_a_run_that_leaves_nothing_names_nothing_and_one_outside_git_says_it_did_not_look(tmp_path, capsys):
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4"}]
    assert mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(_git_repo(tmp_path)),
                        "--focused-only"]) == 0
    captured = capsys.readouterr()
    assert not [line for line in captured.out.splitlines() if line.startswith("LEFT")] and captured.err == ""
    plain = _repo(tmp_path / "plain")
    assert mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(plain), "--focused-only"]) == 0
    assert capsys.readouterr().err.splitlines() == [f"left paths not checked: {plain} is not a git repository"]


def test_a_mutation_name_with_characters_a_file_name_cannot_have_still_gets_its_logs(tmp_path):
    """Windows refuses " : ? * < > | \\ / in a file name; a name with one of them would have made every run fail there."""
    root = _repo(tmp_path)
    name = 'a "wider" window: 4? *<big>* | a\\b/c'  # every character a file name cannot hold
    mutations = [{"name": name, "file": "src/window.py", "old": "return 3", "new": "return 4"}]
    mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs")])
    (run,) = (tmp_path / "runs").iterdir()
    (result,) = json.loads((run / "results.json").read_text(encoding="utf-8"))
    (log,) = result["logs"]
    assert not set('"\\:*?<>|/') & set(log), log
    assert (run / log).is_file()
    assert mutate._slug("a wider window") == "a_wider_window", "a name without such characters is named as before"
    assert len(mutate._slug("x" * 200)) == 80


def test_a_mutation_of_several_lines_is_applied_to_a_file_with_crlf_endings_and_the_file_is_restored_byte_for_byte(tmp_path):
    # a Windows checkout with core.autocrlf=true has CRLF endings; a list's `old` and `new` are written with \n
    root = _repo(tmp_path)
    crlf = SOURCE.replace("\n", "\r\n").encode("utf-8")
    (root / "src" / "window.py").write_bytes(crlf)
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "def limit():\n    return 3", "new": "def limit():\n    return 4"}]
    code = mutate.main([str(_list(tmp_path, mutations, ["tests/test_window.py"])), "--root", str(root), "--runs", str(tmp_path / "runs"),
                        "--focused-only"])
    (run,) = (tmp_path / "runs").iterdir()
    results = json.loads((run / "results.json").read_text(encoding="utf-8"))
    assert [(r["mutation"], r["caught"]) for r in results] == [("a wider window", True)]
    assert code == 0
    assert (root / "src" / "window.py").read_bytes() == crlf


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


def test_a_caught_by_naming_a_test_that_does_not_exist_is_refused_before_any_file_is_touched(tmp_path, capsys):
    """A test file, a test of it, or a test with its parameters names one; a file, a test or a class it lacks does not."""
    root = _repo(tmp_path)
    named = {"a file": "tests/test_window.py", "a test": "tests/test_window.py::test_limit",
             "parameters": "tests/test_window.py::test_limit[wide]", "parameters holding ::": "tests/test_window.py::test_limit[a::b]",
             "no file": "tests/test_gone.py",
             "no test": "tests/test_window.py::test_width", "no class": "tests/test_window.py::TestWindow::test_limit"}
    mutations = [{"name": name, "file": "src/window.py", "old": "return 3", "new": f"return {k}", "caught_by": test}
                 for k, (name, test) in enumerate(named.items(), start=4)]
    assert mutate.main([str(_list(tmp_path, mutations)), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    problems = capsys.readouterr().err.removeprefix("ERROR: ").strip().split("; ")
    assert problems == ["no file: caught_by: no tests/test_gone.py", "no test: caught_by: no tests/test_window.py::test_width",
                        "no class: caught_by: no tests/test_window.py::TestWindow::test_limit"]
    assert not (tmp_path / "runs").exists()


def test_a_caught_by_that_is_not_text_is_refused(tmp_path, capsys):
    root = _repo(tmp_path)
    mutations = [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 4", "caught_by": 3}]
    assert mutate.main([str(_list(tmp_path, mutations)), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    assert capsys.readouterr().err.strip() == "ERROR: a wider window: caught_by: no 3"


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
    assert sorted(p.name for p in run.iterdir()) == [
        "a_wider_window.focused.log", "another_comment.focused.log", "baseline.focused.log", "mutations.yaml", "pid", "results.json"], \
        "the focused tests' logs, and no run of the whole suite"
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


@pytest.mark.skipif(sys.platform == "win32", reason="mutate._alive takes every run for alive on Windows, where os.kill ends it")
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


# --lists-for: the lists a change touches


def _touching_repo(tmp_path: Path) -> Path:
    """_git_repo with more modules, their tests and one list per way a change can touch a list, committed and tagged
    `base`."""
    root = _git_repo(tmp_path)
    for name in ("door", "wall", "gone"):
        (root / "src" / f"{name}.py").write_text(f"{name.upper()} = 1\n", encoding="utf-8")
        (root / "tests" / f"test_{name}.py").write_text(f"def test_{name}():\n    pass\n", encoding="utf-8")
    lists = {"a-file-committed": ("src/window.py", "tests/test_wall.py"),
             "b-focused-test": ("src/wall.py", "tests/test_door.py::test_door"),
             "c-itself": ("src/wall.py", "tests/test_wall.py"),
             "d-file-untracked": ("src/new.py", "tests/test_wall.py"),
             "e-file-deleted": ("src/gone.py", "tests/test_wall.py"),
             "f-untouched": ("src/wall.py", "tests/test_wall.py")}
    (root / "tests" / "mutations").mkdir()
    for name, (file, focused) in lists.items():
        mutation = {"name": name, "file": file, "caught_by": focused, "old": "1", "new": "2"}
        (root / "tests" / "mutations" / f"{name}.yaml").write_text(json.dumps({"focused": [focused], "mutations": [mutation]}),
                                                                    encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "lists")
    _git(root, "tag", "base")
    return root


def test_lists_for_names_each_list_a_change_touches_and_no_other(tmp_path, capsys):
    """A list is touched when the change, committed or not, untracked files included, changes the file of one of its
    mutations (also by deleting it), one of its focused test files (also named with `::`), or the list itself."""
    root = _touching_repo(tmp_path)
    (root / "src" / "window.py").write_text(SOURCE.replace("return 3", "return 4"), encoding="utf-8")
    _git(root, "commit", "-qam", "a wider window")  # committed
    (root / "tests" / "test_door.py").write_text("def test_door():\n    assert True\n", encoding="utf-8")  # not committed
    with (root / "tests" / "mutations" / "c-itself.yaml").open("a", encoding="utf-8") as f:
        f.write("\n")
    (root / "src" / "new.py").write_text("NEW = 1\n", encoding="utf-8")  # untracked
    (root / "src" / "gone.py").unlink()  # its lines only removed
    assert mutate.main(["--lists-for", "base", "--root", str(root)]) == 0
    assert capsys.readouterr().out.splitlines() == [f"tests/mutations/{name}.yaml" for name in
                                                    ("a-file-committed", "b-focused-test", "c-itself", "d-file-untracked",
                                                     "e-file-deleted")]


def test_lists_for_prints_nothing_when_the_change_touches_no_list(tmp_path, capsys):
    root = _touching_repo(tmp_path)
    (root / "README.md").write_text("a file no list names\n", encoding="utf-8")
    assert mutate.main(["--lists-for", "base", "--root", str(root)]) == 0
    assert capsys.readouterr().out == ""


def test_a_list_or_lists_for_is_given_and_lists_for_alone_runs_no_mutation(tmp_path, capsys):
    root = _touching_repo(tmp_path)
    path = _list(tmp_path, [{"name": "a wider window", "file": "src/window.py", "old": "return 3", "new": "return 5"}])
    for argv, said in (([str(path), "--lists-for", "base"], "give a list, --lists-for BASE or --base BASE"),
                       ([], "give a list, --lists-for BASE or --base BASE"),
                       (["--lists-for", "base", "--focused-only"], "--lists-for runs no mutation"),
                       (["--lists-for", "base", "--only", "a wider window"], "--lists-for runs no mutation")):
        with pytest.raises(SystemExit) as stop:
            mutate.main([*argv, "--root", str(root)])
        assert stop.value.code == 2 and said in capsys.readouterr().err, argv
    assert not (root / "out").exists(), "no run starts"
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE


def test_lists_for_names_a_list_that_is_not_yaml_and_reads_one_that_is_not_a_mapping_as_naming_only_itself(tmp_path, capsys):
    """A list that is not YAML is named whatever the change, so its run says what is wrong with it; one that is YAML but
    holds no mapping names no file but itself."""
    root = _touching_repo(tmp_path)
    (root / "tests" / "mutations" / "g-not-yaml.yaml").write_text("focused: [unclosed\n", encoding="utf-8")
    (root / "tests" / "mutations" / "h-a-sequence.yaml").write_text("- src/wall.py\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "two odd lists")
    _git(root, "tag", "-f", "base")
    (root / "src" / "wall.py").write_text("WALL = 2\n", encoding="utf-8")
    assert mutate.main(["--lists-for", "base", "--root", str(root)]) == 0
    assert capsys.readouterr().out.splitlines() == [f"tests/mutations/{name}.yaml" for name in
                                                    ("b-focused-test", "c-itself", "f-untouched", "g-not-yaml")]  # each mutates src/wall.py


def test_lists_for_a_base_git_does_not_know_says_what_git_said(tmp_path, capsys):
    root = _touching_repo(tmp_path)
    assert mutate.main(["--lists-for", "no-such-base", "--root", str(root)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("ERROR: git merge-base no-such-base HEAD: ") and "no-such-base" in err[len("ERROR: git merge-base"):]


def test_an_old_held_back_by_single_quotes_says_to_use_double_quotes_and_no_other_does(tmp_path, capsys):
    r"""In single quotes YAML keeps `\n` as a backslash and an `n`, so an `old` of several lines written there never
    matches; the refusal says so only when reading each `\n` as a newline makes it match once."""
    root = _repo(tmp_path)
    path = tmp_path / "quoted.yaml"
    path.write_text("mutations:\n"
                    "  - {name: two lines, file: src/window.py, old: 'def limit():\\n    return 3', new: 'def limit():\\n    return 4'}\n"
                    "  - {name: one line, file: src/window.py, old: 'return 9', new: 'return 4'}\n"
                    "  - {name: two wrong lines, file: src/window.py, old: 'def limit():\\n    return 9', new: 'x'}\n",
                    encoding="utf-8")
    assert mutate.main([str(path), "--root", str(root), "--runs", str(tmp_path / "runs")]) == 2
    problems = capsys.readouterr().err.removeprefix("ERROR: ").strip().split("; ")
    hint = " (YAML keeps \\n as written in single quotes: write the value in double quotes)"
    assert problems == ["two lines: `old` occurs 0 times in src/window.py" + hint,
                        "one line: `old` occurs 0 times in src/window.py",
                        "two wrong lines: `old` occurs 0 times in src/window.py"]
    assert not (tmp_path / "runs").exists()


# --base: run every list a change touches, and sum them up


def _base_repo(tmp_path: Path) -> Path:
    """_git_repo with two more tests of window.py, a door module and its test, and three lists that load, committed and
    tagged `base`: a-window.yaml (two mutations of window.py: one caught where its caught_by does not name the catching
    test, one caught by a failure with no traceback), b-door.yaml (one mutation of door.py its test misses; the test
    leaves stray.txt each run) and c-wall.yaml (a mutation of wall.py)."""
    root = _git_repo(tmp_path)
    (root / "tests" / "test_window.py").write_text(
        "import pytest\nfrom window import limit\n\n\ndef test_limit():\n    assert limit() != 5\n\n\n"
        "def test_not_two():\n    if limit() == 2:\n        pytest.fail('two', pytrace=False)\n", encoding="utf-8")
    (root / "src" / "door.py").write_text("DOOR = 1\n", encoding="utf-8")
    (root / "tests" / "test_door.py").write_text("import door\n\n\ndef test_door():\n    open('stray.txt', 'w').close()\n",
                                                 encoding="utf-8")
    (root / "src" / "wall.py").write_text("WALL = 1\n", encoding="utf-8")
    (root / "tests" / "test_wall.py").write_text("from wall import WALL\n\n\ndef test_wall():\n    assert WALL == 1\n",
                                                 encoding="utf-8")
    lists = {"a-window": ("tests/test_window.py",
                          [("a wider window", "src/window.py", "return 3", "return 5", "tests/test_door.py::test_door"),
                           ("a narrower window", "src/window.py", "return 3", "return 2", "tests/test_window.py::test_not_two")]),
             "b-door": ("tests/test_door.py", [("another door", "src/door.py", "DOOR = 1", "DOOR = 2", "tests/test_door.py::test_door")]),
             "c-wall": ("tests/test_wall.py", [("another wall", "src/wall.py", "WALL = 1", "WALL = 2", "tests/test_wall.py::test_wall")])}
    (root / "tests" / "mutations").mkdir()
    for name, (focused, made) in lists.items():
        mutations = [{"name": n, "file": f, "old": o, "new": w, "caught_by": c} for n, f, o, w, c in made]
        (root / "tests" / "mutations" / f"{name}.yaml").write_text(json.dumps({"focused": [focused], "mutations": mutations}),
                                                                    encoding="utf-8")
    (root / ".gitignore").write_text("out/\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-qm", "lists")
    _git(root, "tag", "base")
    return root


def test_base_runs_each_list_the_change_touches_focused_and_sums_up_their_lines_and_marks(tmp_path, capsys):
    """The lists are those --lists-for names; each runs as it does alone with --focused-only, and the summary gives each
    list's result line, then the marked catches, the catches with no `at:` and the left paths of all of them."""
    root = _base_repo(tmp_path)
    (root / "src" / "window.py").write_text(SOURCE + "# a change\n", encoding="utf-8")
    (root / "tests" / "test_door.py").write_text(
        (root / "tests" / "test_door.py").read_text(encoding="utf-8") + "# a change\n", encoding="utf-8")
    assert mutate.main(["--lists-for", "base", "--root", str(root)]) == 0
    listed = capsys.readouterr().out.splitlines()
    code = mutate.main(["--base", "base", "--root", str(root)])
    out = capsys.readouterr().out
    assert [line.removeprefix("== ") for line in out.splitlines() if line.startswith("== ")] == listed, "as --lists-for names"
    runs = sorted((root / "out" / "mutations").iterdir())
    assert len(runs) == 2 and all((run / "results.json").is_file() for run in runs)
    assert not any((run / "baseline.suite.log").exists() for run in runs), "focused: the whole suite never runs"
    summary = out[out.index("\nsummary\n") + 1:].splitlines()
    a, b = (f"tests/mutations/{name}.yaml" for name in ("a-window", "b-door"))
    assert summary[1].startswith(f"{a}: 2 of 2 caught; ") and summary[2].startswith(f"{b}: 0 of 1 caught; ")
    assert summary[3] == "marked:" and summary[4].startswith(f"{a}: CAUGHT a wider window  <- tests/test_window.py::test_limit")
    assert summary[4].endswith("  (expected tests/test_door.py::test_door)")
    assert summary[5:7] == ["caught with no at:",
                            f"{a}: CAUGHT a narrower window  <- tests/test_window.py::test_not_two"]
    assert summary[7:] == ["left:", f"{b}: LEFT stray.txt  (baseline)"]
    assert code == 1, "b-door.yaml missed its mutation"


def test_base_refuses_a_list_that_does_not_load_before_any_file_is_touched(tmp_path, capsys):
    root = _base_repo(tmp_path)
    (root / "src" / "door.py").write_text("DOOR = 3\n", encoding="utf-8")  # b-door.yaml's old is now stale
    (root / "src" / "window.py").write_text(SOURCE + "# a change\n", encoding="utf-8")
    assert mutate.main(["--base", "base", "--root", str(root)]) == 2
    err = capsys.readouterr().err
    assert "ERROR: tests/mutations/b-door.yaml: another door: `old` occurs 0 times in src/door.py" in err
    assert not (root / "out").exists(), "no list runs"
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE + "# a change\n"


def test_base_says_so_when_the_change_touches_no_list(tmp_path, capsys):
    root = _base_repo(tmp_path)
    assert mutate.main(["--base", "base", "--root", str(root)]) == 0
    assert capsys.readouterr().out == "the change since base touches no mutation list\n"
    assert not (root / "out").exists()


def test_base_goes_on_past_a_list_whose_baseline_fails_and_exits_2(tmp_path, capsys):
    root = _base_repo(tmp_path)
    (root / "tests" / "test_door.py").write_text("def test_door():\n    assert False\n", encoding="utf-8")
    (root / "src" / "wall.py").write_text("WALL = 1  # a change\n", encoding="utf-8")
    assert mutate.main(["--base", "base", "--root", str(root)]) == 2
    summary = capsys.readouterr().out.split("\nsummary\n")[1].splitlines()
    assert summary[0].startswith("tests/mutations/b-door.yaml: ERROR: the focused tests exit 1 without a mutation")
    assert summary[1].startswith("tests/mutations/c-wall.yaml: 1 of 1 caught; ")


def test_base_takes_no_list_and_neither_lists_for_nor_only_nor_focused_only(tmp_path, capsys):
    root = _base_repo(tmp_path)
    for argv in (["tests/mutations/a-window.yaml", "--base", "base"], ["--base", "base", "--lists-for", "base"],
                 ["--base", "base", "--only", "a wider window"], ["--base", "base", "--focused-only"]):
        with pytest.raises(SystemExit) as stop:
            mutate.main([*argv, "--root", str(root)])
        assert stop.value.code == 2 and "--base runs every list the change touches" in capsys.readouterr().err, argv
    assert not (root / "out").exists()


def test_base_refuses_a_list_with_no_focused_tests_before_any_file_is_touched(tmp_path, capsys):
    root = _base_repo(tmp_path)
    path = root / "tests" / "mutations" / "c-wall.yaml"
    path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), "focused": []}), encoding="utf-8")
    assert mutate.main(["--base", "base", "--root", str(root)]) == 2
    assert "ERROR: tests/mutations/c-wall.yaml: --base runs the focused tests alone, and the list names none" in capsys.readouterr().err
    assert not (root / "out").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="mutate._alive takes every run for alive on Windows, where os.kill ends it")
def test_base_restores_what_a_killed_run_left_before_it_reads_the_change(tmp_path, capsys):
    """A mutant a killed run left in src/window.py is not part of the change: a-window.yaml is not run."""
    root = _base_repo(tmp_path)
    _left(tmp_path, root, SOURCE.replace("return 3", "return 4"), _gone_pid())
    (root / "tests" / "test_door.py").write_text(
        (root / "tests" / "test_door.py").read_text(encoding="utf-8") + "# a change\n", encoding="utf-8")
    code = mutate.main(["--base", "base", "--root", str(root), "--runs", str(tmp_path / "runs")])
    assert (root / "src" / "window.py").read_text(encoding="utf-8") == SOURCE
    out = capsys.readouterr().out
    assert "== tests/mutations/b-door.yaml" in out and "a-window" not in out
    assert code == 1  # b-door.yaml misses its mutation
