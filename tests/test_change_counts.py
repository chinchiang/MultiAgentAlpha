"""scripts/change_counts.py: the mutations of each mutation list, and the tests of each test file, a change adds,
changes and removes, for a human to copy into the CHANGELOG row, the commit message and the pull request body."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import change_counts  # noqa: E402  (not `from change_counts import test_functions`: pytest would collect it)

TESTS = ("import pytest\n\n\n"
         "@pytest.mark.parametrize('n', [1, 2])\n"
         "def test_a(n):\n    assert n\n\n\n"
         "def helper():\n    pass\n\n\n"
         "class TestK:\n    def test_b(self):\n        pass\n\n    def check(self):\n        pass\n\n\n"
         "class Other:\n    def test_c(self):\n        pass\n\n\n"
         "def test_last():\n    pass\n")


def test_a_test_function_is_a_test_at_module_level_or_in_a_test_class_with_its_decorators():
    found = change_counts.test_functions(TESTS)
    assert list(found) == ["test_a", "TestK.test_b", "test_last"], "in the order of the file"
    assert found["test_a"] == "@pytest.mark.parametrize('n', [1, 2])\ndef test_a(n):\n    assert n"
    assert found["TestK.test_b"] == "def test_b(self):\n    pass", "the indentation of a method taken off every line"
    assert change_counts.test_functions(None) == {}


def test_two_sides_are_compared_by_key_and_a_key_on_both_with_another_value_is_changed():
    assert change_counts.compare({"a": 1, "b": 2}, {"b": 3, "c": 4}) == (1, 1, 1)
    assert change_counts.compare({"a": 1}, {"a": 1}) == (0, 0, 0)
    assert change_counts.compare({}, {"a": 1, "b": 2}) == (2, 0, 0)


def test_a_list_gives_its_mutations_by_name_and_its_other_keys():
    text = ('focused: [tests/test_x.py]\nrequires-python: ">=3.13"\nmutations:\n'
            "  - {name: one, file: src/x.py, old: a, new: b}\n  - {name: two, file: src/x.py, old: c, new: d, error: KeyError}\n")
    mutations, keys = change_counts.mutation_list(text)
    assert mutations == {"one": {"name": "one", "file": "src/x.py", "old": "a", "new": "b"},
                         "two": {"name": "two", "file": "src/x.py", "old": "c", "new": "d", "error": "KeyError"}}
    assert keys == {"focused": ["tests/test_x.py"], "requires-python": ">=3.13"}
    assert change_counts.mutation_list(None) == ({}, {})


LIST_A = ("focused: [tests/test_x.py]\nmutations:\n"
          "  - {name: kept, file: src/x.py, old: a, new: b}\n"
          "  - {name: given a caught_by, file: src/x.py, old: c, new: d}\n"
          "  - {name: given an error, file: src/x.py, old: e, new: f}\n"
          "  - {name: renamed, file: src/x.py, old: g, new: h}\n")
LIST_B = "focused: [tests/test_x.py]\nmutations:\n  - {name: one, file: src/x.py, old: a, new: b}\n  - {name: two, file: src/x.py, old: c, new: d}\n"
TEST_X = ("def helper():\n    return 1\n\n\n"
          "def test_kept():\n    assert helper()\n\n\n"
          "def test_changed():\n    assert helper() == 1\n\n\n"
          "def test_removed():\n    pass\n")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo, check=True,
                          capture_output=True, encoding="utf-8").stdout


def _write(repo: Path, rel: str, text: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def _repo(tmp_path: Path) -> Path:
    """A repository whose main holds two mutation lists, a test file and the code they name."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for rel, text in {"src/x.py": "a c e g\n", "tests/mutations/a.yaml": LIST_A, "tests/mutations/b.yaml": LIST_B,
                      "tests/test_x.py": TEST_X}.items():
        _write(repo, rel, text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "switch", "-qc", "change")
    return repo


def _counts(repo: Path, capsys, *args: str) -> list[str]:
    status = _git(repo, "status", "--porcelain")
    assert change_counts.main(["--base", "main", *args, "--repo", str(repo)]) == 0
    assert _git(repo, "status", "--porcelain") == status, "nothing in the repository changes"
    return capsys.readouterr().out.splitlines()


def test_the_mutations_and_tests_a_change_adds_changes_and_removes_are_counted_per_file_and_in_all(tmp_path, capsys):
    """A caught_by or an error given is a change; a renamed mutation is one removed and one added; a deleted list counts
    its mutations removed; an edit of focused is named apart from the counts; a parametrized test is one, a helper is
    none, a method of a Test class is one."""
    repo = _repo(tmp_path)
    _write(repo, "tests/mutations/a.yaml", LIST_A.replace("focused: [tests/test_x.py]", "focused: [tests/test_x.py::test_kept]")
           .replace("given a caught_by, file: src/x.py,", "given a caught_by, file: src/x.py, caught_by: tests/test_x.py,")
           .replace("old: e, new: f}", "old: e, new: f, error: KeyError}").replace("name: renamed,", "name: now named,")
           + "  - {name: new, file: src/x.py, old: i, new: j}\n")
    (repo / "tests/mutations/b.yaml").unlink()
    _write(repo, "tests/test_x.py", TEST_X.replace("def helper():\n    return 1", "def helper():\n    return 2")
           .replace("assert helper() == 1", "assert helper() == 2").replace("def test_removed():\n    pass\n", "")
           + "\n\nimport pytest\n\n\n@pytest.mark.parametrize('n', [1, 2, 3])\ndef test_added(n):\n    assert n\n\n\n"
             "class TestGroup:\n    def test_method(self):\n        pass\n")
    _git(repo, "commit", "-qam", "the change")
    assert _counts(repo, capsys) == [
        "tests/mutations/a.yaml: 2 added, 2 changed, 1 removed (5 in all); focused changed",
        "tests/mutations/b.yaml: 0 added, 0 changed, 2 removed (0 in all)",
        "tests/test_x.py: 2 added, 1 changed, 1 removed",
        "mutations: 2 added, 2 changed, 3 removed",
        "tests: 2 added, 1 changed, 1 removed"]


def test_a_list_whose_old_is_stale_is_still_counted(tmp_path, capsys):
    """Read as YAML, not loaded: mutate.load would refuse the list, since `z` occurs nowhere in src/x.py."""
    repo = _repo(tmp_path)
    _write(repo, "tests/mutations/b.yaml", LIST_B + "  - {name: stale, file: src/x.py, old: z, new: y}\n")
    _git(repo, "commit", "-qam", "a stale mutation")
    assert _counts(repo, capsys)[0] == "tests/mutations/b.yaml: 1 added, 0 changed, 0 removed (3 in all)"


def test_worktree_counts_what_is_not_committed_an_untracked_test_file_included(tmp_path, capsys):
    repo = _repo(tmp_path)
    _write(repo, "tests/unit/test_new.py", "def test_one():\n    pass\n\n\ndef test_two():\n    pass\n")
    assert _counts(repo, capsys) == ["mutations: 0 added, 0 changed, 0 removed", "tests: 0 added, 0 changed, 0 removed"]
    assert _counts(repo, capsys, "--worktree") == ["tests/unit/test_new.py: 2 added, 0 changed, 0 removed",
                                                   "mutations: 0 added, 0 changed, 0 removed",
                                                   "tests: 2 added, 0 changed, 0 removed"]


def test_the_merge_of_pr_335_adds_the_21_mutations_and_11_tests_its_changelog_row_states(capsys):
    """v0.13.103's row: tests/test_mutate.py 新增 11 個測試, and tests/mutations/mutate-where-caught.yaml 21 mutations."""
    if subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", "c8ff6ab^1"], capture_output=True).returncode != 0:
        pytest.skip("this checkout lacks the history of c8ff6ab (#335's merge): a shallow clone")
    assert change_counts.main(["--base", "c8ff6ab^1", "--head", "c8ff6ab", "--repo", str(ROOT)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert "tests/mutations/mutate-where-caught.yaml: 21 added, 0 changed, 0 removed (21 in all)" in out
    assert "tests/test_mutate.py: 11 added, 0 changed, 0 removed" in out


def test_an_edit_of_focused_alone_is_named_with_nothing_counted(tmp_path, capsys):
    repo = _repo(tmp_path)
    _write(repo, "tests/mutations/b.yaml", LIST_B.replace("focused: [tests/test_x.py]", "focused: [tests/test_x.py::test_kept]"))
    _git(repo, "commit", "-qam", "focused alone")
    assert _counts(repo, capsys)[0] == "tests/mutations/b.yaml: 0 added, 0 changed, 0 removed (2 in all); focused changed"


def test_a_file_that_is_not_yaml_or_not_python_or_a_base_git_does_not_know_is_an_error_with_no_count(tmp_path, capsys):
    repo = _repo(tmp_path)
    for rel, text, said in (("tests/mutations/a.yaml", "mutations: [unclosed\n", "ERROR: tests/mutations/a.yaml: not YAML: "),
                            ("tests/test_x.py", "def test_(:\n", "ERROR: tests/test_x.py: not Python: ")):
        _write(repo, rel, text)
        assert change_counts.main(["--base", "main", "--worktree", "--repo", str(repo)]) == 2
        out = capsys.readouterr()
        assert out.err.startswith(said) and out.out == "", out.err
        _git(repo, "checkout", "--", rel)
    assert change_counts.main(["--base", "no-such-base", "--repo", str(repo)]) == 2
    out = capsys.readouterr()
    assert out.err.startswith("ERROR: git merge-base no-such-base failed for --base no-such-base: ") and out.out == ""


def test_a_file_that_is_not_utf8_is_read_alike_on_both_sides(tmp_path, capsys):
    """What is not UTF-8 is replaced, in the working tree as git show's output is: the file is still counted."""
    repo = _repo(tmp_path)
    (repo / "tests" / "test_latin.py").write_bytes(b"# caf\xe9\ndef test_one():\n    pass\n")
    assert _counts(repo, capsys, "--worktree")[0] == "tests/test_latin.py: 1 added, 0 changed, 0 removed"
