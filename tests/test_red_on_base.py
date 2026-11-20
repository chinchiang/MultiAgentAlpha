"""scripts/red_on_base.py runs the working tree's tests against the base's code (pr-flow step 2) and says, for each test,
RED, GREEN, SKIPPED or UNREACHED. Each test of the command line builds a repository of its own: a package `pkg` whose
main, as origin/main, has `f` and whose branch adds `g`, with tests the working tree adds. The tests of
red_on_base.outcomes read JUnit XML as pytest wrote it, its failures shortened and its paths made relative."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "red_on_base.py"
sys.path.insert(0, str(ROOT / "scripts"))
import red_on_base  # noqa: E402

PYPROJECT = '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
BASE_PKG = "def f():\n    return 1\n"
BRANCH_PKG = BASE_PKG + "\n\ndef g():\n    return 2\n"
BASE_TESTS = "import pkg\n\n\ndef test_f():\n    assert pkg.f() == 1\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, encoding="utf-8",
                          check=True).stdout


def _write(repo: Path, rel: str, text: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def _repo(tmp_path: Path) -> Path:
    """A repository whose main, also origin/main, has pkg.f and a test of it, and whose checked-out branch `change` adds
    pkg.g in a commit; the tests of g are for each test to write."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _write(repo, "pyproject.toml", PYPROJECT)
    _write(repo, "src/pkg/__init__.py", BASE_PKG)
    _write(repo, "tests/test_pkg.py", BASE_TESTS)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _git(repo, "switch", "-q", "-c", "change")
    _write(repo, "src/pkg/__init__.py", BRANCH_PKG)
    _git(repo, "commit", "-q", "-am", "g")
    return repo


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """The script run in `repo`, its HOME a directory that is not empty, so that a run on the base with the caller's
    HOME would show."""
    home = repo.parent / "home"
    _write(home, ".gitconfig", "")
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=repo, capture_output=True, encoding="utf-8",
                          env={**os.environ, "HOME": str(home)})


def test_a_test_of_what_the_base_lacks_is_red_with_its_failure_and_one_that_passes_on_both_is_green(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, "tests/test_pkg.py", BASE_TESTS + "\n\ndef test_g():\n    assert pkg.g() == 2\n")
    run = _run(repo, "tests/test_pkg.py")
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "GREEN      tests/test_pkg.py::test_f",
        "RED        tests/test_pkg.py::test_g",
        "    >       assert pkg.g() == 2",
        "    E       AttributeError: module 'pkg' has no attribute 'g'",
        "1 red, 1 green, 0 skipped, 0 unreached",
    ]


def test_a_test_of_a_module_the_base_lacks_is_unreached_with_its_import_error_and_counted_neither_red_nor_green(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, "src/pkg/newmod.py", "def h():\n    return 3\n")
    _write(repo, "tests/test_newmod.py", "from pkg.newmod import h\n\n\ndef test_h():\n    assert h() == 3\n")
    run = _run(repo, "tests/test_pkg.py", "tests/test_newmod.py")
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "UNREACHED  tests/test_newmod.py",
        "    E   ModuleNotFoundError: No module named 'pkg.newmod'",
        "    shown sensitive by its mutations instead (pr-flow step 2)",
        "GREEN      tests/test_pkg.py::test_f",
        "0 red, 1 green, 0 skipped, 1 unreached",
    ]


# what pytest 9 wrote for tests/test_a.py: a test passed, one raised an ImportError in its body, one failed an assertion
# with a message, one skipped, and a class's parametrized test failed one of its cases
JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests"><testsuite name="pytest" errors="0"
failures="3" skipped="1" tests="6">
<testcase classname="tests.test_a" name="test_ok" time="0.001" />
<testcase classname="tests.test_a" name="test_missing" time="0.001"><failure message="ImportError: cannot import name 'g'"
>def test_missing():
&gt;       from pkg import g
E       ImportError: cannot import name 'g' from 'pkg' (src/pkg/__init__.py)

tests/test_a.py:8: ImportError</failure></testcase>
<testcase classname="tests.test_a" name="test_bad" time="0.001"><failure message="AssertionError: nope&#10;assert 1 == 2"
>def test_bad():
        x = f()
&gt;       assert x == 2, "nope"
E       AssertionError: nope
E       assert 1 == 2

tests/test_a.py:13: AssertionError</failure></testcase>
<testcase classname="tests.test_a" name="test_skip" time="0.000"><skipped type="pytest.skip" message="no tool here"
>tests/test_a.py:15: no tool here</skipped></testcase>
<testcase classname="tests.test_a.TestC" name="test_p[1]" time="0.001" />
<testcase classname="tests.test_a.TestC" name="test_p[2]" time="0.001"><failure message="assert 2 == 1"
>self = &lt;test_a.TestC object&gt;, n = 2

&gt;       assert n == 1
E       assert 2 == 1

tests/test_a.py:22: AssertionError</failure></testcase>
</testsuite></testsuites>"""


def test_each_testcase_is_read_as_its_failure_s_first_arrow_and_error_lines_its_skip_reason_or_an_import_error_unreached():
    found = red_on_base.outcomes(JUNIT, ["tests/test_a.py"])
    assert [tuple(v) for v in found] == [
        ("GREEN", "tests/test_a.py::test_ok", []),
        ("UNREACHED", "tests/test_a.py::test_missing",
         ["E       ImportError: cannot import name 'g' from 'pkg' (src/pkg/__init__.py)", red_on_base.UNREACHED_NOTE]),
        ("RED", "tests/test_a.py::test_bad", ['>       assert x == 2, "nope"', "E       AssertionError: nope"]),
        ("SKIPPED", "tests/test_a.py::test_skip", ["no tool here"]),
        ("GREEN", "tests/test_a.py::TestC::test_p[1]", []),
        ("RED", "tests/test_a.py::TestC::test_p[2]", [">       assert n == 1", "E       assert 2 == 1"]),
    ]


TOOL_TESTS = '''from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.skipif(not (ROOT / ".mara-tools").is_dir(), reason="the tools are not installed")
def test_the_tool():
    assert (ROOT / ".mara-tools" / "bin" / "tool").read_text() == "the tool"


@pytest.mark.skip(reason="not on this platform")
def test_elsewhere():
    pass
'''


def test_a_test_that_needs_the_tools_runs_on_the_base_with_the_checkout_s_and_one_skipped_otherwise_says_why(tmp_path):
    """Git ignores .mara-tools, so the base's worktree has none of its own: the main checkout's is linked in, and left as
    it was."""
    repo = _repo(tmp_path)
    _write(repo, ".mara-tools/bin/tool", "the tool")
    _write(repo, ".git/info/exclude", ".mara-tools\n")
    _write(repo, "tests/test_tools.py", TOOL_TESTS)
    run = _run(repo, "tests/test_tools.py")
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == [
        "GREEN      tests/test_tools.py::test_the_tool",
        "SKIPPED    tests/test_tools.py::test_elsewhere",
        "    not on this platform",
        "0 red, 1 green, 1 skipped, 0 unreached",
    ]
    tools = repo / ".mara-tools"
    assert tools.is_dir() and not tools.is_symlink() and (tools / "bin" / "tool").read_text() == "the tool"


def test_a_helper_only_the_working_tree_has_in_tests_is_used_by_the_run_on_the_base(tmp_path):
    """The whole tests/ of the working tree replaces the base's, so a helper or a conftest comes along without being
    named: the test that imports it is reached, and is green, as pkg.f is the base's."""
    repo = _repo(tmp_path)
    _write(repo, "tests/helpers.py", "def one():\n    return 1\n")
    _write(repo, "tests/test_helped.py", "import pkg\nfrom tests.helpers import one\n\n\ndef test_f_is_one():\n    assert pkg.f() == one()\n")
    run = _run(repo, "tests/test_helped.py")
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == ["GREEN      tests/test_helped.py::test_f_is_one", "0 red, 1 green, 0 skipped, 0 unreached"]


@pytest.mark.parametrize("given", ["tests/test_none.py", "pyproject.toml", "../outside/test_x.py"],
                         ids=["not there", "not under tests", "outside the repository"])
def test_a_test_file_not_under_the_working_tree_s_tests_is_refused_with_exit_2_and_no_worktree_made(tmp_path, given):
    repo = _repo(tmp_path)
    _write(tmp_path, "outside/test_x.py", "def test_x():\n    pass\n")
    run = _run(repo, "tests/test_pkg.py", given)
    assert (run.returncode, run.stdout) == (2, "")
    assert run.stderr == f"ERROR: {given}: no such test file under the working tree's tests/\n"
    assert _git(repo, "worktree", "list").count("\n") == 1


ENVIRONMENT_TESTS = '''import os
from pathlib import Path

import pkg


def test_the_code_is_the_base_s_and_home_is_empty():
    tree = Path.cwd()
    assert Path(pkg.__file__).resolve() == tree / "src" / "pkg" / "__init__.py"
    assert tree.parent.name.startswith("red-on-base-") and tree.parent.parent.name == "scratch"
    assert list(Path(os.environ["HOME"]).iterdir()) == []


def test_not_selected():
    pass
'''


def test_the_base_s_code_is_imported_from_its_worktree_with_an_empty_home_and_k_selects_the_tests(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, "tests/test_environment.py", ENVIRONMENT_TESTS)
    run = _run(repo, "tests/test_environment.py", "-k", "base_s")
    assert run.returncode == 0, run.stderr
    assert run.stdout.splitlines() == ["GREEN      tests/test_environment.py::test_the_code_is_the_base_s_and_home_is_empty",
                                       "0 red, 1 green, 0 skipped, 0 unreached"]


def test_a_base_git_does_not_know_is_refused_with_exit_2(tmp_path):
    repo = _repo(tmp_path)
    run = _run(repo, "tests/test_pkg.py", "--base", "origin/none")
    assert (run.returncode, run.stdout) == (2, "")
    assert run.stderr.startswith("ERROR: git merge-base origin/none HEAD: ")


# what pytest 9 wrote for a test file whose import raises on the base an error other than an import's
NOT_COLLECTED = """<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests"><testsuite name="pytest" errors="1"
failures="0" skipped="0" tests="1"><testcase classname="" name="tests.test_b" time="0.000"><error message="collection failure"
>tests/test_b.py:3: in &lt;module&gt;
    G = pkg.g()
        ^^^^^
E   AttributeError: module 'pkg' has no attribute 'g'</error></testcase></testsuite></testsuites>"""


def test_a_test_file_pytest_could_not_collect_is_unreached_whatever_its_error():
    assert [tuple(v) for v in red_on_base.outcomes(NOT_COLLECTED, ["tests/test_a.py", "tests/test_b.py"])] == [
        ("UNREACHED", "tests/test_b.py", ["E   AttributeError: module 'pkg' has no attribute 'g'", red_on_base.UNREACHED_NOTE]),
    ]

def test_pytest_not_running_the_tests_is_exit_2_with_its_output(tmp_path):
    repo = _repo(tmp_path)
    run = _run(repo, "tests/test_pkg.py", "-k", "(")
    assert (run.returncode, run.stdout) == (2, "")
    assert run.stderr.startswith("ERROR: pytest exited 4 on the base:\n") and "-k" in run.stderr

INTERRUPTING = '''import os
import signal


def test_interrupt_the_run():
    os.kill(os.getppid(), signal.SIGINT)  # pytest's parent: scripts/red_on_base.py
'''


@pytest.mark.parametrize("args, code", [
    (["tests/test_pkg.py"], 0),
    (["tests/test_pkg.py", "-k", "("], 2),  # pytest refuses the expression and writes no report
    (["tests/test_interrupt.py"], 130),
], ids=["a run", "pytest failing", "an interrupt"])
def test_no_worktree_is_left_behind_and_the_checkout_s_tools_are_as_they_were(tmp_path, args, code):
    repo = _repo(tmp_path)
    _write(repo, ".mara-tools/bin/tool", "the tool")
    _write(repo, ".git/info/exclude", ".mara-tools\n")
    _write(repo, "tests/test_interrupt.py", INTERRUPTING)
    run = _run(repo, *args)
    assert run.returncode == code, run.stderr
    assert _git(repo, "worktree", "list").count("\n") == 1
    assert list((repo / "scratch").iterdir()) == []
    tools = repo / ".mara-tools"
    assert tools.is_dir() and not tools.is_symlink() and (tools / "bin" / "tool").read_text() == "the tool"
