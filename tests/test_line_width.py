"""scripts/line_width.py: the lines a change adds to Python files, and to the Markdown files it lists, are within 150
columns (CODING_STANDARDS.md), run by scripts/check_local.py and by CI on a pull request; the lines already there
are not its business."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.locale_env import not_utf8_env

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_local  # noqa: E402
import line_width  # noqa: E402

WORKFLOW = (ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8")
WIDE = "x = '" + "w" * 150 + "'\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def _repo(tmp_path: Path) -> Path:
    """A main with one wide line already there, and a branch that adds lines on top of it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "old.py").write_text("a = 1\n" + WIDE, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "switch", "-q", "-c", "change")
    return repo


def test_only_the_wide_lines_a_change_adds_to_python_files_are_reported(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "old.py").write_text("a = 1\n" + WIDE + "b = 2\n" + WIDE, encoding="utf-8")
    (repo / "new.py").write_text("c = 3\n" + "y = 1  # " + "e" * 141 + "\n" + WIDE, encoding="utf-8")  # 150 columns, then 156
    (repo / "notes.md").write_text(WIDE, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["new.py:3: 156 columns", "old.py:4: 156 columns",
                                                    "2 added line(s) wider than 150 columns"]


def test_the_working_tree_mode_reads_what_is_not_committed_yet_tracked_or_untracked(tmp_path, capsys):
    # before the first commit: a wide line in a tracked file edited and in a new file git does not know of yet
    repo = _repo(tmp_path)
    (repo / "old.py").write_text("a = 1\n" + WIDE + "b = 2\n" + WIDE, encoding="utf-8")
    (repo / "new.py").write_text("c = 3\n" + WIDE, encoding="utf-8")
    (repo / "notes.md").write_text(WIDE, encoding="utf-8")  # untracked, not Python
    (repo / ".git" / "info" / "exclude").write_text("ignored.py\n", encoding="utf-8")
    (repo / "ignored.py").write_text(WIDE, encoding="utf-8")  # untracked, and git ignores it
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 0, "the commits add nothing yet"
    capsys.readouterr()
    assert line_width.main(["--base", "main", "--worktree", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["new.py:2: 156 columns", "old.py:4: 156 columns",
                                                    "2 added line(s) wider than 150 columns"]


def _put(repo: Path, mode: str, name: str, data: bytes) -> None:
    """`name` holds `data` in the change: untracked, tracked and edited but not committed, or committed."""
    if mode == "tracked":
        (repo / name).write_bytes(b"placeholder = 1\n")
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", f"add {name}")
    (repo / name).write_bytes(data)
    if mode == "committed":
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", f"change {name}")


MODES = {"untracked": ["--worktree"], "tracked": ["--worktree"], "committed": []}


@pytest.mark.parametrize("mode", MODES)
def test_a_python_file_that_is_not_utf8_is_a_finding_and_the_rest_is_still_read(tmp_path, capsys, mode):
    repo = _repo(tmp_path)
    _put(repo, mode, "latin.py", "x = 'café'\n".encode("latin-1"))
    _put(repo, mode, "other.py", WIDE.encode())
    assert line_width.main(["--base", "main", *MODES[mode], "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["other.py:1: 156 columns", "latin.py: not UTF-8",
                                                    "1 added line(s) wider than 150 columns; 1 file(s) not UTF-8"]


def test_a_python_file_that_is_not_utf8_alone_fails_the_check(tmp_path, capsys):
    repo = _repo(tmp_path)
    _put(repo, "committed", "latin.py", "x = 'café'\n".encode("latin-1"))
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["latin.py: not UTF-8", "1 file(s) not UTF-8"]


LISTED_MARKDOWN = ["AGENTS.md", "CODING_STANDARDS.md", "docs/agents/flow.md", "tests/SEAMS.md"]  # one per entry of the list
PROSE = "w" * 151 + "\n"  # 151 columns
TABLE = "| " + "t" * 148 + " |\n" + "  | " + "t" * 146 + " |\n"  # two table rows of 152 columns, the second indented


@pytest.mark.parametrize("mode", MODES)
def test_the_wide_lines_a_change_adds_to_the_listed_markdown_files_are_reported_but_not_their_table_rows(tmp_path, capsys, mode):
    """The Markdown files the script lists are checked as a Python file is; a table row, which cannot be wrapped, is left
    out, and so is every Markdown file the list does not name. A Python line that begins with `|` is no table row."""
    repo = _repo(tmp_path)
    for name in [*LISTED_MARKDOWN, "GLOSSARY.md", "docs/report.md"]:
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        _put(repo, mode, name, ("Prose.\n" + PROSE + TABLE).encode())
    _put(repo, mode, "flags.py", ("x = (1\n    | " + "2" * 146 + ")\n").encode())  # 153 columns
    assert line_width.main(["--base", "main", *MODES[mode], "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["AGENTS.md:2: 151 columns", "CODING_STANDARDS.md:2: 151 columns",
                                                    "docs/agents/flow.md:2: 151 columns", "flags.py:2: 153 columns",
                                                    "tests/SEAMS.md:2: 151 columns", "5 added line(s) wider than 150 columns"]


def test_a_change_that_adds_wide_lines_only_to_table_rows_and_to_unlisted_markdown_passes(tmp_path, capsys):
    repo = _repo(tmp_path)
    for name, text in (("AGENTS.md", "Prose.\n" + TABLE), ("GLOSSARY.md", PROSE), ("docs/report.md", PROSE)):
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        _put(repo, "committed", name, text.encode())
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 0
    assert capsys.readouterr().out.splitlines() == ["no added line is wider than 150 columns"]


def test_a_wide_line_after_an_added_line_starting_with_plus_plus_is_reported(tmp_path, capsys):
    """"++ x" is written "+++ x", which reads like a header; the 166-column line after it is still wide.py's third."""
    repo = _repo(tmp_path)
    _put(repo, "committed", "wide.py", ("a = 1\n++ x\nb = '" + "w" * 160 + "'\n").encode())
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["wide.py:3: 166 columns", "1 added line(s) wider than 150 columns"]


def test_a_change_that_adds_no_wide_line_passes_even_beside_old_ones(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "old.py").write_text("a = 2\n" + WIDE, encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "change")
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 0
    assert "no added line is wider than 150 columns" in capsys.readouterr().out


def test_the_change_is_read_from_the_merge_base_so_a_base_that_moved_on_adds_nothing(tmp_path, capsys):
    """Compared with main itself, the wide line main rewrote after the branch left would read as one the branch adds."""
    repo = _repo(tmp_path)
    (repo / "new.py").write_text("c = 3\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    _git(repo, "switch", "-q", "main")
    (repo / "old.py").write_text("a = 1\nx = 'short'\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "main moves on")
    _git(repo, "switch", "-q", "change")
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 0, capsys.readouterr().out


def _run_in_a_locale_that_is_not_utf8(repo: Path) -> subprocess.CompletedProcess:
    """The script as check_local and CI run it, in a child whose locale encoding is not UTF-8 (tests/locale_env.py)."""
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "line_width.py"), "--base", "main", "--repo", str(repo)],
                          env=not_utf8_env(), capture_output=True, encoding="utf-8")


def test_a_change_with_text_beyond_ascii_is_read_as_utf8_whatever_the_locale(tmp_path):
    """git writes the diff in UTF-8, whatever the locale's encoding (cp950 on a Windows host, ASCII here): an added line
    is read as UTF-8, so text beyond ASCII is neither a finding nor misread."""
    repo = _repo(tmp_path)
    (repo / "new.py").write_text("s = '" + "中" * 144 + "'\n" + "s = '" + "中" * 145 + "'\n", encoding="utf-8")  # 150, then 151
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    run = _run_in_a_locale_that_is_not_utf8(repo)
    assert (run.returncode, run.stdout.splitlines()) == (1, ["new.py:2: 151 columns", "1 added line(s) wider than 150 columns"]), run.stderr


def test_a_python_file_whose_name_is_beyond_ascii_is_checked_too(tmp_path):
    """With core.quotepath on (git's default) the diff names such a file `+++ "b/\\344\\270\\255.py"`, which is not
    `+++ b/`, so every line it added was skipped and the check passed."""
    repo = _repo(tmp_path)
    (repo / "中文.py").write_text(WIDE, encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    run = _run_in_a_locale_that_is_not_utf8(repo)
    assert (run.returncode, run.stdout.splitlines()) == (1, ["中文.py:1: 156 columns", "1 added line(s) wider than 150 columns"]), run.stderr


@pytest.mark.parametrize("sep", [0x0C, 0x1C, 0x85, 0x2028, 0x2029], ids=hex)
def test_a_line_is_split_at_newlines_only(tmp_path, capsys, sep):
    """git ends a diff line at a newline only; str.splitlines() also split it at form feed, FS, NEL, LS and PS, so the
    line was measured in pieces (the first a "+" line, the rest not) and a wide one passed."""
    repo = _repo(tmp_path)
    (repo / "new.py").write_text("s = '" + "a" * 70 + chr(sep) + "a" * 76 + "'\nc = 3\n" + WIDE, encoding="utf-8")  # 153 columns
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "change")
    assert line_width.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["new.py:1: 153 columns", "new.py:3: 156 columns",
                                                    "2 added line(s) wider than 150 columns"]


def test_a_base_git_does_not_know_is_an_error(tmp_path, capsys):
    assert line_width.main(["--base", "nowhere", "--repo", str(_repo(tmp_path))]) == 2
    assert capsys.readouterr().err.startswith("ERROR: git merge-base nowhere failed for --base nowhere: ")


def test_check_local_and_ci_run_it_on_a_pull_requests_lines():
    argv, _, _ = check_local.CHECKS["lines"](type("A", (), {"base": "origin/main"})())
    assert argv[1:] == [str(ROOT / "scripts" / "line_width.py"), "--base", "origin/main"]
    step = WORKFLOW[WORKFLOW.index("- name: Line width"):]
    step = step[:step.index("\n      - name:")]
    assert "if: github.event_name == 'pull_request'" in step and "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in step
    assert 'run: python3 scripts/line_width.py --base "$BASE_SHA"' in step
