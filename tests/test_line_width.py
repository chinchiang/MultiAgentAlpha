"""scripts/line_width.py: the lines a change adds to Python files are within 150 columns (CODING_STANDARDS.md), run by
scripts/check_local.py and by CI on a pull request; the lines already there are not its business."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

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


def test_a_base_git_does_not_know_is_an_error(tmp_path, capsys):
    assert line_width.main(["--base", "nowhere", "--repo", str(_repo(tmp_path))]) == 2
    assert "nowhere" in capsys.readouterr().err


def test_check_local_and_ci_run_it_on_a_pull_requests_lines():
    argv, _, _ = check_local.CHECKS["lines"](type("A", (), {"base": "origin/main"})())
    assert argv[1:] == [str(ROOT / "scripts" / "line_width.py"), "--base", "origin/main"]
    step = WORKFLOW[WORKFLOW.index("- name: Line width"):]
    step = step[:step.index("\n      - name:")]
    assert "if: github.event_name == 'pull_request'" in step and "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in step
    assert 'run: python3 scripts/line_width.py --base "$BASE_SHA"' in step
