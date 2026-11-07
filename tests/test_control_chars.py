"""scripts/control_chars.py: what a change adds, its lines in every text file and its commit messages, holds no control
character, run by scripts/check_local.py and by CI on a pull request; the lines already there are not its business."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_local  # noqa: E402
import control_chars  # noqa: E402

WORKFLOW = (ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8")

FS, LS = chr(0x1C), chr(0x2028)  # a file separator and a line separator: what a heredoc or a tool input slipped into files


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, encoding="utf-8",
                          check=True).stdout


def _repo(tmp_path: Path) -> Path:
    """A main with one text file, and a branch to change it on."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "notes.md").write_text("ok\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "switch", "-q", "-c", "change")
    return repo


def test_a_control_character_a_change_adds_to_a_text_file_is_named_with_its_line(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "notes.md").write_text(f"ok\nfine\nbad{FS}one\nalso{LS}bad\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "notes")
    assert control_chars.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["notes.md:3: U+001C", "notes.md:4: U+2028",
                                                    "2 control character(s) in what the change adds"]


def test_a_control_character_already_there_is_not_the_changes_business(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "notes.md").write_text(f"ok{FS}\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "an old line")
    _git(repo, "switch", "-q", "main")
    _git(repo, "merge", "-q", "--ff-only", "change")  # main now holds the line, as a repository older than this check might
    _git(repo, "switch", "-q", "-c", "next")
    (repo / "notes.md").write_text(f"ok{FS}\nfine\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "a clean line")
    assert control_chars.main(["--base", "main", "--repo", str(repo)]) == 0
    assert capsys.readouterr().out.splitlines() == ["no control character in what the change adds"]


def test_a_control_character_in_a_commit_message_of_the_change_is_named_with_its_commit(tmp_path, capsys):
    repo = _repo(tmp_path)
    (repo / "notes.md").write_text("ok\nfine\n", encoding="utf-8")
    message = tmp_path / "message.txt"
    message.write_text(f"Notes, one more line\n\nThe body{LS}split by a line separator\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-a", "-F", str(message))
    sha = _git(repo, "rev-parse", "HEAD").strip()
    assert control_chars.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == [f"commit {sha[:12]}, message line 3: U+2028",
                                                    "1 control character(s) in what the change adds"]


def test_check_local_and_ci_run_it_on_what_a_pull_request_adds():
    argv, _, _ = check_local.CHECKS["chars"](type("A", (), {"base": "origin/main"})())
    assert argv[1:] == [str(ROOT / "scripts" / "control_chars.py"), "--base", "origin/main"]
    assert "chars" in check_local.COMMIT_CHECKS, "it reads the branch's commits, so an uncommitted change is warned of"
    step = WORKFLOW[WORKFLOW.index("- name: Control characters"):]
    step = step[:step.index("\n      - name:")]
    assert "if: github.event_name == 'pull_request'" in step and "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in step
    assert 'run: python3 scripts/control_chars.py --base "$BASE_SHA"' in step
