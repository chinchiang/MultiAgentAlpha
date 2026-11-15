"""scripts/control_chars.py: what a change adds, its lines in every text file and its commit messages, holds no control
character, run by scripts/check_local.py and by CI on a pull request; the lines already there are not its business."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

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


def test_the_working_tree_mode_reads_the_lines_not_committed_yet_and_no_commit_message(tmp_path, capsys):
    repo = _repo(tmp_path)
    message = tmp_path / "message.txt"
    message.write_text(f"A message{LS}with a separator\n", encoding="utf-8")
    _git(repo, "commit", "-q", "--allow-empty", "-F", str(message))  # the commits are --head's business, not the working tree's
    (repo / "notes.md").write_text(f"ok\nbad{FS}one\n", encoding="utf-8")  # tracked, edited, not committed
    (repo / "new.txt").write_text(f"also{LS}bad\n", encoding="utf-8")  # untracked
    (repo / "nul.bin").write_bytes(bytes([0x1C, 0]))  # untracked, UTF-8 with a NUL: binary, no lines in it
    (repo / "latin1.bin").write_bytes(bytes([0x1C, 0xFF]))  # untracked, no NUL: text to git, and not UTF-8
    assert control_chars.main(["--base", "main", "--worktree", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["notes.md:2: U+001C", "new.txt:1: U+2028", "latin1.bin: not UTF-8",
                                                    "2 control character(s) in what the change adds; 1 file(s) not UTF-8"]


def _late_nul(repo: Path, outside: Path) -> None:
    (repo / "late.txt").write_bytes(FS.encode() + b"a" * 9000 + b"\0\n")  # git looks for a NUL in the first 8000 bytes only


def _attribute_binary(repo: Path, outside: Path) -> None:
    (repo / ".gitattributes").write_text("*.dat binary\n", encoding="utf-8")
    (repo / "x.dat").write_text(f"{FS}x\n", encoding="utf-8")


def _link_to_a_file(repo: Path, outside: Path) -> None:
    (outside / "target.txt").write_text(f"{FS}target\n", encoding="utf-8")  # outside the change: only the link is in it
    (repo / "link").symlink_to(outside / "target.txt")


def _broken_link(repo: Path, outside: Path) -> None:
    (repo / "broken").symlink_to("nowhere")


CLEAN = ["no control character in what the change adds"]


NEEDS_SYMLINKS = pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege on Windows")


@pytest.mark.parametrize(("make", "expected"), [
    pytest.param(_late_nul, ["late.txt:1: U+001C", "late.txt:1: U+0000", "2 control character(s) in what the change adds"],
                 id="a NUL past the first 8000 bytes"),
    pytest.param(_attribute_binary, CLEAN, id="a file .gitattributes marks binary"),
    pytest.param(_link_to_a_file, CLEAN, id="a symlink to a file", marks=NEEDS_SYMLINKS),
    pytest.param(_broken_link, CLEAN, id="a broken symlink", marks=NEEDS_SYMLINKS),
])
def test_an_untracked_file_reads_as_git_diff_reads_it_once_added(tmp_path, capsys, make, expected):
    """The working-tree mode gives for an untracked file what it gives for the same file after `git add -N`, so git's
    rules decide: its binary heuristic, .gitattributes, and a symlink as the text of its link."""
    repo, outside = _repo(tmp_path), tmp_path / "outside"
    outside.mkdir()
    make(repo, outside)
    args = ["--base", "main", "--worktree", "--repo", str(repo)]
    untracked = (control_chars.main(args), capsys.readouterr().out.splitlines())
    _git(repo, "add", "-N", ".")
    added = (control_chars.main(args), capsys.readouterr().out.splitlines())
    assert added == (0 if expected is CLEAN else 1, expected), "git's own reading of the files"
    assert untracked == added


@NEEDS_SYMLINKS
def test_an_untracked_nested_repository_or_link_to_a_directory_has_no_lines(tmp_path, capsys):
    """git status lists both as one untracked entry (sub/, link); what is inside them is not the change's lines."""
    repo, outside = _repo(tmp_path), tmp_path / "outside"
    outside.mkdir()
    (outside / "inner.txt").write_text(f"{FS}inside\n", encoding="utf-8")
    (repo / "link").symlink_to(outside, target_is_directory=True)
    sub = repo / "sub"
    sub.mkdir()
    _git(sub, "init", "-q")
    (sub / "inner.txt").write_text(f"{FS}inside\n", encoding="utf-8")
    (repo / "new.txt").write_text(f"also{LS}bad\n", encoding="utf-8")  # beside them, still read
    assert control_chars.main(["--base", "main", "--worktree", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["new.txt:1: U+2028", "1 control character(s) in what the change adds"]


def _put(repo: Path, mode: str, name: str, data: bytes) -> None:
    """`name` holds `data` in the change: untracked, tracked and edited but not committed, or committed."""
    if mode == "tracked":
        (repo / name).write_bytes(b"placeholder\n")
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "add a file")
    (repo / name).write_bytes(data)
    if mode == "committed":
        _git(repo, "add", name)
        _git(repo, "commit", "-q", "-m", "change a file")


MODES = {"untracked": ["--worktree"], "tracked": ["--worktree"], "committed": []}


@pytest.mark.parametrize("mode", MODES)
def test_a_text_file_that_is_not_utf8_is_a_finding_and_the_rest_is_still_read(tmp_path, capsys, mode):
    """No text file this repository tracks is in another encoding, so one that a change adds is a finding, in every mode;
    it is named once, the rest of its lines skipped, and every other file of the change is still checked."""
    repo = _repo(tmp_path)
    _put(repo, mode, "latin.txt", "café\n".encode("latin-1"))
    _put(repo, mode, "other.txt", f"also{LS}bad\n".encode())
    assert control_chars.main(["--base", "main", *MODES[mode], "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["other.txt:1: U+2028", "latin.txt: not UTF-8",
                                                    "1 control character(s) in what the change adds; 1 file(s) not UTF-8"]


def test_a_file_that_is_not_utf8_alone_fails_the_check(tmp_path, capsys):
    repo = _repo(tmp_path)
    _put(repo, "committed", "latin.txt", "café\n".encode("latin-1"))
    assert control_chars.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["latin.txt: not UTF-8", "1 file(s) not UTF-8"]


@pytest.mark.skipif(sys.platform == "win32", reason="a file name cannot hold a tab on Windows")
@pytest.mark.parametrize("mode", MODES)
def test_a_path_git_pads_or_quotes_is_named_as_it_is(tmp_path, capsys, mode):
    """git ends a +++ line with a tab when the path holds a space, and quotes the path, C-style, when it holds a tab, a
    quote, a backslash or a newline; either way the path is printed as the file is named."""
    repo = _repo(tmp_path)
    _put(repo, mode, "my file.txt", f"{FS}x\n".encode())
    _put(repo, mode, "tab\tname.txt", f"{FS}y\n".encode())
    assert control_chars.main(["--base", "main", *MODES[mode], "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["my file.txt:1: U+001C", "tab\tname.txt:1: U+001C",
                                                    "2 control character(s) in what the change adds"]


def test_only_the_lines_a_change_adds_must_be_utf8(tmp_path, capsys):
    """A file already in another encoding is the base's business: deleting it, or rewriting it as UTF-8, is no finding."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "main")
    (repo / "old.txt").write_bytes("café\n".encode("latin-1"))
    (repo / "gone.txt").write_bytes("adieu\n".encode("latin-1") + "à\n".encode("latin-1"))
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "latin-1 files")
    _git(repo, "switch", "-q", "change")
    _git(repo, "merge", "-q", "--ff-only", "main")
    (repo / "old.txt").write_text(f"café{FS}\n", encoding="utf-8")
    _git(repo, "rm", "-q", "gone.txt")
    _git(repo, "commit", "-q", "-am", "old.txt as UTF-8, gone.txt deleted")
    assert control_chars.main(["--base", "main", "--repo", str(repo)]) == 1
    assert capsys.readouterr().out.splitlines() == ["old.txt:1: U+001C", "1 control character(s) in what the change adds"]


def test_the_working_tree_mode_leaves_the_index_and_the_status_as_they_were(tmp_path, capsys):
    """It reads the working tree and never stages what it reads, not even for a moment: a commit made at the same time
    must not take an untracked file in."""
    repo = _repo(tmp_path)
    (repo / "notes.md").write_text(f"ok\nbad{FS}one\n", encoding="utf-8")  # tracked, edited
    (repo / "new.txt").write_text(f"also{LS}bad\n", encoding="utf-8")  # untracked
    (repo / "latin.txt").write_bytes("café\n".encode("latin-1"))  # untracked, not UTF-8
    status = _git(repo, "status", "--porcelain", "--untracked-files=all")  # status may refresh the index: before reading it
    index = (repo / ".git" / "index").read_bytes()
    assert control_chars.main(["--base", "main", "--worktree", "--repo", str(repo)]) == 1
    assert (repo / ".git" / "index").read_bytes() == index
    assert _git(repo, "status", "--porcelain", "--untracked-files=all") == status
    assert status.splitlines() == [" M notes.md", "?? latin.txt", "?? new.txt"]


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


def test_it_runs_as_check_local_and_ci_run_it_from_any_directory(tmp_path):
    """As a script, `python3 scripts/control_chars.py`, from a directory that is not the checkout: the modules it
    imports from beside it are found there, not on the caller's path."""
    repo = _repo(tmp_path)
    (repo / "notes.md").write_text(f"ok\nbad{FS}one\n", encoding="utf-8")
    _git(repo, "commit", "-q", "-am", "notes")
    run = subprocess.run([sys.executable, str(ROOT / "scripts" / "control_chars.py"), "--base", "main", "--repo", str(repo)],
                         cwd=tmp_path, capture_output=True, encoding="utf-8")
    assert (run.returncode, run.stdout.splitlines()) == (1, ["notes.md:2: U+001C", "1 control character(s) in what the change adds"]), \
        run.stderr


def test_check_local_and_ci_run_it_on_what_a_pull_request_adds():
    argv, _, _ = check_local.CHECKS["chars"](type("A", (), {"base": "origin/main"})())
    assert argv[1:] == [str(ROOT / "scripts" / "control_chars.py"), "--base", "origin/main"]
    assert "chars" in check_local.COMMIT_CHECKS, "it reads the branch's commits, so an uncommitted change is warned of"
    step = WORKFLOW[WORKFLOW.index("- name: Control characters"):]
    step = step[:step.index("\n      - name:")]
    assert "if: github.event_name == 'pull_request'" in step and "BASE_SHA: ${{ github.event.pull_request.base.sha }}" in step
    assert 'run: python3 scripts/control_chars.py --base "$BASE_SHA"' in step
