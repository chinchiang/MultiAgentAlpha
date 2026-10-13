"""Context fixes from the 2026-10-12 deep review: line numbers count the newlines the tools count,
an incremental review is judged on its increment, and the CLI's evidence inputs stay outside the
review target."""
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mara.context.repo_map as mod
from mara.agents.base import verify_quote
from mara.cli import app
from mara.context.repo_map import build_context, restrict_to_increment, source_lines

ROOT = Path(__file__).resolve().parents[1]


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def commit(root, msg):
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", msg)


# ---------------------------------------------------------------- line numbers


@pytest.mark.parametrize("sep", ["\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ", "\x0b"])
def test_only_newlines_end_a_line(sep):
    """str.splitlines() also breaks on form feeds, separators and NEL, which semgrep, git and every SARIF
    producer count as ordinary characters: the bundle and the quote check numbered lines differently
    from the tools, and tier A corroboration and quotes at a tool's line missed."""
    text = f"x = 1{sep}\nflask\r\nlast"
    assert source_lines(text) == [f"x = 1{sep}", "flask", "last"]
    assert source_lines("a\n") == ["a"] and source_lines("") == []


def test_the_bundle_and_the_quote_check_use_the_tools_line_numbers(tmp_path):
    (tmp_path / "requirements.txt").write_text("x\x0c\nflask\n", encoding="utf-8", newline="")
    ctx = build_context(tmp_path)
    assert "    2| flask" in ctx.bundle()
    assert verify_quote(ctx, "requirements.txt", 2, "flask")


# ---------------------------------------------------------------- increment


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("print('a')\n", encoding="utf-8")
    (root / "b.py").write_text("print('b')\n", encoding="utf-8")
    (root / "big.txt").write_text("x" * (mod.MAX_FILE_BYTES + 10), encoding="utf-8")
    (root / "z.py").write_text("print('z')\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    commit(root, "one")
    (root / "z.py").write_text("print('z2')\n", encoding="utf-8")
    commit(root, "two")
    return root


def test_a_file_outside_the_increment_does_not_make_it_incomplete(repo):
    ctx = build_context(repo)
    assert "big.txt" in ctx.omitted
    restrict_to_increment(ctx, "HEAD~1")
    assert ctx.complete and ctx.omitted == {} and ctx.excluded["big.txt"] == "out_of_increment"
    assert list(ctx.content) == ["z.py"]


def test_a_changed_file_past_the_repository_budget_is_read_for_the_increment(repo, monkeypatch):
    monkeypatch.setattr(mod, "MAX_REPOSITORY_CHARS", 30)  # a.py and b.py fill it; z.py is omitted from the full bundle
    ctx = build_context(repo)
    assert ctx.omitted["z.py"] == "repository_size_limit"
    changed, _ = restrict_to_increment(ctx, "HEAD~1")
    assert changed == ["z.py"] and ctx.content["z.py"].rstrip() == "print('z2')" and ctx.complete


def test_a_changed_file_that_does_not_fit_the_increment_stays_omitted(repo, monkeypatch):
    monkeypatch.setattr(mod, "MAX_REPOSITORY_CHARS", 5)
    ctx = build_context(repo)
    restrict_to_increment(ctx, "HEAD~1")
    assert ctx.omitted.get("z.py") == "repository_size_limit" and not ctx.complete


def test_a_git_failure_survives_the_narrowing(repo, monkeypatch):
    ctx = build_context(repo)
    ctx.omitted["."] = "git_ls_files_failed"
    restrict_to_increment(ctx, "HEAD~1")
    assert ctx.omitted.get(".") == "git_ls_files_failed" and not ctx.complete


# ---------------------------------------------------------------- CLI inputs


@pytest.mark.parametrize("flag", ["--sarif-dir", "--mock-fixtures", "--psirt-event"])
def test_evidence_inputs_inside_the_target_are_refused(tmp_path, flag):
    """Pre-recorded SARIF is tool evidence (tier A) and mock fixtures are the models' answers: from
    inside the reviewed repository, the repository would supply its own verdict."""
    target = tmp_path / "target"
    (target / "evidence").mkdir(parents=True)
    (target / "app.py").write_text("print(1)\n", encoding="utf-8")
    r = CliRunner().invoke(app, ["review", str(target), "--provider", "mock", "--config", str(ROOT / "config" / "mara.mock.yaml"),
                                 flag, str(target / "evidence"), "--out", str(tmp_path / "out")])
    assert r.exit_code != 0 and "inside the review target" in r.output
