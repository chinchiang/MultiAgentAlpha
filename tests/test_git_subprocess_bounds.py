"""git calls in repo_map: bounded by a timeout (a hung git - a held index lock, a stale
fsmonitor - used to hang the review and the test suite forever) and decoded as UTF-8 (with
text=True the output was decoded in the locale code page: on a cp950 Windows host a
non-ASCII directory name came back garbled, and an incremental review of it saw no changes)."""
import json
import subprocess

import pytest

import mara.context.repo_map as mod
from mara.context.repo_map import build_context, git_changed_files, target_identity


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    sub = root / "服務" / "app"
    sub.mkdir(parents=True)
    (sub / "a.py").write_text("print(1)\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "remote", "add", "origin", "https://github.com/example-org/product.git")
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "one")
    (sub / "b.py").write_text("print(2)\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "two")
    return sub


def test_a_non_ascii_target_directory_keeps_its_changes_and_identity(repo):
    assert git_changed_files(repo, "HEAD~1") == ["b.py"]
    assert json.loads(target_identity(repo))[2] == "服務/app"


def test_every_git_call_is_bounded_and_a_timeout_fails_closed(repo, monkeypatch):
    calls = []

    def hung(cmd, *a, **kw):
        assert kw.get("timeout"), f"git called without a timeout: {cmd}"
        calls.append(cmd)
        raise subprocess.TimeoutExpired(cmd, kw["timeout"])

    monkeypatch.setattr(mod.subprocess, "run", hung)
    ctx = build_context(repo)
    assert calls and not ctx.complete and not ctx.content
    with pytest.raises(ValueError, match="cannot resolve base ref"):
        git_changed_files(repo, "HEAD~1")
