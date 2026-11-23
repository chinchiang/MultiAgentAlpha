"""git calls in repo_map: bounded by a timeout (a hung git - a held index lock, a stale
fsmonitor - used to hang the review and the test suite forever) and decoded as UTF-8 (with
text=True the output was decoded in the locale code page: on a cp950 Windows host a
non-ASCII directory name came back garbled, and an incremental review of it saw no changes)."""
import json
import subprocess
import sys

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


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in fsmonitor program is a shell script")
def test_a_program_the_targets_git_config_names_is_not_run(repo, tmp_path):
    """core.fsmonitor in the target's .git/config named a program, and the first git call of a review ran it with the
    review's environment. Every git here runs under GIT_SAFE_CONFIG, which outranks the target's config."""
    marker = tmp_path / "ran"
    program = tmp_path / "fsmonitor.sh"
    program.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    program.chmod(0o755)
    git(repo, "config", "core.fsmonitor", str(program))
    ctx = build_context(repo)
    assert sorted(ctx.content) == ["a.py", "b.py"]
    assert git_changed_files(repo, "HEAD~1") == ["b.py"] and target_identity(repo)
    assert not marker.exists(), "the target's fsmonitor program ran"
    # the program does run for a git that is not given the settings: the test would notice
    subprocess.run(["git", "-C", str(repo), "status"], check=True, capture_output=True)
    assert marker.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in upload-pack program is a shell script")
def test_a_transport_program_the_targets_git_config_names_is_not_run(repo, tmp_path):
    """A partial-clone (promisor) target names an upload-pack program in remote.<name>.uploadpack; git ran it with the
    review's environment when an ordinary read faulted in a missing object. GIT_SAFE_CONFIG denies every transport, so
    the lazy fetch does not run the program; the review's metadata-only git calls are unaffected and still see the
    files."""
    root = repo.parents[1]
    marker = tmp_path / "ran"
    program = tmp_path / "uploadpack.sh"
    program.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
    program.chmod(0o755)
    tree = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD^{tree}"],
                          capture_output=True, text=True, check=True).stdout.strip()
    (root / ".git" / "objects" / tree[:2] / tree[2:]).unlink()  # a read must now lazily fetch the tree
    with (root / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f'[remote "pr"]\n\turl = {root}\n\tpromisor = true\n\tpartialclonefilter = blob:none\n'
                 f'\tuploadpack = "{program}"\n[extensions]\n\tpartialClone = pr\n')
    cfg = (root / ".git" / "config").read_text(encoding="utf-8").replace("repositoryformatversion = 0",
                                                                         "repositoryformatversion = 1")
    (root / ".git" / "config").write_text(cfg, encoding="utf-8")

    ctx = build_context(repo)
    assert not marker.exists(), "the target's upload-pack program ran"
    assert sorted(ctx.content) == ["a.py", "b.py"]
    # the program does run for a git that is not given the settings: the test would notice
    subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", "HEAD:./"], capture_output=True)
    assert marker.exists()


def test_a_tool_runs_git_under_the_same_settings():
    """semgrep lists the target's files with git: a tool's environment carries the settings too."""
    from mara.context.repo_map import GIT_SAFE_CONFIG, git_safe_env
    from mara.tools.runner import tool_env

    env = tool_env()
    assert GIT_SAFE_CONFIG["core.fsmonitor"] == "false"
    assert git_safe_env().items() <= env.items() and env["GIT_CONFIG_COUNT"] == str(len(GIT_SAFE_CONFIG))
    keys = {env[f"GIT_CONFIG_KEY_{i}"]: env[f"GIT_CONFIG_VALUE_{i}"] for i in range(len(GIT_SAFE_CONFIG))}
    assert keys == GIT_SAFE_CONFIG


def test_the_settings_are_added_after_those_the_host_already_gives_through_the_environment(repo, monkeypatch):
    """A container that passes safe.directory through GIT_CONFIG_COUNT keeps it: overwritten, git called the checkout
    of dubious ownership and every review of it ended in git_ls_files_failed."""
    from mara.context.repo_map import GIT_SAFE_CONFIG, git_safe_env

    host = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}
    added = git_safe_env(host)
    assert added["GIT_CONFIG_COUNT"] == str(1 + len(GIT_SAFE_CONFIG)) and "GIT_CONFIG_KEY_0" not in added
    assert {added[f"GIT_CONFIG_KEY_{i}"]: added[f"GIT_CONFIG_VALUE_{i}"] for i in range(1, 1 + len(GIT_SAFE_CONFIG))} == GIT_SAFE_CONFIG
    assert git_safe_env({"GIT_CONFIG_COUNT": "many"})["GIT_CONFIG_COUNT"] == str(len(GIT_SAFE_CONFIG))
    # and git reads both: the host's setting and ours
    for k, v in host.items():
        monkeypatch.setenv(k, v)
    seen = mod._git(repo, "config", "--get-all", "safe.directory")
    assert seen is not None and "*" in seen.splitlines()
    assert mod._git(repo, "config", "--get", "core.fsmonitor") == "false"

