"""The locked gitleaks CLI replaces gitleaks-action: binary only from MARA_TOOLS_DIR (never PATH),
version must match tools/versions.lock, PR range = the PR's own commits, push range = every new
commit, unusable base falls back to the head commit, leaks exit 2 with redacted SARIF."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gitleaks_ci.py"
TOOLS = ROOT / ".mara-tools"
SECRET_LINE = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ7NQ3M2K1\n"

pytestmark = pytest.mark.skipif(not (TOOLS / "bin" / "gitleaks").exists(), reason="locked gitleaks not installed under .mara-tools (run scripts/install_tools.py)")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("clean\n", encoding="utf-8")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-qm", "one")
    (repo / "b.txt").write_text("also clean\n", encoding="utf-8")
    _git(repo, "add", "b.txt")
    _git(repo, "commit", "-qm", "two")
    return repo


def _run(repo: Path, *args: str, tools: Path = TOOLS) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools)}
    return subprocess.run([sys.executable, str(SCRIPT), "--source", str(repo), "--report", str(repo.parent / "out.sarif"), *args],
                          capture_output=True, text=True, env=env)


def test_clean_range_exits_zero_and_reports_version(tmp_path):
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD~1")
    r = _run(repo, "--base", base, "--head", "HEAD", "--event", "pull_request")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "gitleaks 8.30.1" in r.stdout and "lock 8.30.1" in r.stdout and "no leaks found" in r.stdout
    assert "--first-parent" in r.stdout and "the PR's own commits" in r.stdout


def test_leak_in_range_exits_two_with_redacted_sarif(tmp_path):
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "cfg.env").write_text(SECRET_LINE, encoding="utf-8")
    _git(repo, "add", "cfg.env")
    _git(repo, "commit", "-qm", "three")
    r = _run(repo, "--base", base, "--head", "HEAD", "--event", "pull_request")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "LEAKS: 1 finding(s)" in r.stdout and "generic-api-key  cfg.env:1" in r.stdout
    sarif = json.loads((tmp_path / "out.sarif").read_text(encoding="utf-8"))
    res = sarif["runs"][0]["results"]
    assert len(res) == 1 and "wJalrXUtnFEMI" not in json.dumps(sarif), "secret must be redacted"
    assert res[0]["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == "REDACTED"
    # the same leak is outside the range when base is moved past it: the PR scope is what is scanned
    r = _run(repo, "--base", _git(repo, "rev-parse", "HEAD"), "--head", "HEAD", "--event", "pull_request")
    assert r.returncode == 0


def test_unusable_base_falls_back_to_head_commit(tmp_path):
    repo = _repo(tmp_path)
    (repo / "cfg.env").write_text(SECRET_LINE, encoding="utf-8")
    _git(repo, "add", "cfg.env")
    _git(repo, "commit", "-qm", "three")
    r = _run(repo, "--base", "0" * 40, "--head", "HEAD", "--event", "push")
    assert r.returncode == 2 and "all zeros" in r.stdout and "head commit" in r.stdout
    r = _run(repo, "--base", "", "--head", "HEAD~1", "--event", "push")
    assert r.returncode == 0 and "no base given" in r.stdout
    other = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "-b", "side", "HEAD~2")
    (repo / "c.txt").write_text("x\n", encoding="utf-8")
    _git(repo, "add", "c.txt")
    _git(repo, "commit", "-qm", "side")
    r = _run(repo, "--base", other, "--head", "HEAD", "--event", "push")
    assert r.returncode == 0 and "not an ancestor" in r.stdout


def test_push_range_includes_every_new_commit(tmp_path):
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "HEAD~1")
    r = _run(repo, "--base", base, "--head", "HEAD", "--event", "push")
    assert r.returncode == 0 and "every commit in" in r.stdout and "--first-parent" not in r.stdout


def test_binary_only_from_tools_dir_and_version_must_match_lock(tmp_path):
    repo = _repo(tmp_path)
    empty = tmp_path / "no-tools"
    empty.mkdir()
    r = _run(repo, "--base", "", "--head", "HEAD", tools=empty)
    assert r.returncode == 2 and "not installed" in r.stderr and "PATH is never used" in r.stderr
    fake = tmp_path / "tools"
    (fake / "bin").mkdir(parents=True)
    (fake / "bin" / "gitleaks").symlink_to(TOOLS / "bin" / "gitleaks")
    (fake / "manifest.json").write_text(json.dumps({"tools": {"gitleaks": {"version": "8.24.3"}}}), encoding="utf-8")
    r = _run(repo, "--base", "", "--head", "HEAD", tools=fake)
    assert r.returncode == 2 and "does not match tools/versions.lock" in r.stderr
