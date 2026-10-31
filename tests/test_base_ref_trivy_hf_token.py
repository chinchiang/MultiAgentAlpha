"""Regression tests: `--base` cannot inject git options, a review runs trivy only against a database that
passes the same check as `scripts/trivy_db.py status`, and HF_TOKEN goes to huggingface.co only."""

from __future__ import annotations

import datetime as dt
import json
import os
import subprocess
import urllib.request
from pathlib import Path

import pytest

from mara import mlbom
from mara.context.repo_map import git_changed_files
from mara.tools import runner
from mara.tools import trivy_db as tdb
from tests import tool_installs

ROOT = Path(__file__).resolve().parents[1]
EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}]})


# ------------------------------------------------------------------ --base option injection

def _git(repo: Path, *args: str) -> None:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    (r / "a.py").write_text("a = 1\n")
    _git(r, "add", "a.py")
    _git(r, "commit", "-q", "-m", "one")
    (r / "b.py").write_text("b = 1\n")
    _git(r, "add", "b.py")
    _git(r, "commit", "-q", "-m", "two")
    return r


@pytest.mark.parametrize("base", ["--output={out}", "-O{out}", "HEAD~1 --output={out}", "HEAD~1\n--output={out}", ""])
def test_base_ref_that_looks_like_an_option_is_refused_and_writes_nothing(repo, tmp_path, base):
    out = tmp_path / "pwned"
    with pytest.raises(ValueError, match="base ref"):
        git_changed_files(repo, base.format(out=out))
    assert not list(tmp_path.glob("pwned*")), "git must never be handed the value as an option"


def test_a_real_base_ref_still_lists_the_changed_files(repo):
    assert git_changed_files(repo, "HEAD~1") == ["b.py"]


def test_the_range_is_passed_after_end_of_options(repo, monkeypatch):
    calls = []
    real = subprocess.run
    monkeypatch.setattr(subprocess, "run", lambda cmd, *a, **kw: (calls.append(cmd), real(cmd, *a, **kw))[1])
    git_changed_files(repo, "HEAD~1")
    diff = next(c for c in calls if "diff" in c)
    assert diff[diff.index("--end-of-options") + 1] == "HEAD~1...HEAD"


def test_cli_refuses_an_option_shaped_base_as_a_usage_error(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from mara.cli import app

    monkeypatch.chdir(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("unsafe()")
    res = CliRunner().invoke(app, ["review", str(target), "--provider", "mock", "--config", str(ROOT / "config" / "mara.mock.yaml"),
                                   f"--base=--output={tmp_path / 'pwned'}"])
    assert res.exit_code == 2 and not list(tmp_path.glob("pwned*")) and not (tmp_path / "out" / "report.json").exists()


# ------------------------------------------------------------------ trivy database checked at review time

def _iso(hours_ago: float) -> str:
    return (dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _install_db(cache: Path, *, updated: str, recorded: str | None = None, tamper: bool = False) -> None:
    (cache / "db").mkdir(parents=True)
    tdb.db_path(cache).write_bytes(b"fake-db-bytes")
    tdb.metadata_path(cache).write_text(json.dumps({"Version": 2, "UpdatedAt": updated}))
    rec = {"repository": "mirror.gcr.io/aquasec/trivy-db:2", "metadata": {"Version": 2, "UpdatedAt": recorded or updated},
           "trivy_db_sha256": tdb.sha256_file(tdb.db_path(cache))}
    tdb.record_path(cache).write_text(json.dumps(rec))
    if tamper:
        tdb.db_path(cache).write_bytes(b"replaced")


@pytest.fixture
def trivy_env(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, timeout=600, env=None):
        calls.append(cmd)
        if "--output" in cmd:
            Path(cmd[cmd.index("--output") + 1]).write_text(EMPTY_SARIF, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setenv("MARA_HOME", str(tmp_path / "ws"))
    tool_installs.lock_into(tmp_path / "ws")
    tool_installs.manifest(tmp_path / "tools", "trivy")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(runner, "tool_path", lambda tool: tmp_path / "bin" / tool)
    monkeypatch.setattr(runner, "_run", fake_run)
    target = tmp_path / "target"
    target.mkdir()

    def run():
        (trivy,) = runner.run_all(target, tmp_path / "out", enabled=["trivy"])
        return trivy, calls

    return tmp_path / "cache", tmp_path / "ws", run


def test_review_runs_trivy_against_a_database_that_passes_the_check(trivy_env):
    cache, _, run = trivy_env
    _install_db(cache, updated=_iso(2))
    trivy, calls = run()
    assert trivy.ran and len(calls) == 1


@pytest.mark.parametrize("case, expect", [
    ("tampered", "does not match the record"),
    ("stale", "older than"),
    ("edited_metadata", "does not match the record's"),
    ("future", "in the future"),
    ("no_record", "missing"),
])
def test_review_refuses_a_database_status_would_refuse(trivy_env, case, expect):
    cache, _, run = trivy_env
    if case == "tampered":
        _install_db(cache, updated=_iso(2), tamper=True)
    elif case == "stale":
        _install_db(cache, updated=_iso(24 * 30))
    elif case == "edited_metadata":  # a month-old database whose metadata.json was rewritten to look fresh
        _install_db(cache, updated=_iso(1), recorded=_iso(24 * 30))
    elif case == "future":
        _install_db(cache, updated=_iso(-48))
    else:
        _install_db(cache, updated=_iso(2))
        tdb.record_path(cache).unlink()
    trivy, calls = run()
    assert not trivy.ran and "offline database not usable" in trivy.note and expect in trivy.note
    assert calls == [], "trivy is not run against a database that failed the check"


def test_review_uses_the_workspace_freshness_bound(trivy_env):
    cache, ws, run = trivy_env
    _install_db(cache, updated=_iso(5))
    assert tdb.max_age_hours() == tdb.DEFAULT_MAX_AGE_HOURS
    (ws / "tools" / "trivy-db.yaml").write_text("max_age_hours: 3\n")
    assert tdb.max_age_hours() == 3.0
    trivy, _ = run()
    assert not trivy.ran and "older than the 3 h limit" in trivy.note


def test_the_shipped_freshness_bound_is_read(monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(ROOT))
    import yaml

    assert tdb.max_age_hours() == float(yaml.safe_load((ROOT / "tools" / "trivy-db.yaml").read_text())["max_age_hours"])


# ------------------------------------------------------------------ HF_TOKEN only to huggingface.co

class _Opener:
    def __init__(self):
        self.requests = []

    def open(self, req, timeout=60):
        self.requests.append(req)

        class _Resp:
            headers = {}

            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return _Resp()


def _auth(req) -> tuple[str | None, str | None]:
    return req.headers.get("Authorization"), req.unredirected_hdrs.get("Authorization")


def test_token_is_sent_to_huggingface_only_and_never_as_a_redirected_header(monkeypatch):
    monkeypatch.setenv(mlbom.HF_TOKEN_ENV, "hf_secret")
    opener = _Opener()
    monkeypatch.setattr(urllib.request, "build_opener", lambda *handlers: opener)
    mlbom._http_fetch("https://huggingface.co/api/models/org/name/revision/main")
    mlbom._http_fetch("https://cdn-lfs.example.invalid/blob")
    mlbom._http_fetch("http://huggingface.co/api/models/org/name")
    hf, cdn, plain = (_auth(r) for r in opener.requests)
    assert hf == (None, "Bearer hf_secret"), "unredirected: urllib does not copy it onto a redirected request"
    assert cdn == (None, None) and plain == (None, None)


def test_a_redirect_keeps_the_token_only_while_it_stays_on_huggingface():
    handler = mlbom._HfOnlyAuthRedirect()
    req = urllib.request.Request("https://huggingface.co/org/name/resolve/abc/model.safetensors")
    req.add_unredirected_header("Authorization", "Bearer hf_secret")
    away = handler.redirect_request(req, None, 302, "Found", {}, "https://cas-bridge.xethub.example.invalid/x?sig=1")
    assert _auth(away) == (None, None)
    home = handler.redirect_request(req, None, 302, "Found", {}, "https://huggingface.co/new-org/name/resolve/abc/model.safetensors")
    assert _auth(home) == (None, "Bearer hf_secret")


def test_pagination_link_off_huggingface_is_refused():
    ok = {"link": '<https://huggingface.co/api/models/o/n/tree/abc?cursor=2>; rel="next"'}
    assert mlbom._next_link(ok) == "https://huggingface.co/api/models/o/n/tree/abc?cursor=2"
    with pytest.raises(ValueError, match="leaves https://huggingface.co"):
        mlbom._next_link({"link": '<https://evil.example.invalid/collect>; rel="next"'})
    assert mlbom._next_link({}) is None
