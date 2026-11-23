"""An environment job of the workbench can be stopped, and stops by itself (mara.web.jobs; docs/adr/0006-local-web-workbench.md,
amended 2026-11-22): a tool install or a database download that stalled ran for good, and while it ran admission
refused every review. Real `python -c` children stand in for the scripts."""

import http.client
import json
import os
import signal
import sys
import time

import pytest

from mara.web import jobs as jobs_mod
from mara.web import procs
from mara.web.admission import LaunchError
from mara.web.jobs import JobRegistry, JobRequest
from mara.web.server import make_server

SLEEP = "import time; time.sleep(120)"
posix = pytest.mark.skipif(sys.platform == "win32", reason="a stopped child's exit code is the signal's only on POSIX")


def _until(condition, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not condition():
        time.sleep(0.05)
    return condition()


@pytest.fixture
def registry(tmp_path):
    """A job registry whose jobs are `python -c <code>` whatever is asked for, with the processes it started, killed at
    the end; `code` is set on the list it gives."""
    started = []
    code = [SLEEP]

    def start(argv, **kw):
        started.append(procs.spawn([sys.executable, "-c", code[0]], **kw))
        return started[-1]

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "mara.yaml").write_text("{}\n", encoding="utf-8")
    reg = JobRegistry(tmp_path, tmp_path / "out", start=start, table=procs.ChildTable())
    yield reg, started, code
    for proc in started:
        procs.kill(proc)
        proc.wait(timeout=30)


def _job(reg: JobRegistry) -> dict:
    return reg.create(JobRequest(kind="check_config", config="config/mara.yaml"))


@posix
def test_a_running_job_is_stopped_and_recorded_cancelled(registry):
    reg, started, _ = registry
    job = _job(reg)
    assert job["status"] == "running" and reg.children.any_running()
    stopped = reg.cancel(job["id"])
    assert (stopped["status"], stopped["exit_code"]) == ("cancelled", -signal.SIGTERM) and stopped["finished_at"]
    assert started[0].poll() == -signal.SIGTERM and not reg.children.any_running(), "its process ended, and admission is free again"
    assert reg.get(job["id"])["status"] == "cancelled"


def test_a_job_that_is_not_running_cannot_be_cancelled(registry):
    reg, started, code = registry
    code[0] = "pass"
    job = _job(reg)
    assert _until(lambda: reg.get(job["id"])["status"] == "finished")
    for job_id in (job["id"], "20260101-000000-abcdef", "../x"):
        with pytest.raises(LaunchError) as refused:
            reg.cancel(job_id)
        assert (refused.value.code, refused.value.status) == ("job_not_running", 409), job_id
    assert reg.get(job["id"])["status"] == "finished", "a job that ended by itself stays as it ended"


@posix
def test_a_job_that_runs_past_its_timeout_is_stopped_and_recorded_timed_out(registry):
    reg, started, _ = registry
    reg.timeouts["check_config"] = 0.5
    job = _job(reg)
    assert _until(lambda: reg.get(job["id"])["status"] != "running"), "the job was left running past its timeout"
    ended = reg.get(job["id"])
    assert (ended["status"], ended["exit_code"]) == ("timed_out", -signal.SIGTERM)
    assert started[0].poll() == -signal.SIGTERM and not reg.children.any_running()


def test_a_job_that_ends_in_time_is_recorded_by_its_exit_code_and_its_timer_is_dropped(registry):
    reg, started, code = registry
    reg.timeouts["check_config"] = 0.6
    for body, status, exit_code in (("pass", "finished", 0), ("raise SystemExit(3)", "failed", 3)):
        code[0] = body
        job = _job(reg)
        assert _until(lambda job=job: reg.get(job["id"])["status"] != "running")
        ended = reg.get(job["id"])
        assert (ended["status"], ended["exit_code"]) == (status, exit_code)
    assert reg._timers == {}, "no timer is kept for a job that ended"
    time.sleep(0.9)  # past the timeout: a timer left armed would now stop nothing and record nothing
    assert reg._timed_out == set() and reg.get(job["id"])["status"] == "failed"


def test_every_kind_of_job_has_a_timeout():
    from typing import get_args

    assert set(jobs_mod.TIMEOUT_SECONDS) == set(get_args(jobs_mod.JobKind))
    assert all(60 <= seconds <= 3600 for seconds in jobs_mod.TIMEOUT_SECONDS.values())


@posix
def test_the_page_stops_a_job_through_the_server(tmp_path, monkeypatch):
    """POST /api/jobs/<id>/cancel, as the page's stop button sends it."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "mara.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(jobs_mod.procs, "spawn", lambda argv, _spawn=procs.spawn, **kw: _spawn([sys.executable, "-c", SLEEP], **kw))
    httpd = make_server(port=0, root=tmp_path, out_dir=tmp_path / "out")
    import threading

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    def call(method: str, path: str, body: dict | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", httpd.port, timeout=30)
        try:
            conn.request(method, path, body=None if body is None else json.dumps(body).encode(), headers={
                "X-MARA-Token": httpd.token, "Origin": httpd.url.rstrip("/"), "Content-Type": "application/json"})
            res = conn.getresponse()
            return res.status, json.loads(res.read())
        finally:
            conn.close()

    try:
        status, made = call("POST", "/api/jobs", {"kind": "check_config", "config": "config/mara.yaml"})
        assert status == 201 and made["job"]["status"] == "running", made
        job_id = made["job"]["id"]
        status, stopped = call("POST", f"/api/jobs/{job_id}/cancel", {})
        assert status == 200, stopped
        assert stopped["job"]["status"] == "cancelled"
        status, again = call("POST", f"/api/jobs/{job_id}/cancel", {})
        assert (status, again["error"]["code"] if isinstance(again.get("error"), dict) else again.get("error")) == (409, "job_not_running"), again
        assert call("GET", f"/api/jobs/{job_id}")[1]["job"]["status"] == "cancelled"
    finally:
        httpd.close()
        thread.join(timeout=30)
    assert os.path.isdir(tmp_path / "out" / "jobs" / job_id)
