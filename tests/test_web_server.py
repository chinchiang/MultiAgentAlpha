"""The workbench server end to end (mara.web, docs/adr/0006-local-web-workbench.md): a real server on a loopback port,
a real `mara review` subprocess on the seeded fixture in mock mode, and the checks that keep other pages and other
hosts out: the token header (no cookie, which every service on 127.0.0.1 would receive), the Host header, Origin and
Sec-Fetch-Site."""

import http.client
import json
import os
import re
import socket
import sys
import threading
import time
from collections import Counter
from pathlib import Path

import pytest

from mara import progress as prog
from mara.schemas import ReviewReport
from mara.web import procs, runs
from mara.web.server import make_server
from tests.held_children import LostExit, UnrecordedExit

ROOT = Path(__file__).resolve().parents[1]
SENTINEL = "sk-workbench-sentinel-0123456789"  # a credential value that must never reach a response


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    old = {k: os.environ.get(k) for k in ("MARA_HOME", "GEMINI_API_KEY")}
    os.environ["MARA_HOME"] = str(ROOT)
    os.environ["GEMINI_API_KEY"] = SENTINEL
    httpd = make_server(port=0, workspace=ROOT, out_dir=tmp_path_factory.mktemp("workbench-out"))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.close()
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class Client:
    def __init__(self, httpd, *, token=True):
        self.httpd = httpd
        self.token = token

    def request(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.port, timeout=30)
        h = {"Host": f"127.0.0.1:{self.httpd.port}"}
        if self.token:
            h["X-MARA-Token"] = self.httpd.token
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        res = conn.getresponse()
        payload = res.read()
        conn.close()
        try:
            parsed = json.loads(payload) if payload else None
        except ValueError:
            parsed = None
        return res, parsed, payload


def _error(parsed):
    return (parsed or {}).get("error", {}).get("code")


def _wait(client, run_id, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _, data, _ = client.request("GET", f"/api/runs/{run_id}")
        if data["run"]["status"] != "running":
            return data
        time.sleep(0.3)
    raise AssertionError(f"run {run_id} still running after {timeout}s")


# ------------------------------------------------------------------ access


def test_the_page_holds_no_data_and_never_sets_a_cookie(server):
    anon = Client(server, token=False)
    for path in ("/", f"/?token={server.token}"):
        res, _, body = anon.request("GET", path)
        assert res.status == 200 and body.startswith(b"<!DOCTYPE html>") and res.getheader("Set-Cookie") is None
        assert server.token.encode() not in body and str(ROOT).encode() not in body
    assert res.getheader("Content-Security-Policy") == server.csp
    assert res.getheader("X-Content-Type-Options") == "nosniff" and res.getheader("Cache-Control") == "no-store"
    assert res.getheader("Server") == "mara-workbench" and res.getheader("Access-Control-Allow-Origin") is None


def test_the_api_needs_the_token_header_except_health(server):
    anon = Client(server, token=False)
    res, data, _ = anon.request("GET", "/api/health")
    assert res.status == 200 and data["ok"]
    for path in ("/api/runs", "/api/env", "/api/configs", "/api/session"):
        res, data, _ = anon.request("GET", path)
        assert res.status == 401 and _error(data) == "unauthenticated", path
    for headers in ({"X-MARA-Token": "not-the-token"}, {"X-MARA-Token": ""}, {"Cookie": f"mara_session_{server.port}={server.token}"},
                    {"Authorization": f"Bearer {server.token}"}):
        res, data, _ = anon.request("GET", "/api/session", headers=headers)
        assert res.status == 401, headers
    res, data, _ = Client(server).request("GET", "/api/session")
    assert res.status == 200 and data["workspace"] == str(ROOT) and "token" not in json.dumps(data)


@pytest.mark.parametrize("host", ["evil.example", f"evil.example:{0}", "127.0.0.1.nip.io", ""])
def test_a_foreign_host_header_is_refused_even_with_the_token(server, host):
    res, data, _ = Client(server).request("GET", "/api/runs", headers={"Host": host.replace(":0", f":{server.port}")})
    assert res.status == 421 and _error(data) == "bad_host"


def test_localhost_names_the_same_server(server):
    res, _, _ = Client(server).request("GET", "/api/runs", headers={"Host": f"localhost:{server.port}"})
    assert res.status == 200


@pytest.mark.parametrize("headers,code,status", [
    ({"X-MARA-Token": ""}, "unauthenticated", 401),
    ({"Origin": "http://evil.example"}, "cross_origin", 403),
    ({"Origin": "http://127.0.0.1:1"}, "cross_origin", 403),
    ({"Origin": "null"}, "cross_origin", 403),
    ({"Sec-Fetch-Site": "cross-site"}, "cross_origin", 403),
    ({"Sec-Fetch-Site": "same-site"}, "cross_origin", 403),
])
def test_a_change_needs_the_token_and_the_same_origin(server, headers, code, status):
    res, data, _ = Client(server).request("PUT", "/api/settings", body={"language": "en"}, headers=headers)
    assert res.status == status and _error(data) == code


def test_bodies_are_json_objects_of_bounded_size(server):
    c = Client(server)
    res, data, _ = c.request("PUT", "/api/settings", raw=b"language=en", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert res.status == 415 and _error(data) == "json_required"
    res, data, _ = c.request("PUT", "/api/settings", raw=b"[1]", headers={"Content-Type": "application/json"})
    assert res.status == 400 and _error(data) == "bad_json"
    res, data, _ = c.request("PUT", "/api/settings", raw=b"{" * (70 * 1024), headers={"Content-Type": "application/json"})
    assert res.status == 413 and _error(data) == "body_too_large"
    res, data, _ = c.request("PUT", "/api/settings", body={"language": "fr"})
    assert res.status == 400 and _error(data) == "bad_request"


def test_settings_round_trip_even_when_saved_at_once(server):
    c = Client(server)
    res, data, _ = c.request("PUT", "/api/settings", body={"language": "en", "default_provider": "mock", "default_config": ""})
    assert res.status == 200 and c.request("GET", "/api/settings")[1]["language"] == "en"
    statuses = []

    def save(lang):
        statuses.append(Client(server).request("PUT", "/api/settings", body={"language": lang})[0].status)

    threads = [threading.Thread(target=save, args=("en" if i % 2 else "zh-TW",)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert statuses == [200] * 12, "each writer has its own temporary file"
    assert not list(server.out_dir.glob(".web-settings.json.*")), "no temporary file is left behind"


# ------------------------------------------------------------------ launching


@pytest.mark.parametrize("body,code", [
    ({"target": "no/such/dir", "provider": "mock"}, "target_not_dir"),
    ({"target": ".", "provider": "mock"}, "inside_target"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "config": "pyproject.toml"}, "config_not_found"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "config": "../config/mara.mock.yaml"}, "config_not_found"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "config": "config/mara.yaml"}, "provider_mismatch"),
    ({"target": "fixtures/vuln-sample", "provider": "live", "config": "config/mara.mock.yaml"}, "provider_mismatch"),
    ({"target": "fixtures/vuln-sample", "provider": "live", "config": "config/examples/violating.yaml"}, "config_invalid"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "base": "--output=/tmp/pwned"}, "bad_base_ref"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "base": "main; rm -rf /"}, "bad_base_ref"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "sarif_dir": "fixtures/nothing-here"}, "sarif_dir_not_dir"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "argv": ["--notify-psirt"]}, "bad_request"),
    ({"target": "fixtures/vuln-sample", "provider": "local"}, "bad_request"),
    ({"target": "fixtures/vuln\u0000sample", "provider": "mock"}, "bad_path"),
    ({"target": "fixtures/vuln-sample", "provider": "mock", "sarif_dir": "fixtures/\u0000"}, "bad_path"),
])
def test_a_launch_is_refused_as_the_command_line_would_refuse_it(server, body, code):
    before = set(server.runs.runs_dir.glob("*")) if server.runs.runs_dir.exists() else set()
    res, data, _ = Client(server).request("POST", "/api/runs", body=body)
    assert res.status == 400 and _error(data) == code, data
    after = set(server.runs.runs_dir.glob("*")) if server.runs.runs_dir.exists() else set()
    assert after == before, "a refused launch leaves no run behind"


def test_evidence_inputs_must_lie_inside_the_workspace(server, tmp_path):
    res, data, _ = Client(server).request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock",
                                                                      "sarif_dir": str(tmp_path)})
    assert res.status == 400 and _error(data) == "path_outside_workspace"


@pytest.fixture(scope="module")
def mock_run(server):
    c = Client(server)
    res, data, _ = c.request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock", "title": "seeded\x00 fixture\n",
                                                         "sarif_dir": "fixtures/vuln-sample-sarif"})
    assert res.status == 201, data
    run = data["run"]
    assert run["title"] == "seeded fixture" and run["config"] == "config/mara.mock.yaml" and run["status"] == "running"
    assert run["argv"][1:4] == ["-m", "mara.cli", "review"] and "--progress-file" in run["argv"]
    return _wait(c, run["id"])


def test_a_mock_review_launched_through_the_api_finishes_with_every_stage(server, mock_run):
    run = mock_run["run"]
    assert run["status"] == "finished" and run["exit_code"] == 0 and run["has_report"]
    stages = mock_run["progress"]["stages"]
    assert [s["id"] for s in stages] == list(prog.STAGES) and all(s["status"] == "done" for s in stages)
    assert {"report.json", "report.md", "report.sarif", "pipeline.log", "run.log", "progress.json"} <= set(run["artifacts"])
    roles = {g["role"]: g["members"] for g in mock_run["panel"]}
    assert len(roles["reviewers"]) == 3 and all(m["calls"] > 0 for m in roles["reviewers"])
    assert {m["family"] for m in roles["judges"]} == {"anthropic", "deepseek", "nemotron"}


def test_the_report_view_counts_what_the_report_holds(server, mock_run):
    run_id = mock_run["run"]["id"]
    res, view, _ = Client(server).request("GET", f"/api/runs/{run_id}/report")
    assert res.status == 200
    report = ReviewReport.model_validate_json((server.runs.runs_dir / run_id / "report.json").read_bytes())
    finals = Counter(c.final_outcome for c in report.consensus)
    assert {k: view["stats"][k] for k in ("accepted", "rejected", "dropped", "needs_human")} == {
        k: finals.get(k, 0) for k in ("accepted", "rejected", "dropped", "needs_human")}
    assert view["stats"]["findings"] == len(report.findings) == len(view["findings"])
    by_id = {c.finding_id: c for c in report.consensus}
    for f in view["findings"]:
        assert f["consensus"]["jury_outcome"] == by_id[f["id"]].jury_outcome
        assert f["consensus"]["final_outcome"] == by_id[f["id"]].final_outcome
    assert view["known_unknowns"]["incomplete_reasons"] == report.incomplete_reasons and not view["meta"]["gate_passed"]
    assert view["meta"]["review_scope"] == "full" and [d["dimension"] for d in view["dimensions"]] == [d.dimension for d in report.dimensions]
    assert view["budget"]["calls"]["reviewers"] == report.bias_audit["reviewer_calls"]


def test_logs_and_artifacts_of_a_run(server, mock_run):
    c = Client(server)
    run_id = mock_run["run"]["id"]
    _, log, _ = c.request("GET", f"/api/runs/{run_id}/log?tail=50")
    assert any(line.startswith("L2: ") for line in log["progress_log"]) and len(log["progress_log"]) == 50
    assert len(log["pipeline_log"].splitlines()) == 50 and log["pipeline_log"].endswith("L5: PSIRT hand-off disabled")
    assert "MARA" in log["run_log"], "the CLI's own summary table is in run.log"
    res, _, body = c.request("GET", f"/api/runs/{run_id}/files/report.sarif")
    assert res.status == 200 and "attachment" in res.getheader("Content-Disposition") and json.loads(body)["version"] == "2.1.0"
    res, _, _ = Client(server, token=False).request("GET", f"/api/runs/{run_id}/files/report.sarif")
    assert res.status == 401, "downloads need the token like every other call"
    for name in ("run.json", "..%2Frun.json", "..%2F..%2Fpyproject.toml"):
        res, data, _ = c.request("GET", f"/api/runs/{run_id}/files/{name}")
        assert res.status == 404, name
    for bad in ("..%2F..%2Fpyproject.toml", "20261014-000000-zzzzzz", "20261014-000000-abcdef", "20261014-000000-ABCDEF", "workspace-outx"):
        res, data, _ = c.request("GET", f"/api/runs/{bad}")
        assert res.status == 404 and _error(data) == "not_found", bad
        assert server.runs.run_dir(bad) is None, "the run id itself is refused, not just an unknown route"


def test_the_run_list_carries_the_summary(server, mock_run):
    _, data, _ = Client(server).request("GET", "/api/runs")
    listed = next(r for r in data["runs"] if r["id"] == mock_run["run"]["id"])
    assert listed["summary"]["review_status"] == "incomplete" and listed["summary"]["gate_passed"] is False
    assert listed["summary"]["human_queue"] > 0 and listed["title"] == "seeded fixture" and listed["provider"] == "mock"


def test_a_plain_cli_review_in_the_workspace_out_is_listed_read_only(mock_report, tmp_path):
    """`mara review` without --out writes <workspace>/out; the workbench shows that report next to its own runs."""
    _, report = mock_report
    workspace = tmp_path / "ws"
    (workspace / "out").mkdir(parents=True)
    (workspace / "out" / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    reg = runs.RunRegistry(workspace, workspace / "out")
    listed = reg.list()
    assert [r["id"] for r in listed] == [runs.IMPORTED_ID]
    entry = listed[0]
    assert entry["imported"] and entry["status"] == "finished" and entry["target"] == report.target and entry["summary"]["findings"] == len(report.findings)
    assert reg.view(runs.IMPORTED_ID)["stats"]["findings"] == len(report.findings)
    assert reg.artifact(runs.IMPORTED_ID, "report.json") is not None and reg.artifact(runs.IMPORTED_ID, "../ws") is None
    with pytest.raises(runs.LaunchError) as e:
        reg.rerun(runs.IMPORTED_ID)
    assert e.value.code == "not_found"


def _slow_review(real):
    """A child that opens its progress record at the bundle stage and then takes a minute, like a slow live review."""
    def spawn(argv, **kw):
        progress_file = argv[argv.index("--progress-file") + 1] if "--progress-file" in argv else ""
        code = ("import sys, time\nfrom pathlib import Path\nfrom mara.progress import Progress\n"
                "p = Progress(Path(sys.argv[1])) if sys.argv[1] else None\nif p: p.begin('bundle')\ntime.sleep(60)\n")
        return real([sys.executable, "-c", code, progress_file], **kw)
    return spawn


def test_one_review_at_a_time_and_cancel_stops_it(server, monkeypatch):
    real = procs.spawn
    slow = _slow_review(real)

    monkeypatch.setattr(runs.procs, "spawn", slow)
    c = Client(server)
    body = {"target": "fixtures/vuln-sample", "provider": "mock", "sarif_dir": "fixtures/vuln-sample-sarif"}
    res, data, _ = c.request("POST", "/api/runs", body=body)
    assert res.status == 201
    run_id = data["run"]["id"]
    res, busy, _ = c.request("POST", "/api/runs", body=body)
    assert res.status == 409 and _error(busy) == "busy"
    assert busy["error"]["message"] == "a review is already running; wait for it or cancel it"
    res, busy, _ = c.request("POST", "/api/jobs", body={"kind": "install_tools"})
    assert res.status == 409 and _error(busy) == "busy", "the tools a running review executes are never replaced under it"
    assert busy["error"]["message"] == "a review is running with the installed tools; wait for it or cancel it"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and not (prog.read(server.runs.runs_dir / run_id / "progress.json") or {}).get("current"):
        time.sleep(0.1)
    assert prog.read(server.runs.runs_dir / run_id / "progress.json")["current"] == "bundle"
    started = time.monotonic()
    res, data, _ = c.request("POST", f"/api/runs/{run_id}/cancel")
    assert res.status == 200 and data["run"]["status"] == "cancelled" and time.monotonic() - started < 15
    res, again, _ = c.request("POST", f"/api/runs/{run_id}/cancel")
    assert res.status == 409 and _error(again) == "not_running"
    assert not server.runs.busy()
    record = prog.read(server.runs.runs_dir / run_id / "progress.json")
    assert record["status"] == "failed" and record["error"] == "cancelled" and record["current"] is None
    assert [s["status"] for s in record["stages"]][:2] == ["failed", "pending"], "no stage of a killed review is left running"


def test_a_job_replacing_the_tools_holds_reviews_back(server, monkeypatch):
    real = procs.spawn
    from mara.web import jobs as jobs_mod

    monkeypatch.setattr(jobs_mod.procs, "spawn", lambda argv, **kw: real([sys.executable, "-c", "import time; time.sleep(60)"], **kw))
    c = Client(server)
    res, data, _ = c.request("POST", "/api/jobs", body={"kind": "trivy_db_download"})
    assert res.status == 201, data
    try:
        res, busy, _ = c.request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock"})
        assert res.status == 409 and _error(busy) == "busy"
    finally:
        server.jobs.children.stop(data["job"]["id"])  # not table.shutdown(): it would close the module's server
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and server.jobs.children.any_running():
        time.sleep(0.1)
    assert not server.jobs.children.any_running()


@pytest.mark.parametrize("first", ["review", "job"])
def test_a_review_and_a_job_replacing_the_tools_launched_at_once_one_is_refused(tmp_path, monkeypatch, first):
    """The admission and the start are one step under the lock every registry's children share: the second launch, made
    once the first has been admitted, waits for the first to start its child, then sees it running and is refused."""
    from mara.web import admission
    from mara.web import jobs as jobs_mod

    monkeypatch.setenv("MARA_HOME", str(ROOT))
    starting, refusal = threading.Event(), admission.refusal

    def admitted_then_slow(kind, running):
        refused = refusal(kind, running)
        if not starting.is_set():
            starting.set()
            time.sleep(1)  # the second launch is made meanwhile; it is admitted too unless this holds the lock
        return refused

    def sleeping(argv, **kw):
        return procs.spawn([sys.executable, "-c", "import time; time.sleep(60)"], **kw)

    monkeypatch.setattr(admission, "refusal", admitted_then_slow)
    table = procs.ChildTable()  # the two registries' children, as the server shares one between them
    reg = runs.RunRegistry(ROOT, tmp_path / "out", start=sleeping, table=table)
    job_reg = jobs_mod.JobRegistry(ROOT, tmp_path / "out", start=sleeping, table=table)
    create = {"review": lambda: reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock")),
              "job": lambda: job_reg.create(jobs_mod.JobRequest(kind="trivy_db_download"))}
    outcomes: dict[str, str] = {}

    def launch(name):
        try:
            create[name]()
            outcomes[name] = "launched"
        except runs.LaunchError as e:
            outcomes[name] = e.code

    second = "job" if first == "review" else "review"
    threads = [threading.Thread(target=launch, args=(name,), daemon=True) for name in (first, second)]
    try:
        threads[0].start()
        assert starting.wait(30)
        threads[1].start()
        for t in threads:
            t.join(15)
        assert outcomes == {first: "launched", second: "busy"}
    finally:
        reg.children.table.shutdown()  # the job registry's too: they share the table


def test_server_exit_cancels_a_running_run(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(ROOT))
    monkeypatch.setattr(runs.procs, "spawn", _slow_review(procs.spawn))
    reg = runs.RunRegistry(ROOT, tmp_path / "out")
    run = reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))
    assert reg.busy()
    reg.children.table.shutdown()
    assert not reg.busy() and reg.get(run["id"])["status"] == "cancelled"


# a child that touches the file argv[1] names once its SIGTERM handler is set, which takes 2 s to exit
_SLOW_TO_STOP = ("import signal, sys, time\nfrom pathlib import Path\n"
                 "signal.signal(signal.SIGTERM, lambda *_: (time.sleep(2), sys.exit(0)))\nPath(sys.argv[1]).touch()\ntime.sleep(60)\n")


@pytest.mark.parametrize("launched", ["run", "job"])
def test_no_run_or_job_starts_once_the_server_exit_began(tmp_path, monkeypatch, launched):
    """A launch still being handled when the exit took the children (the server does not wait for its request threads):
    refused, nothing written, no child started. The child being stopped is the other registry's, of a kind admission
    lets run beside the launch."""
    from mara.web import jobs as jobs_mod

    monkeypatch.setenv("MARA_HOME", str(ROOT))
    started = []

    def slow_to_stop(argv, **kw):
        started.append(argv)
        return procs.spawn([sys.executable, "-c", _SLOW_TO_STOP, str(tmp_path / "ready")], **kw)

    table = procs.ChildTable()  # the two registries' children, as the server shares one between them
    reg = runs.RunRegistry(ROOT, tmp_path / "out", start=slow_to_stop, table=table)
    job_reg = jobs_mod.JobRegistry(ROOT, tmp_path / "out", start=slow_to_stop, table=table)
    create = {"run": lambda: reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock")),
              "job": lambda: job_reg.create(jobs_mod.JobRequest(kind="trivy_db_status"))}
    create["job" if launched == "run" else "run"]()
    deadline = time.monotonic() + 30
    while not (tmp_path / "ready").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    records = lambda: sorted(p for d in ("runs", "jobs") if (tmp_path / "out" / d).is_dir() for p in (tmp_path / "out" / d).iterdir())  # noqa: E731
    written = records()
    stopper = threading.Thread(target=reg.children.table.shutdown)  # the job registry's too: they share the table
    stopper.start()
    try:
        for when in ("while the children are being stopped", "once the exit stopped them"):
            if when == "once the exit stopped them":
                stopper.join(30)
            else:
                time.sleep(0.5)  # the child got SIGTERM and takes 2 s to exit
            assert stopper.is_alive() == (when == "while the children are being stopped"), when
            with pytest.raises(runs.LaunchError) as refused:
                create[launched]()
            assert (refused.value.code, refused.value.status) == ("stopping", 503), when
            assert records() == written and len(started) == 1, when
    finally:
        stopper.join(30)
        reg.children.table.shutdown()  # a child the launch started when the test fails


def test_closing_a_server_that_never_served_returns(tmp_path):
    """socketserver's shutdown() waits forever for a serve_forever() that never ran: close() asks it of a server that
    serves only."""
    httpd = make_server(port=0, workspace=ROOT, out_dir=tmp_path / "out")
    closer = threading.Thread(target=httpd.close, daemon=True)
    closer.start()
    closer.join(5)
    assert not closer.is_alive()


def test_closing_a_serving_server_stops_serving_and_its_children(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(ROOT))
    monkeypatch.setattr(runs.procs, "spawn", _slow_review(procs.spawn))
    httpd = make_server(port=0, workspace=ROOT, out_dir=tmp_path / "out")
    serving = threading.Thread(target=httpd.serve_forever, daemon=True)
    serving.start()
    run = httpd.runs.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))
    try:
        assert httpd.runs.busy()
        httpd.close()
        serving.join(5)
        assert not serving.is_alive()
        assert httpd.runs.get(run["id"])["status"] == "cancelled"
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", httpd.port), timeout=2).close()
    finally:
        httpd.runs.children.stop(run["id"])  # a child left running when the test fails


def test_closing_a_server_stops_serving_then_its_children_then_closes_its_socket(tmp_path, monkeypatch):
    """Serving stopped first, so that no request is accepted while the children are stopped."""
    httpd = make_server(port=0, workspace=ROOT, out_dir=tmp_path / "out")
    steps = []
    for obj, method, step in ((httpd, "shutdown", "serving"), (httpd.table, "shutdown", "children"),
                              (httpd, "server_close", "socket")):
        real = getattr(obj, method)
        monkeypatch.setattr(obj, method, lambda *a, real=real, step=step, **kw: (steps.append(step), real(*a, **kw))[1])
    serving = threading.Thread(target=httpd.serve_forever, daemon=True)
    serving.start()
    res, _, _ = Client(httpd, token=False).request("GET", "/api/health")  # answered: it serves
    assert res.status == 200
    httpd.close()
    serving.join(5)
    assert steps == ["serving", "children", "socket"]


def test_a_failed_run_is_failed_not_finished(server, monkeypatch):
    """exit 2 is also a usage error: without a finished progress record the run failed"""
    real = procs.spawn
    monkeypatch.setattr(runs.procs, "spawn", lambda argv, **kw: real([sys.executable, "-c", "import sys; sys.exit(2)"], **kw))
    c = Client(server)
    res, data, _ = c.request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock"})
    assert res.status == 201
    done = _wait(c, data["run"]["id"])
    assert done["run"]["status"] == "failed" and done["run"]["exit_code"] == 2 and not done["run"]["gate_enforced"]
    res, err, _ = c.request("GET", f"/api/runs/{data['run']['id']}/report")
    assert res.status == 404 and _error(err) == "no_report"


def _finished_review(real, report_file: Path, exit_code: int):
    """A child that copies `report_file` to its report.json, writes a finished progress record, then exits."""
    def spawn(argv, **kw):
        out, progress_file = argv[argv.index("--out") + 1], argv[argv.index("--progress-file") + 1]
        code = ("import shutil, sys\nfrom pathlib import Path\nfrom mara.progress import Progress\n"
                "shutil.copyfile(sys.argv[3], Path(sys.argv[1], 'report.json'))\nProgress(Path(sys.argv[2])).finish(ok=True)\n"
                "sys.exit(int(sys.argv[4]))\n")
        return real([sys.executable, "-c", code, out, progress_file, str(report_file), str(exit_code)], **kw)
    return spawn


def _exited_run(tmp_path, monkeypatch, child_type):
    """A registry and a run whose review finished and exited 0, its child wrapped in `child_type`."""
    monkeypatch.setenv("MARA_HOME", str(ROOT))
    report_file = tmp_path / "report.json"
    report_file.write_text("{}", encoding="utf-8")
    finished, children = _finished_review(procs.spawn, report_file, 0), []

    def spawn(argv, **kw):
        children.append(child_type(finished(argv, **kw)))
        return children[-1]

    reg = runs.RunRegistry(ROOT, tmp_path / "out", start=spawn)
    run_id = reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))["id"]
    (child,) = children
    assert child.proc.wait(timeout=60) == 0
    return reg, run_id, child


def _until_not_running(reg, run_id, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and reg.get(run_id)["status"] == "running":
        time.sleep(0.1)
    return reg.get(run_id)


def test_no_second_review_starts_while_the_exit_of_the_first_is_not_recorded_yet(tmp_path, monkeypatch):
    """The first run still reads as running, so the registry is still busy with it."""
    reg, run_id, child = _exited_run(tmp_path, monkeypatch, UnrecordedExit)
    try:
        assert reg.busy()
        with pytest.raises(runs.LaunchError) as refused:
            reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))
        assert refused.value.code == "busy"
    finally:
        child.released.set()
    _until_not_running(reg, run_id, 30)
    assert not reg.busy()


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_a_run_whose_waiter_stopped_without_recording_its_exit_is_read_from_its_progress_record(tmp_path, monkeypatch):
    """As for a run of an earlier server, instead of reading as running for good."""
    reg, run_id, child = _exited_run(tmp_path, monkeypatch, LostExit)
    child.released.set()
    run = _until_not_running(reg, run_id, 10)
    assert (run["status"], run["exit_code"]) == ("finished", None)


@pytest.mark.parametrize("recorded_when", ["run.json is read", "running() is asked"])
def test_a_run_whose_exit_is_recorded_while_it_is_read_is_never_read_finished_without_its_exit_code(
    tmp_path, monkeypatch, recorded_when
):
    """run.json and the waiter are read in one step: the exit cannot be recorded between the two."""
    reg, run_id, child = _exited_run(tmp_path, monkeypatch, UnrecordedExit)
    (waiter,) = [t for t in threading.enumerate() if t.name == f"mara-run-{run_id}"]
    read_json, reading = procs.read_json, threading.current_thread()

    def let_the_exit_be_recorded():
        if not child.released.is_set():
            child.released.set()
            waiter.join(2)  # the waiter records the exit unless this read holds the lock it records under

    def read_then_let_the_exit_be_recorded(path):
        data = read_json(path)
        if threading.current_thread() is reading and path.name == "run.json":
            let_the_exit_be_recorded()
        return data

    if recorded_when == "run.json is read":
        monkeypatch.setattr(procs, "read_json", read_then_let_the_exit_be_recorded)
    else:
        running = reg.children.running

        def let_the_exit_be_recorded_then_ask(child_id):
            if threading.current_thread() is reading:
                let_the_exit_be_recorded()
            return running(child_id)

        monkeypatch.setattr(reg.children, "running", let_the_exit_be_recorded_then_ask)
    run = reg.get(run_id)
    assert (run["status"], run["exit_code"]) == ("running", None)
    run = _until_not_running(reg, run_id, 30)
    assert (run["status"], run["exit_code"]) == ("finished", 0)


def test_a_run_whose_child_exits_at_once_keeps_the_exit_code_its_waiter_recorded(tmp_path, monkeypatch):
    """The launch writes the pid into run.json under the lock the exit is recorded under, so it never overwrites the exit."""
    monkeypatch.setenv("MARA_HOME", str(ROOT))
    write_json = procs.write_json

    def exited_at_once(argv, **kw):
        child = procs.spawn([sys.executable, "-c", "import sys; sys.exit(2)"], **kw)
        child.wait(timeout=60)
        return child

    def let_the_exit_be_recorded_then_write(path, data):
        if path.name == "run.json" and data.get("pid") and data.get("status") == "running":
            (waiter,) = [t for t in threading.enumerate() if t.name == f"mara-run-{data['id']}"]
            waiter.join(2)  # the waiter records the exit unless the launch holds the lock it records under
        write_json(path, data)

    monkeypatch.setattr(procs, "write_json", let_the_exit_be_recorded_then_write)
    reg = runs.RunRegistry(ROOT, tmp_path / "out", start=exited_at_once)
    run_id = reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))["id"]
    run = _until_not_running(reg, run_id, 30)
    assert (run["status"], run["exit_code"]) == ("failed", 2)


def _exited_job(tmp_path, monkeypatch, child_type, kind="trivy_db_download"):
    """A run registry, a job registry and a job whose child exited 0; every child spawned, wrapped in `child_type`, is in
    the list returned last."""
    from mara.web import jobs as jobs_mod

    monkeypatch.setenv("MARA_HOME", str(ROOT))
    real, children = procs.spawn, []

    def spawn(argv, **kw):
        children.append(child_type(real([sys.executable, "-c", "pass"], **kw)))
        return children[-1]

    table = procs.ChildTable()  # the two registries' children, as the server shares one between them
    reg = runs.RunRegistry(ROOT, tmp_path / "out", start=spawn, table=table)
    job_reg = jobs_mod.JobRegistry(ROOT, tmp_path / "out", start=spawn, table=table)
    job_id = job_reg.create(jobs_mod.JobRequest(kind=kind))["id"]
    (child,) = children
    assert child.proc.wait(timeout=60) == 0
    return reg, job_reg, job_id, children


def test_no_second_job_starts_while_the_exit_of_the_first_is_not_recorded_yet(tmp_path, monkeypatch):
    """The first job still reads as running, so another job is refused."""
    from mara.web import jobs as jobs_mod

    _, job_reg, job_id, (child,) = _exited_job(tmp_path, monkeypatch, UnrecordedExit)
    try:
        with pytest.raises(runs.LaunchError) as refused:
            job_reg.create(jobs_mod.JobRequest(kind="trivy_db_status"))
        assert refused.value.code == "busy"
    finally:
        child.released.set()
    _until_not_running(job_reg, job_id, 30)


def test_no_review_starts_while_the_exit_of_a_job_replacing_the_tools_is_not_recorded_yet(tmp_path, monkeypatch):
    """The job still reads as running, so it still replaces the trivy database a review would use."""
    reg, job_reg, job_id, (child,) = _exited_job(tmp_path, monkeypatch, UnrecordedExit)
    try:
        with pytest.raises(runs.LaunchError) as refused:
            reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))
        assert refused.value.code == "busy"
    finally:
        child.released.set()
    _until_not_running(job_reg, job_id, 30)


def test_a_job_replacing_no_tools_does_not_hold_a_review_back(tmp_path, monkeypatch):
    reg, job_reg, job_id, children = _exited_job(tmp_path, monkeypatch, UnrecordedExit, kind="trivy_db_status")
    try:
        assert job_reg.get(job_id)["status"] == "running"
        reg.create(runs.LaunchRequest(target="fixtures/vuln-sample", provider="mock"))
    finally:
        for child in children:
            child.released.set()
    _until_not_running(job_reg, job_id, 30)


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_a_job_whose_waiter_stopped_without_recording_its_exit_reads_as_interrupted(tmp_path, monkeypatch):
    """As a job of an earlier server does, instead of reading as running for good."""
    _, job_reg, job_id, (child,) = _exited_job(tmp_path, monkeypatch, LostExit)
    child.released.set()
    job = _until_not_running(job_reg, job_id, 10)
    assert (job["status"], job["exit_code"]) == ("interrupted", None)


@pytest.mark.parametrize("recorded_when", ["job.json is read", "running() is asked"])
def test_a_job_whose_exit_is_recorded_while_it_is_read_is_never_read_as_interrupted(tmp_path, monkeypatch, recorded_when):
    """job.json and the waiter are read in one step: the exit cannot be recorded between the two."""
    _, job_reg, job_id, (child,) = _exited_job(tmp_path, monkeypatch, UnrecordedExit)
    (waiter,) = [t for t in threading.enumerate() if t.name == f"mara-job-{job_id}"]
    read_json, reading = procs.read_json, threading.current_thread()

    def let_the_exit_be_recorded():
        if not child.released.is_set():
            child.released.set()
            waiter.join(2)  # the waiter records the exit unless this read holds the lock it records under

    def read_then_let_the_exit_be_recorded(path):
        data = read_json(path)
        if threading.current_thread() is reading and path.name == "job.json":
            let_the_exit_be_recorded()
        return data

    if recorded_when == "job.json is read":
        monkeypatch.setattr(procs, "read_json", read_then_let_the_exit_be_recorded)
    else:
        running = job_reg.children.running

        def let_the_exit_be_recorded_then_ask(child_id):
            if threading.current_thread() is reading:
                let_the_exit_be_recorded()
            return running(child_id)

        monkeypatch.setattr(job_reg.children, "running", let_the_exit_be_recorded_then_ask)
    job = job_reg.get(job_id)
    assert (job["status"], job["exit_code"]) == ("running", None)
    job = _until_not_running(job_reg, job_id, 30)
    assert (job["status"], job["exit_code"]) == ("finished", 0)


@pytest.mark.parametrize("recorded, exit_code, enforced", [
    (True, 3, True),    # a failed PSIRT hand-off exits 3, outranking the gate's 2: the report still says it was enforced
    (False, 0, False),
    (None, 2, True),    # a report written before gate_enforced: the exit code is all there is
    (None, 0, False),
])
def test_a_run_reads_whether_its_gate_was_enforced_from_the_report(server, mock_report, monkeypatch, tmp_path, recorded,
                                                                   exit_code, enforced):
    """The seeded review's report, a valid ReviewReport, with gate_enforced as recorded (null: written before it)."""
    _, report = mock_report
    report_file = tmp_path / "report.json"
    report_file.write_text(report.model_copy(update={"gate_enforced": recorded}).model_dump_json(), encoding="utf-8")
    monkeypatch.setattr(runs.procs, "spawn", _finished_review(procs.spawn, report_file, exit_code))
    c = Client(server)
    res, data, _ = c.request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock"})
    assert res.status == 201
    done = _wait(c, data["run"]["id"])
    assert done["run"]["status"] == "finished" and done["run"]["exit_code"] == exit_code
    assert done["run"]["gate_enforced"] is enforced


def test_a_report_with_a_gate_code_the_review_status_does_not_write_has_no_report_view(server, mock_report, monkeypatch,
                                                                                       tmp_path):
    """gate_reasons holds only the review status's codes (docs/adr/0007-review-status-and-gate.md), so a report with any
    other code does not validate: the workbench shows the run without a report, while whether its gate was enforced,
    read from the raw JSON, stays readable."""
    _, report = mock_report
    doc = json.loads(report.model_copy(update={"gate_enforced": True}).model_dump_json())
    doc["gate_reasons"] = ["review_incomplete", "blocked_by_the_owner"]
    report_file = tmp_path / "report.json"
    report_file.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(runs.procs, "spawn", _finished_review(procs.spawn, report_file, 3))
    c = Client(server)
    res, data, _ = c.request("POST", "/api/runs", body={"target": "fixtures/vuln-sample", "provider": "mock"})
    assert res.status == 201
    done = _wait(c, data["run"]["id"])
    assert done["run"]["status"] == "finished" and done["run"]["gate_enforced"] is True
    res, err, _ = c.request("GET", f"/api/runs/{data['run']['id']}/report")
    assert res.status == 404 and _error(err) == "no_report"


# ------------------------------------------------------------------ environment


def test_the_environment_lists_every_locked_tool_and_never_a_credential_value(server):
    import yaml

    c = Client(server)
    res, env, body = c.request("GET", "/api/env")
    assert res.status == 200
    lock = yaml.safe_load((ROOT / "tools" / "versions.lock").read_text(encoding="utf-8"))
    rows = {r["name"]: r for r in env["tools"]["rows"]}
    assert set(rows) == set(lock["tools"]) and all(r["status"] == "missing" for r in rows.values()), "conftest isolates the tool directory"
    assert rows["semgrep"]["dimensions"] and env["actions"]["install_tools"] and env["trivy_db"]["ok"] is False
    res, cfgs, body2 = c.request("GET", "/api/configs")
    by_path = {x["path"]: x for x in cfgs["configs"]}
    mock = by_path["config/mara.mock.yaml"]
    assert mock["loadable"] and mock["provider_mode"] == "mock" and len(mock["policies"]) == 8
    assert not by_path["config/examples/violating.yaml"]["loadable"]
    gemini = next(m for m in by_path["config/mara.yaml"]["models"] if m["family"] == "gemini")
    assert gemini["credential"] == {"kind": "env", "env": "GEMINI_API_KEY", "present": True}
    assert SENTINEL.encode() not in body and SENTINEL.encode() not in body2


def test_the_page_lists_exactly_the_configs_a_launch_accepts(tmp_path):
    """A config the page offers is one a review and a check_config job accept, and the other way round: a .yml config,
    a symlink in config/ to a file outside the workspace, a file that is not YAML."""
    from mara.web import env
    from mara.web import jobs as jobs_mod

    mock = (ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8")
    workspace, outside = tmp_path / "ws", tmp_path / "outside"
    for d in (workspace / "config", workspace / "target", outside):
        d.mkdir(parents=True)
    (workspace / "config" / "plain.yaml").write_text(mock, encoding="utf-8")
    (workspace / "config" / "short.yml").write_text(mock, encoding="utf-8")
    (outside / "mara.yaml").write_text(mock, encoding="utf-8")
    (workspace / "config" / "elsewhere.yaml").symlink_to(outside / "mara.yaml")
    (workspace / "config" / "notes.toml").write_text(mock, encoding="utf-8")
    reg = runs.RunRegistry(workspace, workspace / "out")
    job_reg = jobs_mod.JobRegistry(workspace, workspace / "out")

    def accepted(launch) -> set[str]:
        ok = set()
        for name in ("plain.yaml", "short.yml", "elsewhere.yaml", "notes.toml"):
            try:
                launch(f"config/{name}")
                ok.add(f"config/{name}")
            except runs.LaunchError as e:
                assert e.code == "config_not_found", (name, e.code, e.message)
        return ok

    listed = {c["path"] for c in env.configs(workspace)}
    by_review = accepted(lambda cfg: reg.prepare(runs.LaunchRequest(target="target", provider="mock", config=cfg)))
    by_job = accepted(lambda cfg: job_reg.argv(jobs_mod.JobRequest(kind="check_config", config=cfg)))
    assert listed == by_review == by_job == {"config/plain.yaml", "config/short.yml"}


def test_a_check_config_job_runs_the_command_line(server):
    c = Client(server)
    res, data, _ = c.request("POST", "/api/jobs", body={"kind": "check_config", "config": "config/mara.mock.yaml"})
    assert res.status == 201, data
    job_id = data["job"]["id"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        _, data, _ = c.request("GET", f"/api/jobs/{job_id}")
        if data["job"]["status"] != "running":
            break
        time.sleep(0.3)
    assert data["job"]["status"] == "finished" and data["job"]["exit_code"] == 0
    assert re.search(r"8/8 policies pass", data["job"]["log_tail"])
    res, err, _ = c.request("POST", "/api/jobs", body={"kind": "install_tools", "only": ["curl"]})
    assert res.status == 400 and _error(err) == "unknown_tool"
    res, err, _ = c.request("POST", "/api/jobs", body={"kind": "shell", "argv": ["id"]})
    assert res.status == 400 and _error(err) == "bad_request"


def test_the_context_row_shows_the_context_agents_canary_echoes_and_the_reviewers_row_does_not():
    """The context agent's echoes used to share the reviewers' counter and showed on the reviewers' row
    (docs/adr/0008-reply-accounting.md)."""
    from mara.audit import Audit
    from mara.web import views
    from tests.reply_records import extraction

    a = Audit()
    a.record(extraction("context", "anthropic", canary_echoes=1))
    a.record(extraction("reviewer", "anthropic"))
    manifest = {"models": [{"name": "a", "family": "anthropic"}], "roles": {"context": "a", "reviewers": ["a"]}}
    report = ReviewReport.model_construct(bias_audit=dict(a), provider_manifest=[])
    panel = {g["role"]: g["members"] for g in views.roles(manifest, report)}
    assert [m["canary_echoes"] for m in panel["context"]] == [1] and [m["canary_echoes"] for m in panel["reviewers"]] == [0]


def test_a_family_the_audit_counts_but_the_manifest_does_not_name_is_shown_as_unconfigured():
    """A family whose reviewers were called shows on the reviewers' row even when the manifest does not list it."""
    from mara import exchange
    from mara.audit import Audit
    from mara.web import views
    from tests.reply_records import extraction

    a = Audit()
    a.record(extraction("reviewer", "anthropic"))
    a.record(extraction("reviewer", "glm"))
    a.record(extraction("reviewer", "glm", exchange.REFUSAL))
    a.record(extraction("context", "gemini"))
    manifest = {"models": [{"name": "a", "family": "anthropic"}], "roles": {"context": "a", "reviewers": ["a"]}}
    report = ReviewReport.model_construct(bias_audit=dict(a), provider_manifest=[])
    reviewers = next(g["members"] for g in views.roles(manifest, report) if g["role"] == "reviewers")
    assert [(m["family"], m["configured"], m["calls"]) for m in reviewers] == [("anthropic", True, 1), ("glm", False, 2)]
    assert reviewers[1]["failures"]["reviewer_refusals"] == 1
