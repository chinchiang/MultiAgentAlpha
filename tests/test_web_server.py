"""The workbench server end to end (mara.web, docs/adr/0006-local-web-workbench.md): a real server on a loopback port,
a real `mara review` subprocess on the seeded fixture in mock mode, and the checks that keep other pages and other
hosts out: the session cookie, the CSRF header, the Host header, Origin and Sec-Fetch-Site."""

import http.client
import json
import os
import re
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
    httpd.shutdown()
    httpd.shutdown_children()
    httpd.server_close()
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


class Client:
    def __init__(self, httpd, *, cookie=True, csrf=True):
        self.httpd = httpd
        self.cookie = cookie
        self.csrf = csrf

    def request(self, method, path, body=None, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.port, timeout=30)
        h = {"Host": f"127.0.0.1:{self.httpd.port}"}
        if self.cookie:
            h["Cookie"] = f"{self.httpd.cookie_name}={self.httpd.token}"
        if self.csrf and method != "GET":
            h["X-MARA-CSRF"] = self.httpd.csrf
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


def test_the_page_needs_the_printed_token_and_sets_a_strict_cookie(server):
    anon = Client(server, cookie=False)
    res, _, _ = anon.request("GET", "/")
    assert res.status == 401
    res, _, _ = anon.request("GET", "/?token=not-the-token")
    assert res.status == 403
    res, _, _ = anon.request("GET", f"/?token={server.token}")
    cookie = res.getheader("Set-Cookie")
    assert res.status == 303 and res.getheader("Location") == "/"
    assert cookie.startswith(f"{server.cookie_name}={server.token};") and "HttpOnly" in cookie and "SameSite=Strict" in cookie
    res, _, body = Client(server).request("GET", "/")
    assert res.status == 200 and body.startswith(b"<!DOCTYPE html>")
    assert res.getheader("Content-Security-Policy") == server.csp
    assert res.getheader("X-Content-Type-Options") == "nosniff" and res.getheader("Cache-Control") == "no-store"
    assert res.getheader("Server") == "mara-workbench" and res.getheader("Access-Control-Allow-Origin") is None


def test_the_api_needs_the_session_except_health(server):
    anon = Client(server, cookie=False)
    res, data, _ = anon.request("GET", "/api/health")
    assert res.status == 200 and data["ok"]
    for path in ("/api/runs", "/api/env", "/api/configs", "/api/session"):
        res, data, _ = anon.request("GET", path)
        assert res.status == 401 and _error(data) == "unauthenticated", path
    res, data, _ = Client(server).request("GET", "/api/session")
    assert res.status == 200 and data["csrf"] == server.csrf and data["workspace"] == str(ROOT)


@pytest.mark.parametrize("host", ["evil.example", f"evil.example:{0}", "127.0.0.1.nip.io", ""])
def test_a_foreign_host_header_is_refused_even_with_the_cookie(server, host):
    res, data, _ = Client(server).request("GET", "/api/runs", headers={"Host": host.replace(":0", f":{server.port}")})
    assert res.status == 421 and _error(data) == "bad_host"


def test_localhost_names_the_same_server(server):
    res, _, _ = Client(server).request("GET", "/api/runs", headers={"Host": f"localhost:{server.port}"})
    assert res.status == 200


@pytest.mark.parametrize("headers,code,status", [
    ({}, "csrf", 403),
    ({"X-MARA-CSRF": "wrong"}, "csrf", 403),
    ({"Origin": "http://evil.example"}, "cross_origin", 403),
    ({"Sec-Fetch-Site": "cross-site"}, "cross_origin", 403),
])
def test_a_change_needs_the_csrf_header_and_the_same_origin(server, headers, code, status):
    client = Client(server, csrf="X-MARA-CSRF" not in headers and code != "csrf")
    res, data, _ = client.request("PUT", "/api/settings", body={"language": "en"}, headers=headers)
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


def test_settings_round_trip_and_logout_clears_the_cookie(server):
    c = Client(server)
    res, data, _ = c.request("PUT", "/api/settings", body={"language": "en", "default_provider": "mock", "default_config": ""})
    assert res.status == 200 and c.request("GET", "/api/settings")[1]["language"] == "en"
    res, _, _ = c.request("POST", "/api/logout")
    assert res.status == 200 and "Max-Age=0" in res.getheader("Set-Cookie")


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
    for name in ("run.json", "..%2Frun.json", "..%2F..%2Fpyproject.toml"):
        res, data, _ = c.request("GET", f"/api/runs/{run_id}/files/{name}")
        assert res.status == 404, name
    for bad in ("../runs", "20261014-000000-zzzzzz", "20261014-000000-abcdef"):
        res, data, _ = c.request("GET", f"/api/runs/{bad}")
        assert res.status == 404, bad


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


def test_one_review_at_a_time_and_cancel_stops_it(server, monkeypatch):
    real = procs.spawn

    def slow(argv, **kw):  # a review that would take a minute
        return real([sys.executable, "-c", "import time; time.sleep(60)"], **kw)

    monkeypatch.setattr(runs.procs, "spawn", slow)
    c = Client(server)
    body = {"target": "fixtures/vuln-sample", "provider": "mock", "sarif_dir": "fixtures/vuln-sample-sarif"}
    res, data, _ = c.request("POST", "/api/runs", body=body)
    assert res.status == 201
    run_id = data["run"]["id"]
    res, busy, _ = c.request("POST", "/api/runs", body=body)
    assert res.status == 409 and _error(busy) == "busy"
    started = time.monotonic()
    res, data, _ = c.request("POST", f"/api/runs/{run_id}/cancel")
    assert res.status == 200 and data["run"]["status"] == "cancelled" and time.monotonic() - started < 15
    res, again, _ = c.request("POST", f"/api/runs/{run_id}/cancel")
    assert res.status == 409 and _error(again) == "not_running"
    assert not server.runs.busy()


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
