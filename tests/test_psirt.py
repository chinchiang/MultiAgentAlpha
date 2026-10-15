"""G-12: accepted tier-A Critical findings on a shipped product become CRA Article 14 early-warning
payloads with deadlines counted from the review; nothing is sent without --notify-psirt and a token
from the environment; policy P6 keeps the trigger narrow."""

import datetime as dt
import json
import sys
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.cli import app  # noqa: E402
from mara.config import MaraConfig, load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from mara.policy import evaluate_policies  # noqa: E402
from mara.report.markdown_out import render_markdown  # noqa: E402
from mara.report.psirt_out import build_notifications, select_psirt_findings, send_psirt, write_psirt  # noqa: E402
from tests.cli_output import plain  # noqa: E402

PSIRT = {"enabled": True, "webhook_url": "https://psirt.example.internal/intake", "product": "IPC-7000 web console", "shipped": True}


def _mock_cfg(**psirt) -> MaraConfig:
    import yaml

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {**PSIRT, **psirt}
    return MaraConfig.model_validate(raw)


def _accept(c):
    # an accepted jury outcome as scoring writes it (JuryOutcome.consensus_fields): accepted, not needing a human
    c.accepted, c.needs_human, c.human_reasons = True, False, []


def _adjudicate_for_psirt_test(report, cfg):
    count = 0
    for c in report.consensus:
        if c.tier.value == "A" and c.cvss4_severity == "Critical" and count < 3:
            _accept(c)
            count += 1
        elif c.tier.value == "B":
            _accept(c)
    report.psirt = build_notifications(report, cfg)
    report.bias_audit["psirt_notifications"] = len(report.psirt)


def _event(t0):
    return {"event_type": "actively_exploited_vulnerability", "confirmed_by": "test-psirt",
            "awareness_at": t0.isoformat(), "remediation_available_at": t0.isoformat()}


@pytest.fixture(scope="module")
def shipped_report(tmp_path_factory):
    cfg = _mock_cfg()
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path_factory.mktemp("out"))
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    # PSIRT transport tests consume synthetic adjudicated results. The pipeline's independent
    # quorum failures are covered by test_pipeline_mock and must not be bypassed in production.
    _adjudicate_for_psirt_test(report, cfg)
    return cfg, report


def test_only_accepted_tier_a_critical_findings_notify(shipped_report):
    cfg, report = shipped_report
    cons = {c.finding_id: c for c in report.consensus}
    picked = {f.id for f, _, _ in select_psirt_findings(report, cfg)}
    assert picked, "the seeded fixture has tier-A Critical findings"
    for fid in picked:
        assert cons[fid].accepted and cons[fid].tier.value == "A" and cons[fid].cvss4_severity == "Critical"
    excluded = {c.finding_id for c in report.consensus if c.accepted and not (c.tier.value == "A" and c.cvss4_severity == "Critical")}
    assert excluded and not (excluded & picked)
    assert len(report.psirt) == len(picked) and report.bias_audit["psirt_notifications"] == len(picked)


def test_payload_carries_evidence_and_article_14_deadlines(shipped_report):
    cfg, report = shipped_report
    now = dt.datetime(2026, 9, 12, 8, 0, tzinfo=dt.UTC)
    payloads = build_notifications(report, cfg, now)
    p = payloads[0]
    assert p["schema"] == "mara-psirt/2" and "Article 14" in p["regulation"] and p["product"] == PSIRT["product"]
    assert p["deadlines"] == {}
    assert p["internal_sla"] == {"early_warning_by": "2026-09-13T08:00:00+00:00", "notification_by": "2026-09-15T08:00:00+00:00",
                              "final_report_by": "2026-09-26T08:00:00+00:00"}
    for key in ("finding_id", "cwe", "location", "cvss4", "evidence_tier", "ssvc", "exploitable", "families_agreeing", "tool_corroborated"):
        assert key in p
    assert p["location"]["file"] and p["location"]["line"] >= 1 and p["cvss4"]["severity"] == "Critical"
    assert "PSIRT hand-off (EU CRA Article 14)" in render_markdown(report)


def test_not_shipped_or_disabled_means_no_notifications(shipped_report):
    _, report = shipped_report
    assert build_notifications(report, _mock_cfg(shipped=False)) == []
    assert build_notifications(report, _mock_cfg(enabled=False, shipped=True)) == []


def test_send_posts_json_with_bearer_token_and_refuses_without_token(shipped_report, monkeypatch):
    cfg, report = shipped_report
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("Authorization"), json.loads(request.content)["finding_id"]))
        return httpx.Response(202, json={"ticket": "PSIRT-1"})

    monkeypatch.delenv("PSIRT_WEBHOOK_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="PSIRT_WEBHOOK_TOKEN"):
        send_psirt(report.psirt, cfg)
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        results = send_psirt(report.psirt, cfg, client=client)
    assert all(r["ok"] and r["status_code"] == 202 for r in results) and len(seen) == len(report.psirt)
    assert all(url == PSIRT["webhook_url"] and auth == "Bearer s3cret" for url, auth, _ in seen)
    assert {fid for _, _, fid in seen} == {p["finding_id"] for p in report.psirt}


def test_write_and_cli_file_output(shipped_report, tmp_path):
    cfg, report = shipped_report
    write_psirt(report.psirt, tmp_path / "n.json")
    assert json.loads((tmp_path / "n.json").read_text())[0]["stage"] == "internal_handoff"
    cfg_path = tmp_path / "mock-psirt.yaml"
    import yaml

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = PSIRT
    cfg_path.write_text(yaml.safe_dump(raw))
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(cfg_path),
                                  "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--mock-fixtures", str(ROOT / "fixtures" / "mock-responses"),
                                  "--out", str(out)])
    assert res.exit_code == 0, res.output
    text = plain(res.output)  # without colour codes (FORCE_COLOR on CI runners)
    assert (out / "psirt-notifications.json").is_file() and "PSIRT payload" in text


def test_policy_p6_keeps_the_trigger_narrow():
    assert all(r.passed for r in evaluate_policies(_mock_cfg()))
    assert all(r.passed for r in evaluate_policies(load_config(ROOT / "config" / "examples" / "psirt-enabled.yaml")))
    for bad in ({"webhook_url": "http://psirt.example.internal/intake"}, {"product": ""}, {"trigger_tiers": ["A", "C"]},
                {"trigger_severities": ["Critical", "Medium"]}, {"token_env": ""}):
        with pytest.raises(ValueError, match="P6 psirt-scope"):
            _mock_cfg(**bad)
    disabled = _mock_cfg(enabled=False, webhook_url="http://insecure")
    assert next(r for r in evaluate_policies(disabled) if r.id == "P6").passed


# ---------------------------------------------------------------- ledger, stage clock, handshake (scripts/psirt_ops.py)

from mara import psirt_ledger as pl  # noqa: E402


def test_dedupe_key_is_stable_across_reviews_and_in_every_payload(shipped_report):
    cfg, report = shipped_report
    assert all(len(p["dedupe_key"]) == 16 for p in report.psirt)
    p = report.psirt[0]
    assert report.target_id
    f = next(x for x in report.findings if x.id == p["finding_id"])
    assert p["dedupe_key"] == pl.dedupe_key(cfg.psirt.product, report.target_id, p["location"]["file"], p["cwe"], f.provenance[0].quote)
    # the line is not part of it: code moving down by one line is the same finding (mara.identity)
    assert pl.dedupe_key("a", "t", "f.py", "CWE-1", "q = 1") == pl.dedupe_key("a", "t", "./f.py", "cwe-1", "q  =  1")
    assert pl.dedupe_key("a", "t", "f.py", "CWE-1", "q = 1") != pl.dedupe_key("a", "t", "f.py", "CWE-1", "q = 2")
    assert pl.dedupe_key("a", "t", "f.py", "CWE-1", "q = 1") != pl.dedupe_key("a", "t", "g.py", "CWE-1", "q = 1")


def test_dedupe_key_follows_the_target_identity_not_the_checkout_path(shipped_report):
    """Two CI runners check the same repository out under different paths: the report's target differs,
    its target_id does not, and the PSIRT must not receive the same finding twice."""
    from mara.report.psirt_out import build_notifications

    cfg, report = shipped_report
    elsewhere = report.model_copy(update={"target": "/some/other/runner/checkout"})
    keys = [n["dedupe_key"] for n in build_notifications(report, cfg)]
    assert keys and keys == [n["dedupe_key"] for n in build_notifications(elsewhere, cfg)]
    moved = report.model_copy(update={"target_id": report.target_id + "-other"})
    assert keys != [n["dedupe_key"] for n in build_notifications(moved, cfg)], "a different repository is a different finding"


def test_repositories_without_an_origin_do_not_share_an_identity(tmp_path):
    """#74 review, item 3: every repository without an origin remote, reviewed at its top level, was named
    ["git", "", ""]; two of them shared PSIRT dedupe keys and one finding suppressed the other's hand-off."""
    import subprocess

    from mara.context.repo_map import build_context

    ids = []
    for name in ("one", "two"):
        repo = tmp_path / name
        repo.mkdir()
        (repo / "app.py").write_text("unsafe()\n")
        for args in (["init", "-q"], ["add", "-A"], ["-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "x"]):
            subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
        ids.append(json.loads(build_context(repo).identity))
    assert ids == [["path", str((tmp_path / "one").resolve())], ["path", str((tmp_path / "two").resolve())]]
    assert pl.dedupe_key("p", "id-one", "app.py", "CWE-89", "q = 1") != pl.dedupe_key("p", "id-two", "app.py", "CWE-89", "q = 1")


def test_ledger_items_under_the_path_based_key_migrate_instead_of_being_sent_again(shipped_report, monkeypatch, tmp_path):
    """#74 review, item 4: v0.4.10 moved the key from the checkout path to the target identity. An item
    delivered, confirmed and staged under the old key must keep that history under the new key, not be sent
    again as a fresh, unconfirmed hand-off."""
    import datetime as dt

    cfg, report = shipped_report
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    first = report.psirt[0]
    loc = first["location"]
    legacy = pl.line_dedupe_key(first["product"], first["target"], loc["file"], loc["line"], first["cwe"])
    assert legacy != first["dedupe_key"]
    old_payload = {**first, "dedupe_key": legacy}
    ledger_path = tmp_path / "ledger.json"
    led = pl.load_ledger(ledger_path)
    when = dt.datetime(2026, 10, 1, tzinfo=dt.UTC)
    pl.record_attempt(led, old_payload, 202, True, when)
    pl.record_stage(led, legacy, "early_warning", "PSIRT-1", when)
    pl.save_ledger(led, ledger_path)

    calls = []
    with httpx.Client(transport=httpx.MockTransport(lambda r: (calls.append(json.loads(r.content)["dedupe_key"]), httpx.Response(202))[1])) as c:
        results = send_psirt(report.psirt, cfg, client=c, ledger_path=ledger_path)
    assert results[0]["skipped"] and first["dedupe_key"] not in calls, "the delivered finding is not sent again"
    led = pl.load_ledger(ledger_path)
    assert legacy not in led["items"]
    item = led["items"][first["dedupe_key"]]
    assert item["key"] == first["dedupe_key"] and item["migrated_from"] == [legacy]
    assert item["stages"]["early_warning"]["reference"] == "PSIRT-1" and item["stages"]["internal_handoff"]["sent_at"]
    # an operator holding the old key still reaches the item
    pl.record_stage(led, legacy, "notification", "PSIRT-2", when)
    assert led["items"][first["dedupe_key"]]["stages"]["notification"]["reference"] == "PSIRT-2"
    assert not pl.migrate_key(led, legacy, first["dedupe_key"]), "migration runs once"


def test_ledger_items_under_the_line_based_key_migrate_too(shipped_report, monkeypatch, tmp_path):
    """v0.5.3 dropped the line from the key (a line inserted above the code re-notified the finding). An item the
    ledger holds under the line-based target-identity key moves to the new key instead of being sent again."""
    import datetime as dt

    cfg, report = shipped_report
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    first = report.psirt[0]
    loc = first["location"]
    assert first["target_id"] == report.target_id
    line_key = pl.line_dedupe_key(first["product"], first["target_id"], loc["file"], loc["line"], first["cwe"])
    assert line_key != first["dedupe_key"]
    ledger_path = tmp_path / "ledger.json"
    led = pl.load_ledger(ledger_path)
    pl.record_attempt(led, {**first, "dedupe_key": line_key}, 202, True, dt.datetime(2026, 10, 1, tzinfo=dt.UTC))
    pl.save_ledger(led, ledger_path)
    calls = []
    with httpx.Client(transport=httpx.MockTransport(lambda r: (calls.append(json.loads(r.content)["dedupe_key"]), httpx.Response(202))[1])) as c:
        results = send_psirt(report.psirt, cfg, client=c, ledger_path=ledger_path)
    assert results[0]["skipped"] and first["dedupe_key"] not in calls
    assert pl.load_ledger(ledger_path)["items"][first["dedupe_key"]]["migrated_from"] == [line_key]


def test_ledger_skips_delivered_findings_records_attempts_and_sends_idempotency_key(shipped_report, monkeypatch, tmp_path):
    cfg, report = shipped_report
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    calls: list[tuple[str, str]] = []
    codes = iter([202, 503] + [202] * 10)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.headers.get("Idempotency-Key"), json.loads(request.content)["dedupe_key"]))
        return httpx.Response(next(codes))

    ledger = tmp_path / "ledger.json"
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        first = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger)
    assert len(first) == len(report.psirt) == 3 and [r["ok"] for r in first] == [True, False, True]
    assert all(k == d for k, d in calls) and len(calls) == 3, "every request carries Idempotency-Key = dedupe_key"
    led = pl.load_ledger(ledger)
    assert len(led["items"]) == 3 and led["schema"] == pl.LEDGER_SCHEMA
    failed = led["items"][first[1]["dedupe_key"]]
    assert failed["attempts"][0]["status_code"] == 503 and not failed["stages"]["internal_handoff"]
    # second review: the two delivered ones are skipped, the failed one is retried
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        second = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger)
    assert [r["skipped"] for r in second] == [True, False, True] and second[1]["ok"] and len(calls) == 4
    assert "already delivered" in second[0]["reason"]
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        forced = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger, resend=True)
    assert not any(r["skipped"] for r in forced) and len(calls) == 7
    led = pl.load_ledger(ledger)
    assert all(i["stages"]["internal_handoff"].get("sent_at") for i in led["items"].values())
    assert len(led["items"][first[0]["dedupe_key"]]["attempts"]) == 2


def test_items_the_psirt_closed_are_not_sent_again(shipped_report, monkeypatch, tmp_path):
    cfg, report = shipped_report
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    sent: list[str] = []
    codes = iter([202])

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content)["dedupe_key"])
        return httpx.Response(next(codes, 503))  # the open item keeps failing, so it is retried every time

    ledger_path = tmp_path / "ledger.json"
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        first = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger_path)
    delivered, undelivered, still_open = (r["dedupe_key"] for r in first)
    ledger = pl.load_ledger(ledger_path)
    # one closed after delivery (false positive), one closed although every attempt failed (fixed meanwhile)
    pl.close_item(ledger, delivered, "PSIRT: false positive")
    pl.close_item(ledger, undelivered, "fixed before hand-off")
    pl.save_ledger(ledger, ledger_path)
    assert pl.already_sent(ledger, delivered), "closing does not erase the delivery"
    assert pl.closed_at(ledger, still_open) is None and pl.closed_at(ledger, "nope") is None
    for _ in range(2):  # and on every later review
        sent.clear()
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            again = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger_path)
        assert sent == [still_open], "only the open, undelivered item is retried"
        assert [r["skipped"] for r in again] == [True, True, False]
        assert "closed by the PSIRT" in again[0]["reason"] and "false positive" in again[0]["reason"]
        assert "fixed before hand-off" in again[1]["reason"]
    led = pl.load_ledger(ledger_path)
    assert len(led["items"][delivered]["attempts"]) == 1 and len(led["items"][undelivered]["attempts"]) == 1
    sent.clear()
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        send_psirt(report.psirt, cfg, client=client, ledger_path=ledger_path, resend=True)
    assert sent == [delivered, undelivered, still_open], "--psirt-resend still forces every send"


def test_an_unreachable_send_is_recorded_and_does_not_stop_the_others(shipped_report, monkeypatch, tmp_path):
    """A connection error used to abort the loop: later payloads were never attempted and the failed one
    never reached the ledger."""
    import mara.psirt_ledger as pl

    cfg, report = shipped_report
    monkeypatch.setenv(cfg.psirt.token_env, "t0ken")
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 2:
            raise httpx.ConnectError("connection refused by psirt.example.invalid")
        return httpx.Response(202)

    ledger = tmp_path / "ledger.json"
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        results = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger)
    assert len(calls) == 3 and [r["ok"] for r in results] == [True, False, True]
    assert results[1]["status_code"] is None and results[1]["error"] == "connection_failed"
    attempt = pl.load_ledger(ledger)["items"][results[1]["dedupe_key"]]["attempts"][0]
    assert attempt == {"at": attempt["at"], "status_code": None, "ok": False, "error": "connection_failed"}


def _review_with_a_failed_hand_off(payloads, monkeypatch, tmp_path, *flags: str):
    """`mara review --notify-psirt` (and `flags`) of the seeded fixture on a config with the PSIRT hand-off on, every
    send failing. The review runs for real, its gate decided by mara.review_status; only the hand-off's payloads are
    given, since the mock review accepts no tier A Critical finding of its own. Returns the CLI result, its report and
    its output as a reader sees it."""
    import yaml

    import mara.report.psirt_out as po

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = PSIRT
    cfg_path = tmp_path / "mock-psirt.yaml"
    cfg_path.write_text(yaml.safe_dump(raw))
    monkeypatch.setattr(po, "build_notifications", lambda report, cfg, *a, **k: payloads)
    monkeypatch.setattr(po, "send_psirt", lambda sent, *a, **k: [
        {"finding_id": p["finding_id"], "dedupe_key": p["dedupe_key"], "skipped": False, "status_code": None, "ok": False,
         "error": "connection_failed"} for p in sent])
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(cfg_path),
                                  "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--mock-fixtures",
                                  str(ROOT / "fixtures" / "mock-responses"), "--out", str(tmp_path / "out"), "--notify-psirt", *flags])
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    return res, report, plain(res.output)


def test_a_failed_psirt_hand_off_fails_the_cli_run(shipped_report, monkeypatch, tmp_path):
    """The CLI printed FAILED but exited 0: CI showed green after a CRA hand-off that never arrived. The gate blocked
    without being enforced (rollout phase not_started), and its message names the exit code the command ends with."""
    _, shipped = shipped_report
    res, report, text = _review_with_a_failed_hand_off(shipped.psirt, monkeypatch, tmp_path)
    assert res.exit_code == 3, res.output
    assert "connection_failed FAILED" in res.output, "the reports are still written"
    assert not report["gate_passed"] and report["gate_reasons"] and report["gate_enforced"] is False
    assert "the gate blocked: recorded, not enforced (exit 3: the PSIRT hand-off failed)" in text and "exit 0" not in text


def test_an_enforced_gate_with_a_failed_psirt_hand_off_names_the_exit_code_it_gets(shipped_report, monkeypatch, tmp_path):
    """A failed hand-off exits 3, which outranks an enforced gate's 2; the gate's message must say 3, not 2. The same
    review, its blocked gate enforced by --fail-on-gate."""
    _, shipped = shipped_report
    res, report, text = _review_with_a_failed_hand_off(shipped.psirt, monkeypatch, tmp_path, "--fail-on-gate")
    assert res.exit_code == 3, res.output
    assert not report["gate_passed"] and report["gate_enforced"] is True
    assert "the gate blocked: enforced (exit 3: the PSIRT hand-off failed, which outranks the gate)" in text
    assert "(exit 2)" not in text


def test_stage_clock_records_references_and_names_overdue_stages(shipped_report, tmp_path):
    cfg, report = shipped_report
    t0 = dt.datetime(2026, 9, 14, 0, 0, tzinfo=dt.UTC)
    payloads = build_notifications(report, cfg, now=t0, event=_event(t0))
    ledger = pl.load_ledger(tmp_path / "l.json")
    for p in payloads:
        pl.record_attempt(ledger, p, 202, True, now=t0 + dt.timedelta(hours=1))
        pl.record_stage(ledger, p["dedupe_key"], "early_warning", "EW-test", now=t0 + dt.timedelta(hours=2))
    key = payloads[0]["dedupe_key"]
    assert pl.overdue(ledger, now=t0 + dt.timedelta(hours=71)) == []
    late = pl.overdue(ledger, now=t0 + dt.timedelta(hours=73))
    assert {s for _, s, _ in late} == {"notification"} and len(late) == 3
    pl.record_stage(ledger, key, "notification", "PSIRT-123", now=t0 + dt.timedelta(hours=10))
    late = pl.overdue(ledger, now=t0 + dt.timedelta(days=15))
    assert (key, "notification", payloads[0]["deadlines"]["notification_by"]) not in late
    assert any(k == key and s == "final_report" for k, s, _ in late)
    pl.close_item(ledger, key, "PSIRT: not exploited", now=t0 + dt.timedelta(days=2))
    assert all(k != key for k, _, _ in pl.overdue(ledger, now=t0 + dt.timedelta(days=15)))
    rows = {r["key"]: r for r in pl.status_rows(ledger, now=t0 + dt.timedelta(days=15))}
    assert rows[key]["state"].startswith("closed") and rows[payloads[1]["dedupe_key"]]["overdue"] == ["final_report", "notification"]
    with pytest.raises(ValueError):
        pl.record_stage(ledger, key, "invalid_stage", "x")
    with pytest.raises(ValueError):
        pl.close_item(ledger, key, "   ")
    with pytest.raises(KeyError):
        pl.record_stage(ledger, "nope", "notification", "x")
    # an undelivered early warning is overdue after 24 h even though it was never sent
    fresh = pl.load_ledger(tmp_path / "f.json")
    pl.record_attempt(fresh, payloads[0], 500, False, now=t0)
    assert [(s) for _, s, _ in pl.overdue(fresh, now=t0 + dt.timedelta(hours=25))] == ["internal_handoff", "early_warning"]


def test_handshake_records_outcome_and_governance_g12_needs_it(shipped_report, monkeypatch, tmp_path):
    cfg, _ = shipped_report
    monkeypatch.delenv("PSIRT_WEBHOOK_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="PSIRT_WEBHOOK_TOKEN"):
        pl.run_handshake(cfg)
    monkeypatch.setenv("PSIRT_WEBHOOK_TOKEN", "s3cret")
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append((request.headers.get("Authorization"), body["stage"], request.headers.get("Idempotency-Key")))
        return httpx.Response(200 if "ok" in str(request.url) else 401, text="nope" if "ok" not in str(request.url) else "")

    t0 = dt.datetime(2026, 9, 14, 0, 0, tzinfo=dt.UTC)
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        good = pl.run_handshake(_mock_cfg(webhook_url="https://psirt.example.internal/ok"), client=client, now=t0)
        bad = pl.run_handshake(_mock_cfg(webhook_url="https://psirt.example.internal/deny"), client=client, now=t0)
    assert good["ok"] and good["status_code"] == 200 and not bad["ok"] and bad["response"] == "endpoint_rejected"
    assert seen[0] == ("Bearer s3cret", "handshake", good["dedupe_key"] if "dedupe_key" in good else seen[0][2]) and seen[0][1] == "handshake"
    hs = tmp_path / "handshake.json"
    pl.write_handshake(good, hs)
    ok, msg = pl.handshake_status(hs, 90, now=t0 + dt.timedelta(days=10))
    assert ok and "10 days ago" in msg
    assert not pl.handshake_status(hs, 90, now=t0 + dt.timedelta(days=91))[0]
    pl.write_handshake(bad, hs)
    assert "FAILED" in pl.handshake_status(hs, 90, now=t0)[1]
    assert not pl.handshake_status(tmp_path / "missing.json", 90)[0]
    with pytest.raises(RuntimeError, match="https"):
        pl.run_handshake(_mock_cfg(enabled=False, webhook_url="http://insecure"))
    # governance: config complete but no handshake -> FAIL naming it; fresh handshake -> PASS; overdue ledger -> FAIL
    sys.path.insert(0, str(ROOT / "scripts"))
    from governance_check import FAIL, PASS, check_g12

    root = tmp_path / "repo"
    (root / "ops" / "psirt").mkdir(parents=True)
    cfg_path = root / "mara.yaml"
    cfg_path.write_text("models: []\npsirt:\n  enabled: true\n  webhook_url: https://psirt.example.internal/hook\n  product: IPC-7000\n")
    r = check_g12(root, cfg_path)
    assert r.status == FAIL and "握手" in r.evidence
    pl.write_handshake({**good, "sent_at": pl.iso(pl.now_utc())}, root / "ops" / "psirt" / "handshake.json")
    r = check_g12(root, cfg_path)
    assert r.status == PASS and "handshake" in r.evidence and "0 筆進行中" in r.evidence
    ledger = pl.load_ledger(root / "ops" / "psirt" / "ledger.json")
    pl.record_attempt(ledger, build_notifications(shipped_report[1], cfg, now=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))[0], 500, False)
    pl.save_ledger(ledger, root / "ops" / "psirt" / "ledger.json")
    r = check_g12(root, cfg_path)
    assert r.status == FAIL and "逾期" in r.evidence and "internal_handoff" in r.evidence


def test_psirt_ops_cli_dry_run_status_record_and_close(tmp_path, monkeypatch):
    import subprocess

    import yaml

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {**PSIRT, "ledger_file": str(tmp_path / "ledger.json"), "handshake_file": str(tmp_path / "hs.json")}
    cfg_path = tmp_path / "cfg.yaml"
    cfg_path.write_text(yaml.safe_dump(raw))
    script = ROOT / "scripts" / "psirt_ops.py"

    def run(*args):
        return subprocess.run([sys.executable, str(script), "--config", str(cfg_path), *args], capture_output=True, text=True, cwd=ROOT)

    r = run("handshake", "--dry-run")
    assert r.returncode == 0 and '"stage": "handshake"' in r.stdout and "nothing sent" in r.stderr and not (tmp_path / "hs.json").exists()
    r = run("status")
    assert r.returncode == 0 and "no items" in r.stdout
    cfg = _mock_cfg()
    t0 = dt.datetime(2026, 9, 14, 0, 0, tzinfo=dt.UTC)
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / "out")
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    _adjudicate_for_psirt_test(report, cfg)
    ledger = pl.load_ledger(tmp_path / "ledger.json")
    payloads = build_notifications(report, cfg, now=t0, event=_event(t0))
    for p in payloads:
        pl.record_attempt(ledger, p, 202, True, now=t0)
        pl.record_stage(ledger, p["dedupe_key"], "early_warning", "EW-test", now=t0)
    pl.save_ledger(ledger, tmp_path / "ledger.json")
    key = payloads[0]["dedupe_key"]
    r = run("status", "--now", "2026-09-14T12:00:00Z")
    assert r.returncode == 0 and "awaiting 72 h notification" in r.stdout and "none overdue" in r.stdout
    r = run("status", "--now", "2026-09-18T00:00:00Z")
    assert r.returncode == 1 and "OVERDUE" in r.stdout
    r = run("record", "--key", key, "--stage", "notification", "--reference", "PSIRT-42")
    assert r.returncode == 0 and "PSIRT-42" in r.stdout
    r = run("close", "--key", key, "--reason", "PSIRT: false positive after triage")
    assert r.returncode == 0 and "closed" in r.stdout
    r = run("record", "--key", "nope", "--stage", "final_report", "--reference", "x")
    assert r.returncode == 2 and "no ledger item" in r.stderr
    assert pl.load_ledger(tmp_path / "ledger.json")["items"][key]["closed"]["reason"].startswith("PSIRT: false positive")
