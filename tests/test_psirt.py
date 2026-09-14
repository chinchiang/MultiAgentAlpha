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

PSIRT = {"enabled": True, "webhook_url": "https://psirt.example.internal/intake", "product": "IPC-7000 web console", "shipped": True}


def _mock_cfg(**psirt) -> MaraConfig:
    import yaml

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {**PSIRT, **psirt}
    return MaraConfig.model_validate(raw)


@pytest.fixture(scope="module")
def shipped_report(tmp_path_factory):
    cfg = _mock_cfg()
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path_factory.mktemp("out"))
    return cfg, pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")


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
    assert p["schema"] == "mara-psirt/1" and "Article 14" in p["regulation"] and p["product"] == PSIRT["product"]
    assert p["deadlines"] == {"early_warning_by": "2026-09-13T08:00:00+00:00", "notification_by": "2026-09-15T08:00:00+00:00",
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
    assert json.loads((tmp_path / "n.json").read_text())[0]["stage"] == "early_warning"
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
    assert (out / "psirt-notifications.json").is_file() and "PSIRT payload" in res.output


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
    assert p["dedupe_key"] == pl.dedupe_key(cfg.psirt.product, report.target, p["location"]["file"], p["location"]["line"], p["cwe"])
    assert pl.dedupe_key("a", "t", "f", 1, "CWE-1") != pl.dedupe_key("a", "t", "f", 2, "CWE-1")


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
    assert failed["attempts"][0]["status_code"] == 503 and not failed["stages"]["early_warning"]
    # second review: the two delivered ones are skipped, the failed one is retried
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        second = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger)
    assert [r["skipped"] for r in second] == [True, False, True] and second[1]["ok"] and len(calls) == 4
    assert "already delivered" in second[0]["reason"]
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        forced = send_psirt(report.psirt, cfg, client=client, ledger_path=ledger, resend=True)
    assert not any(r["skipped"] for r in forced) and len(calls) == 7
    led = pl.load_ledger(ledger)
    assert all(i["stages"]["early_warning"].get("sent_at") for i in led["items"].values())
    assert len(led["items"][first[0]["dedupe_key"]]["attempts"]) == 2


def test_stage_clock_records_references_and_names_overdue_stages(shipped_report, tmp_path):
    cfg, report = shipped_report
    t0 = dt.datetime(2026, 9, 14, 0, 0, tzinfo=dt.UTC)
    payloads = build_notifications(report, cfg, now=t0)
    ledger = pl.load_ledger(tmp_path / "l.json")
    for p in payloads:
        pl.record_attempt(ledger, p, 202, True, now=t0 + dt.timedelta(hours=1))
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
        pl.record_stage(ledger, key, "early_warning", "x")
    with pytest.raises(ValueError):
        pl.close_item(ledger, key, "   ")
    with pytest.raises(KeyError):
        pl.record_stage(ledger, "nope", "notification", "x")
    # an undelivered early warning is overdue after 24 h even though it was never sent
    fresh = pl.load_ledger(tmp_path / "f.json")
    pl.record_attempt(fresh, payloads[0], 500, False, now=t0)
    assert [(s) for _, s, _ in pl.overdue(fresh, now=t0 + dt.timedelta(hours=25))] == ["early_warning"]


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
    assert good["ok"] and good["status_code"] == 200 and not bad["ok"] and bad["response"] == "nope"
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
    pl.record_attempt(ledger, build_notifications(shipped_report[1], cfg, now=dt.datetime(2020, 1, 1, tzinfo=dt.UTC))[0], 202, True)
    pl.save_ledger(ledger, root / "ops" / "psirt" / "ledger.json")
    r = check_g12(root, cfg_path)
    assert r.status == FAIL and "逾期" in r.evidence and "notification" in r.evidence


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
    ledger = pl.load_ledger(tmp_path / "ledger.json")
    payloads = build_notifications(report, cfg, now=t0)
    for p in payloads:
        pl.record_attempt(ledger, p, 202, True, now=t0)
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
