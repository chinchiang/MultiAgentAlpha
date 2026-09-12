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
