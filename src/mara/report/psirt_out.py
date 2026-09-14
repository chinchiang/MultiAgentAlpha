"""G-12: hand accepted tier-A Critical findings on a shipped product to the PSIRT (EU CRA Article 14).

The pipeline never decides that a vulnerability is "actively exploited" (that is the PSIRT's call
and the legal trigger of Article 14); it starts the clock by delivering, within the review run,
every finding that meets the configured tier and severity with the evidence the PSIRT needs and
the deadlines counted from the review timestamp. Payloads are always written to
out/psirt-notifications.json; sending requires --notify-psirt and a bearer token from the
environment. False positives are bounded by policy P6: only tier A/B and Critical/High may notify.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

import httpx

from ..config import MaraConfig
from ..psirt_ledger import already_sent, dedupe_key, load_ledger, now_utc, record_attempt, save_ledger
from ..schemas import ReviewReport

SCHEMA = "mara-psirt/1"


def select_psirt_findings(report: ReviewReport, cfg: MaraConfig) -> list[tuple]:
    ps = cfg.psirt
    if not (ps.enabled and ps.shipped):
        return []
    cons = {c.finding_id: c for c in report.consensus}
    red = {n.finding_id: n for n in report.redteam}
    out = []
    for f in report.findings:
        c = cons.get(f.id)
        if c and c.accepted and c.tier.value in ps.trigger_tiers and c.cvss4_severity in ps.trigger_severities:
            out.append((f, c, red.get(f.id)))
    return out


def build_notifications(report: ReviewReport, cfg: MaraConfig, now: dt.datetime | None = None) -> list[dict]:
    ps = cfg.psirt
    detected = now or dt.datetime.fromisoformat(report.generated_at)
    if detected.tzinfo is None:
        detected = detected.replace(tzinfo=dt.UTC)
    deadlines = {
        "early_warning_by": (detected + dt.timedelta(hours=ps.early_warning_hours)).isoformat(timespec="seconds"),
        "notification_by": (detected + dt.timedelta(hours=ps.notification_hours)).isoformat(timespec="seconds"),
        "final_report_by": (detected + dt.timedelta(days=ps.final_report_days)).isoformat(timespec="seconds"),
    }
    payloads = []
    for f, c, rt in select_psirt_findings(report, cfg):
        p = f.provenance[0]
        payloads.append({
            "schema": SCHEMA,
            "regulation": "EU CRA (Regulation (EU) 2024/2847) Article 14",
            "stage": "early_warning",
            "product": ps.product,
            "target": report.target,
            "detected_at": detected.isoformat(timespec="seconds"),
            "deadlines": deadlines,
            "dedupe_key": dedupe_key(ps.product, report.target, p.file, p.line, f.cwe),
            "finding_id": f.id,
            "title": f.title,
            "dimension": f.dimension,
            "cwe": f.cwe,
            "standard_refs": list(f.standard_refs),
            "location": {"file": p.file, "line": p.line, "quote": p.quote[:200]},
            "cvss4": {"vector": f.cvss4_vector, "score": c.cvss4_score, "severity": c.cvss4_severity},
            "evidence_tier": c.tier.value,
            "ssvc": c.ssvc_decision,
            "reachability": f.reachability,
            "exploitable": rt.exploitable if rt else "unknown",
            "preconditions": rt.preconditions if rt else "",
            "families_agreeing": [x.value for x in c.families_agreeing],
            "tool_corroborated": c.tool_corroborated,
            "consensus": c.weighted_score,
            "note": ("Automated hand-off from the MARA review; whether the vulnerability is actively exploited "
                     "(the Article 14 trigger) is the PSIRT's determination."),
        })
    return payloads


def write_psirt(payloads: list[dict], path: Path) -> None:
    path.write_text(json.dumps(payloads, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def send_psirt(payloads: list[dict], cfg: MaraConfig, *, client: httpx.Client | None = None, timeout: float = 30.0,
               ledger_path: Path | str | None = None, resend: bool = False, now: dt.datetime | None = None) -> list[dict]:
    """POST each payload as JSON with a bearer token from the environment. Returns per-payload status.

    With a ledger, a finding whose early warning was already delivered is skipped (result `skipped: True`)
    unless resend=True, every attempt is recorded, and the request carries `Idempotency-Key: <dedupe_key>`
    so the receiver can dedupe too."""
    ps = cfg.psirt
    token = os.environ.get(ps.token_env, "")
    if not token:
        raise RuntimeError(f"PSIRT token environment variable {ps.token_env} is not set; refusing to send")
    ledger = load_ledger(ledger_path) if ledger_path else None
    own = client is None
    client = client or httpx.Client(timeout=timeout)
    results = []
    try:
        for payload in payloads:
            key = payload.get("dedupe_key", "")
            if ledger is not None and not resend and (sent := already_sent(ledger, key)):
                results.append({"finding_id": payload["finding_id"], "dedupe_key": key, "skipped": True, "ok": True, "status_code": None,
                                "reason": f"early warning already delivered {sent}"})
                continue
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            if key:
                headers["Idempotency-Key"] = key
            r = client.post(ps.webhook_url, json=payload, headers=headers)
            results.append({"finding_id": payload["finding_id"], "dedupe_key": key, "skipped": False, "status_code": r.status_code,
                            "ok": r.is_success})
            if ledger is not None:
                record_attempt(ledger, payload, r.status_code, r.is_success, now or now_utc())
    finally:
        if own:
            client.close()
        if ledger is not None:
            save_ledger(ledger, ledger_path)
    return results
