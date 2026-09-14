"""G-12 operations around the PSIRT hand-off: a send ledger, the Article 14 stage clock, and the endpoint handshake.

The review produces early-warning payloads (report/psirt_out.py). Three things had to live outside a
single review run:
  * the ledger (`psirt.ledger_file`, default ops/psirt/ledger.json): one item per finding key
    (product + target + file:line:cwe), so a finding re-reviewed tomorrow is not sent to the PSIRT
    again, and every send attempt with its HTTP status is on record;
  * the stage clock: the 72 h notification and the 14 d final report are produced by the PSIRT, not
    by the review, but their deadlines started at the review; `record` writes the PSIRT's reference
    for each stage and `overdue()` names every open item past a deadline, which governance G-12 reads;
  * the handshake (`psirt.handshake_file`): a clearly-marked test payload POSTed to the webhook with
    the real token, recorded with status and time. `enabled: true` in a config proves nothing about
    the endpoint; G-12 requires a successful handshake younger than `handshake_max_age_days`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path

import httpx

from .config import MaraConfig

LEDGER_SCHEMA = "mara-psirt-ledger/1"
HANDSHAKE_SCHEMA = "mara-psirt/1"
STAGES = ("early_warning", "notification", "final_report")
STAGE_DEADLINE = {"early_warning": "early_warning_by", "notification": "notification_by", "final_report": "final_report_by"}


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).isoformat(timespec="seconds")


def parse_iso(s: str) -> dt.datetime:
    t = dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def dedupe_key(product: str, target: str, file: str, line: int, cwe: str) -> str:
    """Stable identity of a finding across reviews: the receiver dedupes on it, so does the ledger."""
    return hashlib.sha256(f"{product}\n{target}\n{file}:{line}:{cwe}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------- ledger

def load_ledger(path: Path | str) -> dict:
    p = Path(path)
    if not p.is_file():
        return {"schema": LEDGER_SCHEMA, "items": {}}
    d = json.loads(p.read_text(encoding="utf-8"))
    if d.get("schema") != LEDGER_SCHEMA or not isinstance(d.get("items"), dict):
        raise ValueError(f"{p}: not a {LEDGER_SCHEMA} ledger")
    return d


def save_ledger(ledger: dict, path: Path | str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(ledger, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def item_for(ledger: dict, payload: dict, now: dt.datetime) -> dict:
    key = payload["dedupe_key"]
    item = ledger["items"].get(key)
    if item is None:
        loc = payload.get("location", {})
        item = ledger["items"][key] = {
            "key": key, "product": payload.get("product", ""), "target": payload.get("target", ""),
            "finding": {"title": payload.get("title", ""), "file": loc.get("file", ""), "line": loc.get("line", 0), "cwe": payload.get("cwe", ""),
                        "severity": (payload.get("cvss4") or {}).get("severity", ""), "tier": payload.get("evidence_tier", "")},
            "first_detected_at": payload.get("detected_at", iso(now)), "deadlines": dict(payload.get("deadlines", {})),
            "stages": {s: {} for s in STAGES}, "attempts": [], "closed": {},
        }
    return item


def already_sent(ledger: dict, key: str) -> str | None:
    """The time the early warning was first delivered (HTTP 2xx), or None."""
    item = ledger["items"].get(key)
    if not item or item.get("closed"):
        return None
    return item["stages"]["early_warning"].get("sent_at")


def record_attempt(ledger: dict, payload: dict, status_code: int, ok: bool, now: dt.datetime | None = None) -> dict:
    now = now or now_utc()
    item = item_for(ledger, payload, now)
    item["attempts"].append({"at": iso(now), "status_code": status_code, "ok": ok})
    if ok and not item["stages"]["early_warning"].get("sent_at"):
        item["stages"]["early_warning"] = {"sent_at": iso(now), "status_code": status_code}
    return item


def record_stage(ledger: dict, key: str, stage: str, reference: str, now: dt.datetime | None = None) -> dict:
    if stage not in ("notification", "final_report"):
        raise ValueError(f"stage must be notification or final_report, not {stage!r}")
    item = ledger["items"].get(key)
    if item is None:
        raise KeyError(f"no ledger item {key}")
    if not reference.strip():
        raise ValueError("a PSIRT reference (ticket, report id) is required")
    item["stages"][stage] = {"recorded_at": iso(now or now_utc()), "reference": reference.strip()}
    return item


def close_item(ledger: dict, key: str, reason: str, now: dt.datetime | None = None) -> dict:
    item = ledger["items"].get(key)
    if item is None:
        raise KeyError(f"no ledger item {key}")
    if not reason.strip():
        raise ValueError("a reason is required to close an item (e.g. not exploited per PSIRT, false positive, fixed and reported)")
    item["closed"] = {"at": iso(now or now_utc()), "reason": reason.strip()}
    return item


def overdue(ledger: dict, now: dt.datetime | None = None) -> list[tuple[str, str, str]]:
    """(key, stage, deadline) for every open item whose stage is missing after its deadline."""
    now = now or now_utc()
    out = []
    for key, item in sorted(ledger["items"].items()):
        if item.get("closed"):
            continue
        for stage in STAGES:
            done = item["stages"].get(stage, {})
            if done.get("sent_at") or done.get("recorded_at"):
                continue
            deadline = item.get("deadlines", {}).get(STAGE_DEADLINE[stage])
            if deadline and parse_iso(deadline) < now:
                out.append((key, stage, deadline))
    return out


def status_rows(ledger: dict, now: dt.datetime | None = None) -> list[dict]:
    now = now or now_utc()
    late = {(k, s) for k, s, _ in overdue(ledger, now)}
    rows = []
    for key, item in sorted(ledger["items"].items()):
        stages = item["stages"]
        if item.get("closed"):
            state = f"closed {item['closed']['at']}: {item['closed']['reason']}"
        elif not stages["early_warning"].get("sent_at"):
            state = "early warning NOT delivered"
        elif not stages["notification"].get("recorded_at"):
            state = "awaiting 72 h notification"
        elif not stages["final_report"].get("recorded_at"):
            state = "awaiting 14 d final report"
        else:
            state = "all stages recorded"
        rows.append({"key": key, "product": item["product"], "finding": item["finding"], "state": state, "deadlines": item["deadlines"],
                     "overdue": sorted(s for k, s in late if k == key)})
    return rows


# ---------------------------------------------------------------- handshake

def handshake_payload(cfg: MaraConfig, now: dt.datetime | None = None) -> dict:
    now = now or now_utc()
    return {"schema": HANDSHAKE_SCHEMA, "stage": "handshake", "product": cfg.psirt.product, "sent_at": iso(now),
            "dedupe_key": f"handshake-{now.strftime('%Y%m%dT%H%M%SZ')}",
            "note": "Connectivity test from the MARA review pipeline; NOT an incident and NOT an Article 14 notification."}


def run_handshake(cfg: MaraConfig, *, client: httpx.Client | None = None, timeout: float = 30.0, now: dt.datetime | None = None) -> dict:
    """POST the test payload with the real token; the record says whether the endpoint accepted it."""
    ps = cfg.psirt
    if not ps.webhook_url.lower().startswith("https://"):
        raise RuntimeError(f"webhook_url must be https:// (got {ps.webhook_url!r})")
    token = os.environ.get(ps.token_env, "")
    if not token:
        raise RuntimeError(f"PSIRT token environment variable {ps.token_env} is not set; refusing to send")
    payload = handshake_payload(cfg, now)
    own = client is None
    client = client or httpx.Client(timeout=timeout)
    try:
        r = client.post(ps.webhook_url, json=payload, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                                               "Idempotency-Key": payload["dedupe_key"]})
        return {"schema": "mara-psirt-handshake/1", "sent_at": payload["sent_at"], "webhook_url": ps.webhook_url, "product": ps.product,
                "status_code": r.status_code, "ok": r.is_success, "response": r.text[:300]}
    finally:
        if own:
            client.close()


def write_handshake(record: dict, path: Path | str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def handshake_status(path: Path | str, max_age_days: int, now: dt.datetime | None = None) -> tuple[bool, str]:
    p = Path(path)
    if not p.is_file():
        return False, f"no handshake record at {p}: run `scripts/psirt_ops.py handshake` against the real endpoint"
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
        sent = parse_iso(rec["sent_at"])
    except (ValueError, KeyError) as e:
        return False, f"{p} unreadable: {e}"
    age = ((now or now_utc()) - sent).days
    if not rec.get("ok"):
        return False, f"last handshake {rec.get('sent_at')} FAILED (HTTP {rec.get('status_code')})"
    if age > max_age_days:
        return False, f"last successful handshake {rec.get('sent_at')} is {age} days old (limit {max_age_days})"
    return True, f"handshake {rec.get('sent_at')} HTTP {rec.get('status_code')} to {rec.get('webhook_url')} ({age} days ago)"
