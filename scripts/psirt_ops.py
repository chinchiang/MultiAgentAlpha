"""G-12 operations: prove the PSIRT endpoint works, and keep the Article 14 stage clock per finding.

  python3 scripts/psirt_ops.py handshake [--config config/mara.yaml] [--dry-run]
      POST a clearly-marked test payload to psirt.webhook_url with the token from psirt.token_env and
      write psirt.handshake_file (time, HTTP status). Governance G-12 needs a successful handshake younger
      than psirt.handshake_max_age_days: `enabled: true` alone proves nothing about the endpoint.
  python3 scripts/psirt_ops.py status [--config ...] [--now ISO]
      every finding in the ledger with its stage and deadlines; exit 1 when any open item is past a
      deadline (early warning not delivered, 72 h notification or 14 d final report not recorded).
  python3 scripts/psirt_ops.py record --key <dedupe_key> --stage notification|final_report --reference PSIRT-123
      the PSIRT produced the 72 h notification / 14 d final report: record its reference.
  python3 scripts/psirt_ops.py close --key <dedupe_key> --reason "..."
      the PSIRT decided the item is not an Article 14 event (not exploited, false positive) or it is done.

Nothing here is a notification to an authority: the early warning goes to the PSIRT from
`mara review --notify-psirt`; whether it becomes an Article 14 report is the PSIRT's call.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import psirt_ledger as pl  # noqa: E402
from mara.config import load_config  # noqa: E402


def cmd_handshake(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    ps = cfg.psirt
    if not ps.enabled:
        print("ERROR: psirt.enabled is false; enable the block (webhook_url, product, token_env) first", file=sys.stderr)
        return 2
    if a.dry_run:
        print(json.dumps(pl.handshake_payload(cfg), indent=2))
        print(f"# dry run: would POST to {ps.webhook_url} with the token from ${ps.token_env}; nothing sent, nothing recorded", file=sys.stderr)
        return 0
    rec = pl.run_handshake(cfg)
    path = ROOT / ps.handshake_file if not Path(ps.handshake_file).is_absolute() else Path(ps.handshake_file)
    pl.write_handshake(rec, path)
    print(f"handshake to {rec['webhook_url']}: HTTP {rec['status_code']} {'ok' if rec['ok'] else 'FAILED'}; recorded in {path}")
    return 0 if rec["ok"] else 1


def _ledger_path(cfg) -> Path:
    p = Path(cfg.psirt.ledger_file)
    return p if p.is_absolute() else ROOT / p


def cmd_status(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    now = pl.parse_iso(a.now) if a.now else pl.now_utc()
    ledger = pl.load_ledger(_ledger_path(cfg))
    rows = pl.status_rows(ledger, now)
    if not rows:
        print(f"ledger {_ledger_path(cfg)}: no items (no early warning has been sent yet)")
        return 0
    for r in rows:
        f = r["finding"]
        print(f"{r['key']}  {r['product']}  {f['file']}:{f['line']} {f['cwe']} {f['severity']} tier {f['tier']}  — {r['state']}"
              + (f"  OVERDUE: {', '.join(r['overdue'])}" if r["overdue"] else ""))
        print(f"    deadlines: early warning {r['deadlines'].get('early_warning_by')}, notification {r['deadlines'].get('notification_by')}, "
              f"final report {r['deadlines'].get('final_report_by')}")
    late = pl.overdue(ledger, now)
    if late:
        print(f"OVERDUE: {len(late)} stage(s) past their deadline")
        return 1
    print(f"{len(rows)} item(s), none overdue as of {pl.iso(now)}")
    return 0


def cmd_record(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    ledger = pl.load_ledger(_ledger_path(cfg))
    item = pl.record_stage(ledger, a.key, a.stage, a.reference)
    pl.save_ledger(ledger, _ledger_path(cfg))
    print(f"{a.key}: {a.stage} recorded ({a.reference}) at {item['stages'][a.stage]['recorded_at']}")
    return 0


def cmd_close(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    ledger = pl.load_ledger(_ledger_path(cfg))
    item = pl.close_item(ledger, a.key, a.reason)
    pl.save_ledger(ledger, _ledger_path(cfg))
    print(f"{a.key}: closed at {item['closed']['at']}: {item['closed']['reason']}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "mara.yaml")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("handshake")
    s.add_argument("--dry-run", action="store_true")
    s = sub.add_parser("status")
    s.add_argument("--now", help="evaluate deadlines as of this ISO time (default: now)")
    s = sub.add_parser("record")
    s.add_argument("--key", required=True)
    s.add_argument("--stage", required=True, choices=["notification", "final_report"])
    s.add_argument("--reference", required=True)
    s = sub.add_parser("close")
    s.add_argument("--key", required=True)
    s.add_argument("--reason", required=True)
    a = ap.parse_args()
    try:
        return {"handshake": cmd_handshake, "status": cmd_status, "record": cmd_record, "close": cmd_close}[a.cmd](a)
    except (RuntimeError, ValueError, KeyError, OSError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
