"""Early warning for scanner exceptions that are about to expire.

tools/osv-*.toml (IgnoredVulns: id + ignoreUntil) and tools/trivyignore.yaml (vulnerabilities/misconfigurations:
id + expired_at) let a finding that cannot be relocked away pass until a date; after it the scan fails again.
scripts/osv_ci.py and scripts/trivy_ci.py call warn() so the job shows a GitHub annotation WARN_DAYS ahead
instead of the first notice being a red L0 job. Standard library plus PyYAML (already in the CI closure).
"""

from __future__ import annotations

import datetime as dt
import tomllib
from pathlib import Path

WARN_DAYS = 30


def _as_date(v: object) -> dt.date | None:
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    if isinstance(v, str):
        try:
            return dt.date.fromisoformat(v[:10])
        except ValueError:
            return None
    return None


def osv_entries(path: Path) -> list[tuple[str, dt.date | None]]:
    d = tomllib.loads(path.read_text(encoding="utf-8"))
    return [(str(e.get("id", "")), _as_date(e.get("ignoreUntil"))) for e in d.get("IgnoredVulns", []) or []]


def trivy_entries(path: Path) -> list[tuple[str, dt.date | None]]:
    import yaml

    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for section in ("vulnerabilities", "misconfigurations", "secrets", "licenses"):
        for e in d.get(section) or []:
            out.append((str(e.get("id", "")), _as_date(e.get("expired_at"))))
    return out


def expiring(entries: list[tuple[str, dt.date | None]], today: dt.date, days: int = WARN_DAYS) -> list[str]:
    """One message per entry that has expired, expires within `days`, or has no readable expiry."""
    msgs = []
    for vid, until in entries:
        if until is None:
            msgs.append(f"{vid}: exception has no readable expiry date")
        elif until < today:
            msgs.append(f"{vid}: exception expired on {until}")
        elif (until - today).days <= days:
            msgs.append(f"{vid}: exception expires on {until} ({(until - today).days} days); re-check for a fixed release and relock, or renew it with a new statement")
    return msgs


def warn(path: Path, entries: list[tuple[str, dt.date | None]], today: dt.date | None = None) -> int:
    msgs = expiring(entries, today or dt.date.today())
    for m in msgs:
        print(f"::warning file={path}::{m}")
    return len(msgs)
