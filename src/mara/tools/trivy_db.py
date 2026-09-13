"""trivy's vulnerability database as an offline, recorded artifact.

trivy downloads its database (an OCI artifact, ~110 MiB compressed) at scan time unless told not to,
which hangs on isolated hosts and makes every review a network event. MARA keeps the database under
MARA_TRIVY_CACHE_DIR (default MARA_TOOLS_DIR/trivy-cache), fetched once by scripts/trivy_db.py, which
also writes mara-trivy-db.json: the repository and OCI digests it came from, trivy's own metadata.json
(UpdatedAt, NextUpdate), the SHA-256 of trivy.db and the trivy version. Scans then run with
--skip-db-update --skip-java-db-update --skip-check-update --offline-scan and never touch the network.
The upstream artifact carries no signature or attestation, so the record is the provenance.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from .runner import tools_dir

RECORD_NAME = "mara-trivy-db.json"
OFFLINE_FLAGS = ["--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--offline-scan"]


def cache_dir() -> Path:
    return Path(os.environ.get("MARA_TRIVY_CACHE_DIR") or (tools_dir() / "trivy-cache")).resolve()


def db_path(cache: Path) -> Path:
    return cache / "db" / "trivy.db"


def metadata_path(cache: Path) -> Path:
    return cache / "db" / "metadata.json"


def record_path(cache: Path) -> Path:
    return cache / RECORD_NAME


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_metadata(cache: Path) -> dict | None:
    p = metadata_path(cache)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return None


def read_record(cache: Path) -> dict | None:
    p = record_path(cache)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        return None


def parse_time(value: str) -> dt.datetime:
    v = value.strip().replace("Z", "+00:00")
    if "." in v:  # trivy writes nanoseconds; fromisoformat takes at most 6 digits
        head, rest = v.split(".", 1)
        frac = "".join(ch for ch in rest if ch.isdigit())[:6]
        tz = rest[len(frac):].lstrip("0123456789")
        v = f"{head}.{frac}{tz}"
    t = dt.datetime.fromisoformat(v)
    return t if t.tzinfo else t.replace(tzinfo=dt.UTC)


def age_hours(metadata: dict, now: dt.datetime | None = None) -> float | None:
    try:
        updated = parse_time(str(metadata["UpdatedAt"]))
    except (KeyError, ValueError):
        return None
    return ((now or dt.datetime.now(dt.UTC)) - updated).total_seconds() / 3600


def check(cache: Path, max_age_hours: float, now: dt.datetime | None = None) -> tuple[bool, list[str]]:
    """(ok, lines): the database exists, matches its record, and is younger than max_age_hours."""
    lines = []
    db = db_path(cache)
    if not db.is_file():
        return False, [f"no database at {db}: run scripts/trivy_db.py download (or import a bundle)"]
    meta = read_metadata(cache)
    if meta is None:
        return False, [f"{metadata_path(cache)} missing or unreadable"]
    rec = read_record(cache)
    if rec is None:
        return False, [f"{record_path(cache)} missing: the database was not installed by scripts/trivy_db.py"]
    ok = True
    digest = sha256_file(db)
    if digest != rec.get("trivy_db_sha256"):
        lines.append(f"trivy.db sha256 {digest[:16]}… does not match the record {str(rec.get('trivy_db_sha256'))[:16]}… (tampered or replaced)")
        ok = False
    age = age_hours(meta, now)
    if age is None:
        lines.append("metadata.json has no readable UpdatedAt")
        ok = False
    elif age > max_age_hours:
        lines.append(f"database is {age:.1f} h old (UpdatedAt {meta.get('UpdatedAt')}), older than the {max_age_hours:g} h limit: re-download")
        ok = False
    else:
        lines.append(f"database UpdatedAt {meta.get('UpdatedAt')} ({age:.1f} h old, limit {max_age_hours:g} h), "
                     f"sha256 {digest[:16]}… matches the record")
    lines.append(f"source {rec.get('repository')} manifest {rec.get('manifest_digest')} layer {rec.get('layer_digest')} "
                 f"fetched {rec.get('downloaded_at')} with trivy {rec.get('trivy_version')}")
    return ok, lines


def scan_args(exe: str, cache: Path, sarif_out: Path, scanners: str = "vuln,misconfig") -> list[str]:
    """`trivy fs` argv without the target: offline against the recorded database, SARIF out."""
    return [exe, "--cache-dir", str(cache), "fs", *OFFLINE_FLAGS, "--scanners", scanners, "--format", "sarif", "--output", str(sarif_out)]
