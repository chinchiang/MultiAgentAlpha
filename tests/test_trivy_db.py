"""trivy offline database, without network: a fake trivy under a temporary MARA_TOOLS_DIR writes the same
files the real one does (db/trivy.db, db/metadata.json), so download's record, status's freshness and tamper
checks, the export/import bundle round-trip and the version pin are exercised deterministically."""

import datetime as dt
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trivy_db.py"
sys.path.insert(0, str(ROOT / "scripts"))

from trivy_db import split_ref  # noqa: E402

from mara.tools import trivy_db as tdb  # noqa: E402


def _fake_trivy(tools: Path, updated_at: str, version: str = "0.74.0") -> None:
    (tools / "bin").mkdir(parents=True, exist_ok=True)
    fake = tools / "bin" / "trivy"
    # image --download-db-only -> write the db into --cache-dir; fs -> write the canned SARIF to --output; --version
    fake.write_text(f"""#!/bin/sh
if [ "$1" = --version ]; then echo 'Version: 0.74.0'; echo 'Vulnerability DB:'; exit 0; fi
echo "$@" >> {tools}/argv.txt
cache=''; out=''
while [ $# -gt 0 ]; do
  case "$1" in --cache-dir) cache=$2; shift;; --output) out=$2; shift;; esac; shift
done
if grep -q -- download-db-only {tools}/argv.txt && [ -z "$out" ]; then
  mkdir -p "$cache/db"; printf 'fake-db-bytes' > "$cache/db/trivy.db"
  printf '{{"Version":2,"NextUpdate":"2099-01-01T00:00:00Z","UpdatedAt":"{updated_at}","DownloadedAt":"{updated_at}"}}' > "$cache/db/metadata.json"
  exit 0
fi
[ -n "$out" ] && cp {tools}/canned.sarif "$out"
exit 0
""")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    (tools / "manifest.json").write_text(json.dumps({"tools": {"trivy": {"version": version}}}))
    (tools / "canned.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}]}))


def _run(tools: Path, *args: str, cache: Path | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools)}
    if cache:
        env["MARA_TRIVY_CACHE_DIR"] = str(cache)
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


def _now_iso(hours_ago: float) -> str:
    return (dt.datetime.now(dt.UTC) - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def test_split_ref_and_time_parsing():
    assert split_ref("mirror.gcr.io/aquasec/trivy-db:2") == ("mirror.gcr.io", "aquasec/trivy-db", "2")
    assert split_ref("ghcr.io/aquasecurity/trivy-db@sha256:abc") == ("ghcr.io", "aquasecurity/trivy-db", "sha256:abc")
    t = tdb.parse_time("2026-09-13T07:13:14.295197098Z")
    assert t.year == 2026 and t.tzinfo is not None and t.microsecond == 295197
    assert 4.5 < tdb.age_hours({"UpdatedAt": _now_iso(5)}) < 5.5


def test_download_records_provenance_and_status_enforces_freshness_and_integrity(tmp_path):
    tools = tmp_path / "tools"
    _fake_trivy(tools, _now_iso(3))
    cache = tmp_path / "cache"
    r = _run(tools, "download", "--repository", "example.invalid/aquasec/trivy-db:2", cache=cache)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "--download-db-only --db-repository example.invalid/aquasec/trivy-db:2" in (tools / "argv.txt").read_text()
    rec = json.loads((cache / tdb.RECORD_NAME).read_text())
    assert rec["repository"] == "example.invalid/aquasec/trivy-db:2" and rec["trivy_version"] == "0.74.0"
    assert rec["manifest_digest"] == "unknown" and "error" not in rec, "an unreachable registry is recorded as unknown, not fatal"
    assert rec["trivy_db_sha256"] == tdb.sha256_file(cache / "db" / "trivy.db") and rec["metadata"]["Version"] == 2
    r = _run(tools, "status", cache=cache)
    assert r.returncode == 0 and "3.0 h old" in r.stdout and "offline database OK" in r.stdout, r.stdout
    r = _run(tools, "status", "--max-age-hours", "2", cache=cache)
    assert r.returncode == 1 and "older than the 2 h limit" in r.stdout
    (cache / "db" / "trivy.db").write_text("replaced")
    r = _run(tools, "status", cache=cache)
    assert r.returncode == 1 and "does not match the record" in r.stdout
    r = _run(tools, "status", cache=tmp_path / "nowhere")
    assert r.returncode == 1 and "no database" in r.stdout


def test_export_import_round_trip_and_tamper_refusal(tmp_path):
    tools = tmp_path / "tools"
    _fake_trivy(tools, _now_iso(1))
    cache = tmp_path / "cache"
    assert _run(tools, "download", "--repository", "example.invalid/x/trivy-db:2", cache=cache).returncode == 0
    bundle = tmp_path / "b" / "trivy-db.tar.gz"
    r = _run(tools, "export", "--out", str(bundle), cache=cache)
    assert r.returncode == 0 and bundle.is_file() and bundle.with_name(bundle.name + ".sha256").is_file(), r.stdout + r.stderr
    digest = bundle.with_name(bundle.name + ".sha256").read_text().split()[0]
    with tarfile.open(bundle) as tf:
        assert sorted(m.name for m in tf.getmembers()) == sorted(["db/trivy.db", "db/metadata.json", tdb.RECORD_NAME])
    other = tmp_path / "other"
    r = _run(tools, "import", "--bundle", str(bundle), "--bundle-sha256", digest, cache=other)
    assert r.returncode == 0 and "imported database" in r.stdout, r.stdout + r.stderr
    assert _run(tools, "status", cache=other).returncode == 0
    assert (other / "db" / "trivy.db").read_bytes() == (cache / "db" / "trivy.db").read_bytes()
    r = _run(tools, "import", "--bundle", str(bundle), "--bundle-sha256", "0" * 64, cache=tmp_path / "o2")
    assert r.returncode == 1 and "does not match the expected" in r.stderr
    # a bundle whose trivy.db was altered after the record was written is refused
    bad = tmp_path / "bad.tar.gz"
    with tarfile.open(bad, "w:gz") as tf:
        tf.add(cache / "db" / "metadata.json", arcname="db/metadata.json")
        tf.add(cache / tdb.RECORD_NAME, arcname=tdb.RECORD_NAME)
        (tmp_path / "evil.db").write_text("evil")
        tf.add(tmp_path / "evil.db", arcname="db/trivy.db")
    r = _run(tools, "import", "--bundle", str(bad), cache=tmp_path / "o3")
    assert r.returncode == 1 and "refusing to import" in r.stderr and not (tmp_path / "o3" / "db").exists()


def test_trivy_only_from_tools_dir_and_version_must_match_lock(tmp_path):
    tools = tmp_path / "tools"
    _fake_trivy(tools, _now_iso(1), version="0.60.0")
    r = _run(tools, "download", cache=tmp_path / "c")
    assert r.returncode == 2 and "does not match tools/versions.lock" in r.stderr
    empty = tmp_path / "none"
    empty.mkdir()
    r = _run(empty, "download", cache=tmp_path / "c")
    assert r.returncode == 2 and "not installed" in r.stderr and "PATH is never used" in r.stderr
