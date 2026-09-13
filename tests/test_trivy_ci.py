"""trivy scan wiring: the CI script and the runner only ever run trivy offline against the recorded database,
never download during a scan, and read packages out of trivy's SARIF messages. Fake trivy, no network."""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trivy_ci.py"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from test_trivy_db import _fake_trivy, _now_iso  # noqa: E402
from trivy_ci import summarize  # noqa: E402

from mara.tools import runner  # noqa: E402
from mara.tools import trivy_db as tdb  # noqa: E402

VULN = "Package: requests Installed Version: 2.19.0 Vulnerability CVE-2018-18074 Severity: HIGH Fixed Version: 2.20.0 Link: [CVE-2018-18074](https://x)"
MISCONF = "Artifact: Dockerfile Type: dockerfile Vulnerability DS-0001 Severity: MEDIUM Message: Specify a tag in the 'FROM' statement"


def _res(rule: str, text: str, uri: str, line: int = 1) -> dict:
    return {"ruleId": rule, "level": "error", "message": {"text": text},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}


def _sarif(*results: dict) -> str:
    return json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy", "version": "0.74.0"}}, "results": list(results)}]})


def _setup(tmp_path: Path, sarif: str, hours_old: float = 2) -> tuple[Path, Path]:
    tools = tmp_path / "tools"
    _fake_trivy(tools, _now_iso(hours_old))
    (tools / "canned.sarif").write_text(sarif)
    cache = tmp_path / "cache"
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools), "MARA_TRIVY_CACHE_DIR": str(cache)}
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "trivy_db.py"), "download", "--repository", "example.invalid/x/db:2"],
                       capture_output=True, text=True, env=env, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    (tools / "argv.txt").unlink()
    return tools, cache


def _run(tools: Path, cache: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools), "MARA_TRIVY_CACHE_DIR": str(cache)}
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


def test_summarize_reads_packages_artifacts_and_severity():
    rows = summarize(json.loads(_sarif(_res("CVE-2018-18074", VULN, "requirements.txt", 2), _res("DS-0001", MISCONF, "Dockerfile"))))
    assert rows[0]["package"] == ("requests", "2.19.0") and rows[0]["severity"] == "HIGH" and rows[0]["artifact"] is None
    assert rows[1]["artifact"] == ("Dockerfile", "dockerfile") and rows[1]["package"] is None and rows[1]["severity"] == "MEDIUM"


def test_fixture_mode_requires_the_expected_package_and_scans_offline(tmp_path):
    tools, cache = _setup(tmp_path, _sarif(_res("CVE-2018-18074", VULN, "requirements.txt", 2)))
    r = _run(tools, cache, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "f.sarif"), "--expect-package", "requests")
    assert r.returncode == 0 and "expected package requests reported vulnerable in 1" in r.stdout, r.stdout + r.stderr
    argv = (tools / "argv.txt").read_text()
    for flag in tdb.OFFLINE_FLAGS:
        assert flag in argv, f"{flag} missing: the scan must never reach the network"
    assert f"--cache-dir {cache}" in argv and "fs" in argv and "--file-patterns" not in argv
    r = _run(tools, cache, "--target", "fixtures/vuln-sample", "--report", str(tmp_path / "g.sarif"), "--expect-package", "urllib3")
    assert r.returncode == 2 and "expected urllib3" in r.stderr


def test_repo_mode_fails_on_findings_and_passes_clean(tmp_path):
    tools, cache = _setup(tmp_path, _sarif(_res("DS-0001", MISCONF, "Dockerfile")))
    r = _run(tools, cache, "--target", ".", "--report", str(tmp_path / "r.sarif"), "--ignorefile", "tools/trivyignore.yaml", "--skip-dirs", "fixtures,calib/samples")
    assert r.returncode == 2 and "FINDINGS: 1" in r.stdout and "DS-0001  MEDIUM  Dockerfile (dockerfile)" in r.stdout, r.stdout + r.stderr
    argv = (tools / "argv.txt").read_text()
    assert "--ignorefile" in argv and "--skip-dirs fixtures,calib/samples" in argv and "--file-patterns pip:.*-requirements\\.txt" in argv
    (tools / "canned.sarif").write_text(_sarif())
    r = _run(tools, cache, "--target", ".", "--report", str(tmp_path / "s.sarif"), "--ignorefile", "tools/trivyignore.yaml")
    assert r.returncode == 0 and "no findings" in r.stdout
    r = _run(tools, cache, "--target", ".", "--report", str(tmp_path / "t.sarif"), "--ignorefile", "tools/nonexistent.yaml")
    assert r.returncode == 2 and "not found" in r.stderr


def test_stale_or_missing_database_blocks_the_scan(tmp_path):
    tools, cache = _setup(tmp_path, _sarif(), hours_old=80)
    r = _run(tools, cache, "--target", ".", "--report", str(tmp_path / "r.sarif"))
    assert r.returncode == 2 and "older than the 48 h limit" in r.stdout and "trivy Version" not in r.stdout, "no scan with a stale database"
    r = _run(tools, tmp_path / "nowhere", "--target", ".", "--report", str(tmp_path / "r.sarif"))
    assert r.returncode == 2 and "no database" in r.stdout


def test_runner_scans_offline_with_the_recorded_database_and_skips_without_it(tmp_path, monkeypatch):
    tools, cache = _setup(tmp_path, _sarif(_res("CVE-2018-18074", VULN, "requirements.txt", 2)))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(cache))
    target = tmp_path / "target"
    target.mkdir()
    (run,) = runner.run_all(target, tmp_path / "out", enabled=["trivy"])
    assert run.ran and run.results[0].rule_id == "CVE-2018-18074" and "db 20" in run.note, run.note
    argv = (tools / "argv.txt").read_text()
    assert all(flag in argv for flag in tdb.OFFLINE_FLAGS) and "download-db-only" not in argv, "a review never downloads the database"
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(tmp_path / "empty"))
    (run,) = runner.run_all(target, tmp_path / "out2", enabled=["trivy"])
    assert not run.ran and "no offline database" in run.note and "trivy_db.py download" in run.note
