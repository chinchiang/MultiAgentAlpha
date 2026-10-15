"""trivy-db import needs an out-of-band digest, the dead CVSS fallback and config key are gone, the report header
says when --fail-on-gate enforced a blocked gate, and the in-country example uses the gateway's DeepSeek alias."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from mara.cli import app
from mara.config import MaraConfig, load_config
from mara.tools import trivy_db as tdb
from tests.cli_output import plain
from tests.test_trivy_db import _fake_trivy, _now_iso

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "trivy_db.py"


def _trivy(tools: Path, *args: str, cache: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools), "MARA_TRIVY_CACHE_DIR": str(cache)}
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=ROOT)


# ------------------------------------------------------------------ trivy-db import needs --bundle-sha256

def test_import_requires_an_out_of_band_bundle_digest(tmp_path):
    tools, cache = tmp_path / "tools", tmp_path / "cache"
    _fake_trivy(tools, _now_iso(1))
    assert _trivy(tools, "download", "--repository", "example.invalid/x/trivy-db:2", "--allow-unknown-provenance", cache=cache).returncode == 0
    bundle = tmp_path / "b" / "trivy-db.tar.gz"
    exported = _trivy(tools, "export", "--out", str(bundle), cache=cache)
    digest = tdb.sha256_file(bundle)
    assert exported.returncode == 0 and f"--bundle-sha256 {digest}" in exported.stdout, "export prints the command to run"
    refused = _trivy(tools, "import", "--bundle", str(bundle), cache=tmp_path / "o1")
    assert refused.returncode == 2 and "--bundle-sha256 is required" in refused.stderr
    assert not (tmp_path / "o1" / "db").exists(), "nothing is imported without the digest"
    assert _trivy(tools, "import", "--bundle", str(bundle), "--bundle-sha256", digest, cache=tmp_path / "o2").returncode == 0
    trusted = _trivy(tools, "import", "--bundle", str(bundle), "--trust-bundle", cache=tmp_path / "o3")
    assert trusted.returncode == 0 and tdb.db_path(tmp_path / "o3").is_file()


# ------------------------------------------------------------------ dead code removed

def test_the_retired_family_diversity_key_is_refused_and_no_shipped_config_uses_it():
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    with pytest.raises(ValueError, match="require_family_diversity"):
        MaraConfig.model_validate({**raw, "require_family_diversity": True})
    for p in [ROOT / "config" / n for n in ("mara.yaml", "mara.mock.yaml", "mara.test.yaml")] + sorted((ROOT / "config" / "examples").glob("*.yaml")):
        assert "require_family_diversity" not in p.read_text(encoding="utf-8"), p.name


def test_scoring_has_no_unknown_cvss_fallback():
    src = (ROOT / "src" / "mara" / "pipeline.py").read_text(encoding="utf-8")
    assert "CVSS4Error" not in src and "invalid_cvss_vector" not in src and "invalid_cvss_vectors" not in src


# ------------------------------------------------------------------ report header under --fail-on-gate

def _shadow_cfg(tmp_path: Path) -> Path:
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = {"phase": "shadow", "started_on": "2026-09-01"}
    cfg = tmp_path / "shadow.yaml"
    cfg.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return cfg


def test_report_header_says_when_fail_on_gate_enforced_the_gate(tmp_path):
    args = ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(_shadow_cfg(tmp_path)),
            "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif")]
    forced = CliRunner().invoke(app, [*args, "--out", str(tmp_path / "forced"), "--fail-on-gate"])
    md = (tmp_path / "forced" / "report.md").read_text(encoding="utf-8")
    header = md.split("\n## ")[0]
    assert forced.exit_code == 2 and "rollout phase `shadow` (enforced)" in header and "recorded, not enforced" not in md
    assert "the gate blocked: enforced (exit 2)" in plain(forced.output)
    # the report records the enforcement (docs/adr/0007-review-status-and-gate.md), and the CLI says why the gate blocked
    assert json.loads((tmp_path / "forced" / "report.json").read_text(encoding="utf-8"))["gate_enforced"] is True
    assert "gate reasons: review_incomplete, blocking_tier_and_severity" in plain(forced.output)
    recorded = CliRunner().invoke(app, [*args, "--out", str(tmp_path / "recorded")])
    md = (tmp_path / "recorded" / "report.md").read_text(encoding="utf-8")
    header = md.split("\n## ")[0]
    assert recorded.exit_code == 0 and "rollout phase `shadow` (recorded, not enforced)" in header and "--fail-on-gate" not in header
    assert json.loads((tmp_path / "recorded" / "report.json").read_text(encoding="utf-8"))["gate_enforced"] is False


def test_in_the_blocking_phase_a_blocked_gate_is_enforced_and_says_so(tmp_path):
    """The CLI and report.md read gate_enforced alone (docs/adr/0007-review-status-and-gate.md), so the blocking phase,
    which enforces without --fail-on-gate, says so like any other enforced gate; before, it said nothing."""
    cfg = _shadow_cfg(tmp_path)
    raw = yaml.safe_load(cfg.read_text(encoding="utf-8"))
    raw["rollout"]["phase"] = "blocking"
    cfg.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(cfg),
                                   "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(tmp_path / "out")])
    assert res.exit_code == 2 and "the gate blocked: enforced (exit 2)" in plain(res.output)
    header = (tmp_path / "out" / "report.md").read_text(encoding="utf-8").split("\n## ")[0]
    assert "rollout phase `blocking` (enforced)" in header
    assert json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))["gate_enforced"] is True


# ------------------------------------------------------------------ in-country example

def test_prc_site_example_uses_the_gateway_aliases_and_passes_the_policies():
    cfg = load_config(ROOT / "config" / "examples" / "prc-site.yaml")
    ds, glm = cfg.model_by_name("deepseek-local"), cfg.model_by_name("glm-local")
    assert ds.model == "deepseek" and glm.model == "glm" and not glm.strict_schema
    assert all(m.data_residency == "on_prem" and m.base_url.startswith("https://10.") for m in (ds, glm))
    assert {m.family.value for m in cfg.models} == {"deepseek", "glm"} and cfg.reduced_panel_reason
