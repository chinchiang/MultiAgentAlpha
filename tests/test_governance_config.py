"""Governance checks G-7, G-8, G-9, G-11, G-12 and G-13 judge the validated config (mara.config.MaraConfig), as a review
reads it: G-7 the one ML-BOM the config names (ml_bom.path), G-8 and G-9 the production families
(mara.govdocs.production_families), G-11 and G-13 the human queue's and the training block's defaults as the config model
has them, and G-12 the trigger scope policy P6 allows (mara.policy)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

from mara import mlbom
from tests.test_ml_bom import _entry, _weights

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance_check as gc  # noqa: E402

EXAMPLE = ROOT / "config" / "examples" / "ml-bom-required.yaml"


def _config(root: Path, **sections) -> Path:
    """The example config with one self-hosted model (example/model-7b), its ML-BOM at sbom/configured.cdx.json, not
    required, and `sections` replacing whole top-level blocks."""
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw["ml_bom"] = {**raw["ml_bom"], "required": False, "require_signature": False, "path": "sbom/configured.cdx.json"}
    raw.update(sections)
    path = root / "config" / "mara.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return path


def _complete_bom(tmp_path: Path) -> str:
    return json.dumps(mlbom.build_bom([_entry(mlbom.hash_dir(_weights(tmp_path)))]))


def test_g7_judges_the_ml_bom_the_config_names_not_any_bom_in_sbom(tmp_path):
    root = tmp_path / "repo"
    cfg = _config(root)
    (root / "sbom").mkdir()
    (root / "sbom" / "other.cdx.json").write_text(_complete_bom(tmp_path), encoding="utf-8")  # complete, but not the config's
    r = gc.check_g7(root, cfg)
    assert r.status == gc.FAIL and "sbom/configured.cdx.json" in r.evidence
    (root / "sbom" / "configured.cdx.json").write_text((root / "sbom" / "other.cdx.json").read_text(encoding="utf-8"), encoding="utf-8")
    r = gc.check_g7(root, cfg)
    assert r.status == gc.PASS and "example/model-7b" in r.evidence


def test_g11_reads_a_config_without_a_human_queue_block_by_the_defaults_the_review_uses(tmp_path):
    """No human_queue block: the review's queue is enabled and files GitHub issues (config.HumanQueueConfig), so the
    config files tickets, whatever else G-11 still needs."""
    root = tmp_path / "repo"
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw.pop("human_queue", None)
    cfg = root / "config" / "mara.yaml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    r = gc.check_g11(root, cfg)
    assert "設定以 GitHub issue 開單" in r.evidence and "要啟用並以 `ticketing: github_issues` 開單" not in r.evidence


def test_g12_refuses_a_trigger_scope_wider_than_policy_p6_allows(tmp_path):
    psirt = yaml.safe_load((ROOT / "config" / "examples" / "psirt-enabled.yaml").read_text(encoding="utf-8"))["psirt"]
    root = tmp_path / "repo"
    wide = gc.check_g12(root, _config(root, psirt={**psirt, "trigger_tiers": ["A", "C"]}))
    assert wide.status == gc.FAIL and "觸發範圍過寬" in wide.evidence
    allowed = gc.check_g12(root, _config(root, psirt={**psirt, "trigger_tiers": ["A", "B"], "trigger_severities": ["Critical", "High"]}))
    assert "觸發範圍過寬" not in allowed.evidence


def test_g13_asks_for_the_roles_the_config_requires_or_by_default_every_role(tmp_path):
    root = tmp_path / "repo"
    (root / "training").mkdir(parents=True)
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    (root / "training" / "records.yaml").write_text(
        "curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
        "  - {person: dana, role: developer, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n",
        encoding="utf-8")
    import datetime as dt

    today = dt.date(2026, 10, 1)
    assert gc.check_g13(root, today, _config(root, training={"required_roles": ["developer"]})).status == gc.PASS
    by_default = gc.check_g13(root, today, _config(root))
    assert by_default.status == gc.FAIL and "security, adjudicator" in by_default.evidence


def _models(**families) -> list[dict]:
    """The example config's models, with the named models' families replaced."""
    models = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))["models"]
    return [{**m, "family": families.get(m["name"], m["family"])} for m in models]


def test_g8_and_g9_refuse_a_config_the_review_refuses_rather_than_ask_for_a_family_no_report_can_cover(tmp_path):
    """A family the config model does not know (here "DeepSeek" for deepseek) makes the review refuse the config. G-8
    and G-9 refuse it as the review does, rather than ask a live report to cover "DeepSeek"."""
    import datetime as dt

    from pydantic import ValidationError

    root = tmp_path / "repo"
    cfg = _config(root, models=_models(**{"deepseek-reviewer": "DeepSeek"}))
    today = dt.date(2026, 10, 1)
    with pytest.raises(ValidationError, match="DeepSeek"):
        gc.check_g8(root, today, cfg)
    with pytest.raises(ValidationError, match="DeepSeek"):
        gc.check_g9(root, today, cfg)


def test_g8_and_g9_ask_live_reports_to_cover_the_production_families_and_need_not_the_policies(tmp_path):
    """The families are the config's production families (mara.govdocs.production_families): not the mock nemotron,
    and anthropic once though two models have it. The second, an unapproved vendor_api_retained model, violates policy
    P5; G-8 and G-9 still give their account, as G-7 does, since G-2 and G-3 report the policies."""
    import datetime as dt

    root = tmp_path / "repo"
    standby = {"name": "claude-standby", "family": "anthropic", "provider": "bedrock", "model": "standby",
               "region": "us-east-1", "data_residency": "vendor_api_retained"}
    cfg = _config(root, models=[*_models(), standby])
    today = dt.date(2026, 10, 1)

    def report(name: str, families: list[str]) -> None:
        meta = {"mode": "live", "families": families, "provider_modes": ["live"], "labels": 3}
        (root / "docs" / f"{name}-2026-09-20.md").write_text("---\n" + yaml.safe_dump(meta) + "---\n# x\n", encoding="utf-8")

    (root / "docs").mkdir()
    for name in ("garak", "cyberseceval", "calibration"):
        report(name, ["anthropic"])
    g8, g9 = gc.check_g8(root, today, cfg), gc.check_g9(root, today, cfg)
    assert g8.status == gc.FAIL and "未涵蓋家族 ['deepseek']" in g8.evidence
    assert g9.status == gc.FAIL and "未涵蓋 ['deepseek']" in g9.evidence
    for name in ("garak", "cyberseceval", "calibration"):
        report(name, ["anthropic", "deepseek"])
    assert gc.check_g8(root, today, cfg).status == gc.PASS
    assert gc.check_g9(root, today, cfg).status == gc.PASS
