"""MARA's own state - calibration evidence, decisions, the backlog, the training register, the PSIRT ledger and
handshake, the ML-BOM signature, the review output - is written and read in one place: the workspace (MARA_HOME,
else the working directory). The scripts used to write it below their own checkout (ROOT) while src/ read it from
the workspace, so with MARA_HOME set every reader missed what the writers wrote (architecture review candidate 3)."""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from mara.config import MaraConfig

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture
def home(tmp_path, monkeypatch):
    """MARA_HOME somewhere, the working directory somewhere else."""
    h = tmp_path / "mara-home"
    h.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(h))
    monkeypatch.chdir(elsewhere)
    return h


def _mock_cfg(**over) -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    for k, v in over.items():
        raw[k] = {**raw.get(k, {}), **v}
    return MaraConfig.model_validate(raw, context={"skip_policies": True})


def test_no_script_builds_a_trust_anchor_path_from_its_checkout():
    anchors = re.compile(r'ROOT / "calib" / "(decisions|latest\.json|history\.json)"|ROOT / "training" / "records\.yaml"'
                         r'|ROOT / ps\.handshake_file|else ROOT / p\b')
    offenders = [f"{p.name}:{n}" for p in sorted((ROOT / "scripts").glob("*.py"))
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if anchors.search(line)]
    assert offenders == [], offenders


def test_calibration_writes_where_policy_p8_reads(home):
    import calibrate

    from mara.policy import AAT_EVIDENCE
    from mara.workspace import resolve

    paths = calibrate.anchor_paths()
    assert paths["latest"] == home / "calib" / "latest.json" == resolve(AAT_EVIDENCE)
    assert paths["history"].parent == paths["decisions"].parent == home / "calib"


def test_the_psirt_ledger_and_handshake_are_where_the_review_writes_them(home):
    import psirt_ops

    cfg = _mock_cfg()
    assert psirt_ops._ledger_path(cfg) == home / cfg.psirt.ledger_file


def test_the_default_review_output_is_in_the_workspace(home):
    from mara.pipeline import Pipeline

    assert Pipeline(_mock_cfg()).out_dir == home / "out"


@pytest.mark.parametrize("content", ["[1, 2]", '"open"', "7"])
def test_a_damaged_backlog_is_unknown_not_a_crash(home, content):
    """A list-shaped backlog.json raised AttributeError in Pipeline.__init__ (read_backlog caught TypeError only)."""
    from mara.pipeline import Pipeline
    from mara.report.human_queue_out import read_backlog

    cfg = _mock_cfg()
    path = home / cfg.human_queue.backlog_file
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    assert read_backlog(cfg) is None
    assert Pipeline(cfg).backlog is None


@pytest.mark.parametrize("content", ["[]", '"live"', "{not json"])
def test_damaged_calibration_evidence_fails_policy_p8_instead_of_crashing(home, content):
    from mara.policy import p8_unsupervised_reject

    (home / "calib").mkdir()
    (home / "calib" / "latest.json").write_text(content, encoding="utf-8")
    result = p8_unsupervised_reject(_mock_cfg(gate={"unsupervised_reject_allowed": True}))
    assert not result.passed and "missing or unreadable" in result.reason


def test_the_ml_bom_signature_bundle_is_found_in_the_workspace(home):
    """P7 looked for the bundle relative to the working directory while the BOM itself was read from the workspace."""
    from mara.policy import p7_ml_bom

    raw = yaml.safe_load((ROOT / "config" / "examples" / "ml-bom-required.yaml").read_text(encoding="utf-8"))
    raw["ml_bom"] = {**raw.get("ml_bom", {}), "require_signature": True, "bundle": "sbom/bom.sigstore.json",
                     "certificate_identity": "ci@example", "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"}
    cfg = MaraConfig.model_validate(raw, context={"skip_policies": True})
    assert "signature bundle sbom/bom.sigstore.json not found" in p7_ml_bom(cfg).reason
    (home / "sbom").mkdir()
    (home / "sbom" / "bom.sigstore.json").write_text(json.dumps({}), encoding="utf-8")
    assert "sbom/bom.sigstore.json not found" not in p7_ml_bom(cfg).reason


# ---------------------------------------------------------------- G-8 model-eval summaries


def _eval_summary(root, date="2026-09-12"):
    (root / "calib").mkdir(parents=True, exist_ok=True)
    (root / "calib" / f"model-eval-{date}.json").write_text(json.dumps(
        {"date": date, "mode": "live", "garak_version": "0.17.0", "cyberseceval_ref": "ref",
         "families": {"glm": {"verdict": {"overall": "pass"}}}}), encoding="utf-8")


def test_calibration_reads_the_model_eval_summary_the_pipeline_reads(home):
    """calibrate.load_model_eval read calib/model-eval-*.json from the script's checkout while the pipeline's
    bias audit (family_eval_status) reads the workspace: with MARA_HOME set the suggested weights ignored G-8."""
    import calibrate

    _eval_summary(home)
    assert (calibrate.load_model_eval() or {}).get("date") == "2026-09-12"


def test_model_eval_report_and_check_use_the_workspace(home, monkeypatch, capsys):
    import model_eval

    monkeypatch.setattr(sys, "argv", ["model_eval.py", "--config", str(ROOT / "config" / "examples" / "psirt-enabled.yaml"), "report",
                                      "--run-dir", str(ROOT / "fixtures" / "model-eval"), "--date", "2026-09-12",
                                      "--docs-dir", str(home / "docs")])
    assert model_eval.main() == 0
    assert (home / "calib" / "model-eval-2026-09-12.json").is_file(), "written where family_eval_status reads"
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["model_eval.py", "check"])
    model_eval.main()
    assert "2026-09-12 mode dry-run" in capsys.readouterr().out


def test_no_script_reads_or_writes_model_eval_summaries_in_its_checkout():
    pattern = re.compile(r"latest_summary\(ROOT\)|\"--summary-root\".*default=ROOT\)")
    offenders = [f"{p.name}:{n}" for p in sorted((ROOT / "scripts").glob("*.py"))
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if pattern.search(line)]
    assert offenders == [], offenders
