"""The calibration loop runs end to end on a labelled sample with label-driven mock families."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mara.config import load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402


def test_label_driven_mock_and_calibrate(root, tmp_path):
    cfg = load_config(root / "config" / "mara.mock.yaml")
    sample = root / "calib" / "samples" / "s1-fastapi-inventory"
    out = tmp_path / "calib-out" / sample.name
    pipe = Pipeline(cfg, out_dir=out)
    report = pipe.run(sample, mode="mock")
    labels = json.loads((sample / "labels.json").read_text())["labels"]
    assert report.findings, "label-driven mock produced no findings"
    assert all(f.finder_families for f in report.findings)
    assert report.bias_audit["reviewer_refusals[nemotron]"] == 1  # nemotron profile refuses error_handling
    fake = [f for f in report.findings if "mock false positive" in f.title]
    assert fake and not any(p.verified for p in fake[0].provenance)
    hit = sum(1 for lab in labels for f in report.findings
              if f.provenance[0].file == lab["file"] and abs(f.provenance[0].line - lab["line"]) <= 3 and f.cwe == lab["cwe"])
    assert hit >= len(labels) * 0.6
    (out / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    rep_md = tmp_path / "calibration.md"
    cp = subprocess.run(
        [sys.executable, str(root / "scripts" / "calibrate.py"), "--out-dir", str(tmp_path / "calib-out"),
         "--samples-dir", str(root / "calib" / "samples"), "--report", str(rep_md)],
        capture_output=True, text=True, cwd=root,
    )
    assert cp.returncode == 0, cp.stderr
    text = rep_md.read_text(encoding="utf-8")
    assert "anthropic" in text and "建議家族權重" in text
    assert "weight=" in cp.stdout


# ------------------------------------------------------------------ per-role refusals, refutation and weight discounts (#30/#38)

def test_audit_rates_reports_per_role_refusals_and_invalid_output():
    import calibrate

    rep = {"bias_audit": {
        "reviewer_calls[anthropic]": 10, "reviewer_refusals[anthropic]": 2, "invalid_findings_dropped[anthropic]": 3,
        "skeptic_calls[anthropic]": 5, "skeptic_refusals[anthropic]": 1, "skeptic_invalid_items[anthropic]": 1,
        "skeptic_refuted[anthropic]": 2, "skeptic_unverified_controls[anthropic]": 1,
        "redteam_calls[anthropic]": 4, "redteam_refusals[anthropic]": 1, "redteam_invalid_items[anthropic]": 1,
        "judge_calls[anthropic]": 8, "judge_refusals[anthropic]": 2, "judge_invalid_items[anthropic]": 1,
    }}
    r = calibrate.audit_rates([("s", rep, [])], ["anthropic"])["anthropic"]
    assert r["refusal_rate"] == 0.2 and r["invalid_rate"] == 0.3
    assert r["skeptic_refusal_rate"] == 0.2 and r["skeptic_invalid_rate"] == 0.2 and r["skeptic_refuted"] == 2
    assert r["redteam_refusal_rate"] == 0.25 and r["redteam_invalid_rate"] == 0.25
    assert r["judge_refusal_rate"] == 0.25 and r["judge_invalid_rate"] == 0.125
    assert r["skeptic_unverified_controls"] == 1


def test_refutation_rates_are_per_finder_family():
    import calibrate

    rep = {"findings": [
        {"id": "F-1", "finder_families": ["anthropic"]},
        {"id": "F-2", "finder_families": ["anthropic", "deepseek"]},
        {"id": "F-3", "finder_families": ["deepseek"]},
    ], "skeptic": [{"finding_id": "F-1", "verdict": "refuted"}, {"finding_id": "F-3", "verdict": "refuted"}]}
    rates = calibrate.refutation_rates([("s", rep, [])], ["anthropic", "deepseek"])
    assert rates["anthropic"] == 0.5 and rates["deepseek"] == 0.5


def test_suggested_weights_discount_refutations_and_invalid_output():
    import calibrate

    stats = {f: {"CWE-79": {"tp": 9, "fp": 1, "fn": 1}} for f in ("a", "b", "c")}
    rel = {f: 0.9 for f in ("a", "b", "c")}
    base = calibrate.suggest_weights(stats, rel, ["a", "b", "c"])
    disc = calibrate.suggest_weights(stats, rel, ["a", "b", "c"],
                                     refuted_rates={"a": 0.5}, rates={"b": {"invalid_rate": 0.2}})
    assert disc["a"]["weight"] == round(base["a"]["weight"] * 0.5, 2)  # over-reporting family
    assert disc["b"]["weight"] == round(base["b"]["weight"] * 0.8, 2) and disc["b"]["invalid_discounted"]
    assert disc["c"]["weight"] == base["c"]["weight"]  # no discount without cause
    assert disc["a"]["skeptic_refuted_rate"] == 0.5 and disc["b"]["invalid_output_rate"] == 0.2
