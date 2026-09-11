"""The calibration loop runs end to end on a labelled sample with label-driven mock families."""

import json
import subprocess
import sys

from mara.config import load_config
from mara.pipeline import Pipeline


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
