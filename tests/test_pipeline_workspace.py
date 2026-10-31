"""A review's MARA workspace (mara.workspace; Pipeline(cfg, workspace=...)): the ticket backlog, the check that no trust
anchor lies inside the target, the decision files and the training register come from the workspace the pipeline was
given, else from the one MARA_HOME named when it was built, and from that one alone for the whole review, whatever
MARA_HOME says later."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mara.config import load_config
from mara.pipeline import Pipeline
from mara.workspace import WorkspaceInsideTarget

ROOT = Path(__file__).resolve().parents[1]
TARGET, SARIF = ROOT / "fixtures" / "vuln-sample", ROOT / "fixtures" / "vuln-sample-sarif"
FIXTURES = str(ROOT / "fixtures" / "mock-responses")
REGISTER = ("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
            "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n")


def _workspace(path: Path) -> Path:
    """A MARA workspace with alice as a trained adjudicator."""
    (path / "training").mkdir(parents=True)
    (path / "training" / "records.yaml").write_text(REGISTER, encoding="utf-8")
    return path


def _decided(workspace: Path, tmp_path: Path, monkeypatch) -> int:
    """Review the fixture in `workspace` (named by MARA_HOME for this one review), then decide every queued finding
    there, as the ticket sync writes it; the number of decisions."""
    with monkeypatch.context() as m:
        m.setenv("MARA_HOME", str(workspace))
        first = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=FIXTURES,
                         out_dir=tmp_path / "first").run(TARGET, sarif_dir=SARIF, provider_mode="mock")
    d = workspace / "calib" / "decisions"
    d.mkdir(parents=True, exist_ok=True)
    for n, item in enumerate(first.human_queue, 1):
        rec = {k: getattr(item, k) for k in ("key", "target_id", "revision", "context_hash", "file", "line", "cwe")}
        rec.update(decision="false_positive", decision_event_id=1000 + n, decided_by="alice", decided_at="2026-10-01T08:00:00Z",
                   issue=n, finding_id=item.finding_id)
        (d / f"{item.key}.json").write_text(json.dumps(rec), encoding="utf-8")
    assert first.human_queue, "the seeded review queues findings to decide"
    return len(first.human_queue)


def test_a_pipeline_reads_its_evidence_from_the_workspace_it_is_given_not_mara_home(tmp_path, monkeypatch):
    given, elsewhere = _workspace(tmp_path / "given"), tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(elsewhere))
    monkeypatch.chdir(elsewhere)
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    decided = _decided(given, tmp_path, monkeypatch)
    # when it is built: the ticket backlog, over its limit only in the given workspace
    (given / cfg.human_queue.backlog_file).write_text(json.dumps({"open": cfg.human_queue.backlog_limit + 1}), encoding="utf-8")
    assert Pipeline(cfg, mock_fixtures=FIXTURES, out_dir=tmp_path / "x", workspace=given).queue_tightened
    (given / cfg.human_queue.backlog_file).unlink()
    # when it scores: the decisions and the register that says alice is trained, both only in the given workspace
    second = Pipeline(cfg, mock_fixtures=FIXTURES, out_dir=tmp_path / "second", workspace=given).run(TARGET, sarif_dir=SARIF,
                                                                                                  provider_mode="mock")
    assert second.bias_audit["human_decisions_applied"] == decided
    # when it starts: the given workspace inside the target is refused, though MARA_HOME lies outside it
    with pytest.raises(WorkspaceInsideTarget):
        Pipeline(cfg, mock_fixtures=FIXTURES, out_dir=tmp_path / "third", workspace=TARGET).run(TARGET, sarif_dir=SARIF,
                                                                                                 provider_mode="mock")


def test_a_pipeline_keeps_the_workspace_mara_home_named_when_it_was_built(tmp_path, monkeypatch):
    built, later = _workspace(tmp_path / "built"), tmp_path / "later"
    later.mkdir()
    monkeypatch.chdir(later)
    decided = _decided(built, tmp_path, monkeypatch)
    monkeypatch.setenv("MARA_HOME", str(built))
    pipe = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=FIXTURES, out_dir=tmp_path / "second")
    monkeypatch.setenv("MARA_HOME", str(later))  # a workspace with no decisions and no register
    report = pipe.run(TARGET, sarif_dir=SARIF, provider_mode="mock")
    assert report.bias_audit["human_decisions_applied"] == decided


def _with_a_self_hosted_model(cfg):
    """`cfg` with one self-hosted model beside its mock panel (in no role, so no exchange reaches it) and the ML-BOM
    signature required: the ML-BOM, its signature bundle and the model evaluations are then read for it. Its endpoint
    is a local address nothing listens on, and the pipeline's provider for it is replaced by a mock one."""
    live = load_config(ROOT / "config" / "mara.yaml")
    # no CA bundle: the live config's names a file on the operator's host, absent elsewhere (CI), and a loopback
    # http:// endpoint needs none
    spec = next(m for m in live.models if m.provider == "openai_compatible").model_copy(
        update={"name": "self-hosted", "base_url": "http://127.0.0.1:9/v1", "ca_bundle": None})
    ml_bom = cfg.ml_bom.model_copy(update={"path": live.ml_bom.path, "bundle": live.ml_bom.bundle, "require_signature": True})
    return cfg.model_copy(update={"models": [*cfg.models, spec], "ml_bom": ml_bom}), spec


def test_a_pipeline_reads_a_self_hosted_models_evidence_from_the_workspace_it_is_given(tmp_path, monkeypatch):
    from mara.providers import make_provider

    given, elsewhere = tmp_path / "given", tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(elsewhere))
    monkeypatch.chdir(elsewhere)
    cfg, spec = _with_a_self_hosted_model(load_config(ROOT / "config" / "mara.mock.yaml"))
    (given / "sbom").mkdir(parents=True)
    (given / cfg.ml_bom.path).write_text((ROOT / "sbom" / "ml-bom.cdx.json").read_text(encoding="utf-8"), encoding="utf-8")
    (given / cfg.ml_bom.bundle).write_text("{}", encoding="utf-8")  # present; cosign then decides, never "not found"
    (given / "calib").mkdir()
    (given / "calib" / "model-eval-2026-10-01.json").write_text(json.dumps(
        {"date": "2026-10-01", "mode": "live", "families": {spec.family.value: {"verdict": {"overall": "pass"}}}}), encoding="utf-8")
    pipe = Pipeline(cfg, mock_fixtures=FIXTURES, out_dir=tmp_path / "out", workspace=given)
    assert pipe.ml_bom_status["self-hosted"].status == "pending", "the given workspace's ML-BOM lists the model, pending"
    pipe.providers["self-hosted"] = make_provider(cfg.models[0], FIXTURES)
    report = pipe.run(TARGET, sarif_dir=SARIF, provider_mode="mock")
    assert report.model_eval[spec.family.value].status == "pass"
    assert report.ml_bom_signature is not None and "not found" not in report.ml_bom_signature


def test_a_pipeline_looks_its_calibration_samples_up_in_the_workspace_it_is_given(tmp_path, monkeypatch):
    import shutil

    given, elsewhere = tmp_path / "given", tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(elsewhere))
    monkeypatch.chdir(elsewhere)
    sample = given / "calib" / "samples" / "s1"
    shutil.copytree(TARGET, sample)
    (sample / "labels.json").write_text(json.dumps({"sample": "s1", "labels": [
        {"dimension": "secrets", "cwe": "CWE-798", "file": "app.py", "line": 3, "quote": "q", "title": "seeded"}]}), encoding="utf-8")
    report = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=FIXTURES, out_dir=tmp_path / "out",
                      workspace=given).run(sample, sarif_dir=SARIF, provider_mode="mock", calibration_sample=True)
    assert report.target == str(sample.resolve())
