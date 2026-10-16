"""Report metadata are fields of the report, the bias audit holds counts and statistics only, and a report written before
reads alike (docs/adr/0009-report-metadata.md)."""

from __future__ import annotations

import pytest

from mara.schemas import LEGACY_METADATA, MlBomEntry, ModelEvalStatus, ReviewReport


def _as_written_before(report: ReviewReport, *, signature: str | None = None) -> dict:
    """`report` as report.json held it before the metadata became fields: each in bias_audit under its old key, the
    counts and tools_ran with them, and none of the new fields."""
    d = report.model_dump(mode="json")
    t = d.pop("human_queue_tightening")
    audit = d["bias_audit"]
    audit.update({
        "human_queue_size": len(d["human_queue"]),
        "human_queue_backlog": "unknown" if t["backlog"] is None else t["backlog"],
        "human_queue_tightened": int(t["tightened"]),
        "human_alpha_threshold": t["alpha_threshold"],
        "psirt_notifications": len(d["psirt"]),
        "ml_bom": d.pop("ml_bom"),
        "rollout_phase": d.pop("rollout_phase"),
        "model_eval": d.pop("model_eval"),
        "tool_results_ingested": len(d["tool_results"]),
        "tools_ran": ",".join(sorted(h["tool"] for h in d["tool_health"] if h["ran"])) or "none",
    })
    d.pop("ml_bom_signature")
    if signature is not None:
        audit["ml_bom_signature"] = signature
    return d


def test_a_review_keeps_no_report_metadata_in_its_bias_audit(mock_report):
    _, report = mock_report
    assert not set(LEGACY_METADATA) & set(report.bias_audit)
    assert report.rollout_phase == "not_started" and report.human_queue_tightening is not None


def test_a_report_written_before_reads_as_the_same_report(mock_report):
    _, report = mock_report
    old = _as_written_before(report)
    assert set(LEGACY_METADATA) - {"ml_bom_signature"} <= set(old["bias_audit"])
    assert ReviewReport.model_validate(old) == report


def _with_metadata(report: ReviewReport) -> ReviewReport:
    """`report` with every metadata field holding something: a self-hosted model the BOM knows, and one family's
    red-team evaluation, under the shadow phase."""
    return report.model_copy(update={
        "rollout_phase": "shadow",
        "ml_bom": {"glm-reviewer": MlBomEntry(model_id="glm-4.7", status="complete", component="glm", version="4.7", sha256="a" * 64),
                   "local": MlBomEntry(model_id="local-1", status="pending")},
        "model_eval": {"glm": ModelEvalStatus(date="2026-10-01", mode="live", status="pass"), "gemini": ModelEvalStatus()},
    })


def test_a_report_written_before_with_every_metadata_recorded_reads_as_the_same_report(mock_report):
    _, report = mock_report
    report = _with_metadata(report)
    assert ReviewReport.model_validate(_as_written_before(report, signature="verified")) == report.model_copy(
        update={"ml_bom_signature": "verified"})


@pytest.mark.parametrize("key, value", [
    ("rollout_phase", "beta"),
    ("ml_bom", {"glm-reviewer": {"status": "complete"}}),  # no model id
    ("model_eval", {"glm": "pass"}),
    ("ml_bom_signature", 5),
    ("human_queue_backlog", "lots"),
    ("human_alpha_threshold", "high"),
])
def test_an_old_value_of_another_shape_reads_as_not_recorded(mock_report, key, value):
    """The workbench refuses a report that does not validate, so one odd old value must not cost the run its report."""
    _, report = mock_report
    old = _as_written_before(_with_metadata(report), signature="verified")
    old["bias_audit"][key] = value
    read = ReviewReport.model_validate(old)
    not_recorded = {"rollout_phase": None, "ml_bom": {}, "model_eval": {}, "ml_bom_signature": None,
                    "human_queue_backlog": None, "human_alpha_threshold": None}[key]
    field = "human_queue_tightening" if key.startswith("human_") else key
    assert getattr(read, field) == not_recorded and not set(LEGACY_METADATA) & set(read.bias_audit)


@pytest.mark.parametrize("backlog", [None, 99])
def test_the_queue_tightening_and_the_bom_signature_read_back_from_an_old_report(mock_report, backlog):
    _, report = mock_report
    tightened = report.model_copy(update={"human_queue_tightening": report.human_queue_tightening.model_copy(
        update={"backlog": backlog, "tightened": backlog is not None, "alpha_threshold": 0.5})})
    read = ReviewReport.model_validate(_as_written_before(tightened, signature="failed: no signature"))
    assert read.human_queue_tightening == tightened.human_queue_tightening
    assert read.ml_bom_signature == "failed: no signature" and "ml_bom_signature" not in read.bias_audit


def test_a_report_older_than_the_metadata_reads_them_as_not_recorded(mock_report):
    """Before the human queue (G-11) and the rollout phase (G-10) were recorded at all: nothing to read, nothing guessed."""
    _, report = mock_report
    old = _as_written_before(report)
    for key in LEGACY_METADATA:
        old["bias_audit"].pop(key, None)
    read = ReviewReport.model_validate(old)
    assert (read.rollout_phase, read.human_queue_tightening, read.ml_bom, read.ml_bom_signature, read.model_eval) == (None, None, {}, None, {})
    assert read.bias_audit == report.bias_audit


def test_a_queue_tightening_recorded_in_part_is_not_guessed(mock_report):
    _, report = mock_report
    old = _as_written_before(report)
    del old["bias_audit"]["human_alpha_threshold"]
    read = ReviewReport.model_validate(old)
    assert read.human_queue_tightening is None and not set(LEGACY_METADATA) & set(read.bias_audit)


@pytest.mark.parametrize("backlog, shown", [(None, "unknown"), (99, 99)])
def test_the_workbench_reads_the_queue_and_the_metadata_from_the_fields(mock_report, backlog, shown):
    from mara.web.views import budget, report_view

    _, report = mock_report
    report = report.model_copy(update={"human_queue_tightening": report.human_queue_tightening.model_copy(
        update={"backlog": backlog, "tightened": backlog is not None})})
    b = budget({}, report, None)
    assert (b["human_queue_backlog"], b["human_queue_tightened"]) == (shown, backlog is not None)
    assert (b["human_queue_size"], b["tool_results_ingested"]) == (len(report.human_queue), len(report.tool_results))
    meta = report_view({}, report, None)["meta"]
    assert (meta["rollout_phase"], meta["ml_bom"], meta["model_eval"]) == ("not_started", {}, {})


def test_the_workbench_shows_no_queue_without_a_report():
    from mara.web.views import budget

    b = budget({}, None, None)
    assert (b["human_queue_backlog"], b["human_queue_tightened"], b["human_queue_size"], b["tool_results_ingested"]) == (None, False, 0, 0)


def test_a_report_that_has_the_field_keeps_it_over_an_old_key(mock_report):
    _, report = mock_report
    both = report.model_dump(mode="json")
    both["rollout_phase"] = "blocking"
    both["bias_audit"]["rollout_phase"] = "shadow"
    read = ReviewReport.model_validate(both)
    assert read.rollout_phase == "blocking" and "rollout_phase" not in read.bias_audit


def test_report_md_names_each_tool_that_ran_once(mock_report):
    """A live review given pre-recorded SARIF runs gitleaks again (docs/adr/0007-review-status-and-gate.md), so a tool can
    have two health entries."""
    from mara.report.markdown_out import render_markdown

    _, report = mock_report
    health = [{"tool": "gitleaks", "ran": True, "note": "pre-recorded"}, {"tool": "gitleaks", "ran": True, "note": "re-run"},
              {"tool": "semgrep", "ran": False, "note": "missing"}]
    md = render_markdown(report.model_copy(update={"tool_health": health}))
    assert f"Tools that ran: gitleaks · {len(report.tool_results)} result(s)" in md.splitlines()
