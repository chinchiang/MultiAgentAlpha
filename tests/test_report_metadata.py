"""Report metadata are fields of the report, the bias audit holds counts and statistics only, and a report written before
reads alike (docs/adr/0009-report-metadata.md)."""

from __future__ import annotations

import pytest

from mara.schemas import LEGACY_METADATA, ReviewReport


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
