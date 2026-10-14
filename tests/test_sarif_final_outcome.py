"""SARIF decides from the final outcome which findings code scanning sees (docs/adr/0007-review-status-and-gate.md)."""

from mara.report.sarif_out import to_sarif


def _results(report) -> dict[str, dict]:
    return {r["properties"]["findingId"]: r for r in to_sarif(report)["runs"][0]["results"]}


def test_a_finding_needing_a_human_is_a_note_even_when_the_human_queue_is_disabled(mock_report):
    """A disabled queue (human_queue.enabled: false) queues nothing; the review is still incomplete on these findings,
    so code scanning must still show them, as notes rather than confirmed alerts."""
    _, report = mock_report
    unqueued = report.model_copy(update={"human_queue": []})
    waiting = {c.finding_id for c in report.consensus if c.final_outcome == "needs_human"}
    assert waiting, "the seeded fixture has findings that need a human"
    results = _results(unqueued)
    assert waiting <= set(results)
    assert {results[fid]["level"] for fid in waiting} == {"note"}
    assert not any(results[fid]["properties"]["humanQueue"] for fid in waiting)


def _old_emitted(report) -> dict[str, str]:
    """to_sarif's emit rule and level before ADR 0007, kept as the reference: finding id -> level."""
    from mara.report.sarif_out import LEVEL

    queued = {i.finding_id for i in report.human_queue}
    out = {}
    for c in report.consensus:
        final_accepted = c.human_decision["decision"] == "true_positive" if c.human_decision else c.accepted
        dismissed = c.resolved_by_human and not final_accepted
        if not final_accepted and c.finding_id not in queued and not dismissed:
            continue
        out[c.finding_id] = "note" if c.finding_id in queued else LEVEL[c.cvss4_severity]
    return out


def test_with_the_human_queue_enabled_code_scanning_sees_what_it_saw_before(mock_report):
    from mara.report.human_queue_out import build_queue

    pipe, report = mock_report
    report = report.model_copy(deep=True)
    cons = {c.finding_id: c for c in report.consensus}
    decided = {"key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}
    # a rejection under review (P8), a human false positive on an accepted finding, a human true positive on a waiting one
    cons["F-0016"].accepted, cons["F-0016"].unsupervised_reject_unverified = False, True
    cons["F-0057"].human_decision = {"decision": "false_positive", **decided}
    cons["F-0009"].human_decision = {"decision": "true_positive", **decided}
    report.human_queue = build_queue(report.findings, cons, {v.finding_id: v for v in report.skeptic},
                                     {n.finding_id: n for n in report.redteam}, report.votes, pipe.cfg)
    assert "F-0016" in {i.finding_id for i in report.human_queue}
    assert {fid: r["level"] for fid, r in _results(report).items()} == _old_emitted(report)
    assert _results(report)["F-0057"]["suppressions"][0]["status"] == "accepted", "the human false positive is dismissed"


def test_the_run_says_why_the_gate_blocked_and_each_blocking_result_why_it_blocks(mock_report):
    _, report = mock_report
    run = to_sarif(report)["runs"][0]
    assert run["properties"]["gateReasons"] == ["review_incomplete", "blocking_tier_and_severity"]
    assert run["properties"]["gateEnforced"] is False
    results = _results(report)
    assert results["F-0001"]["properties"]["blockingReason"] == "blocking_tier_and_severity"
    assert results["F-0001"]["level"] == "error", "a blocking result keeps the level of its severity"
    assert "blockingReason" not in results["F-0016"]["properties"], "only a blocking finding carries one"
