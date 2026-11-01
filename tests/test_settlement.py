"""mara.settlement (GLOSSARY.md: final outcome, blocking finding, usable decision, reviewed content): a review's consensus
rows are finished in one order, the usable decisions first, then why each blocking finding blocks, which depends on the
final outcome the decisions leave (docs/adr/0007-review-status-and-gate.md)."""

from __future__ import annotations

from mara import settlement
from mara.review_status import GatePolicy
from mara.reviewed_content import ReviewedContent
from tests import scored_rows
from tests.usable_decisions import decision, usable

CONTENT = ReviewedContent("t" * 64, "r1", "c" * 64)
GATE = GatePolicy.from_config(scored_rows.MOCK)


def _finish(findings, rows, selection):
    return settlement.finish(findings, rows, selection, CONTENT, outcome_policy=scored_rows.policy(), gate_policy=GATE)


def test_a_ruling_that_rejects_an_accepted_finding_leaves_it_without_a_blocking_reason():
    f, c = scored_rows.finding("F-1"), scored_rows.row("accepted")
    assert _finish([f], [c], usable(decision(f, "false_positive", content=CONTENT))) == 1
    assert c.jury_outcome == "accepted" and c.final_outcome == "rejected"
    assert c.blocking_reason is None, "the reason follows the final outcome, so the ruling is settled before it"


def test_a_ruling_that_accepts_a_rejected_finding_makes_it_block_the_gate():
    f, c = scored_rows.finding("F-1"), scored_rows.row("rejected")  # tier A, High: a blocking tier and severity
    assert _finish([f], [c], usable(decision(f, "true_positive", content=CONTENT))) == 1
    assert c.jury_outcome == "rejected" and c.final_outcome == "accepted"
    assert c.blocking_reason == "blocking_tier_and_severity"


def test_without_a_usable_decision_finish_only_records_why_the_accepted_findings_block():
    findings = [scored_rows.finding("F-1"), scored_rows.finding("F-2")]
    accepted, dropped = scored_rows.row("accepted", "F-1"), scored_rows.row("dropped", "F-2")
    assert _finish(findings, [accepted, dropped], usable()) == 0
    assert accepted.human_decision is None and accepted.blocking_reason == "blocking_tier_and_severity"
    assert dropped.human_decision is None and dropped.blocking_reason is None
