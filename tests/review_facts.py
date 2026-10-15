"""Review facts, policies and consensus rows for tests of mara.review_status and of what reads its results
(docs/adr/0007-review-status-and-gate.md)."""

from __future__ import annotations

from mara.review_status import GatePolicy, ReviewFacts
from mara.schemas import ConsensusResult, DimensionScore, EvidenceTier, ModelFamily
from mara.scoring.outcome import OutcomePolicy

OUTCOME = OutcomePolicy(accept_threshold=0.6, alpha_threshold=0.4, exclude_tier_c=False, tier_c_min_severity="High",
                        unsupervised_reject_allowed=False)
GATE = GatePolicy(block_on_tiers=frozenset({"A", "B"}), block_on_severity=frozenset({"High", "Critical"}), min_dimension_score=60.0)
# a review where every fact is in order
FACTS = ReviewFacts(context_complete=True, egress_blocked=False, required_tools_ran=True, ml_bom_signature=None,
                    context_view_missing=False, incomplete_counters=(), rollout_phase="shadow", fail_on_gate=False)


def dim(name: str, score: float) -> DimensionScore:
    return DimensionScore(dimension=name, score=score, accepted_findings=0, rejected_findings=0, human_queue=0, tool_ran=True)


def row(fid: str, tier: str, severity: str, outcome: str, decision: str | None = None) -> ConsensusResult:
    """A consensus row for assess and the readers of its results, consistent in what they read: the tier, the
    severity, the jury outcome as JuryOutcome.consensus_fields writes it (accepted or needing a human, never both; a
    reason whenever it needs a human; the P8 flag on a rejection under OUTCOME, where unsupervised rejection is not
    allowed), and optionally a usable human decision on it. `outcome` is the jury outcome (accepted, rejected, dropped,
    needs_human).

    The score, votes, agreeing families, tool corroboration and independent judges are illustrative, roughly the
    signals behind such an outcome (a rejection at tier A: tool corroboration and three independent judges, one for),
    not what Pipeline.score would write for the row: scoring, for one, also counts the finders' family as agreeing
    whenever the score reaches the threshold. A test that reads those fields needs rows scoring produced (as
    tests/test_sarif_final_outcome.py rescores them), not these. Which outcomes scoring reaches at which tier depends on
    the panel (docs/adr/0005-jury-outcome.md); the exhaustive comparison in tests/test_review_status.py feeds every
    combination on purpose."""
    human = {"decision": decision, "key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}
    tool = tier == "A"
    if outcome == "accepted":
        score, tp, fp, independent, agreeing, reasons = 1.0, 4, 0, 2, [ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON], []
    elif outcome == "rejected":
        score, tp, fp, independent, agreeing, reasons = 0.3333, 2, 4, 3, [ModelFamily.DEEPSEEK], []
    elif outcome == "dropped":
        score, tp, fp, independent, agreeing, reasons, tool = 0.0, 0, 4, 2, [], [], False
    elif tier == "D":
        score, tp, fp, independent, agreeing, reasons, tool = 1.0, 4, 0, 2, [], ["unverified_provenance"], False
    else:
        score, tp, fp, independent = 1.0, 6, 0, 1
        agreeing, reasons = [ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON], ["insufficient_independent_judges"]
    return ConsensusResult(finding_id=fid, weighted_score=score, votes_tp=tp, votes_fp=fp, votes_human=0,
                           families_agreeing=[*agreeing, *([ModelFamily.TOOL] if tool else [])], tool_corroborated=tool,
                           skeptic_refuted=False, position_consistent=True, tier=EvidenceTier(tier), cvss4_score=7.5,
                           cvss4_severity=severity, ssvc_decision="Track", accepted=outcome == "accepted",
                           needs_human=outcome == "needs_human", human_reasons=reasons, independent_judges=independent,
                           unsupervised_reject_unverified=outcome == "rejected" and not OUTCOME.unsupervised_reject_allowed,
                           human_decision=human if decision else None)
