"""Review facts, policies and consensus rows for tests of mara.review_status and of what reads its results
(docs/adr/0007-review-status-and-gate.md)."""

from __future__ import annotations

from mara.review_status import GatePolicy, ReviewFacts
from mara.schemas import ConsensusResult, DimensionScore, EvidenceTier
from mara.scoring.outcome import OutcomePolicy

OUTCOME = OutcomePolicy(accept_threshold=0.6, alpha_threshold=0.4, exclude_tier_c=False, tier_c_min_severity="High",
                        unsupervised_reject_allowed=False)
GATE = GatePolicy(block_on_tiers=frozenset({"A", "B"}), block_on_severity=frozenset({"High", "Critical"}), min_dimension_score=60.0)
# a review where every fact is in order
FACTS = ReviewFacts(context_complete=True, egress_blocked=False, required_tools_ran=True, ml_bom_signature=None,
                    context_view_missing=False, incomplete_counters=(), rollout_phase="shadow", fail_on_gate=False)


def dim(name: str, score: float) -> DimensionScore:
    return DimensionScore(dimension=name, score=score, accepted_findings=0, rejected_findings=0, human_queue=0, tool_ran=True)


# the jury's score and votes behind each outcome on a three-family panel of weight 1 (accept threshold 0.6)
_JURY = {"accepted": (1.0, 3, 0), "rejected": (0.0, 0, 3), "needs_human": (0.5, 1, 1)}


def row(fid: str, tier: str, severity: str, outcome: str, decision: str | None = None) -> ConsensusResult:
    """A consensus row with its jury outcome written as JuryOutcome.consensus_fields writes it (accepted or needing a
    human, never both; a reason whenever it needs a human), a score and votes that agree with it, and optionally a usable
    human decision on it. Whether scoring can reach that outcome at that tier depends on the panel and the tightening:
    the examples in tests/test_review_status.py use only rows that scoring reaches with the policy each one passes to assess (a tier B finding
    is never rejected by the default panel, docs/adr/0005-jury-outcome.md; tier C at the severity floor is accepted only
    while the queue is tightened). assess itself reads only the tier, severity, outcome and decision."""
    human = {"decision": decision, "key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}
    score, tp, fp = _JURY[outcome]
    return ConsensusResult(finding_id=fid, weighted_score=score, votes_tp=tp, votes_fp=fp, votes_human=0, families_agreeing=[],
                           tool_corroborated=False, skeptic_refuted=False, position_consistent=True, tier=EvidenceTier(tier),
                           cvss4_score=7.5, cvss4_severity=severity, ssvc_decision="Track", accepted=outcome == "accepted",
                           needs_human=outcome == "needs_human",
                           human_reasons=["insufficient_independent_judges"] if outcome == "needs_human" else [],
                           human_decision=human if decision else None)
