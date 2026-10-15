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
    """A consensus row as Pipeline.score writes one: the jury outcome as JuryOutcome.consensus_fields writes it, with
    the score, votes, agreeing families, tool corroboration and independent judges that lead to it at that tier, and
    optionally a usable human decision on it. `outcome` is the jury outcome (accepted, rejected, dropped, needs_human).

      accepted     two independent judges, both for in both passes (4/0, score 1.0); tier A adds the tool's
                   corroboration, B and C have no tool (C: the finding is not shown reachable)
      rejected     three independent judges, one for and two against (2/4, score 0.3333; a fourth judge family is
                   needed, docs/adr/0005-jury-outcome.md), at tier A with the tool; under OUTCOME's P8 (unsupervised
                   rejection not allowed) it is under rejection review
      dropped      tier D: two judges, both against (0/4)
      needs_human  too few independent judges, the finders voting at a discount, all for (6/0); at tier D the
                   provenance is unverified instead

    Scoring reaches each of these at the tiers named; a rejection at B or C, or acceptance at D, is not, and only the
    exhaustive comparison in tests/test_review_status.py feeds such rows, on purpose. assess reads only the tier,
    severity, outcome and decision."""
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
