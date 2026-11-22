"""Dimension score 0-100 from the findings whose final outcome is accepted, each a penalty for its gate severity
(GLOSSARY.md) scaled by its evidence tier, or in full when a human confirmed it (docs/adr/0003-human-resolution.md).
Deterministic and explainable. Pure."""

from __future__ import annotations

from ..schemas import ConsensusResult, DimensionScore, EvidenceTier, Finding

PENALTY = {"Critical": 40.0, "High": 25.0, "Medium": 10.0, "Low": 3.0, "None": 0.0}
TIER_FACTOR = {EvidenceTier.A: 1.0, EvidenceTier.B: 0.8, EvidenceTier.C: 0.4, EvidenceTier.D: 0.0}


def score_dimension(dimension: str, findings: list[Finding], consensus: dict[str, ConsensusResult], tool_ran: bool) -> DimensionScore:
    total = 100.0
    accepted = rejected = human = 0
    for f in findings:
        if f.dimension != dimension:
            continue
        c = consensus.get(f.id)
        if c is None:
            continue
        # the final outcome: a human ruling where there is one (docs/adr/0003-human-resolution.md)
        outcome = c.final_outcome
        if outcome == "accepted":
            accepted += 1
            # a finding a human confirmed counts in full whatever its tier: the tier factor discounts for how little the
            # pipeline's own evidence supports a finding, and a human ruled this one real
            total -= PENALTY[c.gate_severity] * (1.0 if c.human_confirmed else TIER_FACTOR[c.tier])
        elif outcome == "needs_human":
            human += 1  # awaiting a decision, not rejected
        else:
            rejected += 1  # rejected or dropped; a rejection under review (ADR 0005) is decided, not awaiting
    total = max(0.0, round(total, 1))
    note = "" if tool_ran else "no deterministic tool ran for this dimension; tier A unavailable"
    return DimensionScore(
        dimension=dimension, score=total, accepted_findings=accepted, rejected_findings=rejected, human_queue=human,
        tool_ran=tool_ran, notes=note,
    )
