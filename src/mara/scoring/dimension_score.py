"""Dimension score 0-100 from accepted findings. Deterministic and explainable."""

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
        if c.needs_human:
            human += 1
        if c.accepted:
            accepted += 1
            total -= PENALTY[c.cvss4_severity] * TIER_FACTOR[c.tier]
        else:
            rejected += 1
    total = max(0.0, round(total, 1))
    note = "" if tool_ran else "no deterministic tool ran for this dimension; tier A unavailable"
    return DimensionScore(
        dimension=dimension, score=total, accepted_findings=accepted, rejected_findings=rejected, human_queue=human,
        tool_ran=tool_ran, notes=note,
    )
