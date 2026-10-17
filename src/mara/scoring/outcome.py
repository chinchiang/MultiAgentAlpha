"""The jury outcome of a finding, decided from the signals scoring computed (docs/adr/0005-jury-outcome.md). Pure functions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..schemas import SEVERITY_ORDER, EvidenceTier, JuryOutcomeValue

if TYPE_CHECKING:
    from ..config import MaraConfig


# The human reasons the jury outcome writes (GLOSSARY.md: human reason), and JURY_HUMAN_REASONS the order decide()
# writes them in; mara.human_queue adds the queue's own to make every human reason.
UNVERIFIED_PROVENANCE = "unverified_provenance"
SKEPTIC_ABSTAINED = "skeptic_abstained"
INSUFFICIENT_INDEPENDENT_JUDGES = "insufficient_independent_judges"
INVALID_OR_INCOMPLETE_JUDGE_PASSES = "invalid_or_incomplete_judge_passes"
AGREEMENT_BELOW_THRESHOLD = "agreement_below_threshold"
MAJORITY_NEEDS_HUMAN = "majority_needs_human"
POSITION_INCONSISTENT = "position_inconsistent"
TIER_C_HIGH = "tier_c_high"
SKEPTIC_REFUTED_JURY_OVERRODE = "skeptic_refuted_jury_overrode"
JURY_HUMAN_REASONS = (UNVERIFIED_PROVENANCE, SKEPTIC_ABSTAINED, INSUFFICIENT_INDEPENDENT_JUDGES, INVALID_OR_INCOMPLETE_JUDGE_PASSES,
                      AGREEMENT_BELOW_THRESHOLD, MAJORITY_NEEDS_HUMAN, POSITION_INCONSISTENT, TIER_C_HIGH, SKEPTIC_REFUTED_JURY_OVERRODE)


@dataclass(frozen=True)
class OutcomePolicy:
    accept_threshold: float
    alpha_threshold: float  # after tightening
    exclude_tier_c: bool  # after tightening
    tier_c_min_severity: str
    unsupervised_reject_allowed: bool

    @classmethod
    def from_config(cls, cfg: MaraConfig, *, alpha_threshold: float, exclude_tier_c: bool) -> OutcomePolicy:
        """The config in force, with the two values the human queue's tightening may have changed."""
        return cls(accept_threshold=cfg.gate.accept_threshold, alpha_threshold=alpha_threshold, exclude_tier_c=exclude_tier_c,
                   tier_c_min_severity=cfg.human_queue.queue_tier_c_min_severity,
                   unsupervised_reject_allowed=cfg.gate.unsupervised_reject_allowed)


@dataclass(frozen=True)
class OutcomeSignals:
    tier: EvidenceTier
    score: float
    severity: str
    provenance_verified: bool
    skeptic_refuted: bool
    skeptic_abstained: bool
    quorum_ok: bool
    passes_complete: bool
    alpha: float | None
    votes_tp: int
    votes_fp: int
    votes_human: int
    position_consistent: bool


@dataclass(frozen=True)
class JuryOutcome:
    value: JuryOutcomeValue
    reasons: tuple[str, ...]
    unsupervised_reject_unverified: bool

    def consensus_fields(self) -> dict:
        """The outcome as ConsensusResult persists it; ConsensusResult.jury_outcome reads the value back."""
        return {"accepted": self.value == "accepted", "needs_human": self.value == "needs_human",
                "human_reasons": list(self.reasons), "unsupervised_reject_unverified": self.unsupervised_reject_unverified}


def tier_c_needs_human(tier: EvidenceTier, severity: str, min_severity: str) -> bool:
    """G-11: tier C at or above the configured severity rests on one family's word, so a human decides it.
    An unknown severity ranks above every band, so the rule stays fail-closed."""
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return tier == EvidenceTier.C and rank >= SEVERITY_ORDER.index(min_severity)


def decide(s: OutcomeSignals, policy: OutcomePolicy) -> JuryOutcome:
    reasons = []
    if not s.provenance_verified:
        reasons.append(UNVERIFIED_PROVENANCE)
    if s.skeptic_abstained:
        reasons.append(SKEPTIC_ABSTAINED)
    if not s.quorum_ok:
        reasons.append(INSUFFICIENT_INDEPENDENT_JUDGES)
    if not s.passes_complete:
        reasons.append(INVALID_OR_INCOMPLETE_JUDGE_PASSES)
    if s.alpha is not None and s.alpha < policy.alpha_threshold:
        reasons.append(AGREEMENT_BELOW_THRESHOLD)
    if s.votes_human > s.votes_tp and s.votes_human > s.votes_fp:
        reasons.append(MAJORITY_NEEDS_HUMAN)
    if not s.position_consistent and s.votes_tp + s.votes_fp + s.votes_human:
        reasons.append(POSITION_INCONSISTENT)
    # unless the queue is tightened over its backlog limit (tighten_exclude_tier_c): then the jury's consensus decides
    if not policy.exclude_tier_c and tier_c_needs_human(s.tier, s.severity, policy.tier_c_min_severity):
        reasons.append(TIER_C_HIGH)
    if s.skeptic_refuted and s.tier != EvidenceTier.D:
        # assessment #37: a refuted finding never re-enters the blocking logic on the
        # jury's vote alone; the jury may speak, but a human decides.
        reasons.append(SKEPTIC_REFUTED_JURY_OVERRODE)
    if reasons:
        return JuryOutcome("needs_human", tuple(reasons), unsupervised_reject_unverified=False)
    if s.tier == EvidenceTier.D:
        return JuryOutcome("dropped", (), unsupervised_reject_unverified=False)
    if s.score >= policy.accept_threshold:
        return JuryOutcome("accepted", (), unsupervised_reject_unverified=False)
    # assessment #60: without a passing Alternative Annotator Test (policy P8) a human reviews every rejection;
    # the jury outcome stays rejected so the AAT keeps its sample, and the review is not incomplete for it
    return JuryOutcome("rejected", (), unsupervised_reject_unverified=not policy.unsupervised_reject_allowed)
