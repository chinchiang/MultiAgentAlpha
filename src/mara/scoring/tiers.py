"""Evidence tier assignment and SSVC-style decision. Pure functions, no model calls."""

from __future__ import annotations

from ..schemas import EvidenceTier, ModelFamily


def assign_tier(
    *,
    provenance_verified: bool,
    tool_corroborated: bool,
    families_agreeing: list[ModelFamily],
    skeptic_refuted: bool,
    reachability: str,
    consensus_score: float,
    accept_threshold: float,
) -> EvidenceTier:
    if not provenance_verified:
        return EvidenceTier.D
    if skeptic_refuted and consensus_score < accept_threshold:
        return EvidenceTier.D
    model_families = [f for f in families_agreeing if f not in (ModelFamily.TOOL,)]
    if tool_corroborated and len(model_families) >= 1:
        return EvidenceTier.A
    if len(model_families) >= 2 and reachability in ("reachable", "conditional") and not skeptic_refuted:
        return EvidenceTier.B
    if consensus_score >= accept_threshold:
        return EvidenceTier.C
    return EvidenceTier.D


def ssvc_decision(*, severity: str, exploitable: str, tier: EvidenceTier, internet_exposed: bool = True) -> str:
    """Simplified SSVC (CISA deployer tree) outcome: Track / Track* / Attend / Act.

    Exploitation evidence in our setting is the red-team assessment, not KEV, so
    'yes' maps to SSVC 'active' only in the sense of 'demonstrated in review'.
    """
    if tier == EvidenceTier.D:
        return "Track"
    if severity in ("Critical",) and exploitable in ("yes", "conditional"):
        return "Act" if internet_exposed else "Attend"
    if severity in ("High", "Critical"):
        return "Attend" if exploitable != "no" else "Track*"
    if severity == "Medium" and exploitable == "yes":
        return "Track*"
    return "Track"
