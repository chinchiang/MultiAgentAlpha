"""Family-diversity constraints and inter-family agreement bookkeeping."""

from __future__ import annotations

from itertools import combinations

from ..config import MaraConfig, ModelSpec
from ..schemas import JudgeVote, ModelFamily


def pick_skeptic(cfg: MaraConfig, finder_family: ModelFamily) -> ModelSpec:
    """The skeptic must come from a different family than the finder (anti self-preference)."""
    preferred = cfg.model_by_name(cfg.roles.skeptic)
    if preferred.family != finder_family:
        return preferred
    for name in cfg.roles.judges + cfg.roles.reviewers:
        m = cfg.model_by_name(name)
        if m.family != finder_family:
            return m
    raise RuntimeError("no model family available to act as skeptic; configuration violates diversity rule")


def pairwise_family_agreement(votes: list[JudgeVote]) -> dict[str, float]:
    """Fraction of findings on which each pair of judge families gave the same verdict.

    High pairwise agreement between two families on *errors* is the signal that
    their votes should be discounted (correlated-error problem); this is the raw
    input for that calibration step.
    """
    by_family: dict[ModelFamily, dict[str, str]] = {}
    for v in votes:
        by_family.setdefault(v.judge_family, {})[(v.finding_id, v.pass_id).__repr__()] = v.verdict
    out: dict[str, float] = {}
    for a, b in combinations(sorted(by_family, key=lambda f: f.value), 2):
        common = set(by_family[a]) & set(by_family[b])
        if not common:
            continue
        same = sum(1 for k in common if by_family[a][k] == by_family[b][k])
        out[f"{a.value}~{b.value}"] = round(same / len(common), 3)
    return out
