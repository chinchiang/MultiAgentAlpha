"""Family-diversity constraints and inter-family agreement bookkeeping."""

from __future__ import annotations

from itertools import combinations

from ..config import MaraConfig, ModelSpec
from ..schemas import JudgeVote, ModelFamily


def pick_independent(cfg: MaraConfig, preferred: str, finder_families: set[ModelFamily]) -> tuple[ModelSpec, bool]:
    """An L3 model (skeptic, red team) from a family that found none of the finding (anti self-preference).

    Tries the preferred role, then the judges, then the reviewers. When every configured family is a
    finder, returns the preferred model and False so the caller can audit it; such a finding has no
    independent judge either and is left to a human by the quorum rule.
    """
    for name in [preferred] + cfg.roles.judges + cfg.roles.reviewers:
        m = cfg.model_by_name(name)
        if m.family not in finder_families:
            return m, True
    return cfg.model_by_name(preferred), False


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
