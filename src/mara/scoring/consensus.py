"""Weighted consensus over judge votes, plus Krippendorff's alpha (nominal) for agreement.

Alpha rather than kappa because judges may abstain (refusal, timeout), which
kappa cannot handle and alpha can.
"""

from __future__ import annotations

from collections import Counter

from ..schemas import JudgeVote, ModelFamily

VERDICT_VALUE = {"true_positive": 1.0, "false_positive": 0.0, "needs_human": 0.5}


def krippendorff_alpha_nominal(units: dict[str, list[str]]) -> float | None:
    """units: finding_id -> list of nominal labels from different raters (missing allowed).

    Standard nominal-metric alpha: 1 - Do/De over all pairable values.
    Returns None when fewer than two units have >=2 labels.
    """
    pairable = {u: labels for u, labels in units.items() if len(labels) >= 2}
    if len(pairable) < 2:
        return None
    n = sum(len(v) for v in pairable.values())
    total = Counter()
    for labels in pairable.values():
        total.update(labels)
    # observed disagreement
    do_num = 0.0
    for labels in pairable.values():
        m = len(labels)
        c = Counter(labels)
        disagree_pairs = m * (m - 1) - sum(k * (k - 1) for k in c.values())
        do_num += disagree_pairs / (m - 1)
    do = do_num / n
    # expected disagreement
    de = (n * (n - 1) - sum(k * (k - 1) for k in total.values())) / (n * (n - 1))
    if de == 0:
        return 1.0
    return round(1.0 - do / de, 4)


def weighted_consensus(
    votes: list[JudgeVote], weights: dict[ModelFamily, float], self_judge_discount: float = 0.5
) -> tuple[float, int, int, int, list[ModelFamily], bool]:
    """Return (score, tp, fp, human, agreeing_families, position_consistent).

    Each family contributes the mean of its forward and reverse votes so that a
    family that flips with position is worth less than one that is consistent.
    """
    per_family: dict[ModelFamily, list[float]] = {}
    per_family_verdicts: dict[ModelFamily, set[str]] = {}
    discount: dict[ModelFamily, float] = {}
    tp = fp = human = 0
    for v in votes:
        per_family.setdefault(v.judge_family, []).append(VERDICT_VALUE[v.verdict])
        discount[v.judge_family] = self_judge_discount if v.self_family else 1.0
        per_family_verdicts.setdefault(v.judge_family, set()).add(v.verdict)
        tp += v.verdict == "true_positive"
        fp += v.verdict == "false_positive"
        human += v.verdict == "needs_human"
    if not per_family:
        return 0.0, 0, 0, 0, [], False
    num = sum(weights.get(fam, 1.0) * discount[fam] * (sum(vals) / len(vals)) for fam, vals in per_family.items())
    den = sum(weights.get(fam, 1.0) * discount[fam] for fam in per_family)
    score = round(num / den, 4) if den else 0.0
    agreeing = [fam for fam, vals in per_family.items() if sum(vals) / len(vals) >= 0.75]
    position_consistent = all(len(s) == 1 for s in per_family_verdicts.values())
    return score, tp, fp, human, agreeing, position_consistent
