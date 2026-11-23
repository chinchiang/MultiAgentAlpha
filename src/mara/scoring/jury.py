"""Jury scoring (GLOSSARY.md: jury, jury signals): each finding's jury signals measured from its ballots, its finders, the
tool results and the jury, its jury outcome decided from them by mara.scoring.outcome.decide, and the jury's agreement
over the whole review (docs/adr/0005-jury-outcome.md). Pure: nothing is read from disk and nothing is written to the
audit. The rows it returns hold the jury outcome as the jury concluded it; the pipeline has them finished by the usable
decisions and the blocking reasons (mara.settlement) and writes the audit from what it returns."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..bias.diversity import finders_of, pairwise_family_agreement
from ..schemas import SEVERITY_ORDER, ConsensusResult, Finding, JudgeVote, ModelFamily, higher_severity
from ..tools.evidence import corroborates
from ..tools.sarif import ToolResult
from . import cvss4
from .consensus import krippendorff_alpha_nominal, weighted_consensus
from .outcome import OutcomePolicy, OutcomeSignals, decide
from .tiers import assign_tier, ssvc_decision

if TYPE_CHECKING:
    from ..ballot_round import Ballots
    from ..config import MaraConfig


@dataclass(frozen=True)
class Jury:
    """The judges of a review as their votes are counted: each judge family's weight (P3: one judge per family), the
    discount on a vote from a family among a finding's finders, and how many families independent of its finders a
    finding needs for a quorum."""

    weights: dict[ModelFamily, float]
    min_independent_judges: int
    self_judge_discount: float
    finder_corroboration: bool = False

    @classmethod
    def from_config(cls, cfg: MaraConfig) -> Jury:
        # a family's vote carries its judge's weight, not that of whichever same-family model happens to be listed
        # last - a reviewer-only model used to replace it
        judges = [cfg.model_by_name(n) for n in cfg.roles.judges]
        return cls(weights={m.family: m.weight for m in judges}, min_independent_judges=cfg.gate.min_independent_judges,
                   self_judge_discount=cfg.gate.self_judge_discount, finder_corroboration=cfg.gate.finder_corroboration)


@dataclass(frozen=True)
class JuryScoring:
    """One consensus row per finding, in the findings' order, and the jury's agreement over the review: how many
    findings a family judged differently in its two passes, the corpus Krippendorff alpha (None when undefined) and
    each pair of families' agreement, keyed "a~b"."""

    rows: list[ConsensusResult]
    position_flips: int
    global_alpha: float | None
    family_agreement: dict[str, float]

    def rows_by_id(self) -> dict[str, ConsensusResult]:
        """The rows themselves by finding: the human decisions and blocking reasons recorded on them show in the result."""
        return {c.finding_id: c for c in self.rows}


def score(findings: list[Finding], ballots: Ballots, tool_results: list[ToolResult], *,
          jury: Jury, policy: OutcomePolicy, tool_path_prefix: str = "") -> JuryScoring:
    """`findings`, each found by its `finder_families` (a finding without any raises ValueError:
    mara.bias.diversity.finders_of), scored from the ballot round's `ballots` and the tool results
    (whose paths may lie below `tool_path_prefix`, the target's own path below the repository top level), by `jury`
    under `policy`."""
    finders = finders_of(findings)
    by_finding: dict[str, list[JudgeVote]] = defaultdict(list)
    for v in ballots.votes:
        by_finding[v.finding_id].append(v)
    rows: list[ConsensusResult] = []
    flips = 0
    for f in findings:
        raw_votes = by_finding.get(f.id, [])
        counts = Counter((v.judge_family, v.pass_id) for v in raw_votes)
        valid_families = {fam for fam in jury.weights if counts[(fam, "forward")] == counts[(fam, "reverse")] == 1}
        fv = [v.model_copy(update={"self_family": v.judge_family in finders[f.id]}) for v in raw_votes if v.judge_family in valid_families]
        independent = valid_families - finders[f.id]

        weighted, tp, fp, human, agreeing, consistent = weighted_consensus(fv, jury.weights, jury.self_judge_discount)
        flips += int(not consistent and bool(fv))
        alpha = _agreement_proxy(fv)
        sk = ballots.skeptic.get(f.id)
        refuted = bool(sk and sk.verdict == "refuted")
        unchallenged = f.id in ballots.unchallenged
        # Finder corroboration (GLOSSARY.md): the families that found it stand in for the judges it is short of, when
        # every seat independent of them voted, in both passes, that it is a true positive, no other vote is in its
        # score, and a skeptic outside its finders neither refuted it nor abstained. It can only complete a quorum
        # for acceptance: a vote against, a pass that is missing or a family of its finders voting leaves it short.
        seats = set(jury.weights) - finders[f.id]
        by_finders = (
            corroborable(len(finders[f.id]), len(seats), jury.min_independent_judges, jury.finder_corroboration)
            and valid_families == seats
            and all(v.verdict == "true_positive" for v in fv)
            and sk is not None and sk.source_family not in finders[f.id] and not refuted and not unchallenged
            and weighted >= policy.accept_threshold
        )
        quorum_ok = len(independent) >= jury.min_independent_judges or by_finders
        prov_ok = bool(f.provenance) and all(p.verified for p in f.provenance)
        corroborated = corroborates(f, tool_results, tool_path_prefix)
        fams = set(agreeing) | (finders[f.id] if weighted >= policy.accept_threshold else set())
        if corroborated:
            fams.add(ModelFamily.TOOL)
        tier = assign_tier(
            provenance_verified=prov_ok,
            tool_corroborated=corroborated,
            families_agreeing=sorted(fams, key=lambda x: x.value),
            skeptic_refuted=refuted,
            skeptic_abstained=unchallenged,
            reachability=f.reachability,
            consensus_score=weighted,
            accept_threshold=policy.accept_threshold,
        )
        # every Finding's vector was fully parsed and scored when it was built (schemas.Finding._cvss): a model
        # finding with an invalid vector is dropped at L2 as an invalid item, so scoring here cannot fail
        num = cvss4.score(f.cvss4_vector)
        sev = cvss4.severity(num)
        # The mathematical CVSS severity and the jury's operational opinion are recorded apart; the higher of the two is
        # the gate severity (schemas.ConsensusResult.gate_severity), which the tier C rule below reads like the gate
        family_bands = [max((v.severity_band for v in fv if v.judge_family == fam), key=SEVERITY_ORDER.index) for fam in valid_families]
        operational = sorted(family_bands, key=SEVERITY_ORDER.index)[len(family_bands) // 2] if family_bands else None
        rt = ballots.redteam.get(f.id)
        ssvc = ssvc_decision(severity=sev, exploitable=rt.exploitable if rt else "unknown", tier=tier)
        outcome = decide(OutcomeSignals(tier=tier, score=weighted, severity=higher_severity(sev, operational),
                                        provenance_verified=prov_ok, skeptic_refuted=refuted, skeptic_abstained=unchallenged,
                                        quorum_ok=quorum_ok, passes_complete=len(fv) == len(raw_votes),
                                        alpha=alpha, votes_tp=tp, votes_fp=fp, votes_human=human, position_consistent=consistent),
                         policy)
        rows.append(
            ConsensusResult(
                finding_id=f.id,
                weighted_score=weighted,
                votes_tp=tp,
                votes_fp=fp,
                votes_human=human,
                families_agreeing=sorted(fams, key=lambda x: x.value),
                tool_corroborated=corroborated,
                skeptic_refuted=refuted,
                skeptic_abstained=unchallenged,
                position_consistent=consistent,
                tier=tier,
                cvss4_score=num,
                cvss4_severity=sev,
                ssvc_decision=ssvc,
                **outcome.consensus_fields(),
                independent_judges=len(independent),
                agreement_proxy=alpha,
                operational_severity=operational,
                finder_corroborated=by_finders,
            )
        )
    return JuryScoring(rows=rows, position_flips=flips, global_alpha=krippendorff_alpha_nominal(_alpha_units(findings, ballots.votes)),
                       family_agreement=pairwise_family_agreement(ballots.votes))


def corroborable(finder_families: int, independent_seats: int, min_independent_judges: int, enabled: bool) -> bool:
    """Whether a finding may reach its quorum by finder corroboration (GLOSSARY.md), going by the counts alone:
    `gate.finder_corroboration` is on, at least two families found it, and the judge seats independent of them are at
    least one and fewer than the quorum asks for. The ballot round then asks none of the finders' families to judge
    it (mara.ballot_round), and score() says whether its independent judges and its skeptic bore it out."""
    return enabled and finder_families >= 2 and 1 <= independent_seats < min_independent_judges


def attainable_agreement(judge_families: int) -> tuple[float, ...]:
    """Every value the agreement proxy can take on a finding that `judge_families` families voted on, lowest first; none
    for fewer than two, where it is undefined. Each family gives one of three labels, so the values are few: 0.25 and
    1.0 for two families, 0.0, 0.5 and 1.0 for three. A threshold moved between two neighbouring values changes no
    outcome (mara.policy.inert_tightening)."""
    if judge_families < 2:
        return ()
    lowest_modal = -(-judge_families // 3)  # the modal label of n votes over three labels holds at least ceil(n / 3)
    return tuple(round((modal / judge_families - 1 / 3) / (1 - 1 / 3), 3) for modal in range(lowest_modal, judge_families + 1))


def _agreement_proxy(votes: list[JudgeVote]) -> float | None:
    """Agreement among judges on one finding, treating each (judge, pass) as a rater over the
    two-unit set {this finding forward, this finding reverse} is degenerate; instead we report
    the simple share of the modal verdict as a bounded proxy when alpha is undefined."""
    if len(votes) < 2:
        return None

    # one verdict per family: a family whose two passes differ counts as sending the finding to a human
    per_family = defaultdict(set)
    for v in votes:
        per_family[v.judge_family].add(v.verdict)
    if len(per_family) < 2:
        # a single rater family agreeing with itself is not "perfect agreement": undefined, like
        # alpha with fewer than two raters; quorum reasons still gate the acceptance
        return None
    c = Counter(next(iter(values)) if len(values) == 1 else "needs_human" for values in per_family.values())
    modal = c.most_common(1)[0][1]
    return round((modal / len(per_family) - 1 / 3) / (1 - 1 / 3), 3)  # chance-corrected for 3 categories


def _alpha_units(findings: list[Finding], votes: list[JudgeVote]) -> dict[str, list[str]]:
    """Krippendorff units for the corpus alpha: one label per judge family per finding, the verdict
    both of its passes gave. The forward and reverse passes are the same rater seen twice (they exist
    to measure position bias, counted as position_flips); counted as two raters, a family's
    agreement with itself passed for agreement between families (two self-consistent families that
    always disagree scored -0.17 instead of -0.5). A family whose passes differ has no single label
    for that finding and is missing there, which alpha allows."""
    by_finding: dict[str, dict[ModelFamily, list[JudgeVote]]] = defaultdict(lambda: defaultdict(list))
    for v in votes:
        by_finding[v.finding_id][v.judge_family].append(v)
    units: dict[str, list[str]] = {}
    for f in findings:
        labels: list[str] = []
        for vs in by_finding[f.id].values():
            passes = {v.pass_id: v.verdict for v in vs}
            if len(vs) == 2 and set(passes) == {"forward", "reverse"} and passes["forward"] == passes["reverse"]:
                labels.append(passes["forward"])
        units[f.id] = labels
    return units
