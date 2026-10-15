"""Orchestrator: L0 tools -> L1 context -> L2 reviewers -> L3 skeptic/red team -> L4 blinded jury
-> L5 deterministic scoring and reports. No layer talks to another except through validated
schemas; reviewers never see each other's output; judges never see model identity.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import asdict
from functools import partial
from pathlib import Path

from . import exchange
from .agents import base, context_agent, judge, redteam, reviewer, skeptic
from .agents.context_agent import ContextView
from .audit import Audit
from .bias.blinding import blinded_batches
from .bias.diversity import pairwise_family_agreement, pick_independent
from .config import MaraConfig
from .context.repo_map import MAX_TOTAL_CHARS, RepoContext, build_context, bundle_cost, restrict_to_increment
from .identity import NEAR_LINES, norm_cwe, norm_path
from .progress import Progress
from .providers import make_provider
from .providers.base import Provider
from .review_status import GatePolicy, ReviewFacts, assess, secret_preflight
from .schemas import (
    SEVERITY_ORDER,
    ConsensusResult,
    Finding,
    JudgeVote,
    ModelFamily,
    RedTeamNote,
    ReviewReport,
    SkepticVerdict,
)
from .scoring import cvss4
from .scoring.consensus import krippendorff_alpha_nominal, weighted_consensus
from .scoring.dimension_score import score_dimension
from .scoring.idcheck import check_finding_refs
from .scoring.outcome import OutcomePolicy, OutcomeSignals, decide
from .scoring.tiers import assign_tier, ssvc_decision
from .tools.runner import TOOL_DIMENSIONS, ToolRun, load_prerecorded, run_all
from .tools.sarif import ToolResult
from .workspace import check_outside, resolve

# error vocabulary of the agent layer, response-level codes that are not invalid output: "refused" (an abstention),
# an echo, the budget (a truncation is never charged to the model, docs/adr/0001-reply-outcome-accounting.md) and the
# summary markers the agents append when a reply was discarded as a whole. Provider failures are not invalid output
# either (exchange.is_provider_error); they are counted as <role>_errors.
_ERROR_MARKERS = frozenset({"refused", "canary_echoed", "truncated", "incomplete_or_duplicate_response",
                            "incomplete_or_duplicate_judge_response"})


# L3/L4 calls are bounded like the reviewer calls: the skeptic and red team read the evidence files of
# every finding they get, the judges one blinded view per finding. Unbatched, one model's whole share of
# a large review went into one request, overflowed its window or output budget, and left every one of
# those findings unchallenged.
MAX_L3_FINDINGS = 20  # findings per skeptic / red-team call
MAX_L4_FINDINGS = 25  # findings per judge pass


def l3_chunks(ctx: RepoContext, findings: list[Finding]) -> list[list[Finding]]:
    """Consecutive runs of `findings` whose evidence files fit one request (MAX_TOTAL_CHARS, the reviewer
    bound) and that hold at most MAX_L3_FINDINGS findings. A file shared by several findings is counted
    once per chunk; a finding whose own files exceed the bound still gets a chunk of its own."""
    chunks: list[list[Finding]] = []
    cur: list[Finding] = []
    files: set[str] = set()
    size = 0
    for f in findings:
        own = {p.file for p in f.provenance if p.file in ctx.content}
        new = own - files
        cost = sum(bundle_cost(rel, ctx.content[rel]) for rel in new)
        if cur and (len(cur) >= MAX_L3_FINDINGS or size + cost > MAX_TOTAL_CHARS):
            chunks.append(cur)
            cur, files, size = [], set(), 0
            new = own
            cost = sum(bundle_cost(rel, ctx.content[rel]) for rel in new)
        cur.append(f)
        files |= new
        size += cost
    if cur:
        chunks.append(cur)
    return chunks


def l4_chunks(order: list) -> list[list]:
    """`order` cut into the fewest judge chunks of at most MAX_L4_FINDINGS, of near-equal size. Fixed slices of
    25 left 26 findings as 25 + 1, and a one-finding chunk's reverse pass is its forward pass: that finding was
    judged twice in the same position, so position bias could never show for it."""
    if not order:
        return []
    n = -(-len(order) // MAX_L4_FINDINGS)
    size, extra = divmod(len(order), n)
    out, start = [], 0
    for i in range(n):
        end = start + size + (1 if i < extra else 0)
        out.append(order[start:end])
        start = end
    return out


def _retryable(errors: list[str]) -> bool:
    """A reply the agent rejected as malformed, cut off or not covering every finding exactly once: worth one
    more call (GLM as skeptic answered four verdicts for three findings on one call and exactly three on the
    next, 2026-10-08). Refusals and canary echoes are signals, never retried; providers retry their own failures, and
    any other exception in a provider (provider_call_failed:<type>) is a bug a second call would only repeat."""
    return bool(errors) and not any(e in ("refused", "canary_echoed") or exchange.is_provider_error(e) for e in errors)


def _count_invalid(errors: list[str]) -> int:
    """Unusable items only: empty responses, bad shapes, per-item schema failures - never a failed call."""
    return sum(1 for x in errors if x not in _ERROR_MARKERS and not exchange.is_provider_error(x))


class Pipeline:
    def __init__(self, cfg: MaraConfig, *, mock_fixtures: str | None = None, out_dir: Path | None = None,
                 progress: Progress | None = None):
        self.cfg = cfg
        # the live view `mara serve` draws (mara.progress); a no-op unless `mara review --progress-file` is given
        self.progress = progress if progress is not None else Progress()
        self.out_dir = out_dir or resolve("out")  # the workspace, like `mara review --out`
        self.providers: dict[str, Provider] = {m.name: make_provider(m, mock_fixtures) for m in cfg.models}
        # Counters (default 0) plus a few labels and nested tables; becomes the report's bias_audit
        self.audit = Audit()
        self.log: list[str] = []
        # G-11: the human queue tightens when its ticket backlog is over the limit (never loosens)
        from .report.human_queue_out import read_backlog, tightening

        self.backlog = read_backlog(cfg)
        alpha_threshold, exclude_tier_c, self.queue_tightened = tightening(cfg, self.backlog)
        # read once and held only here: the jury outcome, the gate, the audit and the log see the same tightening
        # (docs/adr/0007-review-status-and-gate.md)
        self.outcome_policy = OutcomePolicy.from_config(cfg, alpha_threshold=alpha_threshold, exclude_tier_c=exclude_tier_c)
        self.gate_policy = GatePolicy.from_config(cfg)
        from .mlbom import status_for_config

        self.ml_bom_status = status_for_config(cfg)

    # ------------------------------------------------------------------ helpers
    def _p(self, name: str) -> Provider:
        return self.providers[name]

    def _say(self, msg: str) -> None:
        self.log.append(msg)
        self.progress.log(msg)

    # ------------------------------------------------------------------ L0
    def run_tools(self, target: Path, sarif_dir: Path | None) -> list[ToolRun]:
        if sarif_dir and sarif_dir.is_dir():
            runs = load_prerecorded(sarif_dir)
            self._say(f"L0: ingested {len(runs)} pre-recorded SARIF file(s) from {sarif_dir}")
            return runs
        runs = run_all(target, self.out_dir / "tools")
        for r in runs:
            self._say(f"L0: {r.tool}: {'ran' if r.ran else 'skipped'} {r.note} ({len(r.results)} results)")
        return runs

    # ------------------------------------------------------------------ L1
    def run_context(self, ctx: RepoContext) -> ContextView | None:
        """C4-lite architecture view from a dedicated context agent (assessment #19).

        Every fact must cite a verbatim file:line quote; unverified items are dropped and
        counted. A refused, empty or echoed call yields no view: reviewers then run without
        context facts and the run is marked incomplete (fail-closed, never fabricated).
        """
        name = self.cfg.roles.context
        if not name:
            return None
        prov = self._p(name)
        fam = prov.family.value
        view, audit = context_agent.run_context_agent(prov, ctx)
        self.audit.add("context_calls", fam, audit["calls"])
        for key, counter in (("refused", "context_refusals"), ("truncated", "context_truncations"),
                             ("unparseable", "context_unparseable_replies"),
                             ("errored", "context_errors"), ("canary_echoed", "canary_echoes"), ("canary_reported", "canary_reports"),
                             ("invalid", "context_invalid_items"), ("unverified", "context_unverified_items")):
            self.audit.add(counter, fam, int(audit[key]))
        self.audit["input_tokens"] += audit["input_tokens"]
        self.audit["output_tokens"] += audit["output_tokens"]
        flags = {"refused": " [REFUSED]", "truncated": " [TRUNCATED]", "errored": " [PROVIDER ERROR]",
                 "canary_echoed": " [CANARY ECHOED]", "canary_reported": " [CANARY REPORTED]"}
        self._say(f"L1: context {fam}: {len(view.items) if view else 0} fact(s)"
                  + "".join(tag for key, tag in flags.items() if audit[key]))
        return view

    # ------------------------------------------------------------------ L2
    def run_reviewers(self, ctx: RepoContext, context_view: ContextView | None = None) -> list[Finding]:
        canary = base.Canary()
        raw: list[Finding] = []
        for batch in ctx.batches():
            for dim in self.cfg.dimensions:
                for name in self.cfg.roles.reviewers:
                    prov = self._p(name)
                    findings, audit = reviewer.review_dimension(prov, batch, dim, canary, context_view)
                    fam = prov.family.value
                    for key, counter in (("refused", "reviewer_refusals"), ("truncated", "reviewer_truncations"),
                                         ("unparseable", "reviewer_unparseable_replies"), ("errored", "reviewer_errors"),
                                         ("canary_echoed", "canary_echoes"), ("canary_reported", "canary_reports"),
                                         ("unverified_quotes", "findings_with_unverified_quotes"), ("invalid", "invalid_findings_dropped")):
                        self.audit.add(counter, fam, int(audit[key]))
                    self.audit.add("reviewer_calls", fam)
                    self.audit["input_tokens"] += audit["input_tokens"]
                    self.audit["output_tokens"] += audit["output_tokens"]
                    raw.extend(findings)
                    tags = {"refused": " [REFUSED]", "truncated": " [TRUNCATED]", "errored": " [PROVIDER ERROR]", "canary_echoed": " [CANARY ECHOED]",
                            "canary_reported": " [CANARY REPORTED]"}
                    flags = [tag for key, tag in tags.items() if audit[key]]
                    self._say(f"L2: {dim} × {prov.family.value}: {len(findings)} finding(s)" + "".join(flags))
        # assign ids and strip unknown standard references. Ids are content-ordered (file, line,
        # cwe, dimension, title) rather than call-ordered: consecutive ids no longer reveal which
        # findings shared a reviewer call, so the blinded view leaks no grouping (judge.md promises
        # no source identity; id clusters are a subtle channel back to it).
        raw.sort(key=lambda f: (norm_path(f.provenance[0].file), f.provenance[0].line, f.cwe, f.dimension, f.title))
        out: list[Finding] = []
        for i, f in enumerate(raw, 1):
            f = f.model_copy(update={"id": f"F-{i:04d}"})
            ref = check_finding_refs(f)
            self.audit["standard_refs_stripped"] += len(ref.stripped)
            self.audit["unknown_cwe"] += int(ref.unknown_cwe)
            out.append(ref.finding)
        return out

    @staticmethod
    def dedupe(findings: list[Finding]) -> tuple[list[Finding], dict[str, set[ModelFamily]]]:
        """Merge findings from different families that point at the same file/line(+-3)/CWE."""
        kept: list[Finding] = []
        finders: dict[str, set[ModelFamily]] = {}
        for f in findings:
            p = f.provenance[0]
            match = None
            f_ok = all(x.verified for x in f.provenance)
            for k in kept:
                q = k.provenance[0]
                k_ok = all(x.verified for x in k.provenance)
                # never merge an unverified (possibly fabricated) finding into a verified one:
                # it would inherit the verified finding's acceptance and hide the fabrication
                same_file = norm_path(q.file) == norm_path(p.file)  # ./app.py and app.py are one file
                if k.dimension == f.dimension and k.cwe == f.cwe and same_file and abs(q.line - p.line) <= 3 and k_ok == f_ok:
                    match = k
                    break
            if match is None:
                kept.append(f)
                finders[f.id] = {f.source_family}
            else:
                finders[match.id].add(f.source_family)
        return kept, finders

    def _once_more(self, role: str, fam: str, call: Callable[[], tuple]) -> tuple:
        """`call()` -> (items, errors, ...); called once more when it kept nothing and _retryable(errors). Only
        the answer used counts toward completeness; the discarded attempt is recorded as <role>_retries. The
        retry depends on whether the reply was well-formed, never on what it concluded."""
        out = call()
        if not out[0] and _retryable(out[1]):
            self.audit.add(f"{role}_retries", fam)
            self._say(f"L3/L4: {role} {fam} reply rejected ({', '.join(sorted(set(out[1])))}); asked once more")
            out = call()
        return out

    def _count_ballot(self, role: str, fam: str, errors: list[str], canary_reports: int | None = None) -> int:
        """The audit of one ballot round (skeptic, red team, judge) from the error codes of the answer used: refusals
        (abstentions), provider failures, invalid items, truncations, unparseable replies and - for the roles that
        read the repository and carry a canary - canary echoes and reports. Returns the refusals."""
        refusals = errors.count("refused")
        self.audit.add(f"{role}_refusals", fam, refusals)
        self.audit.add(f"{role}_errors", fam, sum(exchange.is_provider_error(e) for e in errors))
        self.audit.add(f"{role}_invalid_items", fam, _count_invalid(errors))
        self.audit.add(f"{role}_truncations", fam, errors.count("truncated"))
        self.audit.add(f"{role}_unparseable_replies", fam, errors.count("unparseable"))
        if canary_reports is not None:
            self.audit.add(f"{role}_canary_echoes", fam, errors.count("canary_echoed"))
            self.audit.add(f"{role}_canary_reports", fam, canary_reports)
        return refusals

    # ------------------------------------------------------------------ L3
    def run_skeptics(
        self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]
    ) -> tuple[list[SkepticVerdict], frozenset[str]]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            # the skeptic must not share a family with ANY finder of this finding
            spec, independent = pick_independent(self.cfg, self.cfg.roles.skeptic, finders[f.id])
            if not independent:
                self.audit["skeptic_same_family"] += 1
                self._say(f"L3: no skeptic outside the finder families of {f.id}; {spec.family.value} reviews it")
            groups[spec.name].append(f)
        verdicts: list[SkepticVerdict] = []
        abstained: set[str] = set()
        for name, fs in ((n, chunk) for n, group in groups.items() for chunk in l3_chunks(ctx, group)):
            fam = self._p(name).family.value
            self.audit.add("skeptic_calls", fam)
            self.audit[f"skeptic_items[{fam}]"] += len(fs)
            v, errors, unverified, reported = self._once_more("skeptic", fam, partial(skeptic.run_skeptic, self._p(name), ctx, fs))
            refusals = self._count_ballot("skeptic", fam, errors, reported)
            self.audit.add("skeptic_unverified_controls", fam, unverified)
            self.audit.add("skeptic_refuted", fam, sum(x.verdict == "refuted" for x in v))
            if not v:
                # no usable verdict for this group - a refusal, a provider failure, or a reply the
                # agent rejected (unparseable, schema-invalid, or not covering every finding exactly
                # once): the findings went unchallenged, so none of them may reach tier B on the
                # skeptic's strength, and the counters above keep the run incomplete
                abstained.update(f.id for f in fs)
            verdicts.extend(v)
            self._say(
                f"L3: skeptic {fam} judged {len(fs)} → {sum(x.verdict == 'refuted' for x in v)} refuted"
                + (f", {unverified} unverifiable control citation(s) downgraded" if unverified else "")
                + (" [REFUSED]" if refusals else "")
            )
        return verdicts, frozenset(abstained)

    def run_redteam(self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]) -> list[RedTeamNote]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            spec, independent = pick_independent(self.cfg, self.cfg.roles.redteam, finders[f.id])
            if not independent:
                self.audit["redteam_same_family"] += 1
                self._say(f"L3: no red team outside the finder families of {f.id}; {spec.family.value} reviews it")
            groups[spec.name].append(f)
        notes: list[RedTeamNote] = []
        for name, fs in ((n, chunk) for n, group in groups.items() for chunk in l3_chunks(ctx, group)):
            fam = self._p(name).family.value
            self.audit.add("redteam_calls", fam)
            self.audit[f"redteam_items[{fam}]"] += len(fs)
            n, errors, stripped, reported = self._once_more("redteam", fam, partial(redteam.run_redteam, self._p(name), ctx, fs))
            refusals = self._count_ballot("redteam", fam, errors, reported)
            self.audit.add("redteam_exploit_code_stripped", fam, stripped)
            notes.extend(n)
            self._say(f"L3: red team {fam} probed {len(fs)} → {sum(x.exploitable == 'yes' for x in n)} exploitable"
                      + (f", {stripped} preconditions had exploit code removed" if stripped else "")
                      + (" [REFUSED]" if refusals else ""))
        return notes

    # ------------------------------------------------------------------ L4
    def run_jury(
        self, ctx: RepoContext, findings: list[Finding], skeptic_by_id: dict[str, SkepticVerdict], finders: dict[str, set[ModelFamily]]
    ) -> list[JudgeVote]:
        votes: list[JudgeVote] = []
        judge_fams = [self._p(n).family for n in self.cfg.roles.judges]
        min_ind = self.cfg.gate.min_independent_judges

        def independent(f: Finding) -> int:
            return sum(1 for fam in judge_fams if fam not in finders[f.id])

        for name in self.cfg.roles.judges:
            prov = self._p(name)
            fam = prov.family.value
            # anti self-preference: a family never judges a finding it (co-)produced, unless too few
            # independent families remain, in which case it votes with a discounted weight (self_family).
            eligible, self_ids = [], set()
            for f in findings:
                if prov.family not in finders[f.id]:
                    eligible.append(f)
                elif independent(f) < min_ind:
                    eligible.append(f)
                    self_ids.add(f.id)
                else:
                    self.audit["self_preference_exclusions"] += 1
            self.audit["self_family_fallback_votes"] += len(self_ids)
            if not eligible:
                continue
            self.audit[f"judge_items[{fam}]"] += len(eligible)
            # one seeded order over all eligible findings, cut into bounded chunks; each chunk's reverse
            # pass is that chunk mirrored, so every finding is still seen in two mirrored positions
            order, _ = blinded_batches(eligible, skeptic_by_id, ctx.content_hash + prov.family.value)
            for fwd in l4_chunks(order):
                rev = list(reversed(fwd))
                self.audit.add("judge_calls", fam, 2)
                v1, e1 = self._once_more("judge", fam, partial(judge.run_judge, prov, fwd, "forward", self_ids))
                v2, e2 = self._once_more("judge", fam, partial(judge.run_judge, prov, rev, "reverse", self_ids))
                refusals = self._count_ballot("judge", fam, e1 + e2)
                votes.extend(v1 + v2)
                self._say(
                    f"L4: judge {fam}: {len(fwd)} finding(s) ({len(self_ids & {b['finding_id'] for b in fwd})} self-family)"
                    f" × 2 passes → {len(v1) + len(v2)} votes" + (" [REFUSED]" if refusals else "")
                )
        return votes

    # ------------------------------------------------------------------ L5
    def score(
        self,
        findings: list[Finding],
        finders: dict[str, set[ModelFamily]],
        skeptic_by_id: dict[str, SkepticVerdict],
        red_by_id: dict[str, RedTeamNote],
        votes: list[JudgeVote],
        tool_results: list[ToolResult],
        skeptic_abstained_ids: frozenset[str] = frozenset(),
        tool_path_prefix: str = "",
    ) -> list[ConsensusResult]:
        # a family's vote carries its judge's weight (P3: one judge per family), not that of whichever
        # same-family model happens to be listed last - a reviewer-only model used to replace it
        spec = {m.name: m for m in self.cfg.models}
        weights = {spec[n].family: spec[n].weight for n in self.cfg.roles.judges}
        by_finding: dict[str, list[JudgeVote]] = defaultdict(list)
        for v in votes:
            by_finding[v.finding_id].append(v)
        policy = self.outcome_policy
        results: list[ConsensusResult] = []
        flips = 0
        for f in findings:
            raw_votes = by_finding.get(f.id, [])
            counts = Counter((v.judge_family, v.pass_id) for v in raw_votes)
            configured = {self._p(n).family for n in self.cfg.roles.judges}
            valid_families = {fam for fam in configured if counts[(fam, "forward")] == counts[(fam, "reverse")] == 1}
            fv = [v.model_copy(update={"self_family": v.judge_family in finders[f.id]}) for v in raw_votes if v.judge_family in valid_families]
            independent = valid_families - finders[f.id]
            quorum_ok = len(independent) >= self.cfg.gate.min_independent_judges

            score, tp, fp, human, agreeing, consistent = weighted_consensus(fv, weights, self.cfg.gate.self_judge_discount)
            flips += int(not consistent and bool(fv))
            alpha = _agreement_proxy(fv)
            sk = skeptic_by_id.get(f.id)
            refuted = bool(sk and sk.verdict == "refuted")
            abstained = f.id in skeptic_abstained_ids
            prov_ok = bool(f.provenance) and all(p.verified for p in f.provenance)
            corroborated = _tool_corroborates(f, tool_results, tool_path_prefix)
            fams = set(agreeing) | (finders[f.id] if score >= self.cfg.gate.accept_threshold else set())
            if corroborated:
                fams.add(ModelFamily.TOOL)
            tier = assign_tier(
                provenance_verified=prov_ok,
                tool_corroborated=corroborated,
                families_agreeing=sorted(fams, key=lambda x: x.value),
                skeptic_refuted=refuted,
                skeptic_abstained=abstained,
                reachability=f.reachability,
                consensus_score=score,
                accept_threshold=self.cfg.gate.accept_threshold,
            )
            # every Finding's vector was fully parsed and scored when it was built (schemas.Finding._cvss): a model
            # finding with an invalid vector is dropped at L2 as an invalid item, so scoring here cannot fail
            num = cvss4.score(f.cvss4_vector)
            sev = cvss4.severity(num)
            # Keep mathematical CVSS severity separate from the jury's operational opinion.
            family_bands = [max((v.severity_band for v in fv if v.judge_family == fam), key=SEVERITY_ORDER.index) for fam in valid_families]
            operational = sorted(family_bands, key=SEVERITY_ORDER.index)[len(family_bands) // 2] if family_bands else None
            rt = red_by_id.get(f.id)
            ssvc = ssvc_decision(severity=sev, exploitable=rt.exploitable if rt else "unknown", tier=tier)
            outcome = decide(OutcomeSignals(tier=tier, score=score, severity=sev, provenance_verified=prov_ok, skeptic_refuted=refuted,
                                            skeptic_abstained=abstained, quorum_ok=quorum_ok, passes_complete=len(fv) == len(raw_votes),
                                            alpha=alpha, votes_tp=tp, votes_fp=fp, votes_human=human, position_consistent=consistent),
                             policy)
            results.append(
                ConsensusResult(
                    finding_id=f.id,
                    weighted_score=score,
                    votes_tp=tp,
                    votes_fp=fp,
                    votes_human=human,
                    families_agreeing=sorted(fams, key=lambda x: x.value),
                    tool_corroborated=corroborated,
                    skeptic_refuted=refuted,
                    skeptic_abstained=abstained,
                    position_consistent=consistent,
                    tier=tier,
                    cvss4_score=num,
                    cvss4_severity=sev,
                    ssvc_decision=ssvc,
                    **outcome.consensus_fields(),
                    independent_judges=len(independent),
                    agreement_proxy=alpha,
                    operational_severity=operational,
                )
            )
        self.audit["position_flips"] = flips
        return results

    def apply_decisions(self, findings: list[Finding], consensus: list[ConsensusResult], *, target_id: str, revision: str,
                        context_hash: str) -> None:
        """Usable human decisions on this very content settle their findings (docs/adr/0003-human-resolution.md):
        each one is recorded on its consensus row, whose jury outcome stays as it is."""
        from .decisions import TrainingRequirement, select
        from .decisions import load as load_decisions
        from .report.human_queue_out import queue_key
        from .workspace import resolve

        loaded = load_decisions(resolve("calib/decisions"))
        report = {"target_id": target_id, "revision": revision, "coverage": {"content_hash": context_hash}}
        sel = select(loaded.decisions, report, TrainingRequirement.from_config(self.cfg.training))
        usable = {d.key: d for d in sel.usable}
        # a well-formed decision that is not usable settles nothing; the finding says why it still waits
        not_usable = {d.key: why for d, why in sel.excluded if why != "unbound"}
        by_id = {f.id: f for f in findings}
        applied = 0
        for c in consensus:
            f = by_id[c.finding_id]
            key = queue_key(f.provenance[0].file, f.provenance[0].line, f.cwe, target_id=target_id, revision=revision,
                            context_hash=context_hash)
            d = usable.get(key)
            if d is not None:
                c.human_decision = {"decision": d.decision, "key": d.key, "issue": d.issue, "decided_by": d.decided_by,
                                    "decided_at": d.decided_at}
                applied += 1
            elif key in not_usable and c.needs_human:
                c.human_reasons.append(f"decision_not_usable:{not_usable[key]}")
        self.audit["human_decisions_applied"] = applied
        for why, n in sel.by_reason().items():
            if why != "unbound":
                self.audit[f"human_decisions_not_usable[{why}]"] = n

    # ------------------------------------------------------------------ run
    def run(self, target: str | Path, *, sarif_dir: Path | None = None, mode: str = "live",
            base_ref: str | None = None, calibration_sample: bool = False, psirt_event: dict | None = None,
            fail_on_gate: bool = False) -> ReviewReport:
        actual_modes = {p.spec.provider for p in self.providers.values()}
        actual_mode = "mock" if actual_modes == {"mock"} else "live"
        if mode not in {"mock", "live"} or actual_mode != mode or (mode == "live" and "mock" in actual_modes):
            raise ValueError("provider mode does not match the actual provider configuration")
        target = Path(target).resolve()
        # before anything runs: the tools come from, and P8/the backlog were read from, the MARA
        # workspace; none of it may be supplied by the repository under review
        check_outside(target)
        answer_key = calibration_answer_key(target) if calibration_sample else None
        self.out_dir.mkdir(parents=True, exist_ok=True)
        prog = self.progress
        prog.begin("bundle")
        ctx = build_context(target)
        if base_ref:
            # incremental review (assessment #14): keep the changed files, their import
            # neighbours and the manifests/workflows; everything else is excluded, not silently kept
            changed, related = restrict_to_increment(ctx, base_ref)
            self.audit["bundle_files_changed"] = len(changed)
            self.audit["bundle_files_related"] = len(related)
            self._say(f"L1: incremental review vs {base_ref}: {len(changed)} changed, {len(related)} related file(s) in bundle")
        for prov in self.providers.values():
            prov.bind_target(ctx.root)
        self._say(f"L1: {ctx.summary()}")
        prog.done("bundle", f"{len(ctx.content)} file(s) in the bundle, {len(ctx.omitted)} omitted, {len(ctx.excluded)} excluded")
        prog.begin("tools")
        tool_runs = self.run_tools(target, sarif_dir)
        if mode == "live" and sarif_dir:
            # Pre-recorded SARIF cannot authorize egress from the current working tree.
            preflight = run_all(target, self.out_dir / "live-secret-preflight", enabled=["gitleaks"])
            tool_runs = [r for r in tool_runs if r.tool != "gitleaks"] + preflight
        tool_results = [r for run in tool_runs for r in run.results]
        tools_ran = {run.tool for run in tool_runs if run.ran}
        # Live source egress is blocked before any provider sees data if the trusted local
        # secret scan is unavailable or reports secrets (mara.review_status). The masked manifest remains reviewable.
        egress = secret_preflight(mode, [r for r in tool_runs if r.tool == "gitleaks"], answer_key)
        if answer_key is not None and (egress.exempted or egress.unexplained):
            self.audit["secret_preflight_calibration_exempted"] = len(egress.exempted)
            self._say(f"L0: secret preflight: {len(egress.exempted)} seeded secret(s) declared by the calibration answer key, "
                      f"{len(egress.unexplained)} other finding(s)")
        prog.done("tools", f"{len(tools_ran)} of {len(tool_runs)} tool(s) ran, {len(tool_results)} result(s)"
                  + ("; source egress blocked by the secret preflight" if egress.blocked else ""))
        # L1.5: the C4-lite context view is one provider call; it must not run when egress is blocked
        if egress.blocked or not self.cfg.roles.context:
            prog.skip("context", "source egress blocked by the secret preflight" if egress.blocked else "no context role configured")
            context_view = None
        else:
            prog.begin("context")
            context_view = self.run_context(ctx)
            prog.done("context", f"{len(context_view.items) if context_view else 0} verified fact(s)")
        if context_view is not None:
            (self.out_dir / "context.json").write_text(context_view.model_dump_json(indent=2), encoding="utf-8")
            self.audit["context_view_items"] = len(context_view.items)
        if egress.blocked:
            prog.skip("reviewers", "source egress blocked by the secret preflight")
            raw = []
        else:
            prog.begin("reviewers")
            raw = self.run_reviewers(ctx, context_view)
        findings, finders = self.dedupe(raw)
        if not egress.blocked:
            prog.done("reviewers", f"{len(raw)} raw finding(s), {len(findings)} after deduplication")
        findings = [f.model_copy(update={"finder_families": sorted(finders[f.id], key=lambda x: x.value)}) for f in findings]
        self.audit["findings_raw"] = len(raw)
        self.audit["findings_deduped"] = len(findings)
        prog.begin("skeptic")
        sk, abstained_ids = self.run_skeptics(ctx, findings, finders)
        sk_by_id = {v.finding_id: v for v in sk}
        survivors = [f for f in findings if sk_by_id.get(f.id, None) is None or sk_by_id[f.id].verdict != "refuted"]
        prog.done("skeptic", f"{len(sk)} verdict(s) on {len(findings)} finding(s), {len(findings) - len(survivors)} refuted")
        prog.begin("redteam")
        rt = self.run_redteam(ctx, survivors, finders)
        rt_by_id = {n.finding_id: n for n in rt}
        prog.done("redteam", f"{len(rt)} note(s), {sum(n.exploitable == 'yes' for n in rt)} exploitable")
        prog.begin("jury")
        votes = self.run_jury(ctx, findings, sk_by_id, finders)
        prog.done("jury", f"{len(votes)} vote(s) over the forward and reverse passes")
        prog.begin("scoring")
        consensus = self.score(findings, finders, sk_by_id, rt_by_id, votes, tool_results, skeptic_abstained_ids=abstained_ids,
                               tool_path_prefix=ctx.repo_prefix)
        # repository + path below its top level for a committed git target (repo_map.target_identity),
        # so CI, every clone and every calibration run name the same target the same way
        target_id = hashlib.sha256(ctx.identity.encode()).hexdigest()
        self.apply_decisions(findings, consensus, target_id=target_id, revision=ctx.revision, context_hash=ctx.content_hash)
        cons_by_id = {c.finding_id: c for c in consensus}
        dims = []
        for d in self.cfg.dimensions:
            tool_ran = any(d in TOOL_DIMENSIONS.get(t, []) for t in tools_ran)
            dims.append(score_dimension(d, findings, cons_by_id, tool_ran))
        required_tools = {t for t, ds in TOOL_DIMENSIONS.items() if set(ds) & set(self.cfg.dimensions)}
        signed: bool | None = None
        if self.cfg.ml_bom.require_signature:
            # P7 checked offline that the bundle belongs to the BOM; here cosign verifies the signature and its signer
            from .mlbom import verify_signature

            signed, why = verify_signature(self.cfg)
            self.audit["ml_bom_signature"] = "verified" if signed else f"failed: {why}"
        facts = ReviewFacts(context_complete=ctx.complete, egress_blocked=egress.blocked,
                            required_tools_ran=required_tools <= tools_ran and all(r.ran for r in tool_runs), ml_bom_signature=signed,
                            context_view_missing=bool(self.cfg.roles.context) and context_view is None,
                            incomplete_counters=tuple(self.audit.incomplete_reasons()),  # audit.INCOMPLETE_COUNTERS: the one list
                            rollout_phase=self.cfg.rollout.phase, fail_on_gate=fail_on_gate)
        assessment = assess(facts, consensus, tool_results, dims, self.outcome_policy, self.gate_policy)
        for c in consensus:
            c.blocking_reason = assessment.blocking_reasons.get(c.finding_id)
        if assessment.tier_c_blocked_while_tightened:
            self.audit["tier_c_blocked_while_tightened"] = assessment.tier_c_blocked_while_tightened
        global_alpha = krippendorff_alpha_nominal(_alpha_units(findings, votes))
        self.audit["global_krippendorff_alpha"] = global_alpha if global_alpha is not None else "n/a"
        for k, v in pairwise_family_agreement(votes).items():
            self.audit[f"judge_agreement[{k}]"] = v
        self.audit["tool_results_ingested"] = len(tool_results)
        self.audit["tools_ran"] = ",".join(sorted(tools_ran)) or "none"
        prog.done("scoring", f"review {assessment.review_status}, gate {'passed' if assessment.gate_passed else 'blocked'}")
        prog.begin("report")
        report = ReviewReport(
            target=str(target),
            generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            provider_mode=mode,
            families_used=sorted({m.family.value for m in self.cfg.models}),
            findings=findings,
            skeptic=sk,
            redteam=rt,
            review_status=assessment.review_status,
            incomplete_reasons=list(assessment.incomplete_reasons),
            review_scope="incremental" if base_ref else "full",
            coverage=ctx.coverage(),
            tool_results=[asdict(t) for t in tool_results],
            tool_health=[{"tool": t.tool, "ran": t.ran, "note": t.note} for t in tool_runs],
            provider_manifest=[{"name": n, "type": p.spec.provider, "family": p.family.value, "model": p.model,
                                "served_models": sorted(getattr(p, "served_models", ()))} for n, p in self.providers.items()],
            config_hash=hashlib.sha256(self.cfg.model_dump_json().encode()).hexdigest(),
            target_id=target_id,
            revision=ctx.revision,
            votes=votes,
            consensus=consensus,
            dimensions=dims,
            overall_score=assessment.overall_score,
            gate_passed=assessment.gate_passed,
            gate_reasons=list(assessment.gate_reasons),
            gate_enforced=assessment.gate_enforced,
            # the accounting the counts above follow (docs/adr/0001-reply-outcome-accounting.md)
            bias_audit={**self.audit, "exchange_version": exchange.EXCHANGE_VERSION},
        )
        # G-11: the human queue as an object with full context; decisions come back through calib/decisions
        from .report.human_queue_out import build_queue

        report.human_queue = build_queue(
            findings,
            cons_by_id,
            sk_by_id,
            rt_by_id,
            votes,
            self.cfg,
            target_id=target_id,
            revision=ctx.revision,
            context_hash=ctx.content_hash,
        )
        queue_audit: dict[str, float | int | str] = {
            "human_queue_size": len(report.human_queue),
            "human_queue_backlog": self.backlog if self.backlog is not None else "unknown",
            "human_queue_tightened": int(self.queue_tightened),
            "human_alpha_threshold": self.outcome_policy.alpha_threshold,
        }
        for k, qv in queue_audit.items():
            self.audit[k] = qv
            report.bias_audit[k] = qv
        self._say(
            f"L5: human queue: {len(report.human_queue)} item(s)"
            + (
                f" [TIGHTENED: backlog {self.backlog} > {self.cfg.human_queue.backlog_limit}, alpha threshold {self.outcome_policy.alpha_threshold}"
                f"{', tier C not queued' if self.outcome_policy.exclude_tier_c else ''}]"
                if self.queue_tightened
                else ""
            )
        )
        # G-12: accepted tier-A Critical findings on a shipped product start the CRA Article 14 clock
        from .report.psirt_out import build_notifications

        report.psirt = build_notifications(report, self.cfg, event=psirt_event)  # built once: the count below is these
        self.audit["psirt_notifications"] = len(report.psirt)
        report.bias_audit["psirt_notifications"] = len(report.psirt)
        # G-7: which self-hosted weights the report was produced with, as the ML-BOM knows them
        ml_bom = {
            n: {"model_id": st.model_id, "status": st.status, "component": st.component_name, "version": st.component_version, "sha256": st.digest}
            for n, st in self.ml_bom_status.items()
        }
        self.audit["ml_bom"] = ml_bom
        report.bias_audit["ml_bom"] = ml_bom
        self.audit["rollout_phase"] = self.cfg.rollout.phase
        report.bias_audit["rollout_phase"] = self.cfg.rollout.phase
        # G-8: latest red-team evaluation verdict per family (garak / CyberSecEval), 'none' until one has run
        from .model_eval import family_eval_status

        # the MARA workspace (MARA_HOME), like every other piece of MARA's own evidence: never the working
        # directory, which may be the repository under review
        from .workspace import root as workspace_root

        me = family_eval_status(workspace_root(), sorted({m.family.value for m in self.cfg.models if m.provider != "mock"}))
        self.audit["model_eval"] = me
        report.bias_audit["model_eval"] = me
        if ml_bom:
            self._say("L0: ML-BOM: " + ", ".join(f"{n} {v['status']}" for n, v in ml_bom.items()))
        self._say(f"L5: PSIRT hand-off: {len(report.psirt)} finding(s)" if self.cfg.psirt.enabled else "L5: PSIRT hand-off disabled")
        prog.done("report", f"{len(report.human_queue)} human-queue item(s), {len(report.psirt)} PSIRT payload(s)")
        return report


def _agreement_proxy(votes: list[JudgeVote]) -> float | None:
    """Agreement among judges on one finding, treating each (judge, pass) as a rater over the
    two-unit set {this finding forward, this finding reverse} is degenerate; instead we report
    the simple share of the modal verdict as a bounded proxy when alpha is undefined."""
    if len(votes) < 2:
        return None
    from collections import Counter

    # Exactly one family-level verdict; split passes are an explicit abstention.
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


def calibration_answer_key(target: Path) -> list[dict]:
    """The seeded-secret labels (CWE-798) of a calibration sample, for the secret-preflight exemption.

    Only an operator flag (`mara review --calibration-sample`) asks for it, and only a directory below
    the MARA workspace's calib/samples/ with a MARA answer key qualifies: a reviewed repository cannot
    exempt its own secrets by shipping a labels.json, since its location is the operator's choice and
    the exemption is off for every ordinary review."""
    from .context.repo_map import is_calibration_answer_key
    from .workspace import root as workspace_root

    samples = (workspace_root() / "calib" / "samples").resolve()
    target = Path(target).resolve()
    if samples not in target.parents:
        raise ValueError(f"--calibration-sample needs a target below {samples}, got {target}")
    path = target / "labels.json"
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if not is_calibration_answer_key("labels.json", text):
        raise ValueError(f"--calibration-sample: {path} is not a calibration answer key")
    return [lab for lab in json.loads(text)["labels"] if str(lab.get("cwe", "")).upper() == "CWE-798"]


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


def _tool_corroborates(f: Finding, tool_results: list[ToolResult], prefix: str = "") -> bool:
    """A tool result corroborates a finding (tier A) only on the same file, within +-3 lines, with a
    matching CWE (or none), from a tool that scans the finding's dimension, at level error or
    warning - the levels that also block as unresolved tool findings; a note is information.

    Same file means the exact path. Tools that ran from the repository top level report paths
    below it (pre-recorded zizmor: fixtures/vuln-sample/.github/workflows/deploy.yml), so a path
    that is exactly `prefix/<finding path>` also matches, prefix being the target's own path below
    the top level. A bare suffix match did not: `main.py` matched `services/billing/main.py`, and a
    tool hit in another file promoted a single-family finding to tier A."""
    for t in tool_results:
        # a tool only corroborates findings in the dimensions it scans for (TOOL_DIMENSIONS):
        # csp-evaluator emits results without CWEs, and without this guard any such result would
        # corroborate any finding that happens to sit within +-3 lines
        if f.dimension not in TOOL_DIMENSIONS.get(t.tool, []) or t.level not in ("error", "warning"):
            continue
        tf = norm_path(t.file)
        for p in f.provenance:
            pf = norm_path(p.file)
            same_file = tf == pf or (bool(prefix) and tf == f"{prefix}/{pf}")
            if same_file and abs(t.line - p.line) <= NEAR_LINES:
                cwes = {norm_cwe(c) for c in (t.cwes or ([t.cwe] if t.cwe else []))}
                if not cwes or norm_cwe(f.cwe) in cwes:
                    return True
    return False
