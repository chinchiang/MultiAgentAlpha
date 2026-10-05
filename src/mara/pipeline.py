"""Orchestrator: L0 tools -> L1 context -> L2 reviewers -> L3 skeptic/red team -> L4 blinded jury
-> L5 deterministic scoring and reports. No layer talks to another except through validated
schemas; reviewers never see each other's output; judges never see model identity.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .agents import base, context_agent, judge, redteam, reviewer, skeptic
from .agents.context_agent import ContextView
from .bias.blinding import blinded_batches
from .bias.diversity import pairwise_family_agreement, pick_independent
from .config import MaraConfig
from .context.repo_map import RepoContext, build_context, restrict_to_increment
from .providers import make_provider
from .providers.base import Provider
from .schemas import (
    SEVERITY_ORDER,
    ConsensusResult,
    EvidenceTier,
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
from .scoring.tiers import assign_tier, ssvc_decision
from .tools.runner import TOOL_DIMENSIONS, ToolRun, load_prerecorded, run_all
from .tools.sarif import ToolResult
from .workspace import check_outside

# error vocabulary of the agent layer: "refused" marks an abstention (model said no), the
# incomplete_or_duplicate_* entries are summary markers the agents append to signal that a
# partially-failed call returned no verdicts at all; neither is an unusable item itself
_ERROR_MARKERS = frozenset({"refused", "canary_echoed", "incomplete_or_duplicate_response", "incomplete_or_duplicate_judge_response"})


def _count_invalid(errors: list[str]) -> int:
    """Unusable items only: empty responses, bad shapes, per-item schema failures."""
    return sum(1 for x in errors if x not in _ERROR_MARKERS)


class Pipeline:
    def __init__(self, cfg: MaraConfig, *, mock_fixtures: str | None = None, out_dir: Path | None = None):
        self.cfg = cfg
        self.out_dir = out_dir or Path("out")
        self.providers: dict[str, Provider] = {m.name: make_provider(m, mock_fixtures) for m in cfg.models}
        # Counters (default 0) plus a few labels and nested tables; becomes the report's bias_audit
        self.audit: defaultdict[str, Any] = defaultdict(int)
        self.log: list[str] = []
        # G-11: the human queue tightens when its ticket backlog is over the limit (never loosens)
        from .report.human_queue_out import read_backlog, tightening

        self.backlog = read_backlog(cfg)
        self.human_alpha_threshold, self.exclude_tier_c, self.queue_tightened = tightening(cfg, self.backlog)
        from .mlbom import status_for_config

        self.ml_bom_status = status_for_config(cfg)

    # ------------------------------------------------------------------ helpers
    def _p(self, name: str) -> Provider:
        return self.providers[name]

    def _say(self, msg: str) -> None:
        self.log.append(msg)

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
        self.audit["context_calls"] += audit["calls"]
        self.audit[f"context_calls[{fam}]"] += audit["calls"]
        for key, counter in (("refused", "context_refusals"), ("truncated", "context_truncations"),
                             ("errored", "context_errors"), ("canary_echoed", "canary_echoes"),
                             ("invalid", "context_invalid_items"), ("unverified", "context_unverified_items")):
            self.audit[counter] += int(audit[key])
            self.audit[f"{counter}[{fam}]"] += int(audit[key])
        self.audit["input_tokens"] += audit["input_tokens"]
        self.audit["output_tokens"] += audit["output_tokens"]
        flags = {"refused": " [REFUSED]", "truncated": " [TRUNCATED]", "errored": " [PROVIDER ERROR]",
                 "canary_echoed": " [CANARY ECHOED]"}
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
                    self.audit["reviewer_calls"] += 1
                    self.audit["reviewer_refusals"] += int(audit["refused"])
                    self.audit["reviewer_truncations"] += int(audit["truncated"])
                    self.audit["reviewer_errors"] += int(audit["errored"])
                    self.audit["canary_echoes"] += int(audit["canary_echoed"])
                    fam = prov.family.value
                    self.audit[f"reviewer_calls[{fam}]"] += 1
                    self.audit[f"reviewer_refusals[{fam}]"] += int(audit["refused"])
                    self.audit[f"reviewer_truncations[{fam}]"] += int(audit["truncated"])
                    self.audit[f"reviewer_errors[{fam}]"] += int(audit["errored"])
                    self.audit[f"canary_echoes[{fam}]"] += int(audit["canary_echoed"])
                    self.audit[f"findings_with_unverified_quotes[{fam}]"] += audit["unverified_quotes"]
                    self.audit[f"invalid_findings_dropped[{fam}]"] += audit["invalid"]
                    self.audit["invalid_findings_dropped"] += audit["invalid"]
                    self.audit["findings_with_unverified_quotes"] += audit["unverified_quotes"]
                    self.audit["input_tokens"] += audit["input_tokens"]
                    self.audit["output_tokens"] += audit["output_tokens"]
                    raw.extend(findings)
                    tags = {"refused": " [REFUSED]", "truncated": " [TRUNCATED]", "errored": " [PROVIDER ERROR]", "canary_echoed": " [CANARY ECHOED]"}
                    flags = [tag for key, tag in tags.items() if audit[key]]
                    self._say(f"L2: {dim} × {prov.family.value}: {len(findings)} finding(s)" + "".join(flags))
        # assign ids and strip unknown standard references. Ids are content-ordered (file, line,
        # cwe, dimension, title) rather than call-ordered: consecutive ids no longer reveal which
        # findings shared a reviewer call, so the blinded view leaks no grouping (judge.md promises
        # no source identity; id clusters are a subtle channel back to it).
        raw.sort(key=lambda f: (_norm_path(f.provenance[0].file), f.provenance[0].line, f.cwe, f.dimension, f.title))
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
                if k.dimension == f.dimension and k.cwe == f.cwe and q.file == p.file and abs(q.line - p.line) <= 3 and k_ok == f_ok:
                    match = k
                    break
            if match is None:
                kept.append(f)
                finders[f.id] = {f.source_family}
            else:
                finders[match.id].add(f.source_family)
        return kept, finders

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
        for name, fs in groups.items():
            fam = self._p(name).family.value
            self.audit["skeptic_calls"] += 1
            self.audit[f"skeptic_calls[{fam}]"] += 1
            self.audit[f"skeptic_items[{fam}]"] += len(fs)
            v, errors, unverified = skeptic.run_skeptic(self._p(name), ctx, fs)
            refusals = errors.count("refused")
            invalid = _count_invalid(errors)
            self.audit["skeptic_invalid_items"] += invalid
            self.audit[f"skeptic_invalid_items[{fam}]"] += invalid
            self.audit["skeptic_refusals"] += refusals
            self.audit[f"skeptic_refusals[{fam}]"] += refusals
            self.audit["skeptic_unverified_controls"] += unverified
            self.audit[f"skeptic_unverified_controls[{fam}]"] += unverified
            self.audit["skeptic_canary_echoes"] += errors.count("canary_echoed")
            self.audit[f"skeptic_canary_echoes[{fam}]"] += errors.count("canary_echoed")
            for x in v:
                if x.verdict == "refuted":
                    self.audit["skeptic_refuted"] += 1
                    self.audit[f"skeptic_refuted[{fam}]"] += 1
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
        for name, fs in groups.items():
            fam = self._p(name).family.value
            self.audit["redteam_calls"] += 1
            self.audit[f"redteam_calls[{fam}]"] += 1
            self.audit[f"redteam_items[{fam}]"] += len(fs)
            n, errors, stripped = redteam.run_redteam(self._p(name), ctx, fs)
            refusals = errors.count("refused")
            invalid = _count_invalid(errors)
            self.audit["redteam_invalid_items"] += invalid
            self.audit[f"redteam_invalid_items[{fam}]"] += invalid
            self.audit["redteam_refusals"] += refusals
            self.audit[f"redteam_refusals[{fam}]"] += refusals
            self.audit["redteam_exploit_code_stripped"] += stripped
            self.audit[f"redteam_exploit_code_stripped[{fam}]"] += stripped
            self.audit["redteam_canary_echoes"] += errors.count("canary_echoed")
            self.audit[f"redteam_canary_echoes[{fam}]"] += errors.count("canary_echoed")
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
            self.audit["judge_calls"] += 2
            self.audit[f"judge_calls[{fam}]"] += 2
            self.audit[f"judge_items[{fam}]"] += len(eligible)
            fwd, rev = blinded_batches(eligible, skeptic_by_id, ctx.content_hash + prov.family.value)
            v1, e1 = judge.run_judge(prov, fwd, "forward", self_ids)
            v2, e2 = judge.run_judge(prov, rev, "reverse", self_ids)
            refusals = int(e1 == ["refused"]) + int(e2 == ["refused"])
            invalid = _count_invalid(e1) + _count_invalid(e2)
            self.audit["judge_invalid_items"] += invalid
            self.audit[f"judge_invalid_items[{fam}]"] += invalid
            self.audit["judge_refusals"] += refusals
            self.audit[f"judge_refusals[{fam}]"] += refusals
            votes.extend(v1 + v2)
            self._say(
                f"L4: judge {fam}: {len(eligible)} finding(s) ({len(self_ids)} self-family) × 2 passes → {len(v1) + len(v2)} votes"
                + (" [REFUSED]" if refusals else "")
            )
        return votes

    # ------------------------------------------------------------------ L5
    def blocking_reason(self, c: ConsensusResult) -> str | None:
        """Why an accepted finding blocks the gate, or None.

        The configured conjunction (tier in block_on_tiers, severity in block_on_severity), plus one
        rule of G-11's tightening: over the backlog limit tier C at or above
        queue_tier_c_min_severity is no longer queued for a human (tighten_exclude_tier_c), so such
        a finding blocks instead of passing on one family's word plus the jury. Tightening may cut
        human work; it never lets more through. An unknown severity ranks above every band."""
        if not c.accepted:
            return None
        if c.tier.value in self.cfg.gate.block_on_tiers and c.cvss4_severity in self.cfg.gate.block_on_severity:
            return "blocking_tier_and_severity"
        sev_rank = SEVERITY_ORDER.index(c.cvss4_severity) if c.cvss4_severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
        if self.exclude_tier_c and c.tier == EvidenceTier.C and sev_rank >= SEVERITY_ORDER.index(self.cfg.human_queue.queue_tier_c_min_severity):
            return "tier_c_while_tightened"
        return None

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
        weights = {m.family: m.weight for m in self.cfg.models}
        by_finding: dict[str, list[JudgeVote]] = defaultdict(list)
        for v in votes:
            by_finding[v.finding_id].append(v)
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
            try:
                num = cvss4.score(f.cvss4_vector)
                sev = cvss4.severity(num)
            except cvss4.CVSS4Error:
                num, sev = None, "Unknown"
                self.audit["invalid_cvss_vectors"] += 1
            # Keep mathematical CVSS severity separate from the jury's operational opinion.
            family_bands = [max((v.severity_band for v in fv if v.judge_family == fam), key=SEVERITY_ORDER.index) for fam in valid_families]
            operational = sorted(family_bands, key=SEVERITY_ORDER.index)[len(family_bands) // 2] if family_bands else None
            rt = red_by_id.get(f.id)
            ssvc = ssvc_decision(severity=sev, exploitable=rt.exploitable if rt else "unknown", tier=tier)
            reasons = []
            if not prov_ok:
                reasons.append("unverified_provenance")
            if abstained:
                reasons.append("skeptic_abstained")
            if not quorum_ok:
                reasons.append("insufficient_independent_judges")
            if len(fv) != len(raw_votes):
                reasons.append("invalid_or_incomplete_judge_passes")
            if num is None:
                reasons.append("invalid_cvss_vector")
            if alpha is not None and alpha < self.human_alpha_threshold:
                reasons.append("agreement_below_threshold")
            if human > tp and human > fp:
                reasons.append("majority_needs_human")
            if not consistent and fv:
                reasons.append("position_inconsistent")
            # G-11: tier C at or above the configured severity goes to a human - unless the queue is
            # tightened over its backlog limit (config tighten_exclude_tier_c), in which case the
            # jury's consensus decides and build_queue stops queuing tier C. An unknown severity
            # ranks above every band so the queue trigger stays fail-closed.
            min_c = SEVERITY_ORDER.index(self.cfg.human_queue.queue_tier_c_min_severity)
            sev_rank = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else len(SEVERITY_ORDER)
            if tier == EvidenceTier.C and not self.exclude_tier_c and sev_rank >= min_c:
                reasons.append("tier_c_high")
            if refuted and tier != EvidenceTier.D:
                # assessment #37: a refuted finding never re-enters the blocking logic on the
                # jury's vote alone; the jury may speak, but a human decides.
                reasons.append("skeptic_refuted_jury_overrode")
            needs_human = bool(reasons)
            accepted = tier != EvidenceTier.D and score >= self.cfg.gate.accept_threshold and not needs_human
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
                    accepted=accepted,
                    needs_human=needs_human,
                    human_reasons=reasons,
                    independent_judges=len(independent),
                    agreement_proxy=alpha,
                    operational_severity=operational,
                )
            )
        self.audit["position_flips"] = flips
        return results

    # ------------------------------------------------------------------ run
    def run(self, target: str | Path, *, sarif_dir: Path | None = None, mode: str = "live",
            base_ref: str | None = None) -> ReviewReport:
        actual_modes = {p.spec.provider for p in self.providers.values()}
        actual_mode = "mock" if actual_modes == {"mock"} else "live"
        if mode not in {"mock", "live"} or actual_mode != mode or (mode == "live" and "mock" in actual_modes):
            raise ValueError("provider mode does not match the actual provider configuration")
        target = Path(target).resolve()
        # before anything runs: the tools come from, and P8/the backlog were read from, the MARA
        # workspace; none of it may be supplied by the repository under review
        check_outside(target)
        self.out_dir.mkdir(parents=True, exist_ok=True)
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
        tool_runs = self.run_tools(target, sarif_dir)
        if mode == "live" and sarif_dir:
            # Pre-recorded SARIF cannot authorize egress from the current working tree.
            preflight = run_all(target, self.out_dir / "live-secret-preflight", enabled=["gitleaks"])
            tool_runs = [r for r in tool_runs if r.tool != "gitleaks"] + preflight
        tool_results = [r for run in tool_runs for r in run.results]
        tools_ran = {run.tool for run in tool_runs if run.ran}
        # Live source egress is blocked before any provider sees data if the trusted local
        # secret scan is unavailable or reports secrets. The masked manifest remains reviewable.
        secret_runs = [r for r in tool_runs if r.tool == "gitleaks"]
        egress_blocked = mode == "live" and (not secret_runs or any(not r.ran or r.results for r in secret_runs))
        # L1.5: the C4-lite context view is one provider call; it must not run when egress is blocked
        context_view = None if egress_blocked else self.run_context(ctx)
        if context_view is not None:
            (self.out_dir / "context.json").write_text(context_view.model_dump_json(indent=2), encoding="utf-8")
            self.audit["context_view_items"] = len(context_view.items)
        raw = [] if egress_blocked else self.run_reviewers(ctx, context_view)
        findings, finders = self.dedupe(raw)
        findings = [f.model_copy(update={"finder_families": sorted(finders[f.id], key=lambda x: x.value)}) for f in findings]
        self.audit["findings_raw"] = len(raw)
        self.audit["findings_deduped"] = len(findings)
        sk, abstained_ids = self.run_skeptics(ctx, findings, finders)
        sk_by_id = {v.finding_id: v for v in sk}
        survivors = [f for f in findings if sk_by_id.get(f.id, None) is None or sk_by_id[f.id].verdict != "refuted"]
        rt = self.run_redteam(ctx, survivors, finders)
        rt_by_id = {n.finding_id: n for n in rt}
        votes = self.run_jury(ctx, findings, sk_by_id, finders)
        consensus = self.score(findings, finders, sk_by_id, rt_by_id, votes, tool_results, skeptic_abstained_ids=abstained_ids,
                               tool_path_prefix=ctx.repo_prefix)
        cons_by_id = {c.finding_id: c for c in consensus}
        dims = []
        for d in self.cfg.dimensions:
            tool_ran = any(d in TOOL_DIMENSIONS.get(t, []) for t in tools_ran)
            dims.append(score_dimension(d, findings, cons_by_id, tool_ran))
        overall: float | None = round(sum(x.score for x in dims) / len(dims), 1) if dims else 0.0
        incomplete = []
        if not ctx.complete:
            incomplete.append("context_coverage_incomplete")
        if egress_blocked:
            incomplete.append("source_egress_blocked_by_secret_preflight")
        required_tools = {t for t, ds in TOOL_DIMENSIONS.items() if set(ds) & set(self.cfg.dimensions)}
        if not required_tools <= tools_ran or any(not r.ran for r in tool_runs):
            incomplete.append("required_tool_incomplete")
        for key in (
            "reviewer_refusals",
            "reviewer_truncations",
            "reviewer_errors",
            "invalid_findings_dropped",
            "canary_echoes",
            "skeptic_canary_echoes",
            "redteam_canary_echoes",
            "judge_invalid_items",
            "judge_refusals",
            "skeptic_invalid_items",
            "skeptic_refusals",
            "redteam_invalid_items",
            "redteam_refusals",
            "redteam_exploit_code_stripped",
            "context_refusals",
            "context_truncations",
            "context_errors",
            "context_invalid_items",
            "context_unverified_items",
        ):
            if self.audit[key]:
                incomplete.append(key)
        if self.cfg.roles.context and context_view is None and not egress_blocked:
            incomplete.append("context_view_incomplete")
        if any(c.needs_human for c in consensus):
            incomplete.append("unresolved_human_review")
        # Tool evidence remains visible independently of model output. A model's silence or
        # rejection never clears an unsuppressed tool result.
        if any(t.level in {"error", "warning"} for t in tool_results):
            incomplete.append("unresolved_tool_findings")
        gate = not incomplete
        if incomplete:
            overall = None
        for c in consensus:
            reason = self.blocking_reason(c)
            if reason:
                gate = False
                if reason == "tier_c_while_tightened":
                    self.audit["tier_c_blocked_while_tightened"] += 1
        if any(x.score < self.cfg.gate.min_dimension_score for x in dims):
            gate = False
        global_alpha = krippendorff_alpha_nominal(_alpha_units(findings, votes))
        self.audit["global_krippendorff_alpha"] = global_alpha if global_alpha is not None else "n/a"
        for k, v in pairwise_family_agreement(votes).items():
            self.audit[f"judge_agreement[{k}]"] = v
        self.audit["tool_results_ingested"] = len(tool_results)
        self.audit["tools_ran"] = ",".join(sorted(tools_ran)) or "none"
        # repository + path below its top level for a committed git target (repo_map.target_identity),
        # so CI, every clone and every calibration run name the same target the same way
        target_id = hashlib.sha256(ctx.identity.encode()).hexdigest()
        report = ReviewReport(
            target=str(target),
            generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            provider_mode=mode,
            families_used=sorted({m.family.value for m in self.cfg.models}),
            findings=findings,
            skeptic=sk,
            redteam=rt,
            review_status="incomplete" if incomplete else "complete",
            incomplete_reasons=incomplete,
            coverage=ctx.coverage(),
            tool_results=[asdict(t) for t in tool_results],
            tool_health=[{"tool": t.tool, "ran": t.ran, "note": t.note} for t in tool_runs],
            provider_manifest=[{"name": n, "type": p.spec.provider, "family": p.family.value, "model": p.model} for n, p in self.providers.items()],
            config_hash=hashlib.sha256(self.cfg.model_dump_json().encode()).hexdigest(),
            target_id=target_id,
            revision=ctx.revision,
            votes=votes,
            consensus=consensus,
            dimensions=dims,
            overall_score=overall,
            gate_passed=gate,
            bias_audit=dict(self.audit),
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
            exclude_tier_c=self.exclude_tier_c,
            target_id=target_id,
            revision=ctx.revision,
            context_hash=ctx.content_hash,
        )
        queue_audit: dict[str, float | int | str] = {
            "human_queue_size": len(report.human_queue),
            "human_queue_backlog": self.backlog if self.backlog is not None else "unknown",
            "human_queue_tightened": int(self.queue_tightened),
            "human_alpha_threshold": self.human_alpha_threshold,
        }
        for k, qv in queue_audit.items():
            self.audit[k] = qv
            report.bias_audit[k] = qv
        self._say(
            f"L5: human queue: {len(report.human_queue)} item(s)"
            + (
                f" [TIGHTENED: backlog {self.backlog} > {self.cfg.human_queue.backlog_limit}, alpha threshold {self.human_alpha_threshold}"
                f"{', tier C not queued' if self.exclude_tier_c else ''}]"
                if self.queue_tightened
                else ""
            )
        )
        # G-12: accepted tier-A Critical findings on a shipped product start the CRA Article 14 clock
        from .report.psirt_out import build_notifications

        report.psirt = build_notifications(report, self.cfg)
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

        me = family_eval_status(Path.cwd(), sorted({m.family.value for m in self.cfg.models if m.provider != "mock"}))
        self.audit["model_eval"] = me
        report.bias_audit["model_eval"] = me
        if ml_bom:
            self._say("L0: ML-BOM: " + ", ".join(f"{n} {v['status']}" for n, v in ml_bom.items()))
        self._say(f"L5: PSIRT hand-off: {len(report.psirt)} finding(s)" if self.cfg.psirt.enabled else "L5: PSIRT hand-off disabled")
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


def _norm_path(path: str) -> str:
    """Forward slashes, no leading './' (str.lstrip('./') would also eat the dot of '.github')."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


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
        tf = _norm_path(t.file)
        for p in f.provenance:
            pf = _norm_path(p.file)
            same_file = tf == pf or (bool(prefix) and tf == f"{prefix}/{pf}")
            if same_file and abs(t.line - p.line) <= 3:
                cwes = {c.upper() for c in (t.cwes or ([t.cwe] if t.cwe else []))}
                if not cwes or f.cwe.upper() in cwes:
                    return True
    return False
