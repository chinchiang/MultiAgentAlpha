"""Orchestrator: L0 tools -> L1 context -> L2 reviewers -> L3 skeptic/red team -> L4 blinded jury
-> L5 deterministic scoring and reports. No layer talks to another except through validated
schemas; reviewers never see each other's output; judges never see model identity.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from pathlib import Path

from .agents import base, judge, redteam, reviewer, skeptic
from .bias.blinding import blinded_batches
from .bias.diversity import pairwise_family_agreement, pick_skeptic
from .config import MaraConfig
from .context.repo_map import RepoContext, build_context
from .providers import make_provider
from .providers.base import Provider
from .schemas import (
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


class Pipeline:
    def __init__(self, cfg: MaraConfig, *, mock_fixtures: str | None = None, out_dir: Path | None = None):
        self.cfg = cfg
        self.out_dir = out_dir or Path("out")
        self.providers: dict[str, Provider] = {m.name: make_provider(m, mock_fixtures) for m in cfg.models}
        self.audit: dict[str, float | int | str] = defaultdict(int)
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

    # ------------------------------------------------------------------ L2
    def run_reviewers(self, ctx: RepoContext) -> list[Finding]:
        canary = base.Canary()
        raw: list[Finding] = []
        for dim in self.cfg.dimensions:
            for name in self.cfg.roles.reviewers:
                prov = self._p(name)
                findings, audit = reviewer.review_dimension(prov, ctx, dim, canary)
                self.audit["reviewer_calls"] += 1
                self.audit["reviewer_refusals"] += int(audit["refused"])
                self.audit["canary_echoes"] += int(audit["canary_echoed"])
                fam = prov.family.value
                self.audit[f"reviewer_calls[{fam}]"] += 1
                self.audit[f"reviewer_refusals[{fam}]"] += int(audit["refused"])
                self.audit[f"canary_echoes[{fam}]"] += int(audit["canary_echoed"])
                self.audit[f"findings_with_unverified_quotes[{fam}]"] += audit["unverified_quotes"]
                self.audit[f"invalid_findings_dropped[{fam}]"] += audit["invalid"]
                self.audit["invalid_findings_dropped"] += audit["invalid"]
                self.audit["findings_with_unverified_quotes"] += audit["unverified_quotes"]
                self.audit["input_tokens"] += audit["input_tokens"]
                self.audit["output_tokens"] += audit["output_tokens"]
                raw.extend(findings)
                self._say(f"L2: {dim} × {prov.family.value}: {len(findings)} finding(s)"
                          + (" [REFUSED]" if audit["refused"] else "") + (" [CANARY ECHOED]" if audit["canary_echoed"] else ""))
        # assign ids and strip unknown standard references
        out: list[Finding] = []
        for i, f in enumerate(raw, 1):
            f = f.model_copy(update={"id": f"F-{i:04d}"})
            f, reasons = check_finding_refs(f)
            self.audit["standard_refs_stripped"] += len(reasons)
            out.append(f)
        return out

    @staticmethod
    def dedupe(findings: list[Finding]) -> tuple[list[Finding], dict[str, set[ModelFamily]]]:
        """Merge findings from different families that point at the same file/line(+-3)/CWE."""
        kept: list[Finding] = []
        finders: dict[str, set[ModelFamily]] = {}
        for f in findings:
            p = f.provenance[0]
            match = None
            f_ok = any(x.verified for x in f.provenance)
            for k in kept:
                q = k.provenance[0]
                k_ok = any(x.verified for x in k.provenance)
                # never merge an unverified (possibly fabricated) finding into a verified one:
                # it would inherit the verified finding's acceptance and hide the fabrication
                if (k.dimension == f.dimension and k.cwe == f.cwe and q.file == p.file
                        and abs(q.line - p.line) <= 3 and k_ok == f_ok):
                    match = k
                    break
            if match is None:
                kept.append(f)
                finders[f.id] = {f.source_family}
            else:
                finders[match.id].add(f.source_family)
        return kept, finders

    # ------------------------------------------------------------------ L3
    def run_skeptics(self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]) -> list[SkepticVerdict]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            # the skeptic must not share a family with ANY finder of this finding
            fams = finders[f.id]
            spec = None
            for cand in [self.cfg.roles.skeptic] + self.cfg.roles.judges + self.cfg.roles.reviewers:
                if self.cfg.model_by_name(cand).family not in fams:
                    spec = self.cfg.model_by_name(cand)
                    break
            if spec is None:
                spec = pick_skeptic(self.cfg, f.source_family)
            groups[spec.name].append(f)
        verdicts: list[SkepticVerdict] = []
        for name, fs in groups.items():
            v, errors = skeptic.run_skeptic(self._p(name), ctx, fs)
            self.audit["skeptic_invalid_items"] += len(errors)
            verdicts.extend(v)
            self._say(f"L3: skeptic {self._p(name).family.value} judged {len(fs)} → {sum(x.verdict == 'refuted' for x in v)} refuted")
        return verdicts

    def run_redteam(self, ctx: RepoContext, findings: list[Finding], finders: dict[str, set[ModelFamily]]) -> list[RedTeamNote]:
        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            spec = self.cfg.model_by_name(self.cfg.roles.redteam)
            if spec.family in finders[f.id]:
                for cand in self.cfg.roles.judges + self.cfg.roles.reviewers:
                    if self.cfg.model_by_name(cand).family not in finders[f.id]:
                        spec = self.cfg.model_by_name(cand)
                        break
            groups[spec.name].append(f)
        notes: list[RedTeamNote] = []
        for name, fs in groups.items():
            n, errors = redteam.run_redteam(self._p(name), ctx, fs)
            self.audit["redteam_invalid_items"] += len(errors)
            notes.extend(n)
        return notes

    # ------------------------------------------------------------------ L4
    def run_jury(self, ctx: RepoContext, findings: list[Finding], skeptic_by_id: dict[str, SkepticVerdict],
                 finders: dict[str, set[ModelFamily]]) -> list[JudgeVote]:
        votes: list[JudgeVote] = []
        judge_fams = [self._p(n).family for n in self.cfg.roles.judges]
        min_ind = self.cfg.gate.min_independent_judges

        def independent(f: Finding) -> int:
            return sum(1 for fam in judge_fams if fam not in finders[f.id])

        for name in self.cfg.roles.judges:
            prov = self._p(name)
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
            fwd, rev = blinded_batches(eligible, skeptic_by_id, ctx.content_hash + prov.family.value)
            v1, e1 = judge.run_judge(prov, fwd, "forward", self_ids)
            v2, e2 = judge.run_judge(prov, rev, "reverse", self_ids)
            self.audit["judge_invalid_items"] += len(e1) + len(e2)
            if not v1 and not v2:
                self.audit["judge_refusals"] += 1
            votes.extend(v1 + v2)
            self._say(
                f"L4: judge {prov.family.value}: {len(eligible)} finding(s) ({len(self_ids)} self-family) × 2 passes → {len(v1) + len(v2)} votes"
            )
        return votes

    # ------------------------------------------------------------------ L5
    def score(self, findings: list[Finding], finders: dict[str, set[ModelFamily]], skeptic_by_id: dict[str, SkepticVerdict],
              red_by_id: dict[str, RedTeamNote], votes: list[JudgeVote], tool_results: list[ToolResult]) -> list[ConsensusResult]:
        weights = {m.family: m.weight for m in self.cfg.models}
        by_finding: dict[str, list[JudgeVote]] = defaultdict(list)
        for v in votes:
            by_finding[v.finding_id].append(v)
        results: list[ConsensusResult] = []
        flips = 0
        for f in findings:
            fv = by_finding.get(f.id, [])
            score, tp, fp, human, agreeing, consistent = weighted_consensus(fv, weights, self.cfg.gate.self_judge_discount)
            flips += int(not consistent and bool(fv))
            alpha = _per_finding_alpha(fv)
            sk = skeptic_by_id.get(f.id)
            refuted = bool(sk and sk.verdict == "refuted")
            prov_ok = any(p.verified for p in f.provenance)
            corroborated = _tool_corroborates(f, tool_results)
            fams = set(agreeing) | (finders[f.id] if score >= self.cfg.gate.accept_threshold else set())
            if corroborated:
                fams.add(ModelFamily.TOOL)
            tier = assign_tier(provenance_verified=prov_ok, tool_corroborated=corroborated, families_agreeing=sorted(fams, key=lambda x: x.value),
                               skeptic_refuted=refuted, reachability=f.reachability, consensus_score=score,
                               accept_threshold=self.cfg.gate.accept_threshold)
            try:
                num = cvss4.score(f.cvss4_vector)
                sev = cvss4.severity(num)
            except cvss4.CVSS4Error:
                num, sev = 0.0, "None"
                self.audit["invalid_cvss_vectors"] += 1
            # judges' severity bands act as a sanity check on the finder's vector: use the lower of the two
            bands = [v.severity_band for v in fv]
            if bands:
                order = ["None", "Low", "Medium", "High", "Critical"]
                jury_band = sorted(bands, key=order.index)[len(bands) // 2]
                if order.index(jury_band) < order.index(sev):
                    sev = jury_band
                    self.audit["severity_downgraded_by_jury"] += 1
            rt = red_by_id.get(f.id)
            ssvc = ssvc_decision(severity=sev, exploitable=rt.exploitable if rt else "unknown", tier=tier)
            needs_human = (alpha is not None and alpha < self.human_alpha_threshold) or (human > tp and human > fp)
            accepted = tier != EvidenceTier.D and score >= self.cfg.gate.accept_threshold and not needs_human
            results.append(ConsensusResult(
                finding_id=f.id, weighted_score=score, votes_tp=tp, votes_fp=fp, votes_human=human,
                families_agreeing=sorted(fams, key=lambda x: x.value), tool_corroborated=corroborated, skeptic_refuted=refuted,
                position_consistent=consistent, krippendorff_alpha=alpha, tier=tier, cvss4_score=num, cvss4_severity=sev,
                ssvc_decision=ssvc, accepted=accepted,
            ))
        self.audit["position_flips"] = flips
        return results

    # ------------------------------------------------------------------ run
    def run(self, target: str | Path, *, sarif_dir: Path | None = None, mode: str = "live") -> ReviewReport:
        target = Path(target).resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        ctx = build_context(target)
        for prov in self.providers.values():
            prov.bind_target(ctx.root)
        self._say(f"L1: {ctx.summary()}")
        tool_runs = self.run_tools(target, sarif_dir)
        tool_results = [r for run in tool_runs for r in run.results]
        tools_ran = {run.tool for run in tool_runs if run.ran}
        raw = self.run_reviewers(ctx)
        findings, finders = self.dedupe(raw)
        findings = [f.model_copy(update={"finder_families": sorted(finders[f.id], key=lambda x: x.value)}) for f in findings]
        self.audit["findings_raw"] = len(raw)
        self.audit["findings_deduped"] = len(findings)
        sk = self.run_skeptics(ctx, findings, finders)
        sk_by_id = {v.finding_id: v for v in sk}
        survivors = [f for f in findings if sk_by_id.get(f.id, None) is None or sk_by_id[f.id].verdict != "refuted"]
        rt = self.run_redteam(ctx, survivors, finders)
        rt_by_id = {n.finding_id: n for n in rt}
        votes = self.run_jury(ctx, findings, sk_by_id, finders)
        consensus = self.score(findings, finders, sk_by_id, rt_by_id, votes, tool_results)
        cons_by_id = {c.finding_id: c for c in consensus}
        dims = []
        for d in self.cfg.dimensions:
            tool_ran = any(d in TOOL_DIMENSIONS[t] for t in tools_ran)
            dims.append(score_dimension(d, findings, cons_by_id, tool_ran))
        overall = round(sum(x.score for x in dims) / len(dims), 1) if dims else 0.0
        gate = True
        for c in consensus:
            if c.accepted and c.tier.value in self.cfg.gate.block_on_tiers and c.cvss4_severity in self.cfg.gate.block_on_severity:
                gate = False
        if any(x.score < self.cfg.gate.min_dimension_score for x in dims):
            gate = False
        global_alpha = krippendorff_alpha_nominal({f.id: [v.verdict for v in votes if v.finding_id == f.id] for f in findings})
        self.audit["global_krippendorff_alpha"] = global_alpha if global_alpha is not None else "n/a"
        for k, v in pairwise_family_agreement(votes).items():
            self.audit[f"judge_agreement[{k}]"] = v
        self.audit["tool_results_ingested"] = len(tool_results)
        self.audit["tools_ran"] = ",".join(sorted(tools_ran)) or "none"
        report = ReviewReport(
            target=str(target), generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), provider_mode=mode,
            families_used=sorted({m.family.value for m in self.cfg.models}), findings=findings, skeptic=sk, redteam=rt,
            votes=votes, consensus=consensus, dimensions=dims, overall_score=overall, gate_passed=gate, bias_audit=dict(self.audit),
        )
        # G-11: the human queue as an object with full context; decisions come back through calib/decisions
        from .report.human_queue_out import build_queue

        report.human_queue = build_queue(findings, cons_by_id, sk_by_id, rt_by_id, votes, self.cfg, exclude_tier_c=self.exclude_tier_c)
        for k, v in (("human_queue_size", len(report.human_queue)), ("human_queue_backlog", self.backlog if self.backlog is not None else "unknown"),
                     ("human_queue_tightened", int(self.queue_tightened)), ("human_alpha_threshold", self.human_alpha_threshold)):
            self.audit[k] = v
            report.bias_audit[k] = v
        self._say(f"L5: human queue: {len(report.human_queue)} item(s)"
                  + (f" [TIGHTENED: backlog {self.backlog} > {self.cfg.human_queue.backlog_limit}, alpha threshold {self.human_alpha_threshold}"
                     f"{', tier C not queued' if self.exclude_tier_c else ''}]" if self.queue_tightened else ""))
        # G-12: accepted tier-A Critical findings on a shipped product start the CRA Article 14 clock
        from .report.psirt_out import build_notifications

        report.psirt = build_notifications(report, self.cfg)
        self.audit["psirt_notifications"] = len(report.psirt)
        report.bias_audit["psirt_notifications"] = len(report.psirt)
        # G-7: which self-hosted weights the report was produced with, as the ML-BOM knows them
        ml_bom = {n: {"model_id": st.model_id, "status": st.status, "component": st.component_name,
                      "version": st.component_version, "sha256": st.digest} for n, st in self.ml_bom_status.items()}
        self.audit["ml_bom"] = ml_bom
        report.bias_audit["ml_bom"] = ml_bom
        self.audit["rollout_phase"] = self.cfg.rollout.phase
        report.bias_audit["rollout_phase"] = self.cfg.rollout.phase
        if ml_bom:
            self.log("L0: ML-BOM: " + ", ".join(f"{n} {v['status']}" for n, v in ml_bom.items()))
        self._say(f"L5: PSIRT hand-off: {len(report.psirt)} finding(s)" if self.cfg.psirt.enabled else "L5: PSIRT hand-off disabled")
        return report


def _per_finding_alpha(votes: list[JudgeVote]) -> float | None:
    """Agreement among judges on one finding, treating each (judge, pass) as a rater over the
    two-unit set {this finding forward, this finding reverse} is degenerate; instead we report
    the simple share of the modal verdict as a bounded proxy when alpha is undefined."""
    if len(votes) < 2:
        return None
    from collections import Counter

    c = Counter(v.verdict for v in votes)
    modal = c.most_common(1)[0][1]
    return round((modal / len(votes) - 1 / 3) / (1 - 1 / 3), 3)  # chance-corrected for 3 categories


def _norm_path(path: str) -> str:
    """Forward slashes, no leading './' (str.lstrip('./') would also eat the dot of '.github')."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _tool_corroborates(f: Finding, tool_results: list[ToolResult]) -> bool:
    for t in tool_results:
        for p in f.provenance:
            # tools run from the git root report paths relative to it (e.g. zizmor emits
            # fixtures/vuln-sample/.github/workflows/deploy.yml); the review target may be a subdirectory
            tf, pf = _norm_path(t.file), _norm_path(p.file)
            same_file = tf == pf or tf.endswith("/" + pf)
            if same_file and abs(t.line - p.line) <= 3:
                if t.cwe is None or t.cwe.upper() == f.cwe.upper():
                    return True
    return False
