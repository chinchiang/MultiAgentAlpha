"""Orchestrator: L0 tools -> L1 context -> L2 reviewers -> L3 skeptic/red team -> L4 blinded jury
-> L5 deterministic scoring and reports. No layer talks to another except through validated
schemas; reviewers never see each other's output; judges never see model identity.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import ballot_round, exchange
from .agents import context_agent, reviewer
from .agents.context_agent import ContextView
from .audit import Audit, log_tags
from .config import MaraConfig
from .context.repo_map import RepoContext, build_context, restrict_to_increment
from .identity import NEAR_LINES, norm_path
from .progress import Progress
from .providers import make_provider
from .providers.base import Provider
from .report.assembly import ReportMetadata, assemble
from .review_status import Assessment, GatePolicy, ReviewFacts, SecretPreflight, assess, secret_preflight
from .schemas import (
    ConsensusResult,
    DimensionScore,
    Finding,
    MlBomEntry,
    ModelEvalStatus,
    ModelFamily,
    ReviewReport,
)
from .scoring import jury
from .scoring.dimension_score import score_dimension
from .scoring.idcheck import check_finding_refs
from .scoring.outcome import OutcomePolicy
from .tools.evidence import ToolEvidence
from .tools.runner import ToolRun, load_prerecorded, run_all
from .workspace import check_outside, resolve


@dataclass(frozen=True)
class ReviewerFindings:
    """What the reviewers stage hands in: how many findings the reviewers reported, and the deduplicated findings with
    the families that found each."""

    raw_count: int
    findings: list[Finding]
    finders: dict[str, set[ModelFamily]]


@dataclass(frozen=True)
class Stages:
    """What a review's stages handed in, up to its jury scoring and dimension scores: the bundle, the tool evidence, the
    secret preflight's decision on source egress, the context view, the reviewers' findings, the ballots, the jury
    scoring (its rows carry the human decisions applied), the dimension scores, the target's id and the base of an
    incremental review."""

    ctx: RepoContext
    tools: ToolEvidence
    egress: SecretPreflight
    context_view: ContextView | None
    reviewed: ReviewerFindings
    ballots: ballot_round.Ballots
    scoring: jury.JuryScoring
    dimensions: list[DimensionScore]
    target_id: str
    base_ref: str | None


class Pipeline:
    def __init__(self, cfg: MaraConfig, *, mock_fixtures: str | None = None, out_dir: Path | None = None,
                 progress: Progress | None = None, run_tools: Callable[..., list[ToolRun]] = run_all):
        self.cfg = cfg
        self._run_tools = run_tools  # the tools' runner, called as run_all is (mara.tools.runner)
        # the live view `mara serve` draws (mara.progress); a no-op unless `mara review --progress-file` is given
        self.progress = progress if progress is not None else Progress()
        self.out_dir = out_dir or resolve("out")  # the workspace, like `mara review --out`
        self.providers: dict[str, Provider] = {m.name: make_provider(m, mock_fixtures) for m in cfg.models}
        # Counters (default 0) and the jury's statistics; becomes the report's bias_audit (GLOSSARY.md: bias audit)
        self.audit = Audit()
        self.log: list[str] = []
        # G-11: the human queue tightens when its ticket backlog is over the limit (never loosens)
        from .decisions import read_backlog
        from .human_queue import tightening

        self.tightening = tightening(cfg, read_backlog(cfg))
        # read once and held only here: the jury outcome, the gate, the audit and the log see the same tightening
        # (docs/adr/0007-review-status-and-gate.md)
        self.outcome_policy = OutcomePolicy.from_config(cfg, alpha_threshold=self.tightening.alpha_threshold,
                                                        exclude_tier_c=self.tightening.exclude_tier_c)
        self.gate_policy = GatePolicy.from_config(cfg)
        self.jury = jury.Jury.from_config(cfg)
        from .mlbom import status_for_config

        self.ml_bom_status = status_for_config(cfg)

    @property
    def backlog(self) -> int | None:
        return self.tightening.backlog

    @property
    def queue_tightened(self) -> bool:
        return self.tightening.tightened

    # ------------------------------------------------------------------ helpers
    def _p(self, name: str) -> Provider:
        return self.providers[name]

    def _say(self, msg: str) -> None:
        self.log.append(msg)
        self.progress.log(msg)

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
        view, records = context_agent.run_context_agent(prov, ctx)
        for rec in records:
            self.audit.record(rec)
        self._say(f"L1: context {fam}: {len(view.items) if view else 0} fact(s)" + log_tags(*records))
        return view

    # ------------------------------------------------------------------ L2
    def run_reviewers(self, ctx: RepoContext, context_view: ContextView | None = None) -> list[Finding]:
        raw: list[Finding] = []
        for batch in ctx.batches():
            for dim in self.cfg.dimensions:
                for name in self.cfg.roles.reviewers:
                    prov = self._p(name)
                    # every exchange plants a canary of its own (agents.base.extraction_exchange)
                    findings, rec = reviewer.review_dimension(prov, batch, dim, context_view=context_view)
                    self.audit.record(rec)
                    raw.extend(findings)
                    self._say(f"L2: {dim} × {prov.family.value}: {len(findings)} finding(s)" + log_tags(rec))
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
                if k.dimension == f.dimension and k.cwe == f.cwe and same_file and abs(q.line - p.line) <= NEAR_LINES and k_ok == f_ok:
                    match = k
                    break
            if match is None:
                kept.append(f)
                finders[f.id] = {f.source_family}
            else:
                finders[match.id].add(f.source_family)
        return kept, finders

    def apply_decisions(self, findings: list[Finding], consensus: list[ConsensusResult], *, target_id: str, revision: str,
                        context_hash: str) -> None:
        """The decision files, selected against this review, settle the findings their usable decisions bind to
        (mara.human_queue.settle); the audit counts the rows settled and, by why, the decisions not usable on this content
        (a decision on other content is not counted)."""
        from .decisions import TrainingRequirement, select
        from .decisions import load as load_decisions
        from .human_queue import settle
        from .workspace import resolve

        loaded = load_decisions(resolve("calib/decisions"))
        report = {"target_id": target_id, "revision": revision, "coverage": {"content_hash": context_hash}}
        sel = select(loaded.decisions, report, TrainingRequirement.from_config(self.cfg.training))
        self.audit["human_decisions_applied"] = settle(findings, consensus, sel, target_id=target_id, revision=revision,
                                                       context_hash=context_hash)
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
        ctx = self._bundle(target, base_ref)
        tools, egress = self._tools(target, sarif_dir, mode, answer_key)
        context_view = self._context(ctx, egress)
        reviewed = self._reviewers(ctx, context_view, egress)
        ballots = ballot_round.run(ctx, reviewed.findings, reviewed.finders, cfg=self.cfg, providers=self.providers, audit=self.audit,
                                   say=self._say, progress=self.progress)
        stages = self._score(ctx, tools, egress, context_view, reviewed, ballots, base_ref)
        assessment, signature = self._assess(stages, fail_on_gate)
        self.progress.begin("report")
        report = assemble(stages, assessment, self._metadata(signature), cfg=self.cfg, target=target, mode=mode,
                          generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
                          provider_manifest=self._provider_manifest(),
                          bias_audit={**self.audit, "exchange_version": exchange.EXCHANGE_VERSION}, psirt_event=psirt_event)
        self._say(
            f"L5: human queue: {len(report.human_queue)} item(s)"
            + (
                f" [TIGHTENED: backlog {self.tightening.backlog} > {self.cfg.human_queue.backlog_limit}, "
                f"alpha threshold {self.outcome_policy.alpha_threshold}"
                f"{', tier C not queued' if self.outcome_policy.exclude_tier_c else ''}]"
                if self.queue_tightened
                else ""
            )
        )
        if report.ml_bom:
            self._say("L0: ML-BOM: " + ", ".join(f"{n} {v.status}" for n, v in report.ml_bom.items()))
        self._say(f"L5: PSIRT hand-off: {len(report.psirt)} finding(s)" if self.cfg.psirt.enabled else "L5: PSIRT hand-off disabled")
        self.progress.done("report", f"{len(report.human_queue)} human-queue item(s), {len(report.psirt)} PSIRT payload(s)")
        return report

    # ------------------------------------------------------------------ stages
    def _bundle(self, target: Path, base_ref: str | None) -> RepoContext:
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
        return ctx

    def _tools(self, target: Path, sarif_dir: Path | None, mode: str,
               answer_key: list[dict] | None) -> tuple[ToolEvidence, SecretPreflight]:
        prog = self.progress
        prog.begin("tools")
        if sarif_dir and sarif_dir.is_dir():
            tool_runs = load_prerecorded(sarif_dir)
            self._say(f"L0: ingested {len(tool_runs)} pre-recorded SARIF file(s) from {sarif_dir}")
        else:
            tool_runs = self._run_tools(target, self.out_dir / "tools")
            for r in tool_runs:
                self._say(f"L0: {r.tool}: {'ran' if r.ran else 'skipped'} {r.note} ({len(r.results)} results)")
        if mode == "live" and sarif_dir:
            # Pre-recorded SARIF cannot authorize egress from the current working tree.
            preflight = self._run_tools(target, self.out_dir / "live-secret-preflight", enabled=["gitleaks"])
            tool_runs = [r for r in tool_runs if r.tool != "gitleaks"] + preflight
        tools = ToolEvidence(runs=tool_runs)
        # Live source egress is blocked before any provider sees data if the trusted local
        # secret scan is unavailable or reports secrets (mara.review_status). The masked manifest remains reviewable.
        egress = secret_preflight(mode, tools.runs_of("gitleaks"), answer_key)
        if answer_key is not None and (egress.exempted or egress.unexplained):
            self.audit["secret_preflight_calibration_exempted"] = len(egress.exempted)
            self._say(f"L0: secret preflight: {len(egress.exempted)} seeded secret(s) declared by the calibration answer key, "
                      f"{len(egress.unexplained)} other finding(s)")
        prog.done("tools", f"{len(tools.ran)} of {len(tool_runs)} tool(s) ran, {len(tools.results)} result(s)"
                  + ("; source egress blocked by the secret preflight" if egress.blocked else ""))
        return tools, egress

    def _context(self, ctx: RepoContext, egress: SecretPreflight) -> ContextView | None:
        prog = self.progress
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
        return context_view

    def _reviewers(self, ctx: RepoContext, context_view: ContextView | None, egress: SecretPreflight) -> ReviewerFindings:
        prog = self.progress
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
        return ReviewerFindings(raw_count=len(raw), findings=findings, finders=finders)

    def _score(self, ctx: RepoContext, tools: ToolEvidence, egress: SecretPreflight, context_view: ContextView | None,
               reviewed: ReviewerFindings, ballots: ballot_round.Ballots, base_ref: str | None) -> Stages:
        """The jury scoring, the human decisions on it and the dimension scores, with everything the stages before
        handed in."""
        self.progress.begin("scoring")
        findings = reviewed.findings
        scoring = jury.score(findings, reviewed.finders, ballots, tools.results, jury=self.jury, policy=self.outcome_policy,
                             tool_path_prefix=ctx.repo_prefix)
        self.audit["position_flips"] = scoring.position_flips
        # repository + path below its top level for a committed git target (repo_map.target_identity),
        # so CI, every clone and every calibration run name the same target the same way
        target_id = hashlib.sha256(ctx.identity.encode()).hexdigest()
        self.apply_decisions(findings, scoring.rows, target_id=target_id, revision=ctx.revision, context_hash=ctx.content_hash)
        cons_by_id = {c.finding_id: c for c in scoring.rows}
        dims = []
        for d in self.cfg.dimensions:
            dims.append(score_dimension(d, findings, cons_by_id, tools.ran_for(d)))
        return Stages(ctx=ctx, tools=tools, egress=egress, context_view=context_view, reviewed=reviewed, ballots=ballots, scoring=scoring,
                      dimensions=dims, target_id=target_id, base_ref=base_ref)

    def _assess(self, stages: Stages, fail_on_gate: bool) -> tuple[Assessment, str | None]:
        """The review facts the stages handed in, the ML-BOM signature check among them, and the review status and gate
        decided from them; with the signature check's result for the report."""
        tools = stages.tools
        signed: bool | None = None
        signature: str | None = None  # the report's ml_bom_signature
        if self.cfg.ml_bom.require_signature:
            # P7 checked offline that the bundle belongs to the BOM; here cosign verifies the signature and its signer
            from .mlbom import verify_signature

            signed, why = verify_signature(self.cfg)
            signature = "verified" if signed else f"failed: {why}"
        facts = ReviewFacts(context_complete=stages.ctx.complete, egress_blocked=stages.egress.blocked,
                            required_tools_ran=tools.complete_for(self.cfg.dimensions), ml_bom_signature=signed,
                            context_view_missing=bool(self.cfg.roles.context) and stages.context_view is None,
                            incomplete_counters=tuple(self.audit.incomplete_reasons()),  # audit.INCOMPLETE_COUNTERS: the one list
                            rollout_phase=self.cfg.rollout.phase, fail_on_gate=fail_on_gate)
        consensus = stages.scoring.rows
        assessment = assess(facts, consensus, tools.results, stages.dimensions, self.outcome_policy, self.gate_policy)
        for c in consensus:
            c.blocking_reason = assessment.blocking_reasons.get(c.finding_id)
        if assessment.tier_c_blocked_while_tightened:
            self.audit["tier_c_blocked_while_tightened"] = assessment.tier_c_blocked_while_tightened
        self.audit["global_krippendorff_alpha"] = stages.scoring.global_alpha if stages.scoring.global_alpha is not None else "n/a"
        for k, v in stages.scoring.family_agreement.items():
            self.audit[f"judge_agreement[{k}]"] = v
        self.progress.done("scoring", f"review {assessment.review_status}, gate {'passed' if assessment.gate_passed else 'blocked'}")
        return assessment, signature

    def _metadata(self, signature: str | None) -> ReportMetadata:
        """The report metadata (GLOSSARY.md) as this review ran under them."""
        # G-8: latest red-team evaluation verdict per family (garak / CyberSecEval), 'none' until one has run
        from .model_eval import family_eval_status

        # the MARA workspace (MARA_HOME), like every other piece of MARA's own evidence: never the working
        # directory, which may be the repository under review
        from .workspace import root as workspace_root

        evaluated = sorted({m.family.value for m in self.cfg.models if m.provider != "mock"})
        return ReportMetadata(
            rollout_phase=self.cfg.rollout.phase,
            human_queue_tightening=self.tightening.record(),
            # G-7: which self-hosted weights the report was produced with, as the ML-BOM knows them
            ml_bom={n: MlBomEntry(model_id=st.model_id, status=st.status, component=st.component_name, version=st.component_version,
                                  sha256=st.digest)
                    for n, st in self.ml_bom_status.items()},
            ml_bom_signature=signature,
            model_eval={fam: ModelEvalStatus(**v) for fam, v in family_eval_status(workspace_root(), evaluated).items()},
        )

    def _provider_manifest(self) -> list[dict]:
        """Every provider and the models it served in this review (for the report's provider manifest)."""
        return [{"name": n, "type": p.spec.provider, "family": p.family.value, "model": p.model,
                 "served_models": sorted(getattr(p, "served_models", ()))} for n, p in self.providers.items()]



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
