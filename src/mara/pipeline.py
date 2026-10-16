"""Orchestrator: L0 tools -> L1 context -> L2 reviewers -> L3 skeptic/red team -> L4 blinded jury
-> L5 deterministic scoring and reports. No layer talks to another except through validated
schemas; reviewers never see each other's output; judges never see model identity.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from . import ballot_round, exchange
from .agents import base, context_agent, reviewer
from .agents.context_agent import ContextView
from .audit import Audit, log_tags
from .config import MaraConfig
from .context.repo_map import RepoContext, build_context, restrict_to_increment
from .identity import norm_path
from .progress import Progress
from .providers import make_provider
from .providers.base import Provider
from .review_status import GatePolicy, ReviewFacts, assess, secret_preflight
from .schemas import (
    ConsensusResult,
    Finding,
    MlBomEntry,
    ModelEvalStatus,
    ModelFamily,
    QueueTightening,
    ReviewReport,
)
from .scoring import jury
from .scoring.dimension_score import score_dimension
from .scoring.idcheck import check_finding_refs
from .scoring.outcome import OutcomePolicy
from .tools.runner import TOOL_DIMENSIONS, ToolRun, load_prerecorded, run_all
from .workspace import check_outside, resolve


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
        self.jury = jury.Jury.from_config(cfg)
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
        view, records = context_agent.run_context_agent(prov, ctx)
        for rec in records:
            self.audit.record(rec)
        self._say(f"L1: context {fam}: {len(view.items) if view else 0} fact(s)" + log_tags(*records))
        return view

    # ------------------------------------------------------------------ L2
    def run_reviewers(self, ctx: RepoContext, context_view: ContextView | None = None) -> list[Finding]:
        canary = base.Canary()
        raw: list[Finding] = []
        for batch in ctx.batches():
            for dim in self.cfg.dimensions:
                for name in self.cfg.roles.reviewers:
                    prov = self._p(name)
                    findings, rec = reviewer.review_dimension(prov, batch, dim, canary, context_view)
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
                if k.dimension == f.dimension and k.cwe == f.cwe and same_file and abs(q.line - p.line) <= 3 and k_ok == f_ok:
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
        ballots = ballot_round.run(ctx, findings, finders, cfg=self.cfg, providers=self.providers, audit=self.audit,
                                   say=self._say, progress=prog)
        sk_by_id, rt_by_id, votes = ballots.skeptic, ballots.redteam, ballots.votes
        prog.begin("scoring")
        scoring = jury.score(findings, finders, ballots, tool_results, jury=self.jury, policy=self.outcome_policy,
                             tool_path_prefix=ctx.repo_prefix)
        self.audit["position_flips"] = scoring.position_flips
        consensus = scoring.rows
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
        signature: str | None = None  # the report's ml_bom_signature
        if self.cfg.ml_bom.require_signature:
            # P7 checked offline that the bundle belongs to the BOM; here cosign verifies the signature and its signer
            from .mlbom import verify_signature

            signed, why = verify_signature(self.cfg)
            signature = "verified" if signed else f"failed: {why}"
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
        self.audit["global_krippendorff_alpha"] = scoring.global_alpha if scoring.global_alpha is not None else "n/a"
        for k, v in scoring.family_agreement.items():
            self.audit[f"judge_agreement[{k}]"] = v
        prog.done("scoring", f"review {assessment.review_status}, gate {'passed' if assessment.gate_passed else 'blocked'}")
        prog.begin("report")
        report = ReviewReport(
            target=str(target),
            generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            provider_mode=mode,
            families_used=sorted({m.family.value for m in self.cfg.models}),
            findings=findings,
            skeptic=list(sk_by_id.values()),
            redteam=list(rt_by_id.values()),
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
            rollout_phase=self.cfg.rollout.phase,
            human_queue_tightening=QueueTightening(backlog=self.backlog, tightened=self.queue_tightened,
                                                   alpha_threshold=self.outcome_policy.alpha_threshold),
            ml_bom_signature=signature,
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
        # G-7: which self-hosted weights the report was produced with, as the ML-BOM knows them
        report.ml_bom = {
            n: MlBomEntry(model_id=st.model_id, status=st.status, component=st.component_name, version=st.component_version, sha256=st.digest)
            for n, st in self.ml_bom_status.items()
        }
        # G-8: latest red-team evaluation verdict per family (garak / CyberSecEval), 'none' until one has run
        from .model_eval import family_eval_status

        # the MARA workspace (MARA_HOME), like every other piece of MARA's own evidence: never the working
        # directory, which may be the repository under review
        from .workspace import root as workspace_root

        evaluated = sorted({m.family.value for m in self.cfg.models if m.provider != "mock"})
        report.model_eval = {fam: ModelEvalStatus(**v) for fam, v in family_eval_status(workspace_root(), evaluated).items()}
        if report.ml_bom:
            self._say("L0: ML-BOM: " + ", ".join(f"{n} {v.status}" for n, v in report.ml_bom.items()))
        self._say(f"L5: PSIRT hand-off: {len(report.psirt)} finding(s)" if self.cfg.psirt.enabled else "L5: PSIRT hand-off disabled")
        prog.done("report", f"{len(report.human_queue)} human-queue item(s), {len(report.psirt)} PSIRT payload(s)")
        return report



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
