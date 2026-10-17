"""Report assembly: the review report built from what the review's stages handed in, its assessment and its report
metadata (GLOSSARY.md), with the human queue (G-11) and the PSIRT payloads (G-12) that follow from them. Pure: the
pipeline reads the clock, the workspace and cosign, and passes in what they gave."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..schemas import MlBomEntry, ModelEvalStatus, QueueTightening, ReviewReport, RolloutPhase
from .human_queue_out import build_queue
from .psirt_out import build_notifications

if TYPE_CHECKING:
    from ..config import MaraConfig
    from ..pipeline import Stages
    from ..review_status import Assessment


@dataclass(frozen=True)
class ReportMetadata:
    """The report metadata a review records (GLOSSARY.md), as the pipeline read them: the rollout phase, the human
    queue's tightening, the ML-BOM status and the signature check's result, and each family's latest red-team
    evaluation."""

    rollout_phase: RolloutPhase
    human_queue_tightening: QueueTightening
    ml_bom: dict[str, MlBomEntry]
    ml_bom_signature: str | None
    model_eval: dict[str, ModelEvalStatus]


def assemble(stages: Stages, assessment: Assessment, metadata: ReportMetadata, *, cfg: MaraConfig, target: Path, mode: str,
             generated_at: str, provider_manifest: list[dict], bias_audit: dict, psirt_event: dict | None) -> ReviewReport:
    """The report of the review of `target` in provider `mode`, generated at `generated_at`: its findings, ballots, jury
    scoring and dimension scores as `stages` gives them, its status and gate as `assessment` decided them, `metadata`,
    the providers as `provider_manifest` lists them and the `bias_audit` snapshot, with the human queue and the PSIRT
    payloads (under `psirt_event`, when given) built from it."""
    ctx, tools, reviewed, ballots = stages.ctx, stages.tools, stages.reviewed, stages.ballots
    report = ReviewReport(
        target=str(target),
        generated_at=generated_at,
        provider_mode=mode,
        families_used=sorted({m.family.value for m in cfg.models}),
        findings=reviewed.findings,
        skeptic=list(ballots.skeptic.values()),
        redteam=list(ballots.redteam.values()),
        review_status=assessment.review_status,
        incomplete_reasons=list(assessment.incomplete_reasons),
        review_scope="incremental" if stages.base_ref else "full",
        coverage=ctx.coverage(),
        tool_results=[asdict(t) for t in tools.results],
        tool_health=[{"tool": t.tool, "ran": t.ran, "note": t.note} for t in tools.runs],
        provider_manifest=provider_manifest,
        config_hash=hashlib.sha256(cfg.model_dump_json().encode()).hexdigest(),
        target_id=stages.target_id,
        revision=ctx.revision,
        votes=ballots.votes,
        consensus=stages.scoring.rows,
        dimensions=stages.dimensions,
        overall_score=assessment.overall_score,
        gate_passed=assessment.gate_passed,
        gate_reasons=list(assessment.gate_reasons),
        gate_enforced=assessment.gate_enforced,
        # the accounting the counts above follow (docs/adr/0001-reply-outcome-accounting.md)
        bias_audit=bias_audit,
        rollout_phase=metadata.rollout_phase,
        human_queue_tightening=metadata.human_queue_tightening,
        ml_bom=metadata.ml_bom,
        ml_bom_signature=metadata.ml_bom_signature,
        model_eval=metadata.model_eval,
    )
    # G-11: the human queue as an object with full context; decisions come back through calib/decisions
    report.human_queue = build_queue(reviewed.findings, {c.finding_id: c for c in stages.scoring.rows}, ballots.skeptic,
                                     ballots.redteam, ballots.votes, cfg, target_id=stages.target_id, revision=ctx.revision,
                                     context_hash=ctx.content_hash)
    # G-12: accepted tier-A Critical findings on a shipped product start the CRA Article 14 clock
    report.psirt = build_notifications(report, cfg, event=psirt_event)
    return report
