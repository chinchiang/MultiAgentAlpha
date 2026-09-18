"""G-11: the human queue as an object, a file and a ticket.

Selection consumes the pipeline's effective unresolved reasons, including quorum, invalid
CVSS, disagreement and tier C at High severity. Backlog tightening never drops a finding
that still needs a human. Each item carries un-blinded context and its exact review identity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..config import MaraConfig
from ..schemas import ConsensusResult, EvidenceTier, Finding, HumanQueueItem, JudgeVote, RedTeamNote, ReviewReport, SkepticVerdict
from .escaping import literal

SEVERITY_ORDER = ["None", "Low", "Medium", "High", "Critical"]


def queue_key(file: str, line: int, cwe: str, *, target_id: str = "", revision: str = "", context_hash: str = "") -> str:
    norm = file.replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    if not (target_id and revision and context_hash):
        return hashlib.sha256(f"{norm}:{line}:{cwe.upper()}".encode()).hexdigest()[:12]  # legacy: never auto-synced
    identity = json.dumps([target_id, revision, context_hash, norm, line, cwe.upper()], separators=(",", ":"))
    return "v2-" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def read_backlog(cfg: MaraConfig, root: Path | None = None) -> int | None:
    """Open ticket count as last written by scripts/human_queue_issues.py, or None if unknown."""
    path = (root or Path(".")) / cfg.human_queue.backlog_file
    if not path.is_file():
        return None
    try:
        return int(json.loads(path.read_text(encoding="utf-8")).get("open", 0))
    except (OSError, ValueError, TypeError):
        return None


def tightening(cfg: MaraConfig, backlog: int | None) -> tuple[float, bool, bool]:
    """(effective_alpha_threshold, exclude_tier_c, tightened)."""
    hq = cfg.human_queue
    base = cfg.gate.human_threshold_alpha
    if hq.enabled and backlog is not None and backlog > hq.backlog_limit:
        return min(1.0, round(base + hq.tighten_alpha_step, 4)), hq.tighten_exclude_tier_c, True
    return base, False, False


def build_queue(
    findings: list[Finding],
    consensus: dict[str, ConsensusResult],
    skeptic: dict[str, SkepticVerdict],
    redteam: dict[str, RedTeamNote],
    votes: list[JudgeVote],
    cfg: MaraConfig,
    *,
    exclude_tier_c: bool = False,
    target_id: str = "",
    revision: str = "",
    context_hash: str = "",
) -> list[HumanQueueItem]:
    hq = cfg.human_queue
    if not hq.enabled:
        return []
    min_c = SEVERITY_ORDER.index(hq.queue_tier_c_min_severity)
    by_finding: dict[str, list[JudgeVote]] = {}
    for v in votes:
        by_finding.setdefault(v.finding_id, []).append(v)
    items: list[HumanQueueItem] = []
    for f in findings:
        c = consensus.get(f.id)
        if c is None:
            continue
        reasons = list(c.human_reasons)
        if c.needs_human and not reasons:
            reasons.append("unresolved_human_review")
        if (
            c.tier == EvidenceTier.C
            and (SEVERITY_ORDER.index(c.cvss4_severity) if c.cvss4_severity in SEVERITY_ORDER else 4) >= min_c
            and not exclude_tier_c
            and c.accepted
        ):
            reasons.append("tier_c_high")
        if not reasons:
            continue
        p = f.provenance[0]
        sk, rt = skeptic.get(f.id), redteam.get(f.id)
        judge_votes = []
        for v in sorted(by_finding.get(f.id, []), key=lambda v: (v.judge_family.value, v.pass_id)):
            judge_votes.append(
                {
                    "family": v.judge_family.value,
                    "pass": v.pass_id,
                    "verdict": v.verdict,
                    "severity_band": v.severity_band,
                    "reason": v.reason,
                    "self_family": v.self_family,
                }
            )
        items.append(
            HumanQueueItem(
                finding_id=f.id,
                key=queue_key(p.file, p.line, f.cwe, target_id=target_id, revision=revision, context_hash=context_hash),
                target_id=target_id,
                revision=revision,
                context_hash=context_hash,
                reasons=reasons,
                title=f.title,
                dimension=f.dimension,
                cwe=f.cwe,
                file=p.file,
                line=p.line,
                quote=p.quote[:200],
                tier=c.tier.value,
                cvss4_score=c.cvss4_score,
                cvss4_severity=c.cvss4_severity,
                ssvc_decision=c.ssvc_decision,
                weighted_score=c.weighted_score,
                krippendorff_alpha=c.krippendorff_alpha,
                agreement_proxy=c.agreement_proxy,
                votes_tp=c.votes_tp,
                votes_fp=c.votes_fp,
                votes_human=c.votes_human,
                finder_families=[x.value for x in f.finder_families] or [f.source_family.value],
                reachability=f.reachability,
                reachability_argument=f.reachability_argument,
                exploit_sketch=f.exploit_sketch,
                skeptic=None
                if sk is None
                else {"family": sk.source_family.value, "verdict": sk.verdict, "reason": sk.reason, "sanitizer_or_control": sk.sanitizer_or_control},
                redteam=None if rt is None else {"family": rt.source_family.value, "exploitable": rt.exploitable, "preconditions": rt.preconditions},
                judge_votes=judge_votes,
            )
        )
    return items


def render_human_queue(report: ReviewReport) -> str:
    L = [
        f"# Human queue: `{literal(report.target)}`",
        "",
        f"Generated {report.generated_at} · {len(report.human_queue)} item(s) need a human decision.",
        "",
        "Each item shows who found it, what the skeptic and the red team said, and how every judge voted in both passes. "
        "The judges saw a blinded view; you see the identities on purpose. Decide true_positive or false_positive on the ticket; "
        "decisions are written back to calib/decisions/ and feed the next calibration.",
        "",
    ]
    if not report.human_queue:
        L.append("_Empty._")
    for it in report.human_queue:
        L += [
            f"## {it.finding_id} · {literal(it.title)}",
            "",
            f"- Key `{it.key}` · reasons: {', '.join(it.reasons)}",
            f"- {it.dimension} · {it.cwe} · `{literal(it.file)}:{it.line}` · tier {it.tier}"
            f" · CVSS {it.cvss4_score} {it.cvss4_severity} · SSVC {it.ssvc_decision}",
            f"- Consensus {it.weighted_score} (tp {it.votes_tp} / fp {it.votes_fp} / human {it.votes_human}) · agreement proxy {it.agreement_proxy}",
            f"- Found by: {', '.join(it.finder_families)} · reachability {it.reachability}: {literal(it.reachability_argument)}",
            f"- Attacker path: {literal(it.exploit_sketch)}",
            f"- Quote: `{literal(it.quote)}`",
        ]
        if it.skeptic:
            L.append(
                f"- Skeptic ({it.skeptic['family']}): **{it.skeptic['verdict']}** — {literal(it.skeptic['reason'])}"
                + (f" · control: {literal(it.skeptic['sanitizer_or_control'])}" if it.skeptic.get("sanitizer_or_control") else "")
            )
        if it.redteam:
            L.append(f"- Red team ({it.redteam['family']}): exploitable **{it.redteam['exploitable']}** — {literal(it.redteam['preconditions'])}")
        if it.judge_votes:
            L.append("- Judges:")
            for v in it.judge_votes:
                tag = " (self-family)" if v["self_family"] else ""
                L.append(f"  - {v['family']} [{v['pass']}]{tag}: **{v['verdict']}** {v['severity_band']} — {literal(v['reason'])}")
        L.append("")
    return "\n".join(L) + "\n"


def write_human_queue(report: ReviewReport, out_dir: Path) -> None:
    (out_dir / "human_queue.md").write_text(render_human_queue(report), encoding="utf-8")
    (out_dir / "human_queue.json").write_text(
        json.dumps(
            {
                "target": report.target,
                "target_id": report.target_id,
                "revision": report.revision,
                "generated_at": report.generated_at,
                "items": [i.model_dump() for i in report.human_queue],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
