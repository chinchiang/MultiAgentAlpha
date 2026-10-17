"""The human queue (GLOSSARY.md: human queue, queue key, human reason, queue tightening, usable decision): which
findings a human must look at and under which key, the reasons they need one, the tightening while the ticket backlog
is over its limit, and how usable decisions settle the findings they bind to (docs/adr/0002-usable-decisions.md,
docs/adr/0003-human-resolution.md, docs/adr/0005-jury-outcome.md). Pure, except that settle() records decisions on
the consensus rows it is given: the pipeline reads the backlog and the decision files (mara.decisions) and writes the
audit; mara.report.human_queue_out writes the queue.

The queue takes the human reasons the jury outcome recorded on each consensus row (quorum,
disagreement, unverified provenance, tier C at the severity floor) and the rejected findings under
rejection review (policy P8). Queue tightening never drops a finding that still needs a human.
Each item carries un-blinded context and its exact review identity.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .identity import norm_cwe, norm_path
from .schemas import ConsensusResult, Finding, HumanQueueItem, JudgeVote, QueueTightening, RedTeamNote, SkepticVerdict
from .scoring.outcome import JURY_HUMAN_REASONS

if TYPE_CHECKING:
    from .config import MaraConfig
    from .decisions import Selection

# The human reasons the queue writes itself, after the jury's (mara.scoring.outcome.JURY_HUMAN_REASONS); together they
# are HUMAN_REASONS, every human reason. A decision that is not usable is written with why: decision_not_usable:<why>.
UNSUPERVISED_REJECT_UNVERIFIED = "unsupervised_reject_unverified"
DECISION_NOT_USABLE = "decision_not_usable"
HUMAN_REASONS = frozenset(JURY_HUMAN_REASONS) | {UNSUPERVISED_REJECT_UNVERIFIED, DECISION_NOT_USABLE}


def queue_key(file: str, line: int, cwe: str, *, target_id: str = "", revision: str = "", context_hash: str = "") -> str:
    norm = norm_path(file)
    if not (target_id and revision and context_hash):
        return hashlib.sha256(f"{norm}:{line}:{norm_cwe(cwe)}".encode()).hexdigest()[:12]  # legacy: never auto-synced
    identity = json.dumps([target_id, revision, context_hash, norm, line, norm_cwe(cwe)], separators=(",", ":"))
    return "v2-" + hashlib.sha256(identity.encode()).hexdigest()[:24]


@dataclass(frozen=True)
class Tightening:
    """The human queue's tightening for one review: the ticket backlog it was read from (None if unknown), whether it
    is over the limit, and the two jury-outcome settings it gives - the agreement a finding needs and whether tier C
    findings are left to the jury."""

    backlog: int | None
    tightened: bool
    alpha_threshold: float
    exclude_tier_c: bool

    def record(self) -> QueueTightening:
        """The report's record of it (docs/adr/0009-report-metadata.md)."""
        return QueueTightening(backlog=self.backlog, tightened=self.tightened, alpha_threshold=self.alpha_threshold)


def tightening(cfg: MaraConfig, backlog: int | None) -> Tightening:
    """The tightening under `cfg` with `backlog` open tickets."""
    hq = cfg.human_queue
    base = cfg.gate.human_threshold_alpha
    if hq.enabled and backlog is not None and backlog > hq.backlog_limit:
        return Tightening(backlog, True, min(1.0, round(base + hq.tighten_alpha_step, 4)), hq.tighten_exclude_tier_c)
    return Tightening(backlog, False, base, False)


def build_queue(
    findings: list[Finding],
    consensus: dict[str, ConsensusResult],
    skeptic: dict[str, SkepticVerdict],
    redteam: dict[str, RedTeamNote],
    votes: list[JudgeVote],
    cfg: MaraConfig,
    *,
    target_id: str = "",
    revision: str = "",
    context_hash: str = "",
) -> list[HumanQueueItem]:
    hq = cfg.human_queue
    if not hq.enabled:
        return []
    by_finding: dict[str, list[JudgeVote]] = {}
    for v in votes:
        by_finding.setdefault(v.finding_id, []).append(v)
    items: list[HumanQueueItem] = []
    for f in findings:
        c = consensus.get(f.id)
        if c is None or c.resolved_by_human:  # answered: the human ruling is the final outcome
            continue
        reasons = list(c.human_reasons)  # never empty when the jury sent it to a human (decide() always says why)
        if c.in_rejection_review:
            # rejection review (policy P8, docs/adr/0005-jury-outcome.md): the jury outcome stays rejected
            reasons.append(UNSUPERVISED_REJECT_UNVERIFIED)
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


def settle(findings: list[Finding], consensus: list[ConsensusResult], selection: Selection, *, target_id: str, revision: str,
           context_hash: str) -> int:
    """Usable decisions on this very content settle their findings (docs/adr/0003-human-resolution.md): each one is
    recorded on its consensus row, whose jury outcome stays as it is. A well-formed decision that is not usable
    settles nothing, and a finding that still needs a human says why. Returns how many consensus rows a decision was
    recorded on (two findings at one place count twice)."""
    usable = {d.key: d for d in selection.usable}
    not_usable = {d.key: why for d, why in selection.excluded if why != "unbound"}
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
            c.human_reasons.append(f"{DECISION_NOT_USABLE}:{not_usable[key]}")
    return applied
