"""G-11: the human queue as a file and a ticket: human_queue.md for a person and human_queue.json for the ticket sync
(scripts/human_queue_issues.py). What the queue holds is decided in mara.human_queue."""

from __future__ import annotations

import json
from pathlib import Path

from ..schemas import ReviewReport
from .escaping import code, literal


def render_human_queue(report: ReviewReport) -> str:
    L = [
        f"# Human queue: {code(report.target)}",
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
            f"- {it.dimension} · {it.cwe} · {code(f'{it.file}:{it.line}')} · tier {it.tier}"
            f" · CVSS {it.cvss4_score} {it.cvss4_severity} · SSVC {it.ssvc_decision}",
            f"- Consensus {it.weighted_score} (tp {it.votes_tp} / fp {it.votes_fp} / human {it.votes_human}) · agreement proxy {it.agreement_proxy}",
            f"- Found by: {', '.join(it.finder_families)} · reachability {it.reachability}: {literal(it.reachability_argument)}",
            f"- Attacker path: {literal(it.exploit_sketch)}",
            f"- Quote: {code(it.quote)}",
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
