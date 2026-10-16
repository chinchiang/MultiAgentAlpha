from __future__ import annotations

from pathlib import Path

from ..schemas import DIMENSION_LABELS, ReviewReport
from .escaping import code, literal
from .sarif_out import tier_counts


def _decided(c) -> str:
    d = c.human_decision
    return f"decided by human (#{d.get('issue')} by {literal(d.get('decided_by'))}): {d['decision'].replace('_', ' ')}"


def enforcement_wording(gate_enforced: bool) -> str:
    """How a blocked gate is worded wherever MARA shows it, report.md and the CLI alike: enforced, or recorded but not
    enforced (GLOSSARY: Gate). mara.review_status decided which; this only words it."""
    return "enforced" if gate_enforced else "recorded, not enforced"


def render_markdown(r: ReviewReport) -> str:
    """A blocked gate is enforced in the blocking phase or with `mara review --fail-on-gate`, and only recorded otherwise
    (G-10; docs/governance-templates.md). The header says which from the report's `gate_enforced` alone, which
    mara.review_status decided (docs/adr/0007-review-status-and-gate.md), and nothing for a report written before it."""
    cons = {c.finding_id: c for c in r.consensus}
    overall = f"{r.overall_score}/100" if r.overall_score is not None else "unavailable (review incomplete)"
    lines = [
        f"# MARA review: {code(r.target)}",
        "",
        f"Generated {r.generated_at} · mode `{r.provider_mode}` · families {', '.join(r.families_used)}",
        "",
        f"**Overall score {overall} · gate {'PASSED' if r.gate_passed else 'BLOCKED'}**"
        + (f" ({literal(', '.join(r.gate_reasons))})" if r.gate_reasons else "")
        + (f" · rollout phase `{r.rollout_phase}`" if r.rollout_phase else "")
        + ("" if r.gate_passed or r.gate_enforced is None else f" ({enforcement_wording(r.gate_enforced)})"),
        "",
        f"Review status: **{r.review_status}**; incomplete reasons: {literal(', '.join(r.incomplete_reasons)) or 'none'}",
        "",
        f"Review scope: {r.review_scope}",
        "",
        "Scores are heuristic deductions, not a security probability; incomplete reviews have no overall score.",
        "",
        "## Dimension scores",
        "",
        "| Dimension | Score | Accepted | Rejected | Awaiting decision | Tool ran |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for d in r.dimensions:
        tool = "yes" if d.tool_ran else "no"
        lines.append(f"| {DIMENSION_LABELS[d.dimension]} | {d.score} | {d.accepted_findings} | {d.rejected_findings} | {d.human_queue} | {tool} |")
    tc = tier_counts(r)
    lines += ["", f"Evidence tiers: A={tc['A']} B={tc['B']} C={tc['C']} D={tc['D']}", "", "## Accepted findings", ""]
    accepted = [f for f in r.findings if cons.get(f.id) and cons[f.id].final_outcome == "accepted"]
    accepted.sort(key=lambda f: -(cons[f.id].cvss4_score or 0.0))  # accepted implies a valid vector
    if not accepted:
        lines.append("_None._")
    for f in accepted:
        c = cons[f.id]
        p = f.provenance[0]
        lines += [
            f"### {f.id} · {literal(f.title)}",
            f"- Dimension: {DIMENSION_LABELS[f.dimension]} · {f.cwe} · refs: {', '.join(f.standard_refs) or '-'}",
            f"- CVSS 4.0 **{c.cvss4_score} {c.cvss4_severity}** (`{f.cvss4_vector}`) · SSVC **{c.ssvc_decision}**"
            f" · tier **{c.tier.value}** · consensus {c.weighted_score}",
            f"- Families agreeing: {', '.join(x.value for x in c.families_agreeing) or '-'} · tool corroborated: {c.tool_corroborated}"
            f" · skeptic refuted: {c.skeptic_refuted} · position-consistent: {c.position_consistent}",
            f"- Evidence: {code(f'{p.file}:{p.line}')} — {code(p.quote[:160])}",
            f"- Reachability ({f.reachability}): {literal(f.reachability_argument)}",
            f"- Attacker path: {literal(f.exploit_sketch)}",
            *([f"- Human decision: {_decided(c)}"] if c.resolved_by_human else []),
            *([f"- Blocks the gate: {literal(c.blocking_reason)}"] if c.blocking_reason else []),
            "",
        ]
    lines += [
        "## Deterministic tool findings",
        "",
        "These findings remain unresolved until explicitly triaged; model silence does not clear them.",
        "",
        f"Tools that ran: {', '.join(sorted({t['tool'] for t in r.tool_health if t.get('ran')})) or 'none'} · {len(r.tool_results)} result(s)",
        "",
    ]
    for tr in r.tool_results:
        lines.append(
            f"- {literal(tr.get('tool'))} · {literal(tr.get('rule_id'))} · "
            f"{literal(tr.get('file'))}:{tr.get('line')} · {literal(tr.get('message'))}"
        )
    rejected = [f for f in r.findings if cons.get(f.id) and cons[f.id].final_outcome != "accepted"]
    lines += ["## Rejected or unverified findings", ""]
    if not rejected:
        lines.append("_None._")
    for f in rejected:
        c = cons[f.id]
        why = (
            _decided(c)
            if c.resolved_by_human
            else "provenance unverified"
            if c.tier.value == "D" and not any(p.verified for p in f.provenance)
            else f"awaiting human decision: {', '.join(c.human_reasons) or 'no reason recorded'}"
            if c.final_outcome == "needs_human"
            else ("skeptic refuted" if c.skeptic_refuted else f"consensus {c.weighted_score} below threshold")
            # rejection review (policy P8, docs/adr/0005-jury-outcome.md): decided by the jury, queued for a human look
            + (" · rejection review queued" if c.in_rejection_review else "")
        )
        lines.append(f"- {f.id} · {literal(f.title)} · {f.source_family.value} · tier {c.tier.value} · {why}")
    lines += ["", "## Human queue", ""]
    if r.human_queue:
        lines.append(f"{len(r.human_queue)} finding(s) need a human decision (see `human_queue.md`; tickets carry label from config):")
        for it in r.human_queue:
            lines.append(f"- {it.finding_id} · {literal(it.title)} · {', '.join(it.reasons)} · tier {it.tier} · {it.cvss4_severity} · key `{it.key}`")
    else:
        lines.append("_Empty._")
    if (t := r.human_queue_tightening) is not None:
        backlog = "unknown" if t.backlog is None else t.backlog
        state = "tightened" if t.tightened else "not tightened"
        lines += ["", f"Queue tightening: {state} (backlog {backlog}, agreement threshold {t.alpha_threshold})"]
    if r.psirt:
        first = r.psirt[0]
        lines += [
            "",
            "## PSIRT hand-off (EU CRA Article 14)",
            "",
            f"{len(r.psirt)} finding(s) meet the PSIRT trigger for product {code(first['product'])}; "
            f"internal hand-off due {first['internal_sla']['early_warning_by']}.",
            "",
        ]
        for n in r.psirt:
            cv, loc = n["cvss4"], n["location"]
            lines.append(
                f"- {n['finding_id']} · {literal(n['title'])} · {n['cwe']} · CVSS {cv['score']} {cv['severity']} · tier {n['evidence_tier']}"
                f" · exploitable: {n['exploitable']} · {code(str(loc['file']) + ':' + str(loc['line']))}"
            )
    lines += ["", "## Model provenance (ML-BOM, G-7)", ""]
    if r.ml_bom:
        for name, b in r.ml_bom.items():
            detail = f" {b.component}@{b.version} sha256 {b.sha256[:12]}" if b.status == "complete" else ""
            lines.append(f"- {name} ({code(b.model_id)}): {b.status}{detail}")
    else:
        lines.append("_No self-hosted model in this configuration._")
    if r.ml_bom_signature is not None:
        lines.append(f"- BOM signature: {literal(r.ml_bom_signature)}")
    lines += ["", "## Model red-team evaluation (garak / CyberSecEval, G-8)", ""]
    if r.model_eval:
        for fam, e in r.model_eval.items():
            lines.append(f"- {fam}: {e.status}" + (f" ({e.date}, {e.mode})" if e.date else " (no evaluation recorded)"))
    else:
        lines.append("_No non-mock model family in this configuration._")
    lines += ["", "## Bias and integrity audit", ""]
    for k, v in r.bias_audit.items():
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"


def write_markdown(r: ReviewReport, path: Path) -> None:
    path.write_text(render_markdown(r), encoding="utf-8")
