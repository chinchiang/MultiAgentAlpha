from __future__ import annotations

from pathlib import Path

from ..schemas import DIMENSION_LABELS, ReviewReport
from .escaping import literal
from .sarif_out import tier_counts


def render_markdown(r: ReviewReport) -> str:
    cons = {c.finding_id: c for c in r.consensus}
    overall = f"{r.overall_score}/100" if r.overall_score is not None else "unavailable (review incomplete)"
    lines = [
        f"# MARA review: `{literal(r.target)}`",
        "",
        f"Generated {r.generated_at} · mode `{r.provider_mode}` · families {', '.join(r.families_used)}",
        "",
        f"**Overall score {overall} · gate {'PASSED' if r.gate_passed else 'BLOCKED'}**"
        + (f" · rollout phase `{r.bias_audit['rollout_phase']}`" if r.bias_audit.get("rollout_phase") else "")
        + (" (recorded, not enforced)" if r.bias_audit.get("rollout_phase") not in (None, "blocking") and not r.gate_passed else ""),
        "",
        f"Review status: **{r.review_status}**; incomplete reasons: {literal(', '.join(r.incomplete_reasons)) or 'none'}",
        "",
        "Scores are heuristic deductions, not a security probability; incomplete reviews have no overall score.",
        "",
        "## Dimension scores",
        "",
        "| Dimension | Score | Accepted | Rejected | Human queue | Tool ran |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for d in r.dimensions:
        tool = "yes" if d.tool_ran else "no"
        lines.append(f"| {DIMENSION_LABELS[d.dimension]} | {d.score} | {d.accepted_findings} | {d.rejected_findings} | {d.human_queue} | {tool} |")
    tc = tier_counts(r)
    lines += ["", f"Evidence tiers: A={tc['A']} B={tc['B']} C={tc['C']} D={tc['D']}", "", "## Accepted findings", ""]
    accepted = [f for f in r.findings if cons.get(f.id) and cons[f.id].accepted]
    accepted.sort(key=lambda f: -cons[f.id].cvss4_score)
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
            f"- Evidence: `{literal(p.file)}:{p.line}` — `{literal(p.quote[:160])}`",
            f"- Reachability ({f.reachability}): {literal(f.reachability_argument)}",
            f"- Attacker path: {literal(f.exploit_sketch)}",
            "",
        ]
    lines += [
        "## Deterministic tool findings",
        "",
        "These findings remain unresolved until explicitly triaged; model silence does not clear them.",
        "",
    ]
    for tool in r.tool_results:
        lines.append(
            f"- {literal(tool.get('tool'))} · {literal(tool.get('rule_id'))} · "
            f"{literal(tool.get('file'))}:{tool.get('line')} · {literal(tool.get('message'))}"
        )
    rejected = [f for f in r.findings if cons.get(f.id) and not cons[f.id].accepted]
    lines += ["## Rejected or unverified findings", ""]
    if not rejected:
        lines.append("_None._")
    for f in rejected:
        c = cons[f.id]
        why = (
            "provenance unverified"
            if c.tier.value == "D" and not any(p.verified for p in f.provenance)
            else ("skeptic refuted" if c.skeptic_refuted else f"consensus {c.weighted_score} below threshold")
        )
        lines.append(f"- {f.id} · {literal(f.title)} · {f.source_family.value} · tier {c.tier.value} · {why}")
    lines += ["", "## Human queue", ""]
    if r.human_queue:
        lines.append(f"{len(r.human_queue)} finding(s) need a human decision (see `human_queue.md`; tickets carry label from config):")
        for it in r.human_queue:
            lines.append(f"- {it.finding_id} · {literal(it.title)} · {', '.join(it.reasons)} · tier {it.tier} · {it.cvss4_severity} · key `{it.key}`")
    else:
        lines.append("_Empty._")
    if r.psirt:
        first = r.psirt[0]
        lines += [
            "",
            "## PSIRT hand-off (EU CRA Article 14)",
            "",
            f"{len(r.psirt)} finding(s) meet the PSIRT trigger for product `{literal(first['product'])}`; "
            f"internal hand-off due {first['internal_sla']['early_warning_by']}.",
            "",
        ]
        for n in r.psirt:
            cv, loc = n["cvss4"], n["location"]
            lines.append(
                f"- {n['finding_id']} · {literal(n['title'])} · {n['cwe']} · CVSS {cv['score']} {cv['severity']} · tier {n['evidence_tier']}"
                f" · exploitable: {n['exploitable']} · `{literal(loc['file'])}:{loc['line']}`"
            )
    ml_bom = r.bias_audit.get("ml_bom") or {}
    lines += ["", "## Model provenance (ML-BOM, G-7)", ""]
    if ml_bom:
        for name, v in ml_bom.items():
            detail = f" {v['component']}@{v['version']} sha256 {v['sha256'][:12]}" if v.get("status") == "complete" else ""
            lines.append(f"- {name} (`{literal(v['model_id'])}`): {v['status']}{detail}")
    else:
        lines.append("_No self-hosted model in this configuration._")
    me = r.bias_audit.get("model_eval") or {}
    lines += ["", "## Model red-team evaluation (garak / CyberSecEval, G-8)", ""]
    if me:
        for fam, v in me.items():
            lines.append(f"- {fam}: {v.get('status', 'none')}" + (f" ({v['date']}, {v['mode']})" if v.get("date") else " (no evaluation recorded)"))
    else:
        lines.append("_No non-mock model family in this configuration._")
    lines += ["", "## Bias and integrity audit", ""]
    for k, v in r.bias_audit.items():
        if k in ("ml_bom", "model_eval"):
            continue
        lines.append(f"- {k}: {v}")
    return "\n".join(lines) + "\n"


def write_markdown(r: ReviewReport, path: Path) -> None:
    path.write_text(render_markdown(r), encoding="utf-8")
