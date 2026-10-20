"""What the workbench shows of a review (GLOSSARY.md: workbench, run, progress record, review scope, review status,
incomplete reason, gate, tool evidence, tool alert, exchange, ballot role, reply outcome, refusal, truncation, invalid
item, canary echo, jury outcome, final outcome, rejected finding, dropped finding, human-resolved finding, human queue,
human reason, queue tightening, bias audit, report metadata): the report as the run page reads it
(docs/adr/0001-reply-outcome-accounting.md, docs/adr/0005-jury-outcome.md, docs/adr/0006-local-web-workbench.md,
docs/adr/0007-review-status-and-gate.md, docs/adr/0008-reply-accounting.md, docs/adr/0009-report-metadata.md).

The browser derives nothing: the jury outcome and the final outcome are the `ConsensusResult` properties
(docs/adr/0005-jury-outcome.md), read here from the validated report rather than re-implemented in JavaScript, and
every count on the page comes from the same objects the Markdown report is written from. Repository-derived text
(titles, quotes, arguments, notes) passes through unchanged; the page renders it as text, never as markup.

Pure: every function reads only what it is given: a run's `run.json`, its report and its progress record.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from ..audit import INCOMPLETE_COUNTERS, ROLES, Role, by_family
from ..schemas import DIMENSION_LABELS, SEVERITY_ORDER, ConsensusResult, ReviewReport
from ..tools.evidence import is_alert

OUTCOMES = ("accepted", "rejected", "dropped", "needs_human")

# role key in the run manifest -> the role whose counters mara.audit.ROLES names
AUDIT_ROLES: dict[str, Role] = {"context": "context", "reviewers": "reviewer", "skeptic": "skeptic", "redteam": "redteam",
                                "judges": "judge"}
ROLE_ORDER = ("context", "reviewers", "skeptic", "redteam", "judges")
_FAILURES = {role: (ROLES[r].refusals, ROLES[r].truncations, ROLES[r].errors, ROLES[r].invalid) for role, r in AUDIT_ROLES.items()}


def _num(audit: dict[str, Any], key: str) -> int:
    v = audit.get(key, 0)
    return int(v) if isinstance(v, int | float) and not isinstance(v, bool) else 0


def outcome_counts(report: ReviewReport) -> dict[str, int]:
    counts: Counter[str] = Counter(str(c.final_outcome) for c in report.consensus)
    return {o: counts.get(o, 0) for o in OUTCOMES}


def summary(report: ReviewReport) -> dict[str, Any]:
    """The few numbers the run list and the sidebar show."""
    return {
        "generated_at": report.generated_at,
        "provider_mode": report.provider_mode,
        "review_status": report.review_status,
        "review_scope": report.review_scope,
        "overall_score": report.overall_score,
        "gate_passed": report.gate_passed,
        "findings": len(report.findings),
        "counts": outcome_counts(report),
        "human_queue": len(report.human_queue),
        "incomplete_reasons": list(report.incomplete_reasons),
        "families_used": list(report.families_used),
    }


def _consensus(c: ConsensusResult | None) -> dict[str, Any] | None:
    if c is None:
        return None
    return {**c.model_dump(mode="json"), "jury_outcome": c.jury_outcome, "final_outcome": c.final_outcome,
            "resolved_by_human": c.resolved_by_human}


def roles(manifest: dict[str, Any], report: ReviewReport | None) -> list[dict[str, Any]]:
    """The panel per role: the models the run's config named (snapshotted at launch), each with its family's
    exchange counters for that role, plus any family the pipeline reassigned the role to (the skeptic and red team
    are picked per finding outside the finder families)."""
    audit: dict[str, Any] = dict(report.bias_audit) if report else {}
    served = {p.get("name"): p for p in (report.provider_manifest if report else [])}
    models = {m.get("name"): m for m in manifest.get("models") or []}
    if not models and report:  # a run started outside the workbench: only the report's provider manifest
        models = {p.get("name"): {"name": p.get("name"), "family": p.get("family"), "provider": p.get("type"), "model": p.get("model")}
                  for p in report.provider_manifest}
    configured: dict[str, Any] = manifest.get("roles") or {}
    if not configured and report:
        names = [p.get("name") for p in report.provider_manifest]
        configured = {"reviewers": names, "judges": names}
    by_fam = by_family(audit)
    out = []
    for role in ROLE_ORDER:
        names = configured.get(role) or []
        names = [names] if isinstance(names, str) else list(names)
        audit_role = AUDIT_ROLES[role]
        calls = ROLES[audit_role].calls
        members = []
        families_seen = set()
        for name in [n for n in names if n]:
            spec = models.get(name, {"name": name})
            fam = str(spec.get("family") or "")
            families_seen.add(fam)
            members.append(_member(spec, served.get(name), by_fam.get(fam, {}), role, audit_role, fam, configured_member=True))
        # a family the audit counts calls for although the manifest does not name it for this role
        for fam in sorted(f for f, counters in by_fam.items() if f not in families_seen and counters.get(calls)):
            spec = next((m for m in models.values() if m.get("family") == fam), {"name": fam, "family": fam})
            members.append(_member(spec, served.get(spec.get("name")), by_fam[fam], role, audit_role, fam, configured_member=False))
        if members:
            out.append({"role": role, "members": members})
    return out


def _member(spec: dict[str, Any], served: dict[str, Any] | None, counters: dict[str, Any], role: str, audit_role: Role, fam: str,
            *, configured_member: bool) -> dict[str, Any]:
    """One family's row for a role; `counters` are that family's counters (mara.audit.by_family)."""
    failures = {k: _num(counters, k) for k in _FAILURES[role]}
    # a report of EXCHANGE_VERSION 4 counted the context agent's echoes in the reviewers' canary_echoes
    canary = ROLES[audit_role].canary
    echoes = _num(counters, canary.echoes) if canary else 0
    return {
        "name": spec.get("name"),
        "family": fam,
        "provider": spec.get("provider"),
        "model": spec.get("model"),
        "data_residency": spec.get("data_residency"),
        "endpoint_host": spec.get("endpoint_host"),
        "served_models": list((served or {}).get("served_models") or []),
        "calls": _num(counters, ROLES[audit_role].calls),
        "failures": failures,
        "canary_echoes": echoes,
        "configured": configured_member,
    }


def budget(manifest: dict[str, Any], report: ReviewReport | None, progress: dict[str, Any] | None) -> dict[str, Any]:
    """What the run used. MARA has no configured quota, so these are counts, not shares of a limit; tokens are
    recorded for the context and reviewer calls only (the ballot roles do not report them)."""
    audit: dict[str, Any] = dict(report.bias_audit) if report else {}
    tightening = report.human_queue_tightening if report else None
    calls = {role: _num(audit, ROLES[r].calls) for role, r in AUDIT_ROLES.items()}
    started = (progress or {}).get("started_at") or manifest.get("started_at")
    finished = (progress or {}).get("finished_at") or manifest.get("finished_at")
    return {
        "started_at": started,
        "finished_at": finished,
        "calls": calls,
        "calls_total": sum(calls.values()),
        "input_tokens": _num(audit, "input_tokens"),
        "output_tokens": _num(audit, "output_tokens"),
        "tokens_partial": True,
        "findings_raw": _num(audit, "findings_raw"),
        "findings_deduped": _num(audit, "findings_deduped"),
        "tool_results_ingested": len(report.tool_results) if report else 0,
        "human_queue_size": len(report.human_queue) if report else 0,
        # the page reads a backlog nobody knew as "unknown", and one with no report as missing
        "human_queue_backlog": None if tightening is None else ("unknown" if tightening.backlog is None else tightening.backlog),
        "human_queue_tightened": bool(tightening and tightening.tightened),
        "global_krippendorff_alpha": audit.get("global_krippendorff_alpha"),
        "position_flips": _num(audit, "position_flips"),
    }


def report_view(manifest: dict[str, Any], report: ReviewReport, progress: dict[str, Any] | None) -> dict[str, Any]:
    cons = {c.finding_id: c for c in report.consensus}
    sk = {v.finding_id: v for v in report.skeptic}
    rt = {n.finding_id: n for n in report.redteam}
    votes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for v in report.votes:
        votes[v.finding_id].append(v.model_dump(mode="json"))
    findings = []
    for f in report.findings:
        c = cons.get(f.id)
        findings.append({
            **f.model_dump(mode="json"),
            "severity": c.cvss4_severity if c else "None",
            "consensus": _consensus(c),
            "skeptic": sk[f.id].model_dump(mode="json") if f.id in sk else None,
            "redteam": rt[f.id].model_dump(mode="json") if f.id in rt else None,
            "votes": votes.get(f.id, []),
        })
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda x: (-rank.get(x["severity"], 0), x["id"]))
    tool_results = list(report.tool_results)
    audit = dict(report.bias_audit)
    coverage = dict(report.coverage)
    counts = outcome_counts(report)
    return {
        "meta": {
            "target": report.target,
            "target_id": report.target_id,
            "revision": report.revision,
            "config_hash": report.config_hash,
            "review_scope": report.review_scope,
            "provider_mode": report.provider_mode,
            "families_used": list(report.families_used),
            "generated_at": report.generated_at,
            "review_status": report.review_status,
            "gate_passed": report.gate_passed,
            "overall_score": report.overall_score,
            "content_hash": coverage.get("content_hash", ""),
            "commit": coverage.get("commit", ""),
            "exchange_version": audit.get("exchange_version"),
            "rollout_phase": report.rollout_phase,
            "ml_bom": {n: b.model_dump() for n, b in report.ml_bom.items()},
            "model_eval": {fam: e.model_dump() for fam, e in report.model_eval.items()},
        },
        "stats": {
            "findings": len(report.findings),
            **counts,
            "human_queue": len(report.human_queue),
            "tool_results": len(tool_results),
            "tool_results_blocking": sum(1 for t in tool_results if is_alert(t.get("level"))),
            "tools_ran": sum(1 for h in report.tool_health if h.get("ran")),
            "tools_total": len(report.tool_health),
            "incomplete_reasons": len(report.incomplete_reasons),
            "psirt": len(report.psirt),
        },
        "roles": roles(manifest, report),
        "budget": budget(manifest, report, progress),
        "dimensions": [{**d.model_dump(mode="json"), "label": DIMENSION_LABELS.get(d.dimension, d.dimension)} for d in report.dimensions],
        "findings": findings,
        "tool_health": list(report.tool_health),
        "tool_results": tool_results,
        "human_queue": [q.model_dump(mode="json") for q in report.human_queue],
        "known_unknowns": {
            "incomplete_reasons": list(report.incomplete_reasons),
            "audit_failures": {k: _num(audit, k) for k in INCOMPLETE_COUNTERS if _num(audit, k)},
            "tools_not_run": [h for h in report.tool_health if not h.get("ran")],
            "coverage": {
                "complete": coverage.get("complete"),
                "included": len(coverage.get("included") or []),
                "omitted": coverage.get("omitted") or {},
                "excluded": coverage.get("excluded") or {},
                "redacted": coverage.get("redacted") or [],
                "deleted": coverage.get("deleted") or [],
            },
        },
        "bias_audit": audit,
    }
