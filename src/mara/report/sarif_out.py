"""SARIF 2.1.0 writer. Only the subset GitHub code scanning consumes is emitted; the
MARA-specific data (tier, consensus, families, CVSS vector) rides in `properties`."""

from __future__ import annotations

import json
from pathlib import Path

from ..schemas import ConsensusResult, EvidenceTier, Finding, ReviewReport

LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "None": "none"}


def to_sarif(report: ReviewReport) -> dict:
    cons = {c.finding_id: c for c in report.consensus}
    queued = {i.finding_id: i for i in report.human_queue}
    rules: dict[str, dict] = {}
    results = []
    for f in report.findings:
        c = cons.get(f.id)
        if c is None:
            continue
        q = queued.get(f.id)
        if not c.accepted and q is None:
            continue
        rule_id = f"MARA/{f.dimension}/{f.cwe}"
        rules.setdefault(rule_id, {
            "id": rule_id, "name": f.cwe, "shortDescription": {"text": f"{f.dimension}: {f.cwe}"},
            "properties": {"tags": ["security", f.cwe, f.dimension]},
            "defaultConfiguration": {"level": "warning"},
        })
        results.append({
            "ruleId": rule_id,
            # a finding waiting for a human decision is emitted as a note, never as an error, so code
            # scanning does not show it as confirmed; the decision on the ticket settles it (G-11)
            "level": "note" if q is not None else LEVEL[c.cvss4_severity],
            "rank": round(c.weighted_score * 100, 1),
            "message": {"text": f"[{c.tier.value}] {f.title} (CVSS 4.0 {c.cvss4_score} {c.cvss4_severity}; SSVC {c.ssvc_decision})"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": p.file, "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": p.line}}} for p in f.provenance[:1]],
            "partialFingerprints": {"maraFindingId": f.id},
            "properties": {
                "evidenceTier": c.tier.value, "cvss4Vector": f.cvss4_vector, "cvss4Score": c.cvss4_score,
                "ssvc": c.ssvc_decision, "consensus": c.weighted_score, "familiesAgreeing": [x.value for x in c.families_agreeing],
                "toolCorroborated": c.tool_corroborated, "skepticRefuted": c.skeptic_refuted,
                "krippendorffAlpha": c.krippendorff_alpha, "agreementProxy": c.agreement_proxy,
                "standardRefs": f.standard_refs, "sourceFamily": f.source_family.value,
                "humanQueue": q is not None, "humanQueueKey": None if q is None else q.key,
                "humanQueueReasons": [] if q is None else q.reasons,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MARA", "version": "0.1.0", "informationUri": "https://github.com/chinchiang/MultiAgentAlpha",
                                "rules": list(rules.values())}},
            "results": results,
            "invocations": [{"executionSuccessful": report.review_status == "complete"}],
            "properties": {"overallScore": report.overall_score, "gatePassed": report.gate_passed,
                           "reviewStatus": report.review_status, "incompleteReasons": report.incomplete_reasons,
                           "families": report.families_used, "biasAudit": report.bias_audit},
        }],
    }


def write_sarif(report: ReviewReport, path: Path) -> None:
    path.write_text(json.dumps(to_sarif(report), indent=2, ensure_ascii=False), encoding="utf-8")


def tier_counts(report: ReviewReport) -> dict[str, int]:
    out = {t.value: 0 for t in EvidenceTier}
    for c in report.consensus:
        out[c.tier.value] += 1
    return out


__all__ = ["to_sarif", "write_sarif", "tier_counts", "Finding", "ConsensusResult"]
