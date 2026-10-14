"""SARIF 2.1.0 writer. Only the subset GitHub code scanning consumes is emitted; the
MARA-specific data (tier, consensus, families, CVSS vector) rides in `properties`."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from .. import __version__
from ..identity import norm_cwe, norm_path
from ..schemas import ConsensusResult, EvidenceTier, Finding, ReviewReport

LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "None": "none"}


def content_fingerprint(f: Finding, occurrence: int = 0) -> str:
    """Stable alert identity for code scanning: dimension, CWE, file and the whitespace-normalised
    evidence quote, plus the occurrence index among findings sharing all four (ordered by line).

    Not the finding id: F-0001-style ids follow the sort order of the findings, so adding or removing
    an earlier finding renumbered the rest, and code scanning carried an alert's state (dismissals
    included) over to a different finding of the same rule. Not the line either: code moving up or
    down must not make a new alert."""
    p = f.provenance[0]
    identity = json.dumps([f.dimension, norm_cwe(f.cwe), norm_path(p.file), " ".join(p.quote.split()), occurrence], ensure_ascii=False)
    return hashlib.sha256(identity.encode()).hexdigest()[:32]


def to_sarif(report: ReviewReport) -> dict:
    cons = {c.finding_id: c for c in report.consensus}
    queued = {i.finding_id: i for i in report.human_queue}
    rules: dict[str, dict] = {}
    results = []
    # the occurrence index among findings sharing dimension, CWE, file and quote is counted over every finding of the
    # report, whatever its state: counted over the emitted ones only, an alert's index (and with it its dismissal)
    # moved to another finding when an earlier one of the same group was accepted or rejected in a later run
    occurrence_of: dict[str, int] = {}
    seen: Counter[tuple[str, str, str, str]] = Counter()
    for f in sorted(report.findings, key=lambda x: (norm_path(x.provenance[0].file), x.provenance[0].line, x.id)):
        group = (f.dimension, norm_cwe(f.cwe), norm_path(f.provenance[0].file), " ".join(f.provenance[0].quote.split()))
        occurrence_of[f.id] = seen[group]
        seen[group] += 1
    for f in sorted(report.findings, key=lambda x: (norm_path(x.provenance[0].file), x.provenance[0].line, x.id)):
        c = cons.get(f.id)
        if c is None:
            continue
        q = queued.get(f.id)
        # what is emitted follows the final outcome (docs/adr/0007-review-status-and-gate.md), never whether the human
        # queue is on: an accepted finding; a finding needing a human and a rejected finding under rejection review
        # (policy P8), both as notes; and a human false positive (docs/adr/0003-human-resolution.md), dismissed with the
        # ruling as its justification, so code scanning records why the alert closed instead of reading it as fixed
        outcome = c.final_outcome
        dismissed = c.resolved_by_human and outcome == "rejected"
        under_review = not c.resolved_by_human and outcome == "rejected" and c.unsupervised_reject_unverified
        if outcome not in ("accepted", "needs_human") and not dismissed and not under_review:
            continue
        rule_id = f"MARA/{f.dimension}/{f.cwe}"
        occurrence = occurrence_of[f.id]
        rules.setdefault(rule_id, {
            "id": rule_id, "name": f.cwe, "shortDescription": {"text": f"{f.dimension}: {f.cwe}"},
            "properties": {"tags": ["security", f.cwe, f.dimension]},
            "defaultConfiguration": {"level": "warning"},
        })
        result = {
            "ruleId": rule_id,
            # a finding waiting for a human decision is emitted as a note, never as an error, so code
            # scanning does not show it as confirmed; the decision on the ticket settles it (G-11)
            "level": "note" if outcome == "needs_human" or under_review else LEVEL[c.cvss4_severity],
            "rank": round(c.weighted_score * 100, 1),
            "message": {"text": f"[{c.tier.value}] {f.title} (CVSS 4.0 {c.cvss4_score} {c.cvss4_severity}; SSVC {c.ssvc_decision})"},
            # a URI reference: a path with a space or '#' must be percent-encoded to stay one
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(p.file.replace("\\", "/"), safe="/"), "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": p.line}}} for p in f.provenance[:1]],
            "partialFingerprints": {"maraContent/v1": content_fingerprint(f, occurrence)},
            "properties": {
                "findingId": f.id, "evidenceTier": c.tier.value, "cvss4Vector": f.cvss4_vector, "cvss4Score": c.cvss4_score,
                "ssvc": c.ssvc_decision, "consensus": c.weighted_score, "familiesAgreeing": [x.value for x in c.families_agreeing],
                "toolCorroborated": c.tool_corroborated, "skepticRefuted": c.skeptic_refuted,
                "agreementProxy": c.agreement_proxy,
                "standardRefs": f.standard_refs, "sourceFamily": f.source_family.value,
                "humanQueue": q is not None, "humanQueueKey": None if q is None else q.key,
                "humanQueueReasons": [] if q is None else q.reasons,
                "humanDecision": c.human_decision,
                # why this finding blocks the gate; its level stays, so the code-scanning alert does too
                **({"blockingReason": c.blocking_reason} if c.blocking_reason else {}),
            },
        }
        if dismissed and c.human_decision is not None:
            d = c.human_decision
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": f"human decision #{d.get('issue')} by {d.get('decided_by')}: "
                                                        f"{d['decision'].replace('_', ' ')}"}]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MARA", "version": __version__, "informationUri": "https://github.com/chinchiang/MultiAgentAlpha",
                                "rules": list(rules.values())}},
            "results": results,
            "invocations": [{"executionSuccessful": report.review_status == "complete"}],
            "properties": {"overallScore": report.overall_score, "gatePassed": report.gate_passed,
                           "gateReasons": report.gate_reasons, "gateEnforced": report.gate_enforced,
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
