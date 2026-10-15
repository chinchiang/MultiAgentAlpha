"""SARIF decides from the final outcome which findings code scanning sees (docs/adr/0007-review-status-and-gate.md)."""

import hashlib
import json
from collections import Counter
from urllib.parse import quote

from mara import __version__
from mara.identity import norm_cwe, norm_path
from mara.report.sarif_out import to_sarif
from mara.schemas import ConsensusResult, Finding, ReviewReport


def _results(report) -> dict[str, dict]:
    return {r["properties"]["findingId"]: r for r in to_sarif(report)["runs"][0]["results"]}


def test_a_finding_needing_a_human_is_a_note_even_when_the_human_queue_is_disabled(mock_report):
    """A disabled queue (human_queue.enabled: false) queues nothing; the review is still incomplete on these findings,
    so code scanning must still show them, as notes rather than confirmed alerts."""
    _, report = mock_report
    unqueued = report.model_copy(update={"human_queue": []})
    waiting = {c.finding_id for c in report.consensus if c.final_outcome == "needs_human"}
    assert waiting, "the seeded fixture has findings that need a human"
    results = _results(unqueued)
    assert waiting <= set(results)
    assert {results[fid]["level"] for fid in waiting} == {"note"}
    assert not any(results[fid]["properties"]["humanQueue"] for fid in waiting)


# ---------------------------------------------------------------- the old writer, kept as the reference
# LEVEL, content_fingerprint and to_sarif exactly as origin/main had them before ADR 0007 (comments included), renamed,
# with ConsensusResult.final_accepted as it was. Only what is not SARIF's own stays current: the identity rules
# (norm_path, norm_cwe; mara.identity) and the version. An intended change to what SARIF writes is either one of the
# properties _without_gate_properties strips, or it replaces this reference.


def _old_final_accepted(c: ConsensusResult) -> bool:  # ConsensusResult.final_accepted before ADR 0007
    return c.human_decision["decision"] == "true_positive" if c.human_decision else c.accepted


_OLD_LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "None": "none"}


def _old_content_fingerprint(f: Finding, occurrence: int = 0) -> str:
    """Stable alert identity for code scanning: dimension, CWE, file and the whitespace-normalised
    evidence quote, plus the occurrence index among findings sharing all four (ordered by line).

    Not the finding id: F-0001-style ids follow the sort order of the findings, so adding or removing
    an earlier finding renumbered the rest, and code scanning carried an alert's state (dismissals
    included) over to a different finding of the same rule. Not the line either: code moving up or
    down must not make a new alert."""
    p = f.provenance[0]
    identity = json.dumps([f.dimension, norm_cwe(f.cwe), norm_path(p.file), " ".join(p.quote.split()), occurrence], ensure_ascii=False)
    return hashlib.sha256(identity.encode()).hexdigest()[:32]


def _old_to_sarif(report: ReviewReport) -> dict:
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
        # the final outcome (docs/adr/0003-human-resolution.md): a human false positive is still emitted, dismissed with
        # the ruling as its justification, so code scanning records why the alert closed instead of reading it as fixed
        dismissed = c.resolved_by_human and not _old_final_accepted(c)
        if not _old_final_accepted(c) and q is None and not dismissed:
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
            "level": "note" if q is not None else _OLD_LEVEL[c.cvss4_severity],
            "rank": round(c.weighted_score * 100, 1),
            "message": {"text": f"[{c.tier.value}] {f.title} (CVSS 4.0 {c.cvss4_score} {c.cvss4_severity}; SSVC {c.ssvc_decision})"},
            # a URI reference: a path with a space or '#' must be percent-encoded to stay one
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(p.file.replace("\\", "/"), safe="/"), "uriBaseId": "%SRCROOT%"},
                                                "region": {"startLine": p.line}}} for p in f.provenance[:1]],
            "partialFingerprints": {"maraContent/v1": _old_content_fingerprint(f, occurrence)},
            "properties": {
                "findingId": f.id, "evidenceTier": c.tier.value, "cvss4Vector": f.cvss4_vector, "cvss4Score": c.cvss4_score,
                "ssvc": c.ssvc_decision, "consensus": c.weighted_score, "familiesAgreeing": [x.value for x in c.families_agreeing],
                "toolCorroborated": c.tool_corroborated, "skepticRefuted": c.skeptic_refuted,
                "agreementProxy": c.agreement_proxy,
                "standardRefs": f.standard_refs, "sourceFamily": f.source_family.value,
                "humanQueue": q is not None, "humanQueueKey": None if q is None else q.key,
                "humanQueueReasons": [] if q is None else q.reasons,
                "humanDecision": c.human_decision,
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
                           "reviewStatus": report.review_status, "incompleteReasons": report.incomplete_reasons,
                           "families": report.families_used, "biasAudit": report.bias_audit},
        }],
    }


def _without_gate_properties(doc: dict) -> dict:
    """The document without the properties ADR 0007 adds: the run's gateReasons and gateEnforced, each result's
    blockingReason."""
    import copy

    doc = copy.deepcopy(doc)
    for run in doc["runs"]:
        run["properties"].pop("gateReasons")
        run["properties"].pop("gateEnforced")
        for r in run["results"]:
            r["properties"].pop("blockingReason", None)
    return doc


_DECIDED = {"key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}


def _set_state(c: ConsensusResult, state: str) -> None:
    """Write one of the states a consensus row holds, its jury outcome as scoring writes it (rejected is dropped at
    tier D), a rejection under review (P8), or a usable human ruling on the row as scored. Only a rejected finding is
    ever under rejection review (decide(), docs/adr/0005-jury-outcome.md): at tier D the state is a plain drop."""
    if state in ("accepted", "rejected", "rejection_review"):
        c.accepted, c.needs_human, c.human_reasons = state == "accepted", False, []
        c.unsupervised_reject_unverified = state == "rejection_review" and c.tier.value != "D"
    elif state in ("false_positive", "true_positive"):
        c.human_decision = {"decision": state, **_DECIDED}


_STATES = ("as_scored", "accepted", "rejected", "rejection_review", "false_positive", "true_positive")


def _variants(report, cfg):
    """The seeded review, once with three hand-made changes and once per rotation of _STATES over its rows, so every
    row passes through every state; each with the human queue built for it, as the pipeline would."""
    from mara.report.human_queue_out import build_queue

    hand = report.model_copy(deep=True)
    cons = {c.finding_id: c for c in hand.consensus}
    _set_state(cons["F-0016"], "rejection_review")
    _set_state(cons["F-0057"], "false_positive")  # on an accepted finding
    _set_state(cons["F-0009"], "true_positive")  # on a waiting one
    variants = [hand]
    for k in range(len(_STATES)):
        v = report.model_copy(deep=True)
        for i, c in enumerate(v.consensus):
            _set_state(c, _STATES[(i + k) % len(_STATES)])
        variants.append(v)
    for v in variants:
        v.human_queue = build_queue(v.findings, {c.finding_id: c for c in v.consensus}, {x.finding_id: x for x in v.skeptic},
                                    {n.finding_id: n for n in v.redteam}, v.votes, cfg)
    return variants


def test_with_the_human_queue_enabled_code_scanning_sees_what_it_saw_before(mock_report):
    pipe, report = mock_report
    assert pipe.cfg.human_queue.enabled
    variants = _variants(report, pipe.cfg)
    assert "F-0016" in {i.finding_id for i in variants[0].human_queue}
    for v in variants:
        # the whole document, rules, results (levels, messages, fingerprints, properties, suppressions) and run, is
        # what the old to_sarif wrote, apart from the gate properties added on purpose
        assert _without_gate_properties(to_sarif(v)) == _old_to_sarif(v)
    assert any("blockingReason" in r["properties"] for r in _results(variants[0]).values()), \
        "the blockingReason that _without_gate_properties strips is in the new output"
    assert _results(variants[0])["F-0057"]["suppressions"][0]["status"] == "accepted", "the human false positive is dismissed"


def test_the_run_says_why_the_gate_blocked_and_each_blocking_result_why_it_blocks(mock_report):
    _, report = mock_report
    run = to_sarif(report)["runs"][0]
    assert run["properties"]["gateReasons"] == ["review_incomplete", "blocking_tier_and_severity"]
    assert run["properties"]["gateEnforced"] is False
    results = _results(report)
    assert results["F-0001"]["properties"]["blockingReason"] == "blocking_tier_and_severity"
    assert results["F-0001"]["level"] == "error", "a blocking result keeps the level of its severity"
    assert "blockingReason" not in results["F-0016"]["properties"], "only a blocking finding carries one"
