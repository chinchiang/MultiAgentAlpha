"""SARIF decides from the final outcome which findings code scanning sees (docs/adr/0007-review-status-and-gate.md)."""

from mara.report.sarif_out import to_sarif


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


def _old_to_sarif(report) -> dict:
    """to_sarif as it was before ADR 0007, kept verbatim as the reference (final_accepted inlined as the property was)."""
    from collections import Counter
    from urllib.parse import quote

    from mara import __version__
    from mara.identity import norm_cwe, norm_path
    from mara.report.sarif_out import LEVEL, content_fingerprint

    def final_accepted(c):
        return c.human_decision["decision"] == "true_positive" if c.human_decision else c.accepted

    cons = {c.finding_id: c for c in report.consensus}
    queued = {i.finding_id: i for i in report.human_queue}
    rules: dict[str, dict] = {}
    results = []
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
        dismissed = c.resolved_by_human and not final_accepted(c)
        if not final_accepted(c) and q is None and not dismissed:
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
            "level": "note" if q is not None else LEVEL[c.cvss4_severity],
            "rank": round(c.weighted_score * 100, 1),
            "message": {"text": f"[{c.tier.value}] {f.title} (CVSS 4.0 {c.cvss4_score} {c.cvss4_severity}; SSVC {c.ssvc_decision})"},
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


def test_with_the_human_queue_enabled_code_scanning_sees_what_it_saw_before(mock_report):
    from mara.report.human_queue_out import build_queue

    pipe, report = mock_report
    report = report.model_copy(deep=True)
    cons = {c.finding_id: c for c in report.consensus}
    decided = {"key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}
    # a rejection under review (P8), a human false positive on an accepted finding, a human true positive on a waiting one
    cons["F-0016"].accepted, cons["F-0016"].unsupervised_reject_unverified = False, True
    cons["F-0057"].human_decision = {"decision": "false_positive", **decided}
    cons["F-0009"].human_decision = {"decision": "true_positive", **decided}
    report.human_queue = build_queue(report.findings, cons, {v.finding_id: v for v in report.skeptic},
                                     {n.finding_id: n for n in report.redteam}, report.votes, pipe.cfg)
    assert "F-0016" in {i.finding_id for i in report.human_queue}
    # the whole document, rules, results (levels, messages, fingerprints, properties, suppressions) and run, is what
    # the old to_sarif wrote, apart from the gate properties added on purpose
    assert _without_gate_properties(to_sarif(report)) == _old_to_sarif(report)
    assert any("blockingReason" in r["properties"] for r in _results(report).values()), "and those are really there"
    assert _results(report)["F-0057"]["suppressions"][0]["status"] == "accepted", "the human false positive is dismissed"


def test_the_run_says_why_the_gate_blocked_and_each_blocking_result_why_it_blocks(mock_report):
    _, report = mock_report
    run = to_sarif(report)["runs"][0]
    assert run["properties"]["gateReasons"] == ["review_incomplete", "blocking_tier_and_severity"]
    assert run["properties"]["gateEnforced"] is False
    results = _results(report)
    assert results["F-0001"]["properties"]["blockingReason"] == "blocking_tier_and_severity"
    assert results["F-0001"]["level"] == "error", "a blocking result keeps the level of its severity"
    assert "blockingReason" not in results["F-0016"]["properties"], "only a blocking finding carries one"
