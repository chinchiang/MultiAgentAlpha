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
# LEVEL, content_fingerprint and to_sarif exactly as main had them before ADR 0007 (ce58fee, comments included),
# renamed, with ConsensusResult.final_accepted as it was. Only what is not SARIF's own stays current: the identity rules
# (norm_path, norm_cwe; mara.identity), the version, and what the report models read (ConsensusResult.resolved_by_human
# and its fields, Finding). An intended change to what SARIF writes is either one of the properties
# _without_gate_properties strips, or it replaces this reference.


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


def _reachable(c: ConsensusResult, f: Finding, policy) -> tuple[str, ...]:
    """The jury outcomes decide() can give this row under `policy`, from what the row and its finding hold that no vote
    can change: unverified provenance, a skeptic that abstained, tier C at the severity floor while the queue is not
    tightened, or a refutation the jury would overrule always need a human; tier D is otherwise dropped; and with the
    default panel only a tier A finding can be rejected (docs/adr/0005-jury-outcome.md), under rejection review while
    P8 is in force. Needing a human is always reachable (a missing quorum is enough)."""
    from mara.scoring.outcome import tier_c_needs_human

    forced = (not all(p.verified for p in f.provenance) or c.skeptic_abstained
              or (not policy.exclude_tier_c and tier_c_needs_human(c.tier, c.cvss4_severity, policy.tier_c_min_severity))
              or (c.skeptic_refuted and c.tier.value != "D"))
    if forced:
        return ("needs_human",)
    if c.tier.value == "D":
        return ("dropped", "needs_human")
    rejected = (("rejection_review" if not policy.unsupervised_reject_allowed else "rejected"),) if c.tier.value == "A" else ()
    return ("accepted", *rejected, "needs_human")


def _set_state(c: ConsensusResult, outcome: str, decision: str | None) -> None:
    """Write a jury outcome as JuryOutcome.consensus_fields writes it, with a score and votes that agree with it (a
    three-family panel of weight 1, accept threshold 0.6), and optionally a usable human ruling on it. Needing a human
    keeps the row's own reasons, or gets the one a missing quorum gives."""
    c.accepted, c.needs_human, c.unsupervised_reject_unverified = outcome == "accepted", outcome == "needs_human", False
    if outcome == "accepted":
        c.weighted_score, c.votes_tp, c.votes_fp, c.votes_human, c.human_reasons = 1.0, 3, 0, 0, []
    elif outcome in ("rejected", "rejection_review"):
        c.weighted_score, c.votes_tp, c.votes_fp, c.votes_human, c.human_reasons = 0.0, 0, 3, 0, []
        c.unsupervised_reject_unverified = outcome == "rejection_review"
    elif outcome == "dropped":
        c.human_reasons = []
    else:
        c.human_reasons = c.human_reasons or ["insufficient_independent_judges"]
    c.human_decision = {"decision": decision, **_DECIDED} if decision else None


def _states(c: ConsensusResult, f: Finding, policy) -> list[tuple[str, str | None]]:
    """Every state this row can be in: each reachable jury outcome, alone or with a usable human ruling on it."""
    return [(o, d) for o in _reachable(c, f, policy) for d in (None, "false_positive", "true_positive")]


def _variants(report, cfg, policy):
    """The seeded review, once with three hand-made changes and once per rotation of each row's reachable states, so
    every row passes through every state it can be in; each with the human queue built for it, as the pipeline
    would."""
    from mara.report.human_queue_out import build_queue

    hand = report.model_copy(deep=True)
    by_id = {f.id: f for f in hand.findings}
    cons = {c.finding_id: c for c in hand.consensus}
    for fid, (outcome, decision) in (("F-0001", ("rejection_review", None)),  # tier A, voted down
                                      ("F-0057", ("accepted", "false_positive")),
                                      ("F-0009", ("needs_human", "true_positive"))):
        assert (outcome, decision) in _states(cons[fid], by_id[fid], policy), (fid, outcome, decision)
        _set_state(cons[fid], outcome, decision)
    variants = [hand]
    states = {c.finding_id: _states(c, {f.id: f for f in report.findings}[c.finding_id], policy) for c in report.consensus}
    for k in range(max(len(s) for s in states.values())):
        v = report.model_copy(deep=True)
        for i, c in enumerate(v.consensus):
            own = states[c.finding_id]
            _set_state(c, *own[(i + k) % len(own)])
        variants.append(v)
    for v in variants:
        v.human_queue = build_queue(v.findings, {c.finding_id: c for c in v.consensus}, {x.finding_id: x for x in v.skeptic},
                                    {n.finding_id: n for n in v.redteam}, v.votes, cfg)
    return variants


def test_with_the_human_queue_enabled_code_scanning_sees_what_it_saw_before(mock_report):
    pipe, report = mock_report
    assert pipe.cfg.human_queue.enabled
    variants = _variants(report, pipe.cfg, pipe.outcome_policy)
    assert "F-0001" in {i.finding_id for i in variants[0].human_queue}, "the rejection under review is queued"
    seen = {(c.finding_id, c.jury_outcome, (c.human_decision or {}).get("decision")) for v in variants[1:] for c in v.consensus}
    assert {o for _, o, _ in seen} == {"accepted", "rejected", "dropped", "needs_human"}, "every jury outcome is covered"
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
