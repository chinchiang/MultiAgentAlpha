"""SARIF decides from the final outcome which findings code scanning sees (docs/adr/0007-review-status-and-gate.md)."""

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import NamedTuple
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

# How the judges of one finding vote, both passes alike unless split: as they did in the seeded review, all for, all
# against, one family or two for and the rest against, forward for and reverse against, or all asking for a human
_PATTERNS = ("as_cast", "all_tp", "all_fp", "one_family_tp", "two_families_tp", "split_passes", "needs_human")


def _recast(votes, pattern: str):
    """The judge votes on one finding, re-cast to `pattern`."""
    if pattern == "as_cast":
        return list(votes)
    rank = {fam: i for i, fam in enumerate(sorted({v.judge_family.value for v in votes}))}

    def verdict(v) -> str:
        i = rank[v.judge_family.value]
        return {"all_tp": "true_positive", "all_fp": "false_positive", "needs_human": "needs_human",
                "one_family_tp": "true_positive" if i == 0 else "false_positive",
                "two_families_tp": "true_positive" if i < 2 else "false_positive",
                "split_passes": "true_positive" if v.pass_id == "forward" else "false_positive"}[pattern]

    return [v.model_copy(update={"verdict": verdict(v)}) for v in votes]


def _with_a_fourth_judge(cfg, votes, finders):
    """The panel with a fourth judge family (mistral), and the votes the ballot round's jury would collect from it: mistral,
    never a finder here, votes on every finding as one of its other judges did (deepseek where it voted), and a finder's
    family keeps its discounted self-family vote only while fewer than min_independent_judges families are independent
    of the finding's finders (mara.ballot_round's self-preference rule), so a two-finder finding loses those votes here.

    Why a fourth judge: a finding is rejected only when at least three judge families are independent of all its
    finders, one voting for it and two against (agreement 0.5). The mock panel never gets there, nor does any panel of
    three judges that also review (config/mara.yaml's too; docs/adr/0005-jury-outcome.md): one finder leaves two
    judges, whose split is agreement 0.25, below any threshold P4 allows (0.3), and whose joint "false positive"
    leaves no model family agreeing, so the finding is tier D and dropped; two or three finders leave too few
    independent judges for the quorum. Without a rejection there is no rejection review either."""
    from collections import defaultdict

    from mara.config import MaraConfig
    from mara.schemas import ModelFamily

    raw = cfg.model_dump(mode="json")
    raw["models"].append({"name": "mock-m", "family": "mistral", "provider": "mock", "model": "mock-mistral",
                          "data_residency": "on_prem"})
    raw["roles"]["judges"].append("mock-m")
    panel = MaraConfig.model_validate(raw, context={"skip_policies": True})
    judges = {m.family for m in panel.models if m.name in panel.roles.judges}
    by_finding = defaultdict(list)
    for v in votes:
        by_finding[v.finding_id].append(v)
    cast = []
    for fid, own in by_finding.items():
        excused = len(judges - finders[fid]) >= panel.gate.min_independent_judges
        cast += [v for v in own if not (excused and v.judge_family in finders[fid])]
        model = next(fam for fam in (ModelFamily.DEEPSEEK, *sorted({v.judge_family for v in own}))
                     if any(v.judge_family == fam for v in own))
        cast += [v.model_copy(update={"judge_family": ModelFamily.MISTRAL, "judge_model": "mock-mistral", "self_family": False})
                 for v in own if v.judge_family == model]
    return panel, cast


class _Variant(NamedTuple):
    report: ReviewReport
    panel: str  # mock, four judges, or four judges with P8 unlocked
    patterns: dict[str, str]  # finding id -> the vote pattern it was re-cast to


def _variants(report, cfg, tmp_path) -> list[_Variant]:
    """Consensus rows scoring really produces: the seeded review's findings, skeptic, red team and tool results scored
    again by Pipeline.score with the judges' votes re-cast, each finding taking every vote pattern in turn, on the mock
    panel, on the panel with a fourth judge, and on that panel with P8 unlocked. Tier, score, votes and jury outcome therefore agree as scoring writes
    them; no rule of decide() or of tiering is copied here. Every other variant carries usable human rulings, a false
    positive on every third finding and a true positive on the next (a ruling binds to content, whatever the jury
    concluded). Each gets its blocking reasons from assess and the human queue built for it. The report's other
    fields (review status, incomplete reasons, gate, dimensions, overall score) stay those of the seeded review, and the
    queue keys are built without the review identity: both writers copy those as they stand, so the comparison does
    not depend on them."""
    from collections import defaultdict

    from mara.context.repo_map import build_context
    from mara.pipeline import Pipeline
    from mara.report.human_queue_out import build_queue
    from mara.review_status import assess
    from mara.tools.sarif import ToolResult
    from tests.review_facts import FACTS

    finders = {f.id: set(f.finder_families) for f in report.findings}
    skeptic, redteam = {v.finding_id: v for v in report.skeptic}, {n.finding_id: n for n in report.redteam}
    tools = [ToolResult(**t) for t in report.tool_results]
    prefix = build_context(Path(report.target)).repo_prefix
    four, four_cast = _with_a_fourth_judge(cfg, report.votes, finders)
    # P8 unlocked (a passing Alternative Annotator Test): a rejection is then left to the jury, not under review
    unlocked = four.model_copy(update={"gate": four.gate.model_copy(update={"unsupervised_reject_allowed": True})})
    variants = []
    for name, panel, cast in (("mock", cfg, report.votes), ("four judges", four, four_cast),
                              ("four judges, P8 unlocked", unlocked, four_cast)):
        scorer = Pipeline(panel, out_dir=tmp_path)  # its own audit: scoring writes position_flips into it
        by_finding = defaultdict(list)
        for v in cast:
            by_finding[v.finding_id].append(v)
        for k in range(len(_PATTERNS)):
            patterns = {f.id: _PATTERNS[(i + k) % len(_PATTERNS)] for i, f in enumerate(report.findings)}
            votes = [v for f in report.findings for v in _recast(by_finding[f.id], patterns[f.id])]
            consensus = scorer.score(report.findings, finders, skeptic, redteam, votes, tools, tool_path_prefix=prefix)
            if k % 2:
                for i, c in enumerate(consensus):
                    ruling = ("false_positive", "true_positive", None)[i % 3]
                    c.human_decision = {"decision": ruling, **_DECIDED} if ruling else None
            # as Pipeline.run writes them from its assessment; the blocking reasons depend on no fact of the review
            blocking = assess(FACTS, consensus, tools, report.dimensions, scorer.outcome_policy, scorer.gate_policy).blocking_reasons
            for c in consensus:
                c.blocking_reason = blocking.get(c.finding_id)
            v = report.model_copy(update={"votes": votes, "consensus": consensus})
            v.human_queue = build_queue(v.findings, {c.finding_id: c for c in consensus}, skeptic, redteam, votes, panel)
            variants.append(_Variant(v, name, patterns))
    return variants


def test_with_the_human_queue_enabled_code_scanning_sees_what_it_saw_before(mock_report, tmp_path):
    pipe, report = mock_report
    assert pipe.cfg.human_queue.enabled
    variants = _variants(report, pipe.cfg, tmp_path)
    seeded = {c.finding_id: c.model_dump(exclude={"human_decision", "blocking_reason"}) for c in report.consensus}
    as_cast = {c.finding_id: c.model_dump(exclude={"human_decision", "blocking_reason"}) for v in variants if v.panel == "mock"
               for c in v.report.consensus if v.patterns[c.finding_id] == "as_cast"}
    assert as_cast == seeded, "re-scoring every finding's votes as cast gives the seeded review's rows"
    rows = [c for v in variants for c in v.report.consensus]
    assert {c.jury_outcome for c in rows} == {"accepted", "rejected", "dropped", "needs_human"}, "every jury outcome"
    assert any(c.in_rejection_review for c in rows), "a rejection under review"
    assert any(c.jury_outcome == "rejected" and not c.in_rejection_review and not c.resolved_by_human for c in rows), \
        "a rejection left to the jury (P8 unlocked), which code scanning does not see"
    assert {(c.human_decision or {}).get("decision") for c in rows} == {None, "false_positive", "true_positive"}
    for v in variants:
        # the whole document, rules, results (levels, messages, fingerprints, properties, suppressions) and run, is
        # what the old to_sarif wrote, apart from the gate properties added on purpose
        assert _without_gate_properties(to_sarif(v.report)) == _old_to_sarif(v.report), v.panel
    results = [r for v in variants for r in to_sarif(v.report)["runs"][0]["results"]]
    assert any("blockingReason" in r["properties"] for r in results), "the blockingReason that _without_gate_properties strips is there"
    assert any(r.get("suppressions") for r in results), "a human false positive is dismissed"


def test_a_rejection_under_review_is_a_note_even_when_the_human_queue_is_disabled(mock_report, tmp_path):
    """Like a finding needing a human: P8's look at a rejected finding is the finding's state, not the queue's."""
    pipe, report = mock_report
    under_review = 0
    for v in _variants(report, pipe.cfg, tmp_path):
        waiting = {c.finding_id for c in v.report.consensus if c.in_rejection_review}
        results = _results(v.report.model_copy(update={"human_queue": []}))
        assert waiting <= set(results) and {results[fid]["level"] for fid in waiting} <= {"note"}, v.panel
        under_review += len(waiting)
    assert under_review, "the four-judge variants hold rejections under review"


def test_the_run_says_why_the_gate_blocked_and_each_blocking_result_why_it_blocks(mock_report):
    _, report = mock_report
    run = to_sarif(report)["runs"][0]
    assert run["properties"]["gateReasons"] == ["review_incomplete", "blocking_tier_and_severity"]
    assert run["properties"]["gateEnforced"] is False
    results = _results(report)
    assert results["F-0001"]["properties"]["blockingReason"] == "blocking_tier_and_severity"
    assert results["F-0001"]["level"] == "error", "a blocking result keeps the level of its severity"
    assert "blockingReason" not in results["F-0016"]["properties"], "only a blocking finding carries one"
