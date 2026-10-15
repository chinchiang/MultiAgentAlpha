"""mara.review_status: the review status, the gate and the secret preflight (docs/adr/0007-review-status-and-gate.md)."""

from dataclasses import replace
from pathlib import Path

import pytest

from mara.config import load_config
from mara.review_status import INCOMPLETE_REASONS, GatePolicy, ReviewFacts, assess, secret_preflight
from mara.schemas import ConsensusResult, DimensionScore, EvidenceTier
from mara.scoring.outcome import OutcomePolicy
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult

ROOT = Path(__file__).resolve().parents[1]
OUTCOME = OutcomePolicy(accept_threshold=0.6, alpha_threshold=0.4, exclude_tier_c=False, tier_c_min_severity="High",
                        unsupervised_reject_allowed=False)
GATE = GatePolicy(block_on_tiers=frozenset({"A", "B"}), block_on_severity=frozenset({"High", "Critical"}), min_dimension_score=60.0)
# a review where every fact is in order
FACTS = ReviewFacts(context_complete=True, egress_blocked=False, required_tools_ran=True, ml_bom_signature=None,
                    context_view_missing=False, incomplete_counters=(), rollout_phase="shadow", fail_on_gate=False)


def dim(name: str, score: float) -> DimensionScore:
    return DimensionScore(dimension=name, score=score, accepted_findings=0, rejected_findings=0, human_queue=0, tool_ran=True)


# the jury's score and votes behind each outcome on a three-family panel of weight 1 (accept threshold 0.6)
_JURY = {"accepted": (1.0, 3, 0), "rejected": (0.0, 0, 3), "needs_human": (0.5, 1, 1)}


def row(fid: str, tier: str, severity: str, outcome: str, decision: str | None = None) -> ConsensusResult:
    """A consensus row with its jury outcome written as JuryOutcome.consensus_fields writes it (accepted or needing a
    human, never both; a reason whenever it needs a human), a score and votes that agree with it, and optionally a usable
    human decision on it. Whether scoring can reach that outcome at that tier depends on the panel and the tightening:
    the examples below use only rows that scoring reaches with the policy each one passes to assess (a tier B finding
    is never rejected by the default panel, docs/adr/0005-jury-outcome.md; tier C at the severity floor is accepted only
    while the queue is tightened). assess itself reads only the tier, severity, outcome and decision."""
    human = {"decision": decision, "key": "k", "issue": 1, "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"}
    score, tp, fp = _JURY[outcome]
    return ConsensusResult(finding_id=fid, weighted_score=score, votes_tp=tp, votes_fp=fp, votes_human=0, families_agreeing=[],
                           tool_corroborated=False, skeptic_refuted=False, position_consistent=True, tier=EvidenceTier(tier),
                           cvss4_score=7.5, cvss4_severity=severity, ssvc_decision="Track", accepted=outcome == "accepted",
                           needs_human=outcome == "needs_human",
                           human_reasons=["insufficient_independent_judges"] if outcome == "needs_human" else [],
                           human_decision=human if decision else None)


SECRET = ToolResult("gitleaks", "generic-api-key", "error", "secret", "app.py", 3, "CWE-798")


def test_a_mock_review_never_blocks_egress():
    """Nothing leaves the host in a mock review, so even a missing scan or a found secret does not block."""
    assert not secret_preflight("mock", [], None).blocked
    assert not secret_preflight("mock", [ToolRun("gitleaks", True, [SECRET])], None).blocked


def test_a_live_review_blocks_egress_unless_gitleaks_ran_and_found_nothing():
    assert secret_preflight("live", [], None).blocked, "no secret scan at all"
    assert secret_preflight("live", [ToolRun("gitleaks", False)], None).blocked, "the scan did not run"
    assert secret_preflight("live", [ToolRun("gitleaks", True), ToolRun("gitleaks", False)], None).blocked, "one run failed"
    assert secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], None).blocked, "a secret was found"
    assert not secret_preflight("live", [ToolRun("gitleaks", True)], None).blocked


def test_a_seeded_secret_the_calibration_answer_key_declares_is_exempted_and_nothing_else():
    key = [{"file": "./app.py", "line": 3, "cwe": "CWE-798"}]
    other = ToolResult("gitleaks", "aws-access-token", "error", "secret", "app.py", 1, "CWE-798")
    seeded = secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], key)
    assert not seeded.blocked and seeded.exempted == (SECRET,) and seeded.unexplained == ()
    both = secret_preflight("live", [ToolRun("gitleaks", True, [SECRET, other])], key)
    assert both.blocked and both.exempted == (SECRET,) and both.unexplained == (other,)
    assert secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], None).unexplained == (SECRET,), "no key, no exemption"


def test_the_gate_policy_is_the_gate_config():
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    cfg = cfg.model_copy(update={"gate": cfg.gate.model_copy(update={
        "block_on_tiers": ["A"], "block_on_severity": ["Critical"], "min_dimension_score": 70.0})})
    assert GatePolicy.from_config(cfg) == GatePolicy(block_on_tiers=frozenset({"A"}), block_on_severity=frozenset({"Critical"}),
                                                     min_dimension_score=70.0)


def test_a_review_with_every_fact_in_order_is_complete_and_its_gate_passes():
    a = assess(FACTS, [], [], [dim("xss", 80.0), dim("secrets", 95.0)], OUTCOME, GATE)
    assert (a.review_status, a.incomplete_reasons, a.overall_score) == ("complete", (), 87.5)
    assert (a.gate_passed, a.gate_reasons, a.gate_enforced) == (True, (), False)


def test_every_incomplete_reason_in_the_order_reviews_have_always_written_them():
    wrong = ReviewFacts(context_complete=False, egress_blocked=True, required_tools_ran=False, ml_bom_signature=False,
                        context_view_missing=True, incomplete_counters=("reviewer_refusals", "judge_errors"),
                        rollout_phase="shadow", fail_on_gate=False)
    warning = ToolResult("semgrep", "r", "warning", "m", "app.py", 1)
    a = assess(wrong, [row("F-1", "B", "Medium", "needs_human")], [warning], [dim("xss", 80.0)], OUTCOME, GATE)
    assert a.review_status == "incomplete" and a.overall_score is None
    # the context view is not missing when egress was blocked: no context call was made
    assert a.incomplete_reasons == ("context_coverage_incomplete", "source_egress_blocked_by_secret_preflight",
                                    "required_tool_incomplete", "reviewer_refusals", "judge_errors", "ml_bom_signature_unverified",
                                    "unresolved_human_review", "unresolved_tool_findings")
    assert "context_view_incomplete" in assess(replace(wrong, egress_blocked=False), [], [], [dim("xss", 80.0)], OUTCOME,
                                               GATE).incomplete_reasons
    assert (a.gate_passed, a.gate_reasons) == (False, ("review_incomplete",))


def test_an_accepted_finding_at_a_blocking_tier_and_severity_blocks_on_its_final_outcome():
    # rejected by the jury (tier A: corroborated by a tool, voted down); a human true positive on a waiting finding;
    # a human false positive on an accepted one; and tier C, which is not a blocking tier, accepted by a human
    rows = [row("F-1", "A", "High", "accepted"), row("F-2", "A", "Medium", "accepted"), row("F-3", "A", "Critical", "rejected"),
            row("F-4", "B", "Critical", "needs_human", decision="true_positive"),
            row("F-5", "A", "Critical", "accepted", decision="false_positive"),
            row("F-6", "C", "Critical", "needs_human", decision="true_positive")]
    a = assess(FACTS, rows, [], [dim("xss", 80.0)], OUTCOME, GATE)
    assert a.blocking_reasons == {"F-1": "blocking_tier_and_severity", "F-4": "blocking_tier_and_severity"}
    assert (a.review_status, a.gate_passed, a.gate_reasons, a.overall_score) == ("complete", False, ("blocking_tier_and_severity",), 80.0)


def test_while_the_queue_is_tightened_an_accepted_tier_c_finding_at_the_severity_floor_blocks():
    """Tightening (G-11) stops queueing such findings, so nobody looks at them; they block instead of passing on one
    family's word and the jury. Tightening may cut human work, it never lets more through."""
    rows = [row("F-1", "C", "High", "accepted"), row("F-2", "C", "Medium", "accepted"), row("F-3", "C", "Critical", "rejected")]
    tightened = replace(OUTCOME, exclude_tier_c=True)
    a = assess(FACTS, rows, [], [dim("xss", 80.0)], tightened, GATE)
    assert a.blocking_reasons == {"F-1": "tier_c_while_tightened"} and a.tier_c_blocked_while_tightened == 1
    assert a.gate_reasons == ("tier_c_while_tightened",)
    # untightened, tier C at the floor goes to a human; accepted only by a human's ruling, it does not block
    untightened = [row("F-1", "C", "High", "needs_human", decision="true_positive"), row("F-2", "C", "Medium", "accepted")]
    a = assess(FACTS, untightened, [], [dim("xss", 80.0)], OUTCOME, GATE)
    assert a.gate_passed and a.blocking_reasons == {} and a.tier_c_blocked_while_tightened == 0


def test_gate_reasons_come_in_a_fixed_order_without_repeats():
    rows = [row("F-1", "A", "High", "accepted"), row("F-2", "B", "Critical", "accepted"), row("F-3", "C", "High", "accepted"),
            row("F-4", "B", "Medium", "needs_human")]
    a = assess(FACTS, rows, [], [dim("xss", 40.0), dim("secrets", 30.0)], replace(OUTCOME, exclude_tier_c=True), GATE)
    assert a.gate_reasons == ("review_incomplete", "blocking_tier_and_severity", "tier_c_while_tightened", "dimension_below_minimum")
    low = assess(FACTS, [], [], [dim("xss", 59.9), dim("secrets", 100.0)], OUTCOME, GATE)
    assert (low.review_status, low.gate_passed, low.gate_reasons) == ("complete", False, ("dimension_below_minimum",))
    assert assess(FACTS, [], [], [dim("xss", 60.0)], OUTCOME, GATE).gate_passed, "the minimum itself passes"


def test_a_blocked_gate_is_enforced_only_in_the_blocking_phase_or_with_fail_on_gate():
    blocked = [row("F-1", "A", "High", "accepted")]
    for phase, flag, enforced in (("shadow", False, False), ("shadow", True, True), ("blocking", False, True), ("blocking", True, True)):
        facts = replace(FACTS, rollout_phase=phase, fail_on_gate=flag)
        assert assess(facts, blocked, [], [dim("xss", 80.0)], OUTCOME, GATE).gate_enforced is enforced, (phase, flag)
        assert assess(facts, [], [], [dim("xss", 80.0)], OUTCOME, GATE).gate_enforced is False, "a passed gate holds nothing back"


def test_a_review_without_dimensions_is_an_error_not_a_score_of_zero():
    with pytest.raises(ValueError, match="dimension"):
        assess(FACTS, [], [], [], OUTCOME, GATE)


# ---------------------------------------------------------------- the old rules, kept as the reference


def _old_final_accepted(c: ConsensusResult) -> bool:  # ConsensusResult.final_accepted before ADR 0007
    return c.human_decision["decision"] == "true_positive" if c.human_decision else c.accepted


def _old_final_needs_human(c: ConsensusResult) -> bool:  # ConsensusResult.final_needs_human before ADR 0007
    return False if c.human_decision else c.needs_human


def _old_rules(facts: ReviewFacts, consensus, tool_results, dims, *, exclude_tier_c: bool):
    """Pipeline.run()'s gate section and Pipeline.blocking_reason as they were before mara.review_status, with the
    config of OUTCOME and GATE. Returns (incomplete, overall, gate, blocking, tier_c_blocked_while_tightened)."""
    from mara.scoring.outcome import tier_c_needs_human

    block_on_tiers, block_on_severity, min_dimension_score, tier_c_min = ["A", "B"], ["High", "Critical"], 60.0, "High"

    def blocking_reason(c):
        if not _old_final_accepted(c):
            return None
        if c.tier.value in block_on_tiers and c.cvss4_severity in block_on_severity:
            return "blocking_tier_and_severity"
        if exclude_tier_c and tier_c_needs_human(c.tier, c.cvss4_severity, tier_c_min):
            return "tier_c_while_tightened"
        return None

    overall = round(sum(x.score for x in dims) / len(dims), 1) if dims else 0.0
    incomplete = []
    if not facts.context_complete:
        incomplete.append("context_coverage_incomplete")
    if facts.egress_blocked:
        incomplete.append("source_egress_blocked_by_secret_preflight")
    if not facts.required_tools_ran:
        incomplete.append("required_tool_incomplete")
    incomplete.extend(facts.incomplete_counters)
    if facts.ml_bom_signature is not None:
        if not facts.ml_bom_signature:
            incomplete.append("ml_bom_signature_unverified")
    if facts.context_view_missing and not facts.egress_blocked:
        incomplete.append("context_view_incomplete")
    if any(_old_final_needs_human(c) for c in consensus):
        incomplete.append("unresolved_human_review")
    if any(t.level in {"error", "warning"} for t in tool_results):
        incomplete.append("unresolved_tool_findings")
    gate = not incomplete
    if incomplete:
        overall = None
    blocking, tier_c = {}, 0
    for c in consensus:
        reason = blocking_reason(c)
        if reason:
            gate = False
            blocking[c.finding_id] = reason
            if reason == "tier_c_while_tightened":
                tier_c += 1
    if any(x.score < min_dimension_score for x in dims):
        gate = False
    return incomplete, overall, gate, blocking, tier_c


def _row_states():
    """Every outcome a single consensus row can record (row()), over the tiers, a few severities (one unknown) and the
    human decisions; tier D is dropped or needs a human, never accepted or rejected by the jury. This is more than one
    panel and policy reach (a tier B rejection, an untightened tier C accepted at the floor): the old and the new rules
    must agree on every row a report can hold, reachable under today's config or not."""
    for tier in "ABCD":
        for outcome in (("dropped", "needs_human") if tier == "D" else ("accepted", "rejected", "needs_human")):
            for severity in ("Low", "High", "Critical", "Unknown"):
                for decision in (None, "true_positive", "false_positive"):
                    yield row("F-1", tier, severity, "rejected" if outcome == "dropped" else outcome, decision)


def test_the_new_rules_agree_with_the_old_on_every_combination_of_facts():
    """ADR 0007: the rules moved, they did not change. Left out on purpose: no dimensions (now an error, tested above)
    and gate_enforced (the old rules did not decide it, tested above on phase and flag)."""
    import itertools

    rows = [[], *([r] for r in _row_states()),
            [row("F-1", "A", "High", "accepted"), row("F-2", "C", "Critical", "accepted")],
            [row("F-1", "B", "Low", "needs_human"), row("F-2", "B", "Critical", "rejected", "true_positive")]]
    tools = [[], [ToolResult("semgrep", "r", "note", "m", "a.py", 1)], [ToolResult("semgrep", "r", "error", "m", "a.py", 1)]]
    dims = [[dim("xss", 80.0)], [dim("xss", 80.0), dim("secrets", 50.0)], [dim("xss", 60.0)]]
    checked = 0
    for complete, egress, tools_ran, signature, view_missing, counters in itertools.product(
            (True, False), (False, True), (True, False), (None, True, False), (False, True), ((), ("reviewer_refusals",))):
        facts = replace(FACTS, context_complete=complete, egress_blocked=egress, required_tools_ran=tools_ran,
                        ml_bom_signature=signature, context_view_missing=view_missing, incomplete_counters=counters)
        for consensus, tool_results, d, tightened in itertools.product(rows, tools, dims, (False, True)):
            a = assess(facts, consensus, tool_results, d, replace(OUTCOME, exclude_tier_c=tightened), GATE)
            incomplete, overall, gate, blocking, tier_c = _old_rules(facts, consensus, tool_results, d, exclude_tier_c=tightened)
            assert (list(a.incomplete_reasons), a.overall_score, a.gate_passed, a.blocking_reasons, a.tier_c_blocked_while_tightened) \
                == (incomplete, overall, gate, blocking, tier_c), (facts, consensus, tool_results, d, tightened)
            assert a.review_status == ("incomplete" if incomplete else "complete")
            assert set(a.incomplete_reasons) <= INCOMPLETE_REASONS
            checked += 1
    assert checked > 100_000


# ---------------------------------------------------------------- what the pipeline writes into the report


def test_the_report_records_why_its_gate_blocked_and_which_findings_blocked_it(mock_report):
    _, report = mock_report
    assert report.gate_reasons == ["review_incomplete", "blocking_tier_and_severity"]
    assert {c.finding_id: c.blocking_reason for c in report.consensus if c.blocking_reason} == {
        "F-0001": "blocking_tier_and_severity", "F-0033": "blocking_tier_and_severity", "F-0061": "blocking_tier_and_severity"}
    assert report.gate_enforced is False, "rollout phase not_started, no --fail-on-gate"


def test_fail_on_gate_given_to_the_review_is_recorded_as_an_enforced_gate(root, tmp_path):
    from mara.pipeline import Pipeline

    pipe = Pipeline(load_config(root / "config" / "mara.mock.yaml"), mock_fixtures=str(root / "fixtures" / "mock-responses"),
                    out_dir=tmp_path)
    report = pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=root / "fixtures" / "vuln-sample-sarif", mode="mock",
                      fail_on_gate=True)
    assert not report.gate_passed and report.gate_enforced is True


# ---------------------------------------------------------------- what the readers show


def test_the_markdown_report_shows_the_gate_reasons_each_blocking_finding_and_whether_the_gate_was_enforced(mock_report):
    from mara.report.markdown_out import render_markdown

    _, report = mock_report
    md = render_markdown(report)
    header = md.split("\n## ")[0]
    # codes are escaped like the incomplete reasons beside them (report.escaping.literal: "_" is "&#95;")
    assert "gate BLOCKED** (review&#95;incomplete, blocking&#95;tier&#95;and&#95;severity)" in header
    assert "recorded, not enforced" in header, "phase not_started, gate_enforced false"
    f1 = md.split("### F-0001 · ")[1].split("\n### ")[0]
    assert "- Blocks the gate: blocking&#95;tier&#95;and&#95;severity" in f1
    assert "Blocks the gate" not in md.split("### F-0016 · ")[1].split("\n### ")[0]
    enforced = render_markdown(report.model_copy(update={"gate_enforced": True})).split("\n## ")[0]
    assert "(enforced)" in enforced and "recorded, not enforced" not in enforced
    older = render_markdown(report.model_copy(update={"gate_enforced": None})).split("\n## ")[0]
    assert "enforced" not in older, "a report written before gate_enforced says nothing it does not know"


def test_a_row_waiting_for_a_human_without_a_recorded_reason_says_so(mock_report):
    """decide() always gives a reason; a hand-written or damaged report may not, and the markdown report then says
    that no reason was recorded instead of borrowing an incomplete-review code."""
    from mara.report.markdown_out import render_markdown

    _, report = mock_report
    report = report.model_copy(deep=True)
    row = next(c for c in report.consensus if c.final_outcome == "needs_human")
    row.human_reasons = []
    line = next(x for x in render_markdown(report).splitlines() if x.startswith(f"- {row.finding_id} · "))
    assert line.endswith("awaiting human decision: no reason recorded")
