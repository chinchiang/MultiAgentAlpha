"""The review status, its incomplete reasons and the gate, decided from the facts a review gathered; and the secret
preflight that decides whether source may leave the host (docs/adr/0007-review-status-and-gate.md). Pure functions:
the pipeline runs the tools and cosign and passes in only what they found."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .audit import INCOMPLETE_COUNTERS
from .identity import norm_path
from .schemas import ConsensusResult, DimensionScore
from .scoring.outcome import OutcomePolicy, tier_c_needs_human
from .tools.runner import ToolRun
from .tools.sarif import ToolResult

if TYPE_CHECKING:
    from .config import MaraConfig


@dataclass(frozen=True)
class GatePolicy:
    """What the gate alone reads. The tier C rule's values come from the OutcomePolicy in force, so the jury outcome
    and the gate see one tightening (mara.scoring.outcome)."""

    block_on_tiers: frozenset[str]
    block_on_severity: frozenset[str]
    min_dimension_score: float

    @classmethod
    def from_config(cls, cfg: MaraConfig) -> GatePolicy:
        g = cfg.gate
        return cls(block_on_tiers=frozenset(g.block_on_tiers), block_on_severity=frozenset(g.block_on_severity),
                   min_dimension_score=g.min_dimension_score)


@dataclass(frozen=True)
class SecretPreflight:
    blocked: bool
    exempted: tuple[ToolResult, ...] = ()  # seeded secrets a calibration sample's answer key declares
    unexplained: tuple[ToolResult, ...] = ()  # every other secret found


def secret_preflight(mode: str, secret_runs: list[ToolRun], answer_key: list[dict] | None) -> SecretPreflight:
    """Live source egress is blocked before any provider sees data when the trusted local secret scan (gitleaks) is
    missing, did not run, or found a secret. Calibration only (`answer_key`, mara.pipeline.calibration_answer_key): a
    seeded secret the sample's answer key declares at the same file and line is expected and does not block; anything
    else the scan finds still does."""
    found = [res for run in secret_runs for res in run.results]
    exempted = tuple(res for res in found if answer_key is not None and _declared_secret(res, answer_key))
    unexplained = tuple(res for res in found if res not in exempted)
    blocked = mode == "live" and (not secret_runs or any(not r.ran for r in secret_runs) or bool(unexplained))
    return SecretPreflight(blocked=blocked, exempted=exempted, unexplained=unexplained)


def _declared_secret(res: ToolResult, answer_key: list[dict]) -> bool:
    return any(norm_path(str(lab["file"])) == norm_path(res.file) and int(lab["line"]) == res.line for lab in answer_key)


@dataclass(frozen=True)
class ReviewFacts:
    """What `Pipeline.run()` gathered before deciding: run() runs the tools and cosign, assess() only reads results."""

    context_complete: bool  # every file in scope reached the bundle
    egress_blocked: bool  # secret_preflight blocked source egress
    required_tools_ran: bool  # every tool the reviewed dimensions need ran, and none failed
    ml_bom_signature: bool | None  # cosign verified the ML-BOM signature; None when the config does not require one
    context_view_missing: bool  # a context role is configured and produced no view
    incomplete_counters: tuple[str, ...]  # the audit counters that make the review incomplete (Audit.incomplete_reasons)
    rollout_phase: str  # G-10: not_started, shadow, advisory or blocking
    fail_on_gate: bool  # `mara review --fail-on-gate`: enforce a blocked gate for this review in any phase


@dataclass(frozen=True)
class Assessment:
    review_status: Literal["complete", "incomplete"]
    incomplete_reasons: tuple[str, ...]
    gate_passed: bool
    gate_reasons: tuple[str, ...]
    gate_enforced: bool
    overall_score: float | None  # null when the review is incomplete
    blocking_reasons: dict[str, str]  # finding id -> why that blocking finding blocks
    tier_c_blocked_while_tightened: int


# The incomplete reasons this module writes itself, in the order a review writes them; the audit's INCOMPLETE_COUNTERS
# come after the first three. Together they are INCOMPLETE_REASONS, every incomplete reason, which the score summary's
# allowlist imports (docs/adr/0004-score-summary.md).
OWN_INCOMPLETE_REASONS = ("context_coverage_incomplete", "source_egress_blocked_by_secret_preflight", "required_tool_incomplete",
                          "ml_bom_signature_unverified", "context_view_incomplete", "unresolved_human_review",
                          "unresolved_tool_findings")
INCOMPLETE_REASONS = frozenset(OWN_INCOMPLETE_REASONS) | frozenset(INCOMPLETE_COUNTERS)

# The gate reasons, and GATE_REASONS their fixed order in a report. The two finding codes are also each blocking
# finding's blocking_reason.
REVIEW_INCOMPLETE = "review_incomplete"
BLOCKING_TIER_AND_SEVERITY = "blocking_tier_and_severity"
TIER_C_WHILE_TIGHTENED = "tier_c_while_tightened"
DIMENSION_BELOW_MINIMUM = "dimension_below_minimum"
GATE_REASONS = (REVIEW_INCOMPLETE, BLOCKING_TIER_AND_SEVERITY, TIER_C_WHILE_TIGHTENED, DIMENSION_BELOW_MINIMUM)


def assess(facts: ReviewFacts, consensus: list[ConsensusResult], tool_results: list[ToolResult], dimensions: list[DimensionScore],
           outcome_policy: OutcomePolicy, gate_policy: GatePolicy) -> Assessment:
    if not dimensions:
        # the config requires at least one dimension (MaraConfig.dimensions); a review that scored nothing has no score
        raise ValueError("a review needs at least one dimension to score")
    reasons = _incomplete_reasons(facts, consensus, tool_results)
    blocking = {c.finding_id: why for c in consensus if (why := _blocking_reason(c, outcome_policy, gate_policy))}
    applies = {REVIEW_INCOMPLETE: bool(reasons), **dict.fromkeys(blocking.values(), True),
               DIMENSION_BELOW_MINIMUM: any(d.score < gate_policy.min_dimension_score for d in dimensions)}
    gate_reasons = tuple(code for code in GATE_REASONS if applies.get(code))
    overall = None if reasons else round(sum(d.score for d in dimensions) / len(dimensions), 1)
    return Assessment(review_status="incomplete" if reasons else "complete", incomplete_reasons=reasons,
                      gate_passed=not gate_reasons, gate_reasons=gate_reasons,
                      gate_enforced=bool(gate_reasons) and (facts.rollout_phase == "blocking" or facts.fail_on_gate), overall_score=overall,
                      blocking_reasons=blocking,
                      tier_c_blocked_while_tightened=sum(why == TIER_C_WHILE_TIGHTENED for why in blocking.values()))


def _blocking_reason(c: ConsensusResult, outcome_policy: OutcomePolicy, gate_policy: GatePolicy) -> str | None:
    """Why a finding blocks the gate, or None. Only a finding whose final outcome is accepted blocks (a human ruling
    outranks the jury): at a tier and severity the gate blocks on, or, while the human queue is tightened and no
    longer queues tier C at the severity floor (tighten_exclude_tier_c), such a tier C finding, so it does not pass on
    one family's word plus the jury. Tightening may cut human work; it never lets more through. An unknown severity
    ranks above every band."""
    if c.final_outcome != "accepted":
        return None
    if c.tier.value in gate_policy.block_on_tiers and c.cvss4_severity in gate_policy.block_on_severity:
        return BLOCKING_TIER_AND_SEVERITY
    if outcome_policy.exclude_tier_c and tier_c_needs_human(c.tier, c.cvss4_severity, outcome_policy.tier_c_min_severity):
        return TIER_C_WHILE_TIGHTENED
    return None


def _incomplete_reasons(facts: ReviewFacts, consensus: list[ConsensusResult], tool_results: list[ToolResult]) -> tuple[str, ...]:
    out = []
    if not facts.context_complete:
        out.append("context_coverage_incomplete")
    if facts.egress_blocked:
        out.append("source_egress_blocked_by_secret_preflight")
    if not facts.required_tools_ran:
        out.append("required_tool_incomplete")
    out.extend(facts.incomplete_counters)
    if facts.ml_bom_signature is False:
        out.append("ml_bom_signature_unverified")
    if facts.context_view_missing and not facts.egress_blocked:  # no context call is made when egress is blocked
        out.append("context_view_incomplete")
    if any(c.final_outcome == "needs_human" for c in consensus):
        out.append("unresolved_human_review")
    # Tool evidence remains visible independently of model output. A model's silence or rejection never clears an
    # unsuppressed tool result.
    if any(t.level in {"error", "warning"} for t in tool_results):
        out.append("unresolved_tool_findings")
    return tuple(out)
