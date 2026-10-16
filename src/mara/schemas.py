"""Pydantic models shared by every layer.

Every language-model output is validated against these models before it is
allowed to influence a score. Free-text fields are bounded so that verbosity
cannot buy credibility at the judge layer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, TypeAdapter, ValidationError, field_validator, model_validator

DIMENSIONS: list[str] = [
    "architecture",
    "vulnerabilities",
    "xss",
    "csp",
    "authn_authz",
    "dependencies",
    "github_actions",
    "secrets",
    "input_validation",
    "error_handling",
    "supply_chain",
]

DIMENSION_LABELS: dict[str, str] = {
    "architecture": "Application architecture",
    "vulnerabilities": "Security vulnerabilities (general)",
    "xss": "Cross-site scripting (XSS)",
    "csp": "Content Security Policy (CSP)",
    "authn_authz": "Authentication and authorization",
    "dependencies": "Dependency security",
    "github_actions": "GitHub Actions security",
    "secrets": "Secret exposure",
    "input_validation": "Input validation",
    "error_handling": "Insecure error handling",
    "supply_chain": "Supply-chain security",
}


SSVCDecision = Literal["Track", "Track*", "Attend", "Act"]
PassId = Literal["forward", "reverse"]  # judge pass: findings in presented order, then reversed


class ModelFamily(StrEnum):
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"      # Google Gemini (Gemini API)
    GLM = "glm"            # Zhipu GLM, self-hosted; PRC-affiliated, so policy P2 applies as for DeepSeek
    DEEPSEEK = "deepseek"
    NEMOTRON = "nemotron"
    LLAMA = "llama"        # cold-standby family (G-4): self-hosted Llama
    MISTRAL = "mistral"    # cold-standby family (G-4): self-hosted Mistral
    QWEN = "qwen"          # cold-standby family (G-4); PRC-affiliated, so policy P2 applies as for DeepSeek
    OTHER = "other"
    MOCK = "mock"
    TOOL = "tool"


class EvidenceTier(StrEnum):
    """Credibility of a finding (not to be confused with the report's source grading)."""

    A = "A"  # deterministic tool AND at least one model family agree
    B = "B"  # >=2 model families agree, reachability argued, skeptic did not refute
    C = "C"  # single family, or refuted-then-reinstated by judges without corroboration
    D = "D"  # unverified: provenance failed, judges disagree, or skeptic refuted


SEVERITY_ORDER: list[str] = ["None", "Low", "Medium", "High", "Critical"]
"""CVSS 4.0 severity bands, low to high; the single source for gate and queue comparisons."""


class Provenance(BaseModel):
    file: str
    line: int = Field(ge=1)
    quote: str = Field(min_length=3, max_length=400, description="Verbatim excerpt that must exist in the file")
    verified: bool = False

    @field_validator("file")
    @classmethod
    def _one_path_form(cls, v: str) -> str:
        # `./app.py` and `app.py` are one file (mara.identity): the provenance check, dedupe, the bundle and every
        # key read this field, and `./app.py` used to fail the quote check and stay apart from `app.py` in dedupe
        from .identity import norm_path

        return norm_path(v)


class Finding(BaseModel):
    """A single candidate finding emitted by a reviewer agent or a deterministic tool."""

    id: str = Field(description="Stable id assigned by the pipeline, e.g. F-0007")
    dimension: str
    title: str = Field(max_length=120)
    cwe: str = Field(pattern=r"^CWE-\d{1,5}$")
    standard_refs: list[str] = Field(
        default_factory=list,
        description="Requirement ids validated against pinned ground truth, e.g. ASVS 5.0 V6.2.1, OWASP A01:2025",
    )
    provenance: list[Provenance] = Field(min_length=1)
    reachability: Literal["reachable", "conditional", "unreachable", "unknown"] = "unknown"
    reachability_argument: str = Field(max_length=600)
    exploit_sketch: str = Field(max_length=600, description="How an attacker would exercise it; no working exploit code")
    cvss4_vector: str = Field(pattern=r"^CVSS:4\.0/")
    model_confidence: float = Field(ge=0.0, le=1.0, description="Self-reported; never used directly (see consensus)")
    source_family: ModelFamily
    source_model: str
    finder_families: list[ModelFamily] = Field(default_factory=list, description="Families whose reviewers produced this (deduplicated) finding")

    @field_validator("title")
    @classmethod
    def _single_line(cls, v: str) -> str:
        return " ".join(v.split())

    @field_validator("cvss4_vector")
    @classmethod
    def _cvss(cls, v: str) -> str:
        from .scoring.cvss4 import score
        score(v)
        return v

    @field_validator("dimension")
    @classmethod
    def _dim(cls, v: str) -> str:
        if v not in DIMENSIONS:
            raise ValueError(f"unknown dimension {v}")
        return v


class SkepticVerdict(BaseModel):
    finding_id: str
    verdict: Literal["refuted", "weakened", "stands"]
    reason: str = Field(max_length=600)
    sanitizer_or_control: str = Field(default="", max_length=300)
    source_family: ModelFamily
    source_model: str


class RedTeamNote(BaseModel):
    finding_id: str
    exploitable: Literal["yes", "conditional", "no", "unknown"]
    preconditions: str = Field(max_length=500)
    source_family: ModelFamily
    source_model: str


class JudgeVote(BaseModel):
    finding_id: str
    verdict: Literal["true_positive", "false_positive", "needs_human"]
    severity_band: Literal["None", "Low", "Medium", "High", "Critical"]
    reason: str = Field(max_length=400)
    judge_family: ModelFamily
    judge_model: str
    presentation_order: int = Field(ge=0, description="Position in which the judge saw this finding (bias audit)")
    pass_id: PassId
    self_family: bool = Field(default=False, description="Judge family co-produced this finding (fallback only; vote discounted)")


JuryOutcomeValue = Literal["accepted", "rejected", "dropped", "needs_human"]
# Why a gate blocks, in the fixed order a report lists them, and the two of them a blocking finding carries
# (docs/adr/0007-review-status-and-gate.md; mara.review_status writes them)
GateReason = Literal["review_incomplete", "blocking_tier_and_severity", "tier_c_while_tightened", "dimension_below_minimum"]
BlockingReason = Literal["blocking_tier_and_severity", "tier_c_while_tightened"]
RolloutPhase = Literal["not_started", "shadow", "advisory", "blocking"]  # G-10 (config.RolloutConfig)


class ConsensusResult(BaseModel):
    finding_id: str
    weighted_score: float = Field(ge=0.0, le=1.0)
    votes_tp: int
    votes_fp: int
    votes_human: int
    families_agreeing: list[ModelFamily]
    tool_corroborated: bool
    skeptic_refuted: bool
    skeptic_abstained: bool = False
    position_consistent: bool
    tier: EvidenceTier
    cvss4_score: float | None
    cvss4_severity: str
    ssvc_decision: SSVCDecision
    accepted: bool
    needs_human: bool = False
    human_reasons: list[str] = Field(default_factory=list)
    independent_judges: int = 0
    agreement_proxy: float | None = None
    operational_severity: str | None = None
    # accepted / needs_human / human_reasons above are the jury outcome and stay so; a usable human decision on
    # the same content (docs/adr/0003-human-resolution.md) is recorded here and settles the final outcome
    human_decision: dict | None = Field(default=None, description="The usable decision that settles this finding: "
                                        "decision, key, issue, decided_by, decided_at")
    unsupervised_reject_unverified: bool = Field(default=False, description="A rejected finding under rejection review "
                                                 "(policy P8, docs/adr/0005-jury-outcome.md); false in reports written before it")
    blocking_reason: BlockingReason | None = Field(default=None, description="Why this blocking finding blocks the gate "
                                        "(docs/adr/0007-review-status-and-gate.md); null on every other finding and in reports "
                                        "written before it")

    @property
    def jury_outcome(self) -> JuryOutcomeValue:
        """The jury outcome from the persisted fields, so a report written before the field existed reads the same."""
        if self.needs_human:
            return "needs_human"
        if self.accepted:
            return "accepted"
        return "dropped" if self.tier == EvidenceTier.D else "rejected"

    @property
    def final_outcome(self) -> JuryOutcomeValue:
        """The final outcome: the ruling of a usable decision where there is one (true positive accepted, false positive
        rejected), the jury outcome otherwise."""
        if self.human_decision:
            return "accepted" if self.human_decision["decision"] == "true_positive" else "rejected"
        return self.jury_outcome

    @property
    def resolved_by_human(self) -> bool:
        return self.human_decision is not None

    @property
    def in_rejection_review(self) -> bool:
        """A rejected finding no human has ruled on yet, which policy P8 queues for a human look while the jury outcome
        stays rejected (rejection review, docs/adr/0005-jury-outcome.md)."""
        return not self.resolved_by_human and self.jury_outcome == "rejected" and self.unsupervised_reject_unverified


class DimensionScore(BaseModel):
    dimension: str
    score: float = Field(ge=0, le=100)
    accepted_findings: int
    rejected_findings: int
    human_queue: int
    tool_ran: bool
    notes: str = ""


class HumanQueueItem(BaseModel):
    """One finding that needs a human decision, with everything the human needs to decide it:
    who found it, what the skeptic and red team said, and how every judge voted in both passes.
    The judges saw a blinded view; the human deliberately sees who said what (report, 15.1)."""

    finding_id: str
    key: str = Field(description="v2: hash of target, revision, content, file, line and CWE")
    target_id: str = ""
    revision: str = ""
    context_hash: str = ""
    reasons: list[str] = Field(description="Unresolved reasons shared with the effective gate decision")
    title: str
    dimension: str
    cwe: str
    file: str
    line: int
    quote: str
    tier: str
    cvss4_score: float | None
    cvss4_severity: str
    ssvc_decision: str
    weighted_score: float
    agreement_proxy: float | None = None
    votes_tp: int
    votes_fp: int
    votes_human: int
    finder_families: list[str]
    reachability: str
    reachability_argument: str
    exploit_sketch: str
    skeptic: dict | None = None
    redteam: dict | None = None
    judge_votes: list[dict] = Field(default_factory=list, description="family, pass, verdict, severity_band, reason, self_family")


class QueueTightening(BaseModel):
    """The human queue's tightening a review ran under (GLOSSARY.md: queue tightening): the ticket backlog it was judged
    on (None when none was known), whether the queue was tightened, and the agreement threshold that followed."""

    backlog: int | None
    tightened: bool
    alpha_threshold: float


class MlBomEntry(BaseModel):
    """One self-hosted model as the ML-BOM knows it (G-7): its id, the BOM's status for it and, once complete, the
    component, version and digest of its weights."""

    model_id: str
    status: str
    component: str = ""
    version: str = ""
    sha256: str = ""


class ModelEvalStatus(BaseModel):
    """A model family's latest red-team evaluation (G-8, garak / CyberSecEval): its date, mode and verdict, 'none' until
    one has run."""

    date: str | None = None
    mode: str | None = None
    status: str = "none"


# the report metadata reports written before docs/adr/0009-report-metadata.md kept in bias_audit; the counts among
# them (human_queue_size, psirt_notifications, tool_results_ingested) and tools_ran are read from the report's own lists
LEGACY_METADATA = ("human_queue_size", "human_queue_backlog", "human_queue_tightened", "human_alpha_threshold", "psirt_notifications",
                   "ml_bom", "ml_bom_signature", "rollout_phase", "model_eval", "tool_results_ingested", "tools_ran")
# the shape an old value must have to be read into its field; one of another shape reads as not recorded
_LEGACY_SHAPES: dict[str, TypeAdapter[Any]] = {"rollout_phase": TypeAdapter(RolloutPhase), "ml_bom": TypeAdapter(dict[str, MlBomEntry]),
                  "ml_bom_signature": TypeAdapter(str), "model_eval": TypeAdapter(dict[str, ModelEvalStatus]),
                  "human_queue_tightening": TypeAdapter(QueueTightening)}


def _fits(field: str, value) -> bool:
    try:
        _LEGACY_SHAPES[field].validate_python(value)
    except ValidationError:
        return False
    return True


class ReviewReport(BaseModel):
    target: str
    generated_at: str
    provider_mode: str
    families_used: list[str]
    findings: list[Finding]
    skeptic: list[SkepticVerdict]
    redteam: list[RedTeamNote]
    votes: list[JudgeVote]
    consensus: list[ConsensusResult]
    dimensions: list[DimensionScore]
    overall_score: float | None
    review_status: Literal["complete", "incomplete", "error"] = "incomplete"
    # full or incremental (--base); reports written before the field existed read as unknown (docs/adr/0004-score-summary.md)
    review_scope: Literal["full", "incremental", "unknown"] = "unknown"
    incomplete_reasons: list[str] = Field(default_factory=list)
    coverage: dict = Field(default_factory=dict)
    tool_results: list[dict] = Field(default_factory=list)
    tool_health: list[dict] = Field(default_factory=list)
    provider_manifest: list[dict] = Field(default_factory=list)
    config_hash: str = ""
    target_id: str = ""
    revision: str = ""
    gate_passed: bool
    # why the gate blocked, in fixed order; empty in reports written before it (docs/adr/0007-review-status-and-gate.md)
    gate_reasons: list[GateReason] = Field(default_factory=list)
    # whether a blocked gate was enforced (rollout phase blocking, or --fail-on-gate); false when the gate passed,
    # null in reports written before it: unknown, not "not enforced"
    gate_enforced: bool | None = None
    # the bias audit (GLOSSARY.md): counts and statistics only; the report's metadata are fields of their own
    # (docs/adr/0009-report-metadata.md), each None or empty in a report written before it was recorded at all
    bias_audit: dict[str, float | int | str | dict]
    rollout_phase: RolloutPhase | None = None
    human_queue_tightening: QueueTightening | None = None
    ml_bom: dict[str, MlBomEntry] = Field(default_factory=dict)
    ml_bom_signature: str | None = Field(default=None, description="'verified' or 'failed: <why>' when the config requires a signed ML-BOM")
    model_eval: dict[str, ModelEvalStatus] = Field(default_factory=dict)
    psirt: list[dict] = Field(default_factory=list, description="G-12: CRA Article 14 early-warning payloads for accepted tier-A Critical findings")
    human_queue: list[HumanQueueItem] = Field(default_factory=list, description="G-11: findings that need a human decision, with full context")

    @model_validator(mode="before")
    @classmethod
    def _metadata_out_of_the_bias_audit(cls, data):
        """A report written before docs/adr/0009-report-metadata.md held its metadata in bias_audit: read it into the
        fields and out of the audit, so an old report and a new one read alike. The counts and tools_ran are dropped,
        since the report's own lists give them; a backlog recorded as "unknown" is None, and an old value that does not
        have its field's shape reads as not recorded rather than failing the report."""
        if not isinstance(data, dict) or not isinstance(data.get("bias_audit"), dict):
            return data
        audit = dict(data["bias_audit"])
        legacy = {k: audit.pop(k) for k in LEGACY_METADATA if k in audit}
        if not legacy:
            return data
        data = {**data, "bias_audit": audit}
        for key in ("rollout_phase", "ml_bom", "ml_bom_signature", "model_eval"):
            if key in legacy and key not in data and _fits(key, legacy[key]):
                data[key] = legacy[key]
        if {"human_queue_backlog", "human_queue_tightened", "human_alpha_threshold"} <= legacy.keys() and "human_queue_tightening" not in data:
            backlog = legacy["human_queue_backlog"]
            tightening = {"backlog": None if backlog == "unknown" else backlog, "tightened": bool(legacy["human_queue_tightened"]),
                          "alpha_threshold": legacy["human_alpha_threshold"]}
            if _fits("human_queue_tightening", tightening):
                data["human_queue_tightening"] = tightening
        return data
