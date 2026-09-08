"""Pydantic models shared by every layer.

Every language-model output is validated against these models before it is
allowed to influence a score. Free-text fields are bounded so that verbosity
cannot buy credibility at the judge layer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

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


class ModelFamily(StrEnum):
    ANTHROPIC = "anthropic"
    DEEPSEEK = "deepseek"
    NEMOTRON = "nemotron"
    OTHER = "other"
    MOCK = "mock"
    TOOL = "tool"


class EvidenceTier(StrEnum):
    """Credibility of a finding (not to be confused with the report's source grading)."""

    A = "A"  # deterministic tool AND at least one model family agree
    B = "B"  # >=2 model families agree, reachability argued, skeptic did not refute
    C = "C"  # single family, or refuted-then-reinstated by judges without corroboration
    D = "D"  # unverified: provenance failed, judges disagree, or skeptic refuted


class Provenance(BaseModel):
    file: str
    line: int = Field(ge=1)
    quote: str = Field(min_length=3, max_length=400, description="Verbatim excerpt that must exist in the file")
    verified: bool = False


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
    canary_echoed: bool = Field(default=False, description="Set by the harness if the model repeated the injection canary")

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
    pass_id: Literal["forward", "reverse"]
    self_family: bool = Field(default=False, description="Judge family co-produced this finding (fallback only; vote discounted)")


class ConsensusResult(BaseModel):
    finding_id: str
    weighted_score: float = Field(ge=0.0, le=1.0)
    votes_tp: int
    votes_fp: int
    votes_human: int
    families_agreeing: list[ModelFamily]
    tool_corroborated: bool
    skeptic_refuted: bool
    position_consistent: bool
    krippendorff_alpha: float | None
    tier: EvidenceTier
    cvss4_score: float
    cvss4_severity: str
    ssvc_decision: Literal["Track", "Track*", "Attend", "Act"]
    accepted: bool


class DimensionScore(BaseModel):
    dimension: str
    score: float = Field(ge=0, le=100)
    accepted_findings: int
    rejected_findings: int
    human_queue: int
    tool_ran: bool
    notes: str = ""


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
    overall_score: float
    gate_passed: bool
    bias_audit: dict[str, float | int | str]
