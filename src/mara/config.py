"""Configuration model. Family diversity and data-residency rules are enforced here."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, model_validator

from .schemas import DIMENSIONS, ModelFamily


class ModelSpec(BaseModel):
    name: str
    family: ModelFamily
    provider: Literal["anthropic", "openai_compatible", "mock"]
    model: str
    base_url: str | None = None
    api_key_env: str | None = None
    data_residency: Literal["on_prem", "vendor_api_zdr", "vendor_api_30d", "unknown"] = "unknown"
    weight: float = Field(default=1.0, ge=0.0, le=2.0, description="Vote weight; updated by calibration")


class RolesConfig(BaseModel):
    reviewers: list[str] = Field(min_length=1, description="Model names used as dimension reviewers")
    skeptic: str
    redteam: str
    judges: list[str] = Field(min_length=1)


class GateConfig(BaseModel):
    block_on_tiers: list[str] = Field(default_factory=lambda: ["A", "B"])
    block_on_severity: list[str] = Field(default_factory=lambda: ["High", "Critical"])
    min_dimension_score: float = 60.0
    accept_threshold: float = Field(default=0.6, description="Weighted consensus needed to accept a finding")
    human_threshold_alpha: float = Field(default=0.4, ge=0.0, le=1.0, description="Krippendorff alpha below which -> human queue (policy P4: >= 0.3)")
    min_independent_judges: int = Field(default=2, description="If fewer non-finder families can judge, all judges vote")
    self_judge_discount: float = Field(
        default=0.5, ge=0.0, le=1.0, description="Weight multiplier for a judge voting on its own family's finding (policy P4: <= 0.5)"
    )


class PsirtConfig(BaseModel):
    """G-12: hand accepted tier-A Critical findings on a shipped product to the PSIRT so the
    EU CRA Article 14 clocks (24 h early warning, 72 h notification, 14 d final report) start
    from the review, not from someone reading the report."""

    enabled: bool = False
    webhook_url: str = Field(default="", description="HTTPS endpoint of the PSIRT intake (ticketing or SOAR)")
    token_env: str = Field(default="PSIRT_WEBHOOK_TOKEN", description="Environment variable holding the bearer token; never inline")
    product: str = Field(default="", description="Product or component identifier the reviewed code ships in")
    shipped: bool = Field(default=False, description="True when the reviewed target is (part of) a shipped product")
    trigger_tiers: list[str] = Field(default_factory=lambda: ["A"], description="Only these evidence tiers notify (policy P6: subset of A, B)")
    trigger_severities: list[str] = Field(
        default_factory=lambda: ["Critical"], description="Only these CVSS severities notify (policy P6: subset of Critical, High)"
    )
    early_warning_hours: int = Field(default=24, ge=1, le=24)
    notification_hours: int = Field(default=72, ge=1, le=72)
    final_report_days: int = Field(default=14, ge=1, le=14)


class HumanQueueConfig(BaseModel):
    """G-11: the human queue is a ticketed, bounded backlog whose decisions feed calibration.
    When the backlog exceeds backlog_limit the pipeline tightens (higher alpha threshold, tier C
    no longer queued) instead of letting anything through faster."""

    enabled: bool = True
    ticketing: Literal["none", "github_issues"] = "github_issues"
    label: str = Field(default="mara-human-queue", description="Issue label that marks queue tickets")
    backlog_limit: int = Field(default=20, ge=1, description="Open tickets above which the pipeline tightens")
    backlog_file: str = Field(default="calib/decisions/backlog.json", description="Written by scripts/human_queue_issues.py")
    tighten_alpha_step: float = Field(default=0.1, ge=0.0, le=0.5, description="Added to gate.human_threshold_alpha while over the limit")
    tighten_exclude_tier_c: bool = Field(default=True, description="While over the limit, tier C High findings are not queued")
    queue_tier_c_min_severity: Literal["High", "Critical"] = Field(default="High", description="Tier C findings at or above this severity are queued")


class MlBomConfig(BaseModel):
    """G-7: the self-hosted model weights are inference dependencies and must be listed in a
    CycloneDX 1.6 ML-BOM (source, licence, safetensors-only per-file SHA-256, signature). Policy P7
    enforces it once `required` is true; until then `mara check-config` and the review report only
    show each self-hosted model's BOM status."""

    required: bool = Field(default=False, description="Policy P7: every self-hosted model must have a complete ML-BOM component")
    path: str = Field(default="sbom/ml-bom.cdx.json", description="Built by scripts/ml_bom.py from sbom/models.yaml")
    require_signature: bool = Field(default=False, description="Policy P7: the BOM must come with a Sigstore bundle (cosign sign-blob --bundle)")
    bundle: str = Field(default="", description="Path of the Sigstore bundle for the BOM")
    certificate_identity: str = Field(default="", description="Expected signer identity for cosign verify-blob (keyless)")
    certificate_oidc_issuer: str = Field(default="", description="Expected OIDC issuer for cosign verify-blob (keyless)")


class TrainingConfig(BaseModel):
    """G-13 (EU AI Act Article 4): the people operating the pipeline hold a valid AI-literacy
    record in training/records.yaml. Human-queue decisions taken by someone without a valid
    adjudicator record are recorded but not applied to calibration."""

    register_file: str = Field(default="training/records.yaml", description="Written by scripts/training_register.py")
    require_trained_adjudicator: bool = Field(default=True, description="Calibration applies only decisions by trained adjudicators")
    required_roles: list[str] = Field(default_factory=lambda: ["developer", "security", "adjudicator"],
                                      description="Roles that must each have a valid record for governance check G-13")


class MaraConfig(BaseModel):
    models: list[ModelSpec]
    roles: RolesConfig
    dimensions: list[str] = Field(default_factory=lambda: list(DIMENSIONS))
    gate: GateConfig = Field(default_factory=GateConfig)
    allow_source_code_to_non_on_prem: bool = Field(
        default=False,
        description="If false, any model without on_prem/vendor_api_zdr residency is refused source code",
    )
    require_family_diversity: bool = Field(default=True, description="Kept for compatibility; policy P3 now enforces the panel size")
    anthropic_covered_models_authorized: bool = Field(
        default=False, description="Policy P1: allow Fable/Mythos-class models only with a recorded authorization"
    )
    anthropic_covered_models_authorization_ref: str = Field(
        default="", description="Policy P1: reference of the authorization (ticket, contract clause)"
    )
    reduced_panel_reason: str = Field(default="", description="Policy P3: why only two model families are available (e.g. PRC in-country pipeline)")
    psirt: PsirtConfig = Field(default_factory=PsirtConfig, description="G-12: PSIRT / CRA Article 14 hand-off")
    human_queue: HumanQueueConfig = Field(default_factory=HumanQueueConfig, description="G-11: ticketed human queue with decision write-back")
    ml_bom: MlBomConfig = Field(default_factory=MlBomConfig, description="G-7: ML-BOM for the self-hosted model weights")
    training: TrainingConfig = Field(default_factory=TrainingConfig, description="G-13: AI-literacy training register")

    def model_by_name(self, name: str) -> ModelSpec:
        for m in self.models:
            if m.name == name:
                return m
        raise KeyError(name)

    @model_validator(mode="after")
    def _validate(self) -> MaraConfig:
        names = {m.name for m in self.models}
        for role_names in ([self.roles.skeptic, self.roles.redteam], self.roles.reviewers, self.roles.judges):
            for n in role_names:
                if n not in names:
                    raise ValueError(f"role references unknown model {n!r}")
        for d in self.dimensions:
            if d not in DIMENSIONS:
                raise ValueError(f"unknown dimension {d!r}")
        from .policy import evaluate_policies

        failed = [r for r in evaluate_policies(self) if not r.passed]
        if failed:
            raise ValueError("configuration violates policy: " + " | ".join(f"{r.id} {r.name}: {r.reason}" for r in failed))
        return self


def load_config(path: str | Path) -> MaraConfig:
    with open(path, encoding="utf-8") as fh:
        return MaraConfig.model_validate(yaml.safe_load(fh))
