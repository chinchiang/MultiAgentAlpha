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
