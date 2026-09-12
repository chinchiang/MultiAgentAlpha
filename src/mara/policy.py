"""Policy-as-code for the MARA configuration (Appendix E, prompt 6; governance G-2, G-3).

Every policy is evaluated independently so `mara check-config` can list all violations at
once; `MaraConfig` then refuses to load when any policy fails. Policies are pure functions of
the parsed configuration and never consult the network.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from .schemas import ModelFamily

if TYPE_CHECKING:
    from .config import MaraConfig

COVERED_MODEL_MARKERS = ("fable", "mythos")
PRIVATE_SUFFIXES = (".internal", ".local", ".lan")
MAX_SELF_JUDGE_DISCOUNT = 0.5
MIN_HUMAN_THRESHOLD_ALPHA = 0.3
MIN_FAMILIES = 3


@dataclass(frozen=True)
class PolicyResult:
    id: str
    name: str
    passed: bool
    reason: str


def _host_is_private(url: str) -> tuple[bool, str]:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False, "unparseable base_url"
    if not host:
        return False, "base_url has no host"
    if "deepseek.com" in host:
        return False, f"host {host} is the DeepSeek vendor API"
    if host == "localhost" or host.endswith(PRIVATE_SUFFIXES):
        return True, f"host {host} is a private name"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, f"host {host} is neither RFC 1918, loopback nor a .internal/.local/.lan name"
    if ip.is_private or ip.is_loopback:
        return True, f"host {host} is RFC 1918 or loopback"
    return False, f"host {host} is a public address"


def p1_covered_models(cfg: MaraConfig) -> PolicyResult:
    covered = [m for m in cfg.models if m.provider == "anthropic" and any(k in m.model.lower() for k in COVERED_MODEL_MARKERS)]
    if not covered:
        return PolicyResult("P1", "covered-models", True, "no Fable/Mythos-class Anthropic model configured")
    names = ", ".join(f"{m.name}({m.model})" for m in covered)
    if cfg.anthropic_covered_models_authorized and cfg.anthropic_covered_models_authorization_ref.strip():
        return PolicyResult("P1", "covered-models", True, f"{names} allowed under authorization {cfg.anthropic_covered_models_authorization_ref}")
    return PolicyResult(
        "P1", "covered-models", False,
        f"{names} are Covered Models (30-day retention, not ZDR-eligible); set anthropic_covered_models_authorized: true "
        "and anthropic_covered_models_authorization_ref to use them",
    )


def p2_deepseek_on_prem(cfg: MaraConfig) -> PolicyResult:
    problems, notes = [], []
    for m in cfg.models:
        if m.family != ModelFamily.DEEPSEEK:
            continue
        if m.provider == "mock":
            notes.append(f"{m.name}: mock provider, exempt")
            continue
        if m.provider != "openai_compatible":
            problems.append(f"{m.name}: provider must be openai_compatible (self-hosted), got {m.provider}")
            continue
        ok, why = _host_is_private(m.base_url or "")
        (notes if ok else problems).append(f"{m.name}: {why}")
    if not any(m.family == ModelFamily.DEEPSEEK for m in cfg.models):
        return PolicyResult("P2", "deepseek-on-prem", True, "no DeepSeek model configured")
    if problems:
        return PolicyResult("P2", "deepseek-on-prem", False, "; ".join(problems))
    return PolicyResult("P2", "deepseek-on-prem", True, "; ".join(notes))


def p3_panel_size(cfg: MaraConfig) -> PolicyResult:
    rev = {cfg.model_by_name(n).family for n in cfg.roles.reviewers}
    jud = {cfg.model_by_name(n).family for n in cfg.roles.judges}
    n_rev, n_jud = len(rev), len(jud)
    skeptic_fam = cfg.model_by_name(cfg.roles.skeptic).family
    if n_rev == 1 and skeptic_fam in rev:
        return PolicyResult("P3", "panel-size", False, "skeptic shares the only reviewer family (self-preference)")
    if n_rev >= MIN_FAMILIES and n_jud >= MIN_FAMILIES:
        return PolicyResult("P3", "panel-size", True, f"reviewers span {n_rev} families, judges {n_jud}")
    if n_rev >= 2 and n_jud >= 2 and cfg.reduced_panel_reason.strip():
        return PolicyResult("P3", "panel-size", True, f"reduced panel ({n_rev}/{n_jud} families) justified: {cfg.reduced_panel_reason.strip()}")
    return PolicyResult(
        "P3", "panel-size", False,
        f"reviewers span {n_rev} model families and judges {n_jud}; at least {MIN_FAMILIES} required "
        "(exactly 2 is allowed only with a non-empty reduced_panel_reason)",
    )


def p4_gate_bounds(cfg: MaraConfig) -> PolicyResult:
    problems = []
    if cfg.gate.self_judge_discount > MAX_SELF_JUDGE_DISCOUNT:
        problems.append(f"gate.self_judge_discount={cfg.gate.self_judge_discount} exceeds {MAX_SELF_JUDGE_DISCOUNT}")
    if cfg.gate.human_threshold_alpha < MIN_HUMAN_THRESHOLD_ALPHA:
        problems.append(f"gate.human_threshold_alpha={cfg.gate.human_threshold_alpha} below {MIN_HUMAN_THRESHOLD_ALPHA}")
    if problems:
        return PolicyResult("P4", "gate-bounds", False, "; ".join(problems))
    return PolicyResult("P4", "gate-bounds", True,
                        f"self_judge_discount={cfg.gate.self_judge_discount}, human_threshold_alpha={cfg.gate.human_threshold_alpha}")


def p5_data_residency(cfg: MaraConfig) -> PolicyResult:
    if cfg.allow_source_code_to_non_on_prem:
        return PolicyResult("P5", "data-residency", True, "allow_source_code_to_non_on_prem is true (explicit override)")
    bad = [f"{m.name}: data_residency={m.data_residency}" for m in cfg.models
           if m.provider != "mock" and m.data_residency not in ("on_prem", "vendor_api_zdr")]
    if bad:
        return PolicyResult("P5", "data-residency", False,
                            "source code may only be sent to on_prem or vendor_api_zdr models: " + "; ".join(bad))
    return PolicyResult("P5", "data-residency", True, "every non-mock model is on_prem or vendor_api_zdr")


POLICIES = (p1_covered_models, p2_deepseek_on_prem, p3_panel_size, p4_gate_bounds, p5_data_residency)


def evaluate_policies(cfg: MaraConfig) -> list[PolicyResult]:
    return [p(cfg) for p in POLICIES]
