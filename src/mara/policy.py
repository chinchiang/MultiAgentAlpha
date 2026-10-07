"""Policy-as-code for the MARA configuration (Appendix E, prompt 6; governance G-2, G-3, G-7, G-12).

Every policy is evaluated independently so `mara check-config` can list all violations at
once; `MaraConfig` then refuses to load when any policy fails. Policies are pure functions of
the parsed configuration and never consult the network.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
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
AAT_MAX_AGE_DAYS = 90
AAT_EVIDENCE = Path("calib/latest.json")  # below the MARA workspace root (mara.workspace.resolve)
# scripts/calibrate.py::alternative_annotator_test tags its result with this; P8 accepts no other.
# The untagged first version tested agreement against a fixed 0.5 baseline (a constant labeller
# could pass) and never looked at the rejections P8 unlocks, so its "passed" is not evidence.
AAT_METHOD = "chance-corrected-agreement+rejection-miss-bound/v2"


@dataclass(frozen=True)
class PolicyResult:
    id: str
    name: str
    passed: bool
    reason: str


# RFC 1918, loopback and IPv6 unique-local only. ipaddress' is_private also admits link-local
# (169.254/16, fe80::/10), the documentation ranges and other special-purpose blocks, which are
# no evidence of an on-prem inference host.
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                         "::1/128", "fc00::/7"))
# Vendor APIs of the PRC-affiliated families (policy P2): never a destination for source code.
PRC_VENDOR_API_HOSTS = ("deepseek.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "bigmodel.cn", "z.ai")
PRC_MODEL_MARKERS = ("deepseek", "qwen", "glm")


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_vendor_api(host: str) -> bool:
    return any(host == h or host.endswith("." + h) for h in PRC_VENDOR_API_HOSTS)


def _host_is_private(url: str, extra_suffixes: tuple[str, ...] = ()) -> tuple[bool, str]:
    """extra_suffixes: the organisation's private DNS zones from the config (private_dns_suffixes)."""
    host = _host(url)
    if not host:
        return False, "base_url has no host (or cannot be parsed)"
    if _is_vendor_api(host):
        return False, f"host {host} is a DeepSeek/Qwen vendor API"
    if host == "localhost" or host.endswith(PRIVATE_SUFFIXES):
        return True, f"host {host} is a private name"
    if extra_suffixes and host.endswith(tuple(extra_suffixes)):
        return True, f"host {host} is in a private DNS zone the config declares ({', '.join(extra_suffixes)})"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, f"host {host} is neither RFC 1918, loopback nor a .internal/.local/.lan name"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped  # ::ffff:10.0.0.1 is judged as 10.0.0.1
    if any(ip in net for net in PRIVATE_NETWORKS if net.version == ip.version):
        return True, f"host {host} is RFC 1918, loopback or IPv6 unique-local"
    return False, f"host {host} is not RFC 1918, loopback or IPv6 unique-local (public, link-local and documentation addresses are refused)"


def p1_covered_models(cfg: MaraConfig) -> PolicyResult:
    # Claude on Bedrock counts too: the authorization concerns the model class, not the transport
    covered = [m for m in cfg.models if m.provider in ("anthropic", "bedrock") and any(k in m.model.lower() for k in COVERED_MODEL_MARKERS)]
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


PRC_AFFILIATED = (ModelFamily.DEEPSEEK, ModelFamily.QWEN, ModelFamily.GLM)


def _prc_affiliated(m) -> bool:
    """By what the model is, not only by what the config declares: the family, a DeepSeek/Qwen
    model id, or a DeepSeek/Qwen vendor API host. `family: other` must not switch P2 off."""
    return (m.family in PRC_AFFILIATED or any(k in m.model.lower() for k in PRC_MODEL_MARKERS)
            or _is_vendor_api(_host(m.base_url or "")))


def p2_deepseek_on_prem(cfg: MaraConfig) -> PolicyResult:
    """PRC-affiliated families (DeepSeek, and Qwen when used as a cold standby) run only as
    self-hosted weights on private endpoints; never the vendor API. A model that is one of them
    by its id or host but declares another family fails: the family drives the panel-diversity
    and judging rules, so a misdeclared family is itself a violation."""
    problems, notes = [], []
    for m in cfg.models:
        if not _prc_affiliated(m):
            continue
        if m.family not in PRC_AFFILIATED and m.provider != "mock":
            problems.append(f"{m.name}: model {m.model!r} at {_host(m.base_url or '') or 'no host'} is DeepSeek/Qwen "
                            f"but declares family {m.family.value!r}")
            continue
        if m.provider == "mock":
            notes.append(f"{m.name}: mock provider, exempt")
            continue
        if m.provider != "openai_compatible":
            problems.append(f"{m.name}: provider must be openai_compatible (self-hosted), got {m.provider}")
            continue
        ok, why = _host_is_private(m.base_url or "", tuple(cfg.private_dns_suffixes))
        (notes if ok else problems).append(f"{m.name}: {why}")
    if not any(_prc_affiliated(m) for m in cfg.models):
        return PolicyResult("P2", "deepseek-on-prem", True, "no DeepSeek/Qwen model configured")
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
           if m.provider != "mock" and m.data_residency not in ("on_prem", "vendor_api_zdr", "vendor_api_retained")]
    retained = []
    for m in cfg.models:
        if m.provider == "mock" or m.data_residency != "vendor_api_retained":
            continue
        # a per-model, recorded exception: the vendor keeps prompts for a while (abuse monitoring) but the
        # organisation approved sending source code to this one model; it never widens P5 for any other
        if not m.retention_approval_ref.strip():
            bad.append(f"{m.name}: data_residency=vendor_api_retained needs retention_approval_ref (ticket or contract clause)")
        else:
            retained.append(f"{m.name} (approval {m.retention_approval_ref.strip()})")
    # on_prem is a claim about where the weights run; it must match the endpoint: a self-hosted
    # OpenAI-compatible server on a private host. A public URL declared on_prem is not on-prem.
    for m in cfg.models:
        if m.provider == "mock" or m.data_residency != "on_prem":
            continue
        if m.provider != "openai_compatible":
            bad.append(f"{m.name}: data_residency=on_prem but provider {m.provider} is a vendor API")
            continue
        ok, why = _host_is_private(m.base_url or "", tuple(cfg.private_dns_suffixes))
        if not ok:
            bad.append(f"{m.name}: data_residency=on_prem but {why}")
    if bad:
        return PolicyResult("P5", "data-residency", False,
                            "source code may only be sent to on_prem or vendor_api_zdr models, or to a vendor_api_retained "
                            "model with a recorded approval: " + "; ".join(bad))
    if retained:
        return PolicyResult("P5", "data-residency", True,
                            "every non-mock model is on_prem or vendor_api_zdr, except approved vendor_api_retained: " + ", ".join(retained))
    return PolicyResult("P5", "data-residency", True, "every non-mock model is on_prem or vendor_api_zdr")


PSIRT_ALLOWED_TIERS = ("A", "B")
PSIRT_ALLOWED_SEVERITIES = ("Critical", "High")


def p6_psirt_scope(cfg: MaraConfig) -> PolicyResult:
    """G-12: the PSIRT hand-off, when enabled, must be narrow (tier A/B, Critical/High) so review
    false positives do not consume PSIRT judgement, must go over HTTPS, and must never carry an
    inline secret."""
    ps = cfg.psirt
    if not ps.enabled:
        return PolicyResult("P6", "psirt-scope", True, "PSIRT hand-off disabled (G-12 not yet wired; see governance check)")
    problems = []
    if not ps.webhook_url.lower().startswith("https://"):
        problems.append(f"webhook_url must be https:// (got {ps.webhook_url!r})")
    if not ps.product.strip():
        problems.append("product identifier is empty")
    if not ps.token_env.strip():
        problems.append("token_env is empty; the bearer token must come from the environment")
    bad_t = [x for x in ps.trigger_tiers if x not in PSIRT_ALLOWED_TIERS]
    bad_s = [x for x in ps.trigger_severities if x not in PSIRT_ALLOWED_SEVERITIES]
    if bad_t or not ps.trigger_tiers:
        problems.append(f"trigger_tiers must be a non-empty subset of {list(PSIRT_ALLOWED_TIERS)} (got {ps.trigger_tiers})")
    if bad_s or not ps.trigger_severities:
        problems.append(f"trigger_severities must be a non-empty subset of {list(PSIRT_ALLOWED_SEVERITIES)} (got {ps.trigger_severities})")
    if problems:
        return PolicyResult("P6", "psirt-scope", False, "; ".join(problems))
    return PolicyResult("P6", "psirt-scope", True,
                        f"PSIRT hand-off for product {ps.product!r}: tiers {ps.trigger_tiers}, severities {ps.trigger_severities}, "
                        f"token from ${ps.token_env}, {ps.early_warning_hours} h early warning")


def p7_ml_bom(cfg: MaraConfig) -> PolicyResult:
    """G-7: every self-hosted (openai_compatible) model must be a complete machine-learning-model
    component in the CycloneDX ML-BOM (safetensors-only per-file SHA-256, licence, source, signature
    method), and the BOM must be signed when require_signature is set. Reads the BOM file, never
    the network. Until ml_bom.required is true the policy only reports."""
    from pathlib import Path

    from .mlbom import STATUS_COMPLETE, status_for_config

    mb = cfg.ml_bom
    statuses = status_for_config(cfg)
    if not statuses:
        return PolicyResult("P7", "ml-bom", True, "no self-hosted model configured; nothing to list in an ML-BOM")
    complete = [n for n, s in statuses.items() if s.status == STATUS_COMPLETE]
    summary = "; ".join(f"{n}({s.model_id}) {s.status}" for n, s in statuses.items())
    if not mb.required:
        return PolicyResult("P7", "ml-bom", True,
                            f"not required yet; {len(complete)}/{len(statuses)} self-hosted models have a complete component in {mb.path}: {summary}")
    problems = [f"{n}({s.model_id}): " + "; ".join(s.problems) for n, s in statuses.items() if s.status != STATUS_COMPLETE]
    if mb.require_signature:
        if not mb.bundle.strip():
            problems.append("require_signature is set but ml_bom.bundle is empty")
        elif not Path(mb.bundle).exists():
            problems.append(f"signature bundle {mb.bundle} not found")
        if not mb.certificate_identity.strip() or not mb.certificate_oidc_issuer.strip():
            problems.append("require_signature needs certificate_identity and certificate_oidc_issuer for keyless verification")
    if problems:
        return PolicyResult("P7", "ml-bom", False, "; ".join(problems))
    sig = f", signature bundle {mb.bundle}" if mb.require_signature else ""
    return PolicyResult("P7", "ml-bom", True, f"{len(complete)}/{len(statuses)} self-hosted models complete in {mb.path}{sig}: {summary}")


def p8_unsupervised_reject(cfg: MaraConfig) -> PolicyResult:
    """Assessment #60: unsupervised rejection needs a passing Alternative Annotator Test.

    `gate.unsupervised_reject_allowed: true` is only valid while `calib/latest.json` (written by
    scripts/calibrate.py) records a passing test on a live calibration within the last 90 days.
    While it is false - the default - every rejected non-D finding goes to the human queue
    instead of being dropped without review.
    """
    if not cfg.gate.unsupervised_reject_allowed:
        return PolicyResult(
            "P8", "unsupervised-reject", True,
            "unsupervised_reject_allowed is false: every rejected non-D finding goes to the human queue",
        )
    try:
        from .workspace import resolve

        latest = json.loads(resolve(AAT_EVIDENCE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return PolicyResult(
            "P8", "unsupervised-reject", False,
            "unsupervised_reject_allowed is true but calib/latest.json is missing or unreadable; "
            "run scripts/calibrate.py --mode live first",
        )
    aat = latest.get("aat") or {}
    if latest.get("mode") != "live":
        return PolicyResult("P8", "unsupervised-reject", False,
                            f"the recorded test ran in mode {latest.get('mode')!r}, not live; a mock run can never justify unsupervised rejection")
    if aat.get("method") != AAT_METHOD:
        return PolicyResult("P8", "unsupervised-reject", False,
                            f"the recorded test uses method {aat.get('method')!r}, not {AAT_METHOD!r}; rerun scripts/calibrate.py --mode live")
    if not aat.get("passed") or not (aat.get("rejection") or {}).get("passed"):
        return PolicyResult("P8", "unsupervised-reject", False, "the recorded Alternative Annotator Test did not pass")
    try:
        when = dt.date.fromisoformat(str(latest.get("date")))
    except ValueError:
        return PolicyResult("P8", "unsupervised-reject", False, "calib/latest.json has no valid date")
    age = (dt.date.today() - when).days
    if age < 0:
        return PolicyResult(
            "P8", "unsupervised-reject", False,
            f"the recorded date {when.isoformat()} is in the future; calib/latest.json must record a real, past run",
        )
    if age > AAT_MAX_AGE_DAYS:
        return PolicyResult("P8", "unsupervised-reject", False,
                            f"the test passed {age} days ago (limit {AAT_MAX_AGE_DAYS}); rerun the calibration")
    return PolicyResult(
        "P8", "unsupervised-reject", True,
        f"Alternative Annotator Test passed {when.isoformat()} ({age} days ago, n={aat.get('n')}, "
        f"agreement={aat.get('agreement')} vs chance {aat.get('chance_agreement')}, p={aat.get('p_value')}; "
        f"{aat['rejection'].get('n')} decided rejections, miss-rate upper bound {aat['rejection'].get('miss_rate_upper')})",
    )


POLICIES = (
    p1_covered_models,
    p2_deepseek_on_prem,
    p3_panel_size,
    p4_gate_bounds,
    p5_data_residency,
    p6_psirt_scope,
    p7_ml_bom,
    p8_unsupervised_reject,
)


def evaluate_policies(cfg: MaraConfig) -> list[PolicyResult]:
    return [p(cfg) for p in POLICIES]
