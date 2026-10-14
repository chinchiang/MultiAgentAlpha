"""The review status, its incomplete reasons and the gate, decided from the facts a review gathered; and the secret
preflight that decides whether source may leave the host (docs/adr/0007-review-status-and-gate.md). Pure functions:
the pipeline runs the tools and cosign and passes in only what they found."""

from __future__ import annotations

from dataclasses import dataclass

from .identity import norm_path
from .tools.runner import ToolRun
from .tools.sarif import ToolResult


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
