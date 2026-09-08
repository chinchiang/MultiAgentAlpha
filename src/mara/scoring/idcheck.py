"""Deterministic post-processor: strips standard references that do not exist in pinned ground truth."""

from __future__ import annotations

from ..groundtruth import cwe_known, validate_ref
from ..schemas import Finding


def check_finding_refs(f: Finding) -> tuple[Finding, list[str]]:
    """Return a copy of the finding with invalid refs removed and a list of rejection reasons."""
    kept: list[str] = []
    reasons: list[str] = []
    for ref in f.standard_refs:
        ok, why = validate_ref(ref)
        if ok:
            kept.append(ref)
        else:
            reasons.append(f"{ref}: {why}")
    if not cwe_known(f.cwe):
        reasons.append(f"{f.cwe}: not in pinned CWE subset")
    return f.model_copy(update={"standard_refs": kept}), reasons
