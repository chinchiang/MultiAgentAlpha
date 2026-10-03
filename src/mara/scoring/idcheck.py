"""Deterministic post-processor: strips standard references that do not exist in pinned ground truth."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..groundtruth import cwe_known, validate_ref
from ..schemas import Finding


@dataclass(frozen=True)
class RefCheck:
    finding: Finding
    stripped: list[str] = field(default_factory=list)  # refs removed because they are not in the pinned lists
    unknown_cwe: bool = False  # the finding's CWE is not in the pinned subset (a separate signal, not a stripped ref)


def check_finding_refs(f: Finding) -> RefCheck:
    """Return a copy of the finding with invalid refs removed, what was stripped, and whether the CWE is unknown."""
    kept: list[str] = []
    stripped: list[str] = []
    for ref in f.standard_refs:
        ok, _why = validate_ref(ref)
        if ok:
            kept.append(ref)
        else:
            stripped.append(ref)
    return RefCheck(f.model_copy(update={"standard_refs": kept}), stripped, not cwe_known(f.cwe))
