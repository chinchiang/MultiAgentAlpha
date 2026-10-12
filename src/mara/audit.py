"""The review's audit counters (the report's bias_audit) and the rule of which of them make a review incomplete.

Every counter is kept twice, in total and per model family (`name` and `name[family]`): `Audit.add` writes both,
so no call site can update one and forget the other. INCOMPLETE_COUNTERS is the one list of counters any non-zero
value of which marks the review incomplete (fail closed); tests/test_audit.py checks that every counter the
pipeline writes under a failure name (refusals, truncations, errors, invalid items, canary echoes) is on it.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

INCOMPLETE_COUNTERS = (
    "reviewer_refusals",
    "reviewer_truncations",
    "reviewer_errors",
    "invalid_findings_dropped",
    "canary_echoes",
    "context_refusals",
    "context_truncations",
    "context_errors",
    "context_invalid_items",
    "context_unverified_items",
    "skeptic_refusals",
    "skeptic_truncations",
    "skeptic_errors",
    "skeptic_invalid_items",
    "skeptic_canary_echoes",
    "redteam_refusals",
    "redteam_truncations",
    "redteam_errors",
    "redteam_invalid_items",
    "redteam_canary_echoes",
    "redteam_exploit_code_stripped",
    "judge_refusals",
    "judge_truncations",
    "judge_errors",
    "judge_invalid_items",
)


class Audit(defaultdict[str, Any]):
    """Counters (default 0) plus a few labels and nested tables."""

    def __init__(self) -> None:
        super().__init__(int)

    def add(self, key: str, family: str, n: int = 1) -> None:
        """Count `n` under `key`, in total and for `family`."""
        self[key] += n
        self[f"{key}[{family}]"] += n

    def incomplete_reasons(self) -> list[str]:
        """The counters of INCOMPLETE_COUNTERS that are non-zero, in that order. Every one of them is then present
        in the audit (0 when nothing was counted), so a report always shows the whole list."""
        return [k for k in INCOMPLETE_COUNTERS if self[k]]
