"""Shared agent harness: the provenance check and ballot coverage, the checks of what a role's answer claims.

The exchange itself - the prompt layout and its fences, the call, the reply classification, the canary and item
validation - is mara.exchange.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..context.repo_map import RepoContext, fence_safe
from ..exchange import CANARY_PATH, COMMON_SYSTEM, PROVIDER_ERROR_RE, Canary, cites_canary, load_prompt

__all__ = ["CANARY_PATH", "COMMON_SYSTEM", "PROVIDER_ERROR_RE", "Canary", "ballot_errors", "cites_canary", "coverage_errors", "load_prompt",
           "verify_quote"]


MIN_QUOTE_CHARS = 8  # non-whitespace characters a quote needs, unless it is the whole claimed line


def verify_quote(ctx: RepoContext, file: str, line: int, quote: str) -> bool:
    """Quote must appear verbatim in the file, within +-3 lines of the claimed line, and pin something.

    A quote such as "}", "==" or "if " occurs almost anywhere, so it proves nothing about the claim: a
    quote needs a letter or digit and at least MIN_QUOTE_CHARS non-whitespace characters, unless it is
    exactly the claimed line (whitespace-normalised), which keeps short real lines such as "flask" in a
    requirements file or "DEBUG = True" verifiable.
    """
    if not quote.strip() or file not in ctx.content or ".." in Path(file).parts or Path(file).is_absolute():
        return False
    lines = ctx.content[file].splitlines()
    if not 1 <= line <= len(lines):
        return False
    norm = " ".join(quote.split())
    if not any(ch.isalnum() for ch in norm):
        return False
    if len(norm.replace(" ", "")) < MIN_QUOTE_CHARS and norm != " ".join(lines[line - 1].split()):
        return False
    lo, hi = max(0, line - 4), min(len(lines), line + 3)
    window = " ".join("\n".join(lines[lo:hi]).split())
    # a line with a prompt fence tag was shown with that tag defused (repo_map.fence_safe): quoting what the
    # model saw is as verbatim as quoting the file
    return norm in window or norm in fence_safe(window)


def coverage_errors(expected: set[str], ids: list[str], errors: list[str]) -> list[str]:
    """One error per finding a ballot-style reply (skeptic, red team, judge) failed to cover exactly
    once: a missing, duplicated or unknown finding_id each count as an unusable item.

    Without these a well-formed but incomplete reply - `{"items": []}`, one verdict dropped - left
    the error list holding only the summary marker, which the invalid-output audit does not count:
    nothing was counted, the run stayed complete and the unchallenged findings could still reach
    tier B. Only for a reply the model actually gave as a list: a refusal, a provider failure or an
    unparseable body is already one response-level error and is not multiplied by the batch size
    (an outage is never charged to the model item by item). Schema-invalid items already count once
    each and their ids are unknown, so they are subtracted from the missing ones."""
    if any(not e.startswith("invalid_item:") for e in errors):
        return []
    seen = Counter(ids)
    missing = max(0, len(expected - set(seen)) - len(errors))
    duplicated = sum(n - 1 for i, n in seen.items() if i in expected)
    unexpected = sum(n for i, n in seen.items() if i not in expected)
    return ["missing_verdict"] * missing + ["duplicate_verdict"] * duplicated + ["unexpected_verdict"] * unexpected


def ballot_errors(expected: set[str], ids: list[str], errors: list[str], marker: str) -> list[str] | None:
    """The one rule every ballot role (skeptic, red team, judge) applies to a validated reply: None when it rules on
    every expected finding exactly once and has no error; otherwise the errors that void it.

    A bare refusal stays exactly ["refused"] - an abstention, not invalid output - and anything else gets the
    coverage errors plus `marker`, the summary that the whole reply was discarded."""
    counts = Counter(ids)
    if set(counts) == expected and all(n == 1 for n in counts.values()) and not errors:
        return None
    if errors == ["refused"]:
        return errors
    return errors + coverage_errors(expected, ids, errors) + [marker]
