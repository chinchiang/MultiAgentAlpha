"""Shared agent harness: the provenance check and ballot coverage, the checks of what a role's answer claims.

The exchange itself - the prompt layout and its fences, the call, the reply classification, the canary and item
validation - is mara.exchange.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..context.repo_map import RepoContext, fence_safe, source_lines
from ..exchange import CANARY_PATH, COMMON_SYSTEM, PROVIDER_ERROR_RE, Canary, Outcome, cites_canary, load_prompt, parse_items

__all__ = ["CANARY_PATH", "COMMON_SYSTEM", "PROVIDER_ERROR_RE", "Canary", "ballot_items", "cites_canary", "coverage_gaps", "load_prompt",
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
    lines = source_lines(ctx.content[file])
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


def coverage_gaps(expected: set[str], ids: list[str], invalid: int) -> tuple[str, ...]:
    """One code per finding a ballot reply (skeptic, red team, judge) that held a list failed to cover exactly once:
    a missing, duplicated or unknown finding_id each count as an invalid item, and any of them voids the reply.

    Without these a well-formed but incomplete reply - `{"items": []}`, one verdict dropped - counted nothing, the run
    stayed complete and the unchallenged findings could still reach tier B. A reply without a list (a refusal, a
    provider failure, an unparseable body) is counted once by its kind and is not multiplied by the batch size (an
    outage is never charged to the model item by item). The `invalid` schema-invalid items already count once each
    and their ids are unknown, so they are subtracted from the missing ones."""
    seen = Counter(ids)
    missing = max(0, len(expected - set(seen)) - invalid)
    duplicated = sum(n - 1 for i, n in seen.items() if i in expected)
    unexpected = sum(n for i, n in seen.items() if i not in expected)
    return ("missing_verdict",) * missing + ("duplicate_verdict",) * duplicated + ("unexpected_verdict",) * unexpected


def ballot_items(outcome: Outcome, model_cls, expected: set[str]) -> tuple[list | None, int, tuple[str, ...]]:
    """The one rule every ballot role (skeptic, red team, judge) applies to its reply: (the items, or None when the
    reply is voided; the invalid items it held; the coverage codes, for the log). A reply is voided when it holds no
    list, holds an invalid item, or does not rule on every expected finding exactly once."""
    items, invalid = parse_items(outcome, model_cls)
    gaps = coverage_gaps(expected, [i.finding_id for i in items], invalid) if items is not None else ()
    if items is None or invalid or gaps:
        return None, invalid + len(gaps), gaps
    return items, 0, ()
