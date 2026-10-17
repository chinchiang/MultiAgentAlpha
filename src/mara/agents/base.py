"""Shared agent harness: the provenance check and ballot coverage, and the one exchange of each kind of role
(GLOSSARY.md: extraction role, ballot role, voided reply, invalid item; docs/adr/0008-reply-accounting.md). Each plants
the exchange's own canary when its role carries one, voids a reply that echoes the canary or whose reply outcome is not
ok before it reads the answer's shape - an echo counts either way - and writes the reply record; an agent gives only its
own reading of the answer.

The exchange's parts - the prompt layout and its fences, the call, the reply classification, the canary and item
validation - are mara.exchange.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit import ReplyRecord, Role
from ..context.repo_map import RepoContext, fence_safe, source_lines
from ..exchange import (
    CANARY_PATH,
    COMMON_SYSTEM,
    PROVIDER_ERROR_RE,
    Canary,
    Derived,
    Outcome,
    ask,
    cites_canary,
    load_prompt,
    parse_items,
)
from ..providers.base import Provider

__all__ = ["CANARY_PATH", "COMMON_SYSTEM", "PROVIDER_ERROR_RE", "Canary", "Read", "ballot_exchange", "ballot_items",
           "cites_canary", "coverage_gaps", "extraction_exchange", "load_prompt", "verify_quote"]


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


@dataclass(frozen=True)
class Read:
    """What an extraction role read from an answer the exchange did not void: its items, the items it could not read,
    those whose quote could not be verified, and whether the answer is not of the shape the role asks for after all
    (voided, with its invalid items)."""

    items: list[Any] = field(default_factory=list)
    invalid: int = 0
    unverified: int = 0
    voided: bool = False


def extraction_exchange(provider: Provider, ctx: RepoContext, *, role: Role, asked_as: str, system_extra: str, schema: dict,
                        lead: str, close: str, keys: tuple[str, ...], unverified_as: str, read: Callable[[dict], Read],
                        canary: Canary | None = None, derived: tuple[Derived, ...] = ()) -> tuple[Read | None, ReplyRecord]:
    """One reviewer or context exchange: (what `read` made of the answer, or None when the reply is voided; its record).

    A canary of its own is planted unless one is given. The answer's items under `keys` that cite the planted file
    report the injection and are set aside; the token anywhere else is an echo. The reply is voided when its outcome is
    not ok, then when it echoes, then - one invalid item - when the answer is not an object; `read` then reads the
    object and may still void it. `unverified_as` is the role's local name for the items whose quote is unverified."""
    canary = canary or Canary()
    outcome = ask(provider, role=asked_as, system_extra=system_extra, schema=schema, lead=lead, ctx=ctx, canary=canary,
                  derived=derived, close=close)
    data, echoed, reported = canary.screen(outcome, keys)

    def record(invalid: int = 0, unverified: int = 0, voided: bool = False) -> ReplyRecord:
        return ReplyRecord.of(outcome, role, provider.family.value, canary_echoes=int(echoed), canary_reports=reported,
                              invalid_items=invalid, voided=voided, counts={unverified_as: unverified})

    if outcome.data is None or echoed:
        return None, record(voided=True)
    if not isinstance(data, dict):
        return None, record(invalid=1, voided=True)
    got = read(data)
    if got.voided:
        return None, record(invalid=got.invalid, voided=True)
    return got, record(got.invalid, got.unverified)


def ballot_exchange(provider: Provider, *, role: Role, system_extra: str, schema: dict, lead: str, model_cls: type,
                    expected: set[str], findings: int, rule: Callable[[list, set[str]], tuple[list, Mapping[str, int]]],
                    ctx: RepoContext | None = None, paths: list[str] | None = None, derived: tuple[Derived, ...] = (),
                    canary: bool = True) -> tuple[list | None, ReplyRecord]:
    """One skeptic, red-team or judge exchange over `findings` findings: (what `rule` made of the verdicts, or None when
    the reply is voided; its record, which counts the findings it was asked about).

    With `canary`, one is planted for this exchange: a verdict that names the token together with the planted file
    reports it (tainted, and `rule` decides what that verdict may still do); the token anywhere else is an echo. The
    reply is voided when it echoes, then when it holds no list, an invalid item or not exactly one verdict on every
    `expected` finding (ballot_items); `rule(items, tainted)` gives the role's items and its own counts."""
    planted = Canary() if canary else None
    outcome = ask(provider, role=role, system_extra=system_extra, schema=schema, lead=lead, ctx=ctx, canary=planted, paths=paths,
                  derived=derived)
    echoed, tainted = planted.screen_verdicts(outcome) if planted is not None else (False, set())

    def record(*, canary_echoes: int = 0, invalid_items: int = 0, voided: bool = False, log_codes: tuple[str, ...] = (),
               counts: Mapping[str, int] | None = None) -> ReplyRecord:
        return ReplyRecord.of(outcome, role, provider.family.value, canary_echoes=canary_echoes,
                              canary_reports=0 if canary_echoes else len(tainted), invalid_items=invalid_items, voided=voided,
                              log_codes=log_codes, counts={"findings": findings, **(counts or {})})

    if echoed:
        # followed the planted instruction: none of its verdicts counts
        return None, record(canary_echoes=1, voided=True)
    items, invalid, gaps = ballot_items(outcome, model_cls, expected)
    if items is None:
        return None, record(invalid_items=invalid, voided=True, log_codes=gaps)
    out, counts = rule(items, tainted)
    return out, record(counts=counts)
