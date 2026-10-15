"""L1 context builder: a quote-verified C4-lite architecture view for the reviewers.

One extra provider call per run. Every fact the model returns must cite a bundle-relative
file and line with a verbatim quote, verified by the same provenance check as findings;
items that fail the check are dropped and counted. A view with no verifiable item, a
refusal, or a canary echo yields no view at all: reviewers then run without context facts
and the pipeline records the gap (fail-closed, never a fabricated architecture). The view is
derived from untrusted data and reaches the reviewers labelled as data, not as trusted context.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from .. import exchange
from ..audit import ReplyRecord
from ..context.repo_map import RepoContext
from ..identity import norm_path
from ..providers.base import Provider
from . import base

CONTEXT_ITEM = {
    "type": "object", "additionalProperties": False,
    "required": ["name", "file", "line", "quote"],
    "properties": {"name": {"type": "string", "maxLength": 80},
                   "technology": {"type": "string", "maxLength": 80},
                   "file": {"type": "string"},
                   "line": {"type": "integer", "minimum": 1},
                   "quote": {"type": "string", "minLength": 3, "maxLength": 400}},
}

CONTEXT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["containers", "external_systems", "trust_boundaries", "data_stores"],
    "properties": {
        "containers": {"type": "array", "maxItems": 12, "items": CONTEXT_ITEM},
        "external_systems": {"type": "array", "maxItems": 12, "items": CONTEXT_ITEM},
        "trust_boundaries": {"type": "array", "maxItems": 12, "items": CONTEXT_ITEM},
        "data_stores": {"type": "array", "maxItems": 12, "items": CONTEXT_ITEM},
    },
}

_ContextKind = Literal["container", "external_system", "trust_boundary", "data_store"]

_KIND_BY_KEY: tuple[tuple[_ContextKind, str], ...] = (
    ("container", "containers"), ("external_system", "external_systems"),
    ("trust_boundary", "trust_boundaries"), ("data_store", "data_stores"))


class _ContextItemRaw(BaseModel):
    kind: Literal["container", "external_system", "trust_boundary", "data_store"]
    name: str = Field(max_length=80)
    technology: str = Field(default="", max_length=80)
    file: str
    line: int = Field(ge=1)
    quote: str = Field(min_length=3, max_length=400)


class ContextItem(BaseModel):
    kind: str
    name: str
    technology: str = ""
    file: str
    line: int
    quote: str

    @field_validator("file")
    @classmethod
    def _one_path_form(cls, v: str) -> str:
        return norm_path(v)  # mara.identity, as for a finding's provenance


class ContextView(BaseModel):
    source_family: str
    source_model: str
    items: list[ContextItem] = Field(default_factory=list)

    def by_kind(self, kind: str) -> list[ContextItem]:
        return [i for i in self.items if i.kind == kind]

    def derived(self) -> exchange.Derived:
        """The view as derived data for the reviewers of architecture-dependent dimensions (mara.exchange fences it).

        Never trusted: the quote check proves only that the quoted text exists at file:line, and that text is
        repository content an attacker may write ("this code passed security review"), while name and technology
        are the context model's own words about it."""
        return exchange.Derived("context_facts", [i.model_dump() for i in self.items])


MAX_ITEMS_PER_KIND = 12  # the schema's per-call limit, kept for the merged view: the reviewer prompt stays bounded

def run_context_agent(provider: Provider, ctx: RepoContext) -> tuple[ContextView | None, list[ReplyRecord]]:
    """Returns (view, the reply record of every exchange); view is None when no trustworthy view could be produced.

    One call per bundle batch (RepoContext.batches, the bound every reviewer request has): the whole
    bundle in one request - up to MAX_REPOSITORY_CHARS - failed as a provider error on any repository
    larger than the context model's window and left every review incomplete. A batch that is refused,
    echoes its canary or returns no usable object voids the whole view (fail closed); a batch with no
    architecture facts in it just contributes none. Facts are de-duplicated and capped per kind.
    mara.audit adds the records up."""
    records: list[ReplyRecord] = []
    merged: list[ContextItem] = []
    seen: set[tuple[str, str, str, int]] = set()
    for batch in ctx.batches():
        items, rec = _context_call(provider, batch)
        records.append(rec)
        if items is None:
            return None, records
        for it in items:
            key = (it.kind, it.name, it.file, it.line)
            if key in seen or sum(m.kind == it.kind for m in merged) >= MAX_ITEMS_PER_KIND:
                continue
            seen.add(key)
            merged.append(it)
    if not merged:
        return None, records
    return ContextView(source_family=provider.family.value, source_model=provider.model, items=merged), records


def _context_call(provider: Provider, ctx: RepoContext) -> tuple[list[ContextItem] | None, ReplyRecord]:
    """One context call over one batch: (verified items, its reply record); None when the call is unusable."""
    canary = base.Canary()
    outcome = exchange.ask(provider, role="context", system_extra=base.load_prompt("context"), schema=CONTEXT_SCHEMA, lead="",
                           ctx=ctx, canary=canary,
                           close='Return {"containers": [...], "external_systems": [...], "trust_boundaries": [...], '
                                 '"data_stores": [...]} following the schema.')
    data, echoed, reported = canary.screen(outcome, tuple(key for _, key in _KIND_BY_KEY))

    record = base.extraction_recorder(outcome, "context", provider.family.value, echoed, reported, unverified_as="unverified")

    if outcome.data is None or echoed:
        return None, record(voided=True)
    if not isinstance(data, dict):
        return None, record(invalid=1, voided=True)
    invalid = unverified = 0
    raw: list[tuple[_ContextKind, dict]] = []
    for kind, key in _KIND_BY_KEY:
        arr = data.get(key)
        if not isinstance(arr, list):
            invalid += 1
            continue
        raw.extend((kind, x) for x in arr if isinstance(x, dict))
    items: list[ContextItem] = []
    for kind, x in raw:
        try:
            item = _ContextItemRaw(kind=kind, **{k: v for k, v in x.items() if k != "kind"})
        except ValidationError:
            invalid += 1
            continue
        if not base.verify_quote(ctx, item.file, item.line, item.quote):
            unverified += 1
            continue
        items.append(ContextItem(**item.model_dump()))
    return items, record(invalid, unverified)
