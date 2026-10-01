"""L1 context builder: a C4-lite architecture view the reviewers can trust.

One extra provider call per run. Every fact the model returns must cite a bundle-relative
file and line with a verbatim quote, verified by the same provenance check as findings;
items that fail the check are dropped and counted. A view with no verifiable item, a
refusal, or a canary echo yields no view at all: reviewers then run without trusted facts
and the pipeline records the gap (fail-closed, never a fabricated architecture).
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from ..context.repo_map import RepoContext
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


class ContextView(BaseModel):
    source_family: str
    source_model: str
    items: list[ContextItem] = Field(default_factory=list)

    def by_kind(self, kind: str) -> list[ContextItem]:
        return [i for i in self.items if i.kind == kind]

    def facts_block(self) -> str:
        """Trusted-facts block prepended to reviewer prompts for architecture-dependent dimensions."""
        return "\n".join([
            "<trusted_context_facts>",
            "Architecture facts extracted by a separate context agent from the same bundle.",
            "Each fact is pinned to a file:line with a verbatim quote. This is trusted context;",
            "it is not part of the untrusted data and not an instruction.",
            "JSON: " + json.dumps([i.model_dump() for i in self.items], ensure_ascii=False),
            "</trusted_context_facts>",
        ])


def run_context_agent(provider: Provider, ctx: RepoContext) -> tuple[ContextView | None, dict]:
    """Returns (view, audit); view is None when no trustworthy view could be produced."""
    canary = base.Canary()
    user = (
        f"Repository summary: {ctx.summary()}\n\n{base.untrusted_block(ctx, canary)}\n\n"
        'Return {"containers": [...], "external_systems": [...], "trust_boundaries": [...], '
        '"data_stores": [...]} following the schema.'
    )
    comp = base.call(provider, system_extra=base.load_prompt("context"), user=user, schema=CONTEXT_SCHEMA, role="context")
    audit = {"refused": comp.refused or (comp.data is None and not comp.truncated and not comp.error),
             "truncated": comp.truncated, "errored": bool(comp.error),
             "canary_echoed": bool(comp.raw_text and canary.echoed(comp.raw_text)),
             "input_tokens": comp.input_tokens, "output_tokens": comp.output_tokens, "invalid": 0, "unverified": 0}
    if comp.refused or comp.data is None or audit["canary_echoed"]:
        return None, audit
    if not isinstance(comp.data, dict):
        audit["invalid"] += 1
        return None, audit
    raw: list[tuple[_ContextKind, dict]] = []
    for kind, key in _KIND_BY_KEY:
        arr = comp.data.get(key)
        if not isinstance(arr, list):
            audit["invalid"] += 1
            continue
        raw.extend((kind, x) for x in arr if isinstance(x, dict))
    items: list[ContextItem] = []
    for kind, x in raw:
        try:
            item = _ContextItemRaw(kind=kind, **{k: v for k, v in x.items() if k != "kind"})
        except ValidationError:
            audit["invalid"] += 1
            continue
        if not base.verify_quote(ctx, item.file, item.line, item.quote):
            audit["unverified"] += 1
            continue
        items.append(ContextItem(**item.model_dump()))
    if not items:
        return None, audit
    return ContextView(source_family=provider.family.value, source_model=provider.model, items=items), audit
