"""L2 dimension reviewer. One call per (dimension, model family)."""

from __future__ import annotations

from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import DIMENSION_LABELS, Finding, Provenance
from . import base

FINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["title", "cwe", "standard_refs", "provenance", "reachability",
                             "reachability_argument", "exploit_sketch", "cvss4_vector", "model_confidence"],
                "properties": {
                    "title": {"type": "string", "maxLength": 120},
                    "cwe": {"type": "string", "pattern": "^CWE-[0-9]{1,5}$"},
                    "standard_refs": {"type": "array", "items": {"type": "string"}, "maxItems": 6},
                    "provenance": {
                        "type": "array", "minItems": 1, "maxItems": 3,
                        "items": {"type": "object", "additionalProperties": False,
                                  "required": ["file", "line", "quote"],
                                  "properties": {"file": {"type": "string"}, "line": {"type": "integer", "minimum": 1},
                                                 "quote": {"type": "string", "minLength": 3, "maxLength": 400}}},
                    },
                    "reachability": {"type": "string", "enum": ["reachable", "conditional", "unreachable", "unknown"]},
                    "reachability_argument": {"type": "string", "maxLength": 600},
                    "exploit_sketch": {"type": "string", "maxLength": 600},
                    "cvss4_vector": {"type": "string", "pattern": "^CVSS:4\\.0/"},
                    "model_confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        }
    },
}


def review_dimension(provider: Provider, ctx: RepoContext, dimension: str, canary: base.Canary) -> tuple[list[Finding], dict]:
    system_extra = base.load_prompt(f"reviewer_{dimension}")
    user = (
        f"Dimension under review: {DIMENSION_LABELS[dimension]}\n"
        f"Repository summary: {ctx.summary()}\n\n"
        f"{base.untrusted_block(ctx, canary)}\n\n"
        "Return {\"findings\": [...]} following the schema."
    )
    comp = base.call(provider, system_extra=system_extra, user=user, schema=FINDING_SCHEMA, role=f"reviewer:{dimension}")
    audit = {"refused": comp.refused or comp.data is None, "canary_echoed": bool(comp.raw_text and canary.echoed(comp.raw_text)),
             "input_tokens": comp.input_tokens, "output_tokens": comp.output_tokens, "invalid": 0, "unverified_quotes": 0}
    if comp.refused or comp.data is None:
        return [], audit
    if not isinstance(comp.data, dict) or not isinstance(comp.data.get("findings"), list):
        audit["invalid"] += 1
        return [], audit
    if audit["canary_echoed"]:
        return [], audit
    findings: list[Finding] = []
    for raw in comp.data.get("findings", []):
        try:
            prov = [Provenance(**p) for p in raw["provenance"]]
            for p in prov:
                p.verified = base.verify_quote(ctx, p.file, p.line, p.quote)
            if not all(p.verified for p in prov):
                audit["unverified_quotes"] += 1
            f = Finding(
                id="pending", dimension=dimension, title=raw["title"], cwe=raw["cwe"],
                standard_refs=raw.get("standard_refs", []), provenance=prov, reachability=raw["reachability"],
                reachability_argument=raw["reachability_argument"], exploit_sketch=raw["exploit_sketch"],
                cvss4_vector=raw["cvss4_vector"], model_confidence=raw["model_confidence"],
                source_family=provider.family, source_model=provider.model, canary_echoed=audit["canary_echoed"],
            )
            findings.append(f)
        except (KeyError, ValueError, TypeError):
            audit["invalid"] += 1
    return findings, audit
