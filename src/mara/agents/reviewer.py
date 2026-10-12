"""L2 dimension reviewer. One call per (dimension, model family)."""

from __future__ import annotations

from .. import exchange
from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import DIMENSION_LABELS, Finding, Provenance
from . import base
from .context_agent import ContextView

# The 11 base metrics in specification order, then optional supplemental/environmental ones (scoring/cvss4.py
# parses and scores the vector; this only shapes what a constrained decoder may emit).
CVSS4_VECTOR_PATTERN = (r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]"
                        r"/SC:[HLN]/SI:[HLN]/SA:[HLN](/[A-Z]{1,3}:[A-Za-z]{1,5})*$")

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
                    # anchored at both ends: grammar-constrained decoders (vLLM strict json_schema) full-match a
                    # pattern, so a prefix-only "^CVSS:4\.0/" admitted nothing but "CVSS:4.0/" itself
                    "cvss4_vector": {"type": "string", "pattern": CVSS4_VECTOR_PATTERN},
                    "model_confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        }
    },
}


CONTEXT_DIMENSIONS = ("architecture", "authn_authz")


def review_dimension(provider: Provider, ctx: RepoContext, dimension: str, canary: base.Canary,
                     context_view: ContextView | None = None) -> tuple[list[Finding], dict]:
    system_extra = base.load_prompt(f"reviewer_{dimension}")
    derived: tuple[exchange.Derived, ...] = ()
    if context_view is not None and dimension in CONTEXT_DIMENSIONS:
        # the C4-lite view (assessment #19): boundaries a reviewer must reason about, derived
        # by a separate context agent and quote-verified. It is derived data: fenced like the repository
        derived = (context_view.derived(),)
    outcome = exchange.ask(provider, role=f"reviewer:{dimension}", system_extra=system_extra, schema=FINDING_SCHEMA,
                           lead=f"Dimension under review: {DIMENSION_LABELS[dimension]}", ctx=ctx, canary=canary, derived=derived,
                           close="Return {\"findings\": [...]} following the schema.")
    # a finding that cites the planted file reports the injection attempt (resisting it); it is set aside, and
    # only the token anywhere else in the answer counts as an echo
    data, echoed, reported = canary.screen(outcome, ("findings",))
    # an unparseable reply is invalid output, one per reply (docs/adr/0001-reply-outcome-accounting.md)
    audit = {**exchange.extraction_flags(outcome), "canary_echoed": echoed, "canary_reported": reported,
             "input_tokens": outcome.input_tokens, "output_tokens": outcome.output_tokens, "invalid": int(outcome.unparseable),
             "unverified_quotes": 0}
    if outcome.data is None:
        return [], audit
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        audit["invalid"] += 1
        return [], audit
    if audit["canary_echoed"]:
        return [], audit
    findings: list[Finding] = []
    for raw in data.get("findings", []):
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
                source_family=provider.family, source_model=provider.model,
            )
            findings.append(f)
        except (KeyError, ValueError, TypeError):
            audit["invalid"] += 1
    return findings, audit
