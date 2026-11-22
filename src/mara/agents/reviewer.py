"""L2 dimension reviewer. One call per (dimension, model family)."""

from __future__ import annotations

from .. import exchange
from ..audit import ReplyRecord
from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import DIMENSION_LABELS, Finding, Provenance
from ..scoring import cvss4
from . import base
from .context_agent import ContextView

# The 11 base metrics in specification order, then optional supplemental ones, which change no score (scoring/cvss4.py
# parses and scores the vector; this only shapes what a constrained decoder may emit). Threat and environmental metrics
# are not a reviewer's to set: read() refuses a vector that carries one (base_vector_only).
CVSS4_VECTOR_PATTERN = (r"^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]"
                        r"/SC:[HLN]/SI:[HLN]/SA:[HLN](/(S|AU|R|V|RE|U):[A-Za-z]{1,5})*$")


def base_vector_only(vector: str) -> str:
    """`vector` when it scores on its base metrics alone (CVSS-B); ValueError when it carries a threat or environmental
    metric. Those describe the deployment and the threat landscape, which no reviewer of the source knows, and they
    only ever lower a score: `/MVC:N/MVI:N/MVA:N` takes a 9.3 to 0.0, so one reviewer could keep its own finding from
    blocking the gate."""
    if cvss4.nomenclature(vector) != "CVSS-B":
        raise ValueError("a reviewer's CVSS vector carries threat or environmental metrics")
    return vector

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


def review_dimension(provider: Provider, ctx: RepoContext, dimension: str, canary: base.Canary | None = None,
                     context_view: ContextView | None = None) -> tuple[list[Finding], ReplyRecord]:
    """One reviewer exchange for `dimension` (base.extraction_exchange, a canary of its own unless one is given): the
    findings of its answer, every one with its quotes checked, and the reply record."""
    derived: tuple[exchange.Derived, ...] = ()
    if context_view is not None and dimension in CONTEXT_DIMENSIONS:
        # the C4-lite view (assessment #19): boundaries a reviewer must reason about, derived
        # by a separate context agent and quote-verified. It is derived data: fenced like the repository
        derived = (context_view.derived(),)

    def read(data: dict) -> base.Read:
        if not isinstance(data.get("findings"), list):
            return base.Read(invalid=1, voided=True)
        invalid = unverified = 0
        findings: list[Finding] = []
        for raw in data["findings"]:
            try:
                prov = [Provenance(**p) for p in raw["provenance"]]
                for p in prov:
                    p.verified = base.verify_quote(ctx, p.file, p.line, p.quote)
                if not all(p.verified for p in prov):
                    unverified += 1
                f = Finding(
                    id="pending", dimension=dimension, title=raw["title"], cwe=raw["cwe"],
                    standard_refs=raw.get("standard_refs", []), provenance=prov, reachability=raw["reachability"],
                    reachability_argument=raw["reachability_argument"], exploit_sketch=raw["exploit_sketch"],
                    cvss4_vector=base_vector_only(raw["cvss4_vector"]), model_confidence=raw["model_confidence"],
                    source_family=provider.family, source_model=provider.model,
                )
                findings.append(f)
            except (KeyError, ValueError, TypeError):
                invalid += 1
        return base.Read(findings, invalid, unverified)

    # a finding that cites the planted file reports the injection attempt (resisting it); it is set aside, and
    # only the token anywhere else in the answer counts as an echo
    got, record = base.extraction_exchange(
        provider, ctx, role="reviewer", asked_as=f"reviewer:{dimension}", system_extra=base.load_prompt(f"reviewer_{dimension}"),
        schema=FINDING_SCHEMA, lead=f"Dimension under review: {DIMENSION_LABELS[dimension]}",
        close="Return {\"findings\": [...]} following the schema.", keys=("findings",), unverified_as="unverified_quotes",
        read=read, canary=canary, derived=derived)
    return (got.items if got is not None else []), record
