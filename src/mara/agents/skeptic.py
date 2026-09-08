from __future__ import annotations

import json

from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import Finding, SkepticVerdict
from . import base

SKEPTIC_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["items"],
    "properties": {"items": {"type": "array", "items": {
        "type": "object", "additionalProperties": False,
        "required": ["finding_id", "verdict", "reason", "sanitizer_or_control"],
        "properties": {"finding_id": {"type": "string"},
                       "verdict": {"type": "string", "enum": ["refuted", "weakened", "stands"]},
                       "reason": {"type": "string", "maxLength": 600},
                       "sanitizer_or_control": {"type": "string", "maxLength": 300}}}}},
}


def _view(f: Finding) -> dict:
    return {"finding_id": f.id, "claim": f.title, "cwe": f.cwe,
            "evidence": [{"file": p.file, "line": p.line, "quote": p.quote} for p in f.provenance],
            "reachability_argument": f.reachability_argument}


def run_skeptic(provider: Provider, ctx: RepoContext, findings: list[Finding]) -> tuple[list[SkepticVerdict], list[str]]:
    if not findings:
        return [], []
    user = (
        f"Repository summary: {ctx.summary()}\n\n{base.untrusted_block(ctx, None)}\n\n"
        "Findings to refute.\nBEGIN_JSON_ARRAY\n" + json.dumps([_view(f) for f in findings], ensure_ascii=False)
    )
    comp = base.call(provider, system_extra=base.load_prompt("skeptic"), user=user, schema=SKEPTIC_SCHEMA, role="skeptic")
    items, errors = base.parse_items(comp, _SkepticRaw)
    out = [SkepticVerdict(**i.model_dump(), source_family=provider.family, source_model=provider.model) for i in items]
    known = {f.id for f in findings}
    return [v for v in out if v.finding_id in known], errors


from pydantic import BaseModel, Field  # noqa: E402


class _SkepticRaw(BaseModel):
    finding_id: str
    verdict: str
    reason: str = Field(max_length=600)
    sanitizer_or_control: str = Field(default="", max_length=300)
