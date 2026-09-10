from __future__ import annotations

import json

from pydantic import BaseModel, Field

from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import Finding, RedTeamNote
from . import base

REDTEAM_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["items"],
    "properties": {"items": {"type": "array", "items": {
        "type": "object", "additionalProperties": False, "required": ["finding_id", "exploitable", "preconditions"],
        "properties": {"finding_id": {"type": "string"},
                       "exploitable": {"type": "string", "enum": ["yes", "conditional", "no", "unknown"]},
                       "preconditions": {"type": "string", "maxLength": 500}}}}},
}


class _RedRaw(BaseModel):
    finding_id: str
    exploitable: str
    preconditions: str = Field(default="", max_length=500)


def run_redteam(provider: Provider, ctx: RepoContext, findings: list[Finding]) -> tuple[list[RedTeamNote], list[str]]:
    if not findings:
        return [], []
    view = [{"finding_id": f.id, "claim": f.title, "cwe": f.cwe, "exploit_sketch": f.exploit_sketch,
             "evidence": [{"file": p.file, "line": p.line, "quote": p.quote} for p in f.provenance]} for f in findings]
    user = (
        f"Repository summary: {ctx.summary()}\n\n{base.untrusted_block(ctx, None)}\n\nFindings.\nBEGIN_JSON_ARRAY\n"
        + json.dumps(view, ensure_ascii=False)
    )
    comp = base.call(provider, system_extra=base.load_prompt("redteam"), user=user, schema=REDTEAM_SCHEMA, role="redteam")
    items, errors = base.parse_items(comp, _RedRaw)
    known = {f.id for f in findings}
    out = [RedTeamNote(**i.model_dump(), source_family=provider.family, source_model=provider.model) for i in items]
    return [n for n in out if n.finding_id in known], errors
