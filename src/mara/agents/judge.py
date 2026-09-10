"""L4 juror. Sees only blinded batches; runs forward and reverse passes."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from ..providers.base import Provider
from ..schemas import JudgeVote
from . import base

JUDGE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["items"],
    "properties": {"items": {"type": "array", "items": {
        "type": "object", "additionalProperties": False, "required": ["finding_id", "verdict", "severity_band", "reason"],
        "properties": {"finding_id": {"type": "string"},
                       "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_human"]},
                       "severity_band": {"type": "string", "enum": ["None", "Low", "Medium", "High", "Critical"]},
                       "reason": {"type": "string", "maxLength": 400}}}}},
}


class _JudgeRaw(BaseModel):
    finding_id: str
    verdict: str
    severity_band: str
    reason: str = Field(max_length=400)


def run_judge(provider: Provider, batch: list[dict], pass_id: str, self_ids: set[str] | None = None) -> tuple[list[JudgeVote], list[str]]:
    if not batch:
        return [], []
    user = f"pass_id: {pass_id}\nBlinded findings, judge each independently.\nBEGIN_JSON_ARRAY\n" + json.dumps(batch, ensure_ascii=False)
    comp = base.call(provider, system_extra=base.load_prompt("judge"), user=user, schema=JUDGE_SCHEMA, role="judge")
    items, errors = base.parse_items(comp, _JudgeRaw)
    order = {b["finding_id"]: i for i, b in enumerate(batch)}
    votes = []
    for i in items:
        if i.finding_id not in order:
            continue
        votes.append(JudgeVote(finding_id=i.finding_id, verdict=i.verdict, severity_band=i.severity_band,
                               reason=i.reason, judge_family=provider.family, judge_model=provider.model,
                               presentation_order=order[i.finding_id], pass_id=pass_id,
                               self_family=bool(self_ids and i.finding_id in self_ids)))
    return votes, errors
