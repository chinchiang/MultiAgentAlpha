"""L4 juror. Sees only blinded batches; runs forward and reverse passes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .. import exchange
from ..providers.base import Provider
from ..schemas import JudgeVote, PassId
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
    verdict: Literal["true_positive", "false_positive", "needs_human"]
    severity_band: Literal["None", "Low", "Medium", "High", "Critical"]
    reason: str = Field(max_length=400)


def run_judge(provider: Provider, batch: list[dict], pass_id: PassId, self_ids: set[str] | None = None) -> tuple[list[JudgeVote], list[str]]:
    if not batch:
        return [], []
    # the blinded views quote the repository verbatim: derived data, fenced (no canary: a judge sees no bundle)
    outcome = exchange.ask(provider, role="judge", system_extra=base.load_prompt("judge"), schema=JUDGE_SCHEMA,
                           lead=f"pass_id: {pass_id}\nBlinded findings, judge each independently: every finding in the findings "
                                "block below, by finding_id.",
                           derived=(exchange.Derived("findings", batch),))
    items, errors = exchange.parse_items(outcome, _JudgeRaw)
    order = {b["finding_id"]: i for i, b in enumerate(batch)}
    errs = base.ballot_errors(set(order), [i.finding_id for i in items], errors, "incomplete_or_duplicate_judge_response")
    if errs is not None:
        return [], errs
    votes = []
    for i in items:
        # every finding_id of the batch is covered exactly once (checked above), so no lookup guard is needed
        votes.append(JudgeVote(finding_id=i.finding_id, verdict=i.verdict, severity_band=i.severity_band,
                               reason=i.reason, judge_family=provider.family, judge_model=provider.model,
                               presentation_order=order[i.finding_id], pass_id=pass_id,
                               self_family=bool(self_ids and i.finding_id in self_ids)))
    return votes, errors
