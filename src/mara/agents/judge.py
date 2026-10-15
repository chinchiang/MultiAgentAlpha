"""L4 juror. Sees only blinded batches; runs forward and reverse passes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from .. import exchange
from ..audit import ReplyRecord
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


def run_judge(provider: Provider, batch: list[dict], pass_id: PassId,
              self_ids: set[str] | None = None) -> tuple[list[JudgeVote], ReplyRecord | None]:
    """Returns (votes, the reply record; None when there was nothing to ask). The votes are empty when the reply is
    voided."""
    if not batch:
        return [], None
    # the blinded views quote the repository verbatim: derived data, fenced (no canary: a judge sees no bundle)
    outcome = exchange.ask(provider, role="judge", system_extra=base.load_prompt("judge"), schema=JUDGE_SCHEMA,
                           lead=f"pass_id: {pass_id}\nBlinded findings, judge each independently: every finding in the findings "
                                "block below, by finding_id.",
                           derived=(exchange.Derived("findings", batch),))
    # a finding is judged in two mirrored passes and counted once, with the forward one
    findings = {"findings": len(batch) if pass_id == "forward" else 0}
    items, invalid = exchange.parse_items(outcome, _JudgeRaw)
    order = {b["finding_id"]: i for i, b in enumerate(batch)}
    gaps = base.coverage_gaps(set(order), [i.finding_id for i in items], invalid) if items is not None else ()
    if items is None or invalid or gaps:
        return [], ReplyRecord.of(outcome, "judge", provider.family.value, invalid_items=invalid + len(gaps), voided=True,
                                  counts=findings, details=gaps)
    votes = []
    for i in items:
        # every finding_id of the batch is covered exactly once (checked above), so no lookup guard is needed
        votes.append(JudgeVote(finding_id=i.finding_id, verdict=i.verdict, severity_band=i.severity_band,
                               reason=i.reason, judge_family=provider.family, judge_model=provider.model,
                               presentation_order=order[i.finding_id], pass_id=pass_id,
                               self_family=bool(self_ids and i.finding_id in self_ids)))
    return votes, ReplyRecord.of(outcome, "judge", provider.family.value, counts=findings)
