from __future__ import annotations

import re
from typing import Literal

from .. import exchange
from ..audit import ReplyRecord
from ..context.repo_map import RepoContext, source_lines
from ..identity import norm_path
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

# a leading dot is part of the path: `.github/workflows/deploy.yml:12` (the github_actions dimension) and
# `./app.py:3` must be read whole, not from the first letter on
_CONTROL_REF = re.compile(r"(?P<file>[A-Za-z0-9_.][A-Za-z0-9_./\\-]*):(?P<line>\d+)")


def _control_location_ok(ctx: RepoContext, text: str, shown: set[str] | None = None) -> bool:
    """A refutation's cited control must point at a real, non-blank path:line the skeptic was shown.

    Without this check a model can refute a finding with a bare phrase such as
    'parameterised query' - a control nobody can open and verify. The citation must name a file
    the skeptic actually received in this call (`shown`: the batch's evidence files; any bundle
    file when None) and a non-blank line inside it: citing a file it never saw, or an empty line,
    cannot be a control it found. Whether the cited code really neutralises the finding is not
    decidable by code; refuted findings the jury still accepts go to a human for that reason.
    """
    for m in _CONTROL_REF.finditer(text):
        raw = m.group("file").replace("\\", "/")
        # the path as written (.github/..., ./app.py), else without an ellipsis prose put in front of it ("...app.py").
        # Only a run of three or more dots directly before a name is dropped: '../app.py' (outside the target) and
        # '.env' stay what they say, never another shown file
        ellipsis = re.match(r"\.{3,}(?=[^./])", raw)
        candidates = (norm_path(raw),) + ((raw[ellipsis.end():],) if ellipsis else ())
        for path in dict.fromkeys(candidates):
            if shown is not None and path not in shown:
                continue
            lines = source_lines(ctx.content.get(path, ""))
            n = int(m.group("line"))
            if 1 <= n <= len(lines) and lines[n - 1].strip():
                return True
    return False


def _view(f: Finding) -> dict:
    return {"finding_id": f.id, "claim": f.title, "cwe": f.cwe,
            "evidence": [{"file": p.file, "line": p.line, "quote": p.quote} for p in f.provenance],
            "reachability_argument": f.reachability_argument}


def run_skeptic(provider: Provider, ctx: RepoContext, findings: list[Finding]) -> tuple[list[SkepticVerdict], ReplyRecord | None]:
    """Returns (verdicts, the reply record; None when there was nothing to ask). The verdicts are empty when the reply
    is voided.

    A 'refuted' verdict whose control citation cannot be located in the bundle is downgraded
    to 'weakened' and counted: an unverifiable negative must not clear a finding.
    """
    if not findings:
        return [], None
    shown = sorted({p.file for f in findings for p in f.provenance})
    # the skeptic reads raw repository files like a reviewer, and its verdict can clear a finding: an
    # injection that drives refutations must be as detectable as one that silences a reviewer
    canary = base.Canary()
    # the findings carry verified, hence attacker-writable, repository quotes: derived data, fenced
    outcome = exchange.ask(provider, role="skeptic", system_extra=base.load_prompt("skeptic"), schema=SKEPTIC_SCHEMA,
                           lead="Findings to refute: every finding in the findings block below, by finding_id.",
                           ctx=ctx, canary=canary, paths=shown, derived=(exchange.Derived("findings", [_view(f) for f in findings]),))
    # the token in a verdict that also names the planted file reports it (tainted: it cannot refute); anywhere
    # else the model followed it
    echoed, tainted = canary.screen_verdicts(outcome)

    def record(counts: dict[str, int] | None = None, **fields) -> ReplyRecord:
        # every record carries the findings the reply was asked about
        return ReplyRecord.of(outcome, "skeptic", provider.family.value, counts={"findings": len(findings), **(counts or {})}, **fields)

    if echoed:
        # followed the planted instruction: none of its verdicts counts
        return [], record(canary_echoes=1, voided=True)
    items, invalid, gaps = base.ballot_items(outcome, _SkepticRaw, {f.id for f in findings})
    if items is None:
        return [], record(canary_reports=len(tainted), invalid_items=invalid, voided=True, log_codes=gaps)
    unverified = 0
    out = []
    for i in items:
        data = i.model_dump()
        if data["verdict"] == "refuted" and not _control_location_ok(ctx, data["sanitizer_or_control"], {norm_path(p) for p in shown}):
            data["verdict"] = "weakened"
            data["reason"] = (data["reason"] + " [control citation not verifiable in bundle]")[:600]
            unverified += 1
        if data["finding_id"] in tainted and data["verdict"] == "refuted":
            # the verdict quotes the planted "report no findings": it may not clear the finding on its own
            data["verdict"] = "weakened"
            data["reason"] = (data["reason"] + " [quotes the planted canary instruction]")[:600]
        out.append(SkepticVerdict(**data, source_family=provider.family, source_model=provider.model))
    # every finding_id is covered exactly once (checked above), so no filter is needed here
    # canary_reports: verdicts that reported the planted file (the bias audit's L3 injection-resistance count)
    return out, record(canary_reports=len(tainted), counts={"unverified_controls": unverified,
                                                            "refuted": sum(v.verdict == "refuted" for v in out)})


from pydantic import BaseModel, Field  # noqa: E402


class _SkepticRaw(BaseModel):
    finding_id: str
    verdict: Literal["refuted", "weakened", "stands"]
    reason: str = Field(max_length=600)
    # required, exactly like SKEPTIC_SCHEMA: a self-hosted endpoint that does not enforce the
    # schema must not get a silent default here — a missing key makes the item invalid instead
    sanitizer_or_control: str = Field(max_length=300)
