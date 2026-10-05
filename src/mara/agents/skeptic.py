from __future__ import annotations

import json
import re
from collections import Counter
from typing import Literal

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

_CONTROL_REF = re.compile(r"(?P<file>[A-Za-z0-9_][A-Za-z0-9_./\\-]*):(?P<line>\d+)")


def _norm_ref_path(path: str) -> str:
    """Forward slashes, no leading './' pairs (str.lstrip('./') would also eat the dot of '.github')."""
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


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
        path = _norm_ref_path(m.group("file"))
        if shown is not None and path not in shown:
            continue
        lines = ctx.content.get(path, "").splitlines()
        n = int(m.group("line"))
        if 1 <= n <= len(lines) and lines[n - 1].strip():
            return True
    return False


def _view(f: Finding) -> dict:
    return {"finding_id": f.id, "claim": f.title, "cwe": f.cwe,
            "evidence": [{"file": p.file, "line": p.line, "quote": p.quote} for p in f.provenance],
            "reachability_argument": f.reachability_argument}


def run_skeptic(provider: Provider, ctx: RepoContext, findings: list[Finding]) -> tuple[list[SkepticVerdict], list[str], int]:
    """Returns (verdicts, errors, unverified_controls).

    A 'refuted' verdict whose control citation cannot be located in the bundle is downgraded
    to 'weakened' and counted: an unverifiable negative must not clear a finding.
    """
    if not findings:
        return [], [], 0
    shown = sorted({p.file for f in findings for p in f.provenance})
    # the skeptic reads raw repository files like a reviewer, and its verdict can clear a finding: an
    # injection that drives refutations must be as detectable as one that silences a reviewer
    canary = base.Canary()
    user = (
        f"Repository summary: {ctx.summary()}\n\n{base.untrusted_block(ctx, canary, shown)}\n\n"
        "Findings to refute.\nBEGIN_JSON_ARRAY\n" + json.dumps([_view(f) for f in findings], ensure_ascii=False)
    )
    comp = base.call(provider, system_extra=base.load_prompt("skeptic"), user=user, schema=SKEPTIC_SCHEMA, role="skeptic")
    if comp.raw_text and canary.echoed(comp.raw_text):
        return [], ["canary_echoed"], 0  # followed the planted instruction: none of its verdicts counts
    items, errors = base.parse_items(comp, _SkepticRaw)
    counts = Counter(i.finding_id for i in items)
    if set(counts) != {f.id for f in findings} or any(n != 1 for n in counts.values()) or errors:
        # a bare refusal is an abstention, not invalid output: keep its error list clean
        errs = errors if errors == ["refused"] else (
            errors + base.coverage_errors({f.id for f in findings}, [i.finding_id for i in items], errors) + ["incomplete_or_duplicate_response"])
        return [], errs, 0
    unverified = 0
    out = []
    for i in items:
        data = i.model_dump()
        if data["verdict"] == "refuted" and not _control_location_ok(ctx, data["sanitizer_or_control"], {_norm_ref_path(p) for p in shown}):
            data["verdict"] = "weakened"
            data["reason"] = (data["reason"] + " [control citation not verifiable in bundle]")[:600]
            unverified += 1
        out.append(SkepticVerdict(**data, source_family=provider.family, source_model=provider.model))
    # every finding_id is covered exactly once (checked above), so no filter is needed here
    return out, errors, unverified


from pydantic import BaseModel, Field  # noqa: E402


class _SkepticRaw(BaseModel):
    finding_id: str
    verdict: Literal["refuted", "weakened", "stands"]
    reason: str = Field(max_length=600)
    # required, exactly like SKEPTIC_SCHEMA: a self-hosted endpoint that does not enforce the
    # schema must not get a silent default here — a missing key makes the item invalid instead
    sanitizer_or_control: str = Field(max_length=300)
