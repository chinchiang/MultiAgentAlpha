from __future__ import annotations

import json
import re
from collections import Counter
from typing import Literal

from pydantic import BaseModel, Field

from ..context.repo_map import RepoContext
from ..providers.base import Provider
from ..schemas import Finding, RedTeamNote
from . import base

REDTEAM_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["items"],
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["finding_id", "exploitable", "preconditions"],
                "properties": {
                    "finding_id": {"type": "string"},
                    "exploitable": {"type": "string", "enum": ["yes", "conditional", "no", "unknown"]},
                    "preconditions": {"type": "string", "maxLength": 500},
                },
            },
        }
    },
}


class _RedRaw(BaseModel):
    finding_id: str
    exploitable: Literal["yes", "conditional", "no", "unknown"]
    # required, exactly like REDTEAM_SCHEMA (see _SkepticRaw for why there is no default)
    preconditions: str = Field(max_length=500)


# Exploit-code stripping (assessment L3 #35, defence in depth behind the prompt's "do not write
# exploit code"). The patterns are deliberately high-precision: a false positive strips a legitimate
# precondition line from the report AND marks the whole run incomplete, so plain prose about
# accounts, sessions or config flags must never match. Line-level patterns only match lines that
# START as a command would; payload patterns match anywhere but are things prose does not contain.
EXPLOIT_STRIP_PLACEHOLDER = "[exploit code removed by the review harness]"
_FENCE_RE = re.compile(r"^\s*(```|~~~)\s*$")
_SHELL_PROMPT_RE = re.compile(r"^\s*\$\s+\S")
_INTERPRETER_RE = re.compile(
    r"^\s*(?:python3?|perl|ruby|php|node|powershell|pwsh|bash|zsh|sh)\s+-(?:c|e|r|x|Command|EncodedCommand)\b", re.IGNORECASE)
_TOOL_RE = re.compile(r"^\s*(?:curl|wget|ncat?|sqlmap|nmap|hydra|msfvenom|certutil)\s+\S", re.IGNORECASE)
_PAYLOAD_RE = re.compile(
    r"(?:"
    r"alert\(|eval\(|exec\(|os\.system\(|subprocess\.(?:run|call|Popen|check_output)\b|child_process"
    r"|;\s*drop\s+table\b|union\s+(?:all\s+)?select\b[^;\n]*\bfrom\b|javascript:|onerror\s*=|document\.cookie"
    r"|\.\./\.\./|/etc/(?:passwd|shadow)\b|\$\((?:cat|curl|wget|id|whoami)\b"
    r")",
    re.IGNORECASE,
)
_BACKTICK_CMD_RE = re.compile(
    r"`(?:curl|wget|python3?|perl|ruby|ncat?|nc|sqlmap|nmap|hydra|sudo|rm|chmod|cat|echo|sh|bash|powershell)\s[^`\n]+`",
    re.IGNORECASE,
)


def strip_exploit_code(text: str) -> tuple[str, bool]:
    """Remove executable material from a free-text preconditions field.

    Fenced blocks, shell one-liners and payload strings are dropped line by line; surviving prose is
    kept verbatim. Returns (clean_text, stripped) — stripped is True as soon as anything was
    removed, even if prose remains, so one stripped item counts once.
    """
    kept: list[str] = []
    stripped = False
    in_fence = False
    for line in text.splitlines():
        if _FENCE_RE.match(line):
            in_fence = not in_fence
            stripped = True
            continue
        if in_fence or _SHELL_PROMPT_RE.match(line) or _INTERPRETER_RE.match(line) or _TOOL_RE.match(line):
            stripped = True
            continue
        if _PAYLOAD_RE.search(line) or _BACKTICK_CMD_RE.search(line):
            stripped = True
            continue
        kept.append(line)
    clean = "\n".join(kept).strip()
    if stripped and not clean:
        clean = EXPLOIT_STRIP_PLACEHOLDER
    return clean, stripped


def run_redteam(provider: Provider, ctx: RepoContext, findings: list[Finding]) -> tuple[list[RedTeamNote], list[str], int]:
    if not findings:
        return [], [], 0
    view = [
        {
            "finding_id": f.id,
            "claim": f.title,
            "cwe": f.cwe,
            "exploit_sketch": f.exploit_sketch,
            "evidence": [{"file": p.file, "line": p.line, "quote": p.quote} for p in f.provenance],
        }
        for f in findings
    ]
    canary = base.Canary()  # raw repository files again: an injection steering exploitability must show
    user = (
        f"Repository summary: {ctx.summary()}\n\n"
        f"{base.untrusted_block(ctx, canary, sorted({p.file for f in findings for p in f.provenance}))}\n\nFindings.\nBEGIN_JSON_ARRAY\n"
        + json.dumps(view, ensure_ascii=False)
    )
    comp = base.call(provider, system_extra=base.load_prompt("redteam"), user=user, schema=REDTEAM_SCHEMA, role="redteam")
    echoed, _reported = canary.screen_verdicts(comp)  # same rule as the skeptic's (base.Canary.screen_verdicts)
    if echoed:
        return [], ["canary_echoed"], 0  # followed the planted instruction: none of its notes counts
    items, errors = base.parse_items(comp, _RedRaw)
    counts = Counter(i.finding_id for i in items)
    if set(counts) != {f.id for f in findings} or any(n != 1 for n in counts.values()) or errors:
        # a bare refusal is an abstention, not invalid output: keep its error list clean
        errs = errors if errors == ["refused"] else (
            errors + base.coverage_errors({f.id for f in findings}, [i.finding_id for i in items], errors) + ["incomplete_or_duplicate_response"])
        return [], errs, 0
    stripped = 0
    out = []
    for i in items:
        clean, had_code = strip_exploit_code(i.preconditions)
        stripped += int(had_code)
        out.append(RedTeamNote(finding_id=i.finding_id, exploitable=i.exploitable, preconditions=clean,
                               source_family=provider.family, source_model=provider.model))
    # every finding_id is covered exactly once (checked above), so no filter is needed here
    return out, errors, stripped
