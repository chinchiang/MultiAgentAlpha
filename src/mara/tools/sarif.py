"""Minimal SARIF 2.1.0 reader for deterministic-tool output (L0)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

CWE_RE = re.compile(r"CWE-\d{1,5}", re.I)


@dataclass
class ToolResult:
    tool: str
    rule_id: str
    level: str
    message: str
    file: str
    line: int
    cwe: str | None = None          # first CWE the rule names (display / compatibility)
    cwes: list[str] = field(default_factory=list)  # every CWE the rule names; corroboration matches any of them


def read_sarif(path: str | Path, tool_hint: str = "") -> list[ToolResult]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    out: list[ToolResult] = []
    for run in doc.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", tool_hint or "unknown")
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 1)
            rule = rules.get(res.get("ruleId"), {})
            tags = rule.get("properties", {}).get("tags", []) if rule else []
            # semgrep tags read "CWE-89: Improper Neutralization of ..." and a rule may name several CWEs
            # (tainted-sql-string lists CWE-704 and CWE-89) — keep only the identifiers so they compare equal
            # to a finding's cwe; a bare rule id such as CWE-79 (gitleaks-style) also counts
            cwes = [m.group(0).upper() for t in tags if (m := CWE_RE.match(str(t)))]
            if not cwes and (m := CWE_RE.match(res.get("ruleId", ""))):
                cwes = [m.group(0).upper()]
            cwe = cwes[0] if cwes else None
            # semgrep omits result.level and relies on the rule's defaultConfiguration
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            out.append(ToolResult(tool=tool, rule_id=res.get("ruleId", ""), level=level,
                                  message=res.get("message", {}).get("text", ""), file=uri, line=int(line or 1), cwe=cwe, cwes=cwes))
    return out
