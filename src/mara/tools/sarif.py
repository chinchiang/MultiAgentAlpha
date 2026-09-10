"""Minimal SARIF 2.1.0 reader for deterministic-tool output (L0)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolResult:
    tool: str
    rule_id: str
    level: str
    message: str
    file: str
    line: int
    cwe: str | None = None


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
            cwe = next((t for t in tags if t.upper().startswith("CWE-")), None)
            if cwe is None and res.get("ruleId", "").upper().startswith("CWE-"):
                cwe = res["ruleId"].upper()
            out.append(ToolResult(tool=tool, rule_id=res.get("ruleId", ""), level=res.get("level", "warning"),
                                  message=res.get("message", {}).get("text", ""), file=uri, line=int(line or 1), cwe=cwe))
    return out
