"""L0 deterministic tools. Each wrapper runs the binary if present, emits SARIF, and
returns [] with a recorded 'not run' otherwise. Tool output is ground truth: a model
finding that coincides with a tool result is corroborated (tier A); a tool result no
model reproduced is still kept, attributed to the TOOL family.

Tools are never executed against code they could run: they parse, they do not build.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .sarif import ToolResult, read_sarif

TOOL_DIMENSIONS = {
    "semgrep": ["vulnerabilities", "xss", "input_validation", "error_handling", "authn_authz"],
    "gitleaks": ["secrets"],
    "osv-scanner": ["dependencies", "supply_chain"],
    "zizmor": ["github_actions"],
    "trivy": ["dependencies", "supply_chain"],
}


@dataclass
class ToolRun:
    tool: str
    ran: bool
    results: list[ToolResult] = field(default_factory=list)
    note: str = ""


def _run(cmd: list[str], cwd: Path, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)


def run_all(target: Path, out_dir: Path, enabled: list[str] | None = None) -> list[ToolRun]:
    out_dir.mkdir(parents=True, exist_ok=True)
    runs: list[ToolRun] = []
    wanted = enabled or list(TOOL_DIMENSIONS)
    for tool in wanted:
        exe = shutil.which(tool)
        if not exe:
            runs.append(ToolRun(tool=tool, ran=False, note="binary not found on PATH"))
            continue
        sarif = out_dir / f"{tool}.sarif"
        try:
            if tool == "semgrep":
                _run([exe, "scan", "--config", "auto", "--sarif", "--output", str(sarif), "--quiet", "."], target)
            elif tool == "gitleaks":
                _run(
                    [exe, "detect", "--no-git", "--source", ".", "--report-format", "sarif", "--report-path", str(sarif), "--exit-code", "0"],
                    target,
                )
            elif tool == "osv-scanner":
                _run([exe, "scan", "--format", "sarif", "--output", str(sarif), "-r", "."], target)
            elif tool == "zizmor":
                cp = _run([exe, "--format", "sarif", "."], target)
                sarif.write_text(cp.stdout, encoding="utf-8")
            elif tool == "trivy":
                _run([exe, "fs", "--scanners", "vuln,misconfig", "--format", "sarif", "--output", str(sarif), "."], target)
            if not sarif.exists() or not sarif.read_text(encoding="utf-8").strip():
                runs.append(ToolRun(tool=tool, ran=True, note="ran but produced no SARIF"))
                continue
            json.loads(sarif.read_text(encoding="utf-8"))
            runs.append(ToolRun(tool=tool, ran=True, results=read_sarif(sarif, tool)))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            runs.append(ToolRun(tool=tool, ran=False, note=f"failed: {e}"))
    return runs


def load_prerecorded(sarif_dir: Path) -> list[ToolRun]:
    """Ingest SARIF files produced elsewhere (CI job, another runner). Used by tests and by
    the GitHub Actions workflow where the tool step runs in an isolated job."""
    runs = []
    for p in sorted(sarif_dir.glob("*.sarif")):
        runs.append(ToolRun(tool=p.stem, ran=True, results=read_sarif(p, p.stem)))
    return runs
