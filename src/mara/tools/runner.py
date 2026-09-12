"""L0 deterministic tools. Each wrapper runs the pinned binary from .mara-tools/bin, emits SARIF,
and returns [] with a recorded 'not run' otherwise. Tool output is ground truth: a model
finding that coincides with a tool result is corroborated (tier A); a tool result no
model reproduced is still kept, attributed to the TOOL family.

Tools are executed only from the directory populated by scripts/install_tools.py (version,
SHA-256 and publisher signature checked against tools/versions.lock); whatever happens to be on
PATH is ignored. Override the directory with MARA_TOOLS_DIR.

Tools are never executed against code they could run: they parse, they do not build.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .sarif import ToolResult, read_sarif

NOT_INSTALLED = "not installed under {bin_dir}; run `python scripts/install_tools.py`"


def tools_dir() -> Path:
    return Path(os.environ.get("MARA_TOOLS_DIR", ".mara-tools")).resolve()


def tool_path(tool: str) -> Path | None:
    """The pinned, verified binary for `tool`, or None. Never consults PATH."""
    p = tools_dir() / "bin" / tool
    return p if p.is_file() and os.access(p, os.X_OK) else None


def installed_version(tool: str) -> str | None:
    manifest = tools_dir() / "manifest.json"
    if not manifest.is_file():
        return None
    try:
        return json.loads(manifest.read_text(encoding="utf-8")).get("tools", {}).get(tool, {}).get("version")
    except (OSError, ValueError):
        return None

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


def _offline_zizmor() -> bool:
    """zizmor's online audits (impostor-commit, known-vulnerable-actions) call the GitHub API and abort the
    whole run when the token or the network is missing, so the pipeline runs zizmor offline unless
    MARA_ZIZMOR_ONLINE=1 is set and a token is present. CI runs the online audits separately via zizmor-action."""
    online = os.environ.get("MARA_ZIZMOR_ONLINE") == "1" and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    return not online


def run_all(target: Path, out_dir: Path, enabled: list[str] | None = None) -> list[ToolRun]:
    # tools run with cwd=target, so the report path must be absolute or it lands inside the target
    out_dir = out_dir.resolve()
    target = target.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    runs: list[ToolRun] = []
    wanted = enabled or list(TOOL_DIMENSIONS)
    for tool in wanted:
        exe_path = tool_path(tool)
        if exe_path is None:
            runs.append(ToolRun(tool=tool, ran=False, note=NOT_INSTALLED.format(bin_dir=tools_dir() / "bin")))
            continue
        exe = str(exe_path)
        version = installed_version(tool)
        sarif = out_dir / f"{tool}.sarif"
        sarif.unlink(missing_ok=True)
        try:
            if tool == "semgrep":
                # Explicit rulesets, never `--config auto`: auto requires metrics to be on (it sends project
                # identity to semgrep.dev to pick rules), which data-residency policy P5 forbids.
                cfg = [c for c in os.environ.get("MARA_SEMGREP_CONFIG", "p/default").split(",") if c.strip()]
                args = [exe, "scan", "--metrics=off", "--sarif", "--output", str(sarif)]
                for c in cfg:
                    args += ["--config", c.strip()]
                cp = _run(args + ["."], target)
            elif tool == "gitleaks":
                cp = _run(
                    [exe, "detect", "--no-git", "--source", ".", "--report-format", "sarif", "--report-path", str(sarif), "--exit-code", "0"],
                    target,
                )
            elif tool == "osv-scanner":
                cp = _run([exe, "scan", "--format", "sarif", "--output", str(sarif), "-r", "."], target)
            elif tool == "zizmor":
                cp = _run([exe, "--no-progress", "--format", "sarif"] + (["--offline"] if _offline_zizmor() else []) + ["."], target)
                if cp.stdout.strip():
                    sarif.write_text(cp.stdout, encoding="utf-8")
            elif tool == "trivy":
                cp = _run([exe, "fs", "--scanners", "vuln,misconfig", "--format", "sarif", "--output", str(sarif), "."], target)
            if not sarif.exists() or not sarif.read_text(encoding="utf-8").strip():
                tail = " ".join((cp.stderr or cp.stdout).strip().splitlines()[-2:])[:300]
                note = f"exit {cp.returncode}, no SARIF produced" + (f": {tail}" if tail else "")
                runs.append(ToolRun(tool=tool, ran=False, note=note))
                continue
            json.loads(sarif.read_text(encoding="utf-8"))
            runs.append(ToolRun(tool=tool, ran=True, results=read_sarif(sarif, tool), note=f"pinned {version}" if version else "pinned"))
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
