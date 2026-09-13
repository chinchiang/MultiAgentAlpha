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


def installed_manifest_entry(tool: str) -> dict | None:
    manifest = tools_dir() / "manifest.json"
    if not manifest.is_file():
        return None
    try:
        entry = json.loads(manifest.read_text(encoding="utf-8")).get("tools", {}).get(tool)
    except (OSError, ValueError):
        return None
    return entry if isinstance(entry, dict) else None


def installed_version(tool: str) -> str | None:
    entry = installed_manifest_entry(tool)
    return entry.get("version") if entry else None

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


def _run(cmd: list[str], cwd: Path, timeout: int = 600, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)


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
                # Pinned local rulesets (tools/versions.lock `semgrep-rules`) unless MARA_SEMGREP_CONFIG says
                # otherwise; never `--config auto`, which turns metrics on and sends project identity to
                # semgrep.dev (data-residency policy P5). Rule ids are normalised to the registry form.
                from .semgrep_rules import default_configs, normalize_sarif, scan_args, scan_env

                cp = _run(scan_args(exe, default_configs(), sarif) + ["."], target, env=scan_env())
                if sarif.exists() and sarif.read_text(encoding="utf-8").strip():
                    normalize_sarif(sarif)
            elif tool == "gitleaks":
                cp = _run(
                    [exe, "detect", "--no-git", "--source", ".", "--report-format", "sarif", "--report-path", str(sarif), "--exit-code", "0"],
                    target,
                )
            elif tool == "osv-scanner":
                cp = _run([exe, "scan", "source", "--format", "sarif", "--output-file", str(sarif), "-r", "."], target)
                if cp.returncode not in (0, 1, 130):
                    # 127 no packages, 128 general error (e.g. api.osv.dev unreachable): osv-scanner may still write an
                    # empty SARIF, which must not be read as "ran, nothing found"
                    sarif.unlink(missing_ok=True)
            elif tool == "zizmor":
                cp = _run([exe, "--no-progress", "--format", "sarif"] + (["--offline"] if _offline_zizmor() else []) + ["."], target)
                if cp.stdout.strip():
                    sarif.write_text(cp.stdout, encoding="utf-8")
            elif tool == "trivy":
                # Offline only: the database recorded by scripts/trivy_db.py (never downloaded during a review)
                from .trivy_db import cache_dir, db_path, read_metadata, scan_args

                cache = cache_dir()
                if not db_path(cache).is_file():
                    note = f"no offline database under {cache}; run scripts/trivy_db.py download (or import a bundle)"
                    runs.append(ToolRun(tool=tool, ran=False, note=note))
                    continue
                cp = _run(scan_args(exe, cache, sarif) + ["."], target)
                updated = (read_metadata(cache) or {}).get("UpdatedAt", "?")
                version = f"{version}, db {str(updated)[:10]}" if version else f"db {str(updated)[:10]}"
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
