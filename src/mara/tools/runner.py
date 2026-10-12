"""L0 deterministic tools. Each wrapper runs the pinned binary from .mara-tools/bin and emits SARIF.
A tool that is not installed, writes no SARIF, exits with an unexpected code or reports an incomplete
scan is recorded as ran=False; the pipeline then marks the review incomplete
(required_tool_incomplete) and the gate fails closed. Tool output is ground truth: a model
finding that coincides with a tool result is corroborated (tier A); a tool result no
model reproduced is still kept, attributed to the TOOL family.

Tools are executed only from the directory populated by scripts/install_tools.py (version,
SHA-256 and publisher signature checked against tools/versions.lock); whatever happens to be on
PATH is ignored. Override the directory with MARA_TOOLS_DIR; a relative one, like the default
.mara-tools, resolves against the MARA workspace (mara.workspace), never inside the review target.

Tools are never executed against code they could run: they parse, they do not build.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .sarif import ToolResult, read_sarif, scan_complete

_log = logging.getLogger("mara.tools")
NOT_INSTALLED = "not installed under {bin_dir}; run `python scripts/install_tools.py`"

# The only parent environment variables a tool subprocess sees. The tools scan an untrusted target and some
# reach the network (osv-scanner queries api.osv.dev), so the review's own secrets - provider keys, AWS
# credentials, GH_TOKEN, HF_TOKEN, the PSIRT token - must not be in their environment; neither may a TRIVY_*,
# GITLEAKS_* or SEMGREP_* setting change what the pinned, explicitly configured scan does. What remains is what
# a process needs to run and to reach the network: the search path, home and temp directories, locale and time
# zone, proxies and CA bundles, and the Windows system variables.
TOOL_ENV_ALLOWLIST = (
    "PATH", "HOME", "USER", "LOGNAME", "SHELL", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ",
    "TMPDIR", "TMP", "TEMP",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "PROGRAMFILES",
)


def tool_env(*extra: str, **set_vars: str) -> dict[str, str]:
    """The environment for a tool subprocess: the allowlisted parent variables, plus the named `extra` ones a
    particular call needs (zizmor's online audits: GH_TOKEN), plus `set_vars` set explicitly."""
    keep = set(TOOL_ENV_ALLOWLIST) | set(extra)
    env = {k: v for k, v in os.environ.items() if k in keep}
    env.update(set_vars)
    return env


def tools_dir() -> Path:
    from ..workspace import resolve

    return resolve(os.environ.get("MARA_TOOLS_DIR") or ".mara-tools").resolve()


def tool_path(tool: str) -> Path | None:
    """The pinned, verified binary for `tool`, or None. Never consults PATH."""
    base = tools_dir() / "bin" / tool
    candidates = [base.with_suffix(".cmd"), base.with_suffix(".bat"), base.with_suffix(".exe"), base] if sys.platform == "win32" else [base]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            return p
    return None


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
    "csp-evaluator": ["csp"],
}


@dataclass
class ToolRun:
    tool: str
    ran: bool
    results: list[ToolResult] = field(default_factory=list)
    note: str = ""


def _run(cmd: list[str], cwd: Path, timeout: int = 600, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a tool; without an explicit `env`, with tool_env() - never the full parent environment."""
    env = tool_env() if env is None else env
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)
    except OSError as e:
        if sys.platform == "win32" and getattr(e, "winerror", None) == 193:
            import shutil
            sh = shutil.which("sh")
            if not sh:
                git = shutil.which("git")
                if git:
                    for cand in (Path(git).parent.parent / "bin" / "sh.exe", Path(git).parent.parent / "usr" / "bin" / "sh.exe"):
                        if cand.exists():
                            sh = str(cand)
                            break
            if sh:
                return subprocess.run([sh, *cmd], cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False, env=env)
        raise


def _offline_zizmor() -> bool:
    """zizmor's online audits (impostor-commit, known-vulnerable-actions) call the GitHub API and abort the
    whole run when the token or the network is missing, so the pipeline runs zizmor offline unless
    MARA_ZIZMOR_ONLINE=1 is set and a token is present. CI runs the online audits separately, through
    scripts/zizmor_ci.py with GH_TOKEN."""
    online = os.environ.get("MARA_ZIZMOR_ONLINE") == "1" and bool(os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"))
    return not online


def neutral_configs(out_dir: Path) -> dict[str, Path]:
    """Empty configuration files handed to the tools explicitly, so none of them loads the reviewed
    repository's own: the target is untrusted, and a pull request that adds `.trivyignore`, an
    `osv-scanner.toml` with `ignore = true` overrides, a `zizmor.yml` or a `.semgrepignore` listing
    `*` would otherwise make the tool report "ran, nothing found" and clear the gate. They live in
    the run's output directory, never in the target."""
    d = out_dir / "neutral-tool-config"
    d.mkdir(parents=True, exist_ok=True)
    files = {"osv-scanner": d / "osv-scanner.toml", "trivyignore": d / "trivyignore", "trivy": d / "trivy.yaml"}
    files["osv-scanner"].write_text("", encoding="utf-8")
    files["trivyignore"].write_text("", encoding="utf-8")
    files["trivy"].write_text("{}\n", encoding="utf-8")
    return files


# Flags that stop each tool from honouring suppressions the reviewed repository controls (verified
# against the pinned versions: semgrep 1.179.0, osv-scanner 2.5.1, zizmor 1.30.1, trivy 0.74.0).
# semgrep's `# nosemgrep` needs nothing: its SARIF keeps those results, marked kind inSource, and
# read_sarif only drops status "accepted". gitleaks gets an explicit config and no allowlist below.
SEMGREP_TARGET_FLAGS = ["--x-ignore-semgrepignore-files"]
ZIZMOR_TARGET_FLAGS = ["--no-config", "--no-ignores", "--collect=all"]  # all: also what .gitignore hides


def has_actions_inputs(target: Path) -> bool:
    """Whether the target holds anything zizmor --collect=all audits: a workflow under .github/workflows/, an
    action.yml / action.yaml anywhere, or .github/dependabot.yml. Walked without following symlinks."""
    for dirpath, _dirs, files in os.walk(target, followlinks=False):
        d = Path(dirpath)
        for f in files:
            if f in ("action.yml", "action.yaml"):
                return True
            if f.endswith((".yml", ".yaml")) and d.name == "workflows" and d.parent.name == ".github":
                return True
            if f in ("dependabot.yml", "dependabot.yaml") and d.name == ".github":
                return True
    return False


def run_all(target: Path, out_dir: Path, enabled: list[str] | None = None) -> list[ToolRun]:
    # tools run with cwd=target, so the report path must be absolute or it lands inside the target
    out_dir = out_dir.resolve()
    target = target.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    neutral = neutral_configs(out_dir)
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
                from .semgrep_rules import default_configs, normalize_sarif, override_configs, scan_env
                from .semgrep_rules import scan_args as semgrep_args

                configs = default_configs()
                override = override_configs()
                if override:
                    # MARA_SEMGREP_CONFIG replaced the pinned rules: the run is still recorded, but never as pinned
                    from .semgrep_rules import unpinned_note

                    rules_note = unpinned_note(override)
                    _log.warning("semgrep: %s", rules_note)
                    version = f"{version}; {rules_note}" if version else rules_note
                if not configs:
                    runs.append(ToolRun(tool=tool, ran=False, note="pinned semgrep-rules not installed under "
                                        f"{tools_dir() / 'semgrep-rules'} (scripts/install_tools.py); no registry fallback"))
                    continue
                cp = _run(semgrep_args(exe, configs, sarif) + SEMGREP_TARGET_FLAGS + ["."], target, env=scan_env())
                if sarif.exists() and sarif.read_text(encoding="utf-8").strip():
                    normalize_sarif(sarif)
            elif tool == "gitleaks":
                secret_config = out_dir / "gitleaks-preflight.toml"
                secret_config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
                (out_dir / "no-allowlist").write_text("", encoding="utf-8")
                cp = _run(
                    [exe, "dir", "--config", str(secret_config), "--redact", "--ignore-gitleaks-allow", "--gitleaks-ignore-path",
                     str(out_dir / "no-allowlist"), "--report-format", "sarif", "--report-path", str(sarif), "."],
                    target,
                )
            elif tool == "osv-scanner":
                cp = _run([exe, "scan", "source", "--config", str(neutral["osv-scanner"]), "--format", "sarif",
                           "--output-file", str(sarif), "-r", "."], target)
                if cp.returncode not in (0, 1):
                    # 127 no packages, 128 general error (e.g. api.osv.dev unreachable): osv-scanner may still write an
                    # empty SARIF, which must not be read as "ran, nothing found"
                    sarif.unlink(missing_ok=True)
            elif tool == "zizmor":
                offline = _offline_zizmor()
                # the token reaches zizmor only for the online audits it is needed for
                cp = _run([exe, "--no-progress", "--format", "sarif", *ZIZMOR_TARGET_FLAGS] + (["--offline"] if offline else []) + ["."],
                          target, env=tool_env() if offline else tool_env("GH_TOKEN", "GITHUB_TOKEN"))
                if cp.stdout.strip():
                    sarif.write_text(cp.stdout, encoding="utf-8")
                elif cp.returncode == 3 and "no inputs collected" in cp.stderr and not has_actions_inputs(target):
                    # zizmor exits 3 when there is nothing to audit. A target without workflows, actions or a
                    # dependabot file (checked here, not taken from zizmor's word) has been fully covered.
                    runs.append(ToolRun(tool=tool, ran=True, note=f"pinned {version}; the target has no GitHub Actions inputs"
                                        if version else "pinned; the target has no GitHub Actions inputs"))
                    continue
            elif tool == "trivy":
                # Offline only: the database recorded by scripts/trivy_db.py (never downloaded during a review)
                from . import trivy_db as tdb
                from .trivy_db import read_metadata
                from .trivy_db import scan_args as trivy_args

                cache = tdb.cache_dir()
                if not tdb.db_path(cache).is_file():
                    note = f"no offline database under {cache}; run scripts/trivy_db.py download (or import a bundle)"
                    runs.append(ToolRun(tool=tool, ran=False, note=note))
                    continue
                # the same check as `scripts/trivy_db.py status`: a database that no longer matches its record
                # or is past the freshness bound must not count as dependency coverage
                db_ok, db_lines = tdb.check(cache, tdb.max_age_hours())
                if not db_ok:
                    problems = [line for line in db_lines if not line.startswith("source ")]
                    runs.append(ToolRun(tool=tool, ran=False, note="offline database not usable: " + "; ".join(problems)[:300]))
                    continue
                cp = _run(trivy_args(exe, cache, sarif) + ["--ignorefile", str(neutral["trivyignore"]), "--config", str(neutral["trivy"]), "."],
                          target)
                updated = (read_metadata(cache) or {}).get("UpdatedAt", "?")
                version = f"{version}, db {str(updated)[:10]}" if version else f"db {str(updated)[:10]}"
            elif tool == "csp-evaluator":
                # Parses CSPs out of the target and grades them with the pinned npm package; the
                # SARIF is written by the wrapper itself (node runs the driver inside the package dir).
                from .csp_eval import run_csp_eval
                cp = run_csp_eval(target, sarif, version=version)
            if not sarif.exists() or not sarif.read_text(encoding="utf-8").strip():
                tail = " ".join((cp.stderr or cp.stdout).strip().splitlines()[-2:])[:300]
                note = f"exit {cp.returncode}, no SARIF produced" + (f": {tail}" if tail else "")
                runs.append(ToolRun(tool=tool, ran=False, note=note))
                continue
            doc = json.loads(sarif.read_text(encoding="utf-8"))
            allowed = {"semgrep": {0}, "gitleaks": {0, 1}, "osv-scanner": {0, 1}, "zizmor": {0, 11, 12, 13, 14},
                       "trivy": {0}, "csp-evaluator": {0}}
            if cp.returncode not in allowed[tool] or not scan_complete(doc):
                runs.append(ToolRun(tool=tool, ran=False, results=read_sarif(sarif, tool), note="scanner_incomplete"))
                continue
            runs.append(ToolRun(tool=tool, ran=True, results=read_sarif(sarif, tool), note=f"pinned {version}" if version else "pinned"))
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
            runs.append(ToolRun(tool=tool, ran=False, note=f"failed: {e}"))
    return runs


def load_prerecorded(sarif_dir: Path) -> list[ToolRun]:
    """Ingest SARIF files produced elsewhere (CI job, another runner). Used by tests and by
    the GitHub Actions workflow where the tool step runs in an isolated job."""
    runs = []
    for p in sorted(sarif_dir.glob("*.sarif")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        runs.append(ToolRun(tool=p.stem, ran=scan_complete(doc), results=read_sarif(p, p.stem), note="prerecorded"))
    return runs
