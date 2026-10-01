"""L0 CSP review with Google's csp-evaluator (pinned npm package, driven via node).

The scanner extracts every Content-Security-Policy string it can find in the target —
HTML <meta> tags, CSP header assignments in source (dict/object literals, framework
set_header calls), and web-server configs (nginx/apache) — and asks the pinned evaluator
to grade each policy. Every reported weakness becomes a SARIF result attached to the file
and line where the policy was declared; a policy the evaluator could not parse is recorded
as a note-level notification, never silently dropped.

Like every L0 tool this parses source, it does not execute it, and it runs only the pinned
package installed under MARA_TOOLS_DIR (node >= 18 is the only interpreter used, from PATH,
because it is a platform runtime — the package and the driver always come from the pinned
install directory).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .sarif import ToolResult

DRIVER_NAME = "mara_driver.js"
PACKAGE_DIR = "csp-evaluator"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
MAX_POLICIES = 400
MAX_FILE_BYTES = 512 * 1024

SCAN_EXTS = {".html", ".htm", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".py", ".conf", ".cfg", ".htaccess"}
SKIP_DIRS = {".git", ".mara-tools", "node_modules", "out", "__pycache__", ".venv", "venv",
             ".pytest_cache", ".ruff_cache", ".mypy_cache"}

_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.I)
_HTTP_EQUIV_RE = re.compile(r"""http-equiv\s*=\s*["']?\s*content-security-policy\s*["']?""", re.I)
_CONTENT_ATTR_RE = re.compile(r"""content\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
# The value alternation ("..."|'...') keeps the *other* quote character legal inside the policy,
# so a double-quoted value may itself contain single quotes (as CSP keyword sources always do).
_ASSIGN_RE = re.compile(r"""["']content-security-policy["']\s*[:=]\s*(?:"([^"]{3,})"|'([^']{3,})')""", re.I)
_SET_HEADER_RE = re.compile(r"""set_header\s*\(\s*["']content-security-policy["']\s*,\s*(?:"([^"]{3,})"|'([^']{3,})')""", re.I)
# Quoted values may contain ';' (multi-directive policies); an unquoted value runs to the ';'.
_NGINX_RE = re.compile(r"""(?im)^[ \t]*add_header[ \t]+Content-Security-Policy[ \t]+(?:"([^"\r\n]+)"|'([^'\r\n]+)'|([^;"'\r\n]+))""")
_APACHE_RE = re.compile(r"""(?im)^[ \t]*Header[ \t]+(?:always[ \t]+)?set[ \t]+Content-Security-Policy[ \t]+"?([^"\r\n]+)""")
_DIRECTIVE_RE = re.compile(
    r"""\b(?:default-src|script-src(?:-attr|-elem)?|style-src(?:-attr|-elem)?|img-src|connect-src|font-src|object-src|"""
    r"""media-src|frame-src|child-src|worker-src|manifest-src|prefetch-src|form-action|frame-ancestors|base-uri|"""
    r"""report-uri|report-to|upgrade-insecure-requests|block-all-mixed-content|sandbox|require-trusted-types-for|"""
    r"""trusted-types|plugin-types|referrer|disown-opener|navigate-to|reflected-xss|require-sri-for|webrtc)\b""", re.I)

# csp-evaluator Severity -> SARIF level. NONE findings (affirmations that a hardening is in
# place) are dropped by the driver already; anything unknown lands at note level.
SEVERITY_LEVELS = {
    "HIGH": "error",
    "SYNTAX": "warning",
    "MEDIUM": "warning",
    "HIGH_MAYBE": "warning",
    "STRICT_CSP": "warning",
    "MEDIUM_MAYBE": "warning",
    "INFO": "note",
}


@dataclass(frozen=True)
class CspPolicy:
    file: str      # POSIX path relative to the target root
    line: int
    policy: str


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if name in SCAN_EXTS or p.suffix.lower() in SCAN_EXTS:
                yield p


def extract_policies(root: Path) -> tuple[list[CspPolicy], bool]:
    """Every CSP string in the target, in deterministic (file, line) order. `truncated` reports
    that MAX_POLICIES was hit: the remaining files were not read, and the run note says so."""
    policies: list[CspPolicy] = []
    truncated = False
    for path in _iter_source_files(root):
        if truncated:
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root).as_posix()
        hits: list[tuple[int, str]] = []
        for tag in _META_TAG_RE.finditer(text):
            if _HTTP_EQUIV_RE.search(tag.group(0)):
                m = _CONTENT_ATTR_RE.search(tag.group(0))
                if m:
                    hits.append((_line_of(text, tag.start()), m.group(1) or m.group(2) or ""))
        for m in _SET_HEADER_RE.finditer(text):
            hits.append((_line_of(text, m.start()), m.group(1) or m.group(2) or ""))
        for m in _ASSIGN_RE.finditer(text):
            hits.append((_line_of(text, m.start()), m.group(1) or m.group(2) or ""))
        for m in _NGINX_RE.finditer(text):
            hits.append((_line_of(text, m.start()), m.group(1) or m.group(2) or m.group(3) or ""))
        for m in _APACHE_RE.finditer(text):
            hits.append((_line_of(text, m.start()), m.group(1)))
        seen: set[tuple[int, str]] = set()
        for line, raw in hits:
            policy = re.sub(r"\s+", " ", raw.strip())
            key = (line, policy.lower())
            if not policy or key in seen or not _DIRECTIVE_RE.search(policy):
                continue
            seen.add(key)
            policies.append(CspPolicy(file=rel, line=line, policy=policy))
            if len(policies) >= MAX_POLICIES:
                truncated = True
                break
    return policies, truncated


def driver_path() -> Path | None:
    p = tools_dir() / PACKAGE_DIR / DRIVER_NAME
    return p if p.is_file() else None


def tools_dir() -> Path:
    from .runner import tools_dir as _t
    return _t()


def node_exe() -> str | None:
    return os.environ.get("MARA_NODE") or shutil.which("node")


def evaluate(policies: list[CspPolicy], *, driver: Path, node: str,
             timeout: int = 120) -> tuple[dict[int, dict] | None, str]:
    """Ask the pinned evaluator to grade every policy. Returns {policy index: driver result},
    or (None, note) when the driver could not be run or its output was unusable."""
    request = json.dumps({"policies": [{"id": i, "policy": p.policy} for i, p in enumerate(policies)]})
    try:
        cp = subprocess.run([node, str(driver), "-"], input=request, capture_output=True, text=True,
                            timeout=timeout, check=False, cwd=str(driver.parent))
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"failed: {e}"
    if cp.returncode != 0:
        return None, f"driver exit {cp.returncode}: {(cp.stderr or cp.stdout).strip()[-300:]}"
    try:
        doc = json.loads(cp.stdout)
        results = {int(r["id"]): r for r in doc["results"]}
    except (ValueError, KeyError, TypeError) as e:
        return None, f"driver output unusable: {e}"
    return results, ""


def to_results(policies: list[CspPolicy], results: dict[int, dict]) -> list[ToolResult]:
    out: list[ToolResult] = []
    for i, p in enumerate(policies):
        r = results.get(i)
        if not r:
            continue
        for f in r.get("findings", []):
            sev = str(f.get("severity", ""))
            out.append(ToolResult(
                tool="csp-evaluator",
                rule_id=str(f.get("type", "CSP_FINDING")),
                level=SEVERITY_LEVELS.get(sev, "note"),
                message=f"[{sev or 'UNKNOWN'}] {f.get('description', '')}"
                        + (f" (value: {f['value']})" if f.get("value") else ""),
                file=p.file,
                line=p.line,
                cwe=None,
                cwes=[],
            ))
    return out


def build_sarif(policies: list[CspPolicy], results: list[ToolResult], *, version: str | None,
                note: str = "", truncated: bool = False, parse_errors: list[str] | None = None) -> dict:
    notifications = [{"level": "note", "descriptor": {"id": "CSP_PARSE_ERROR"}, "message": {"text": m}}
                     for m in (parse_errors or [])]
    props = {"policies": len(policies), "truncated": truncated}
    if note:
        props["note"] = note
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "csp-evaluator",
                "informationUri": "https://github.com/google/csp-evaluator",
                "version": version or "0",
                "rules": [],
            }},
            "invocations": [{
                "executionSuccessful": True,
                "properties": props,
                "toolExecutionNotifications": notifications,
            }],
            "results": [{
                "ruleId": r.rule_id,
                "level": r.level,
                "message": {"text": r.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": r.file, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": r.line},
                }}],
            } for r in results],
        }],
    }


def run_csp_eval(target: Path, sarif_path: Path, *, version: str | None = None,
                 node: str | None = None) -> subprocess.CompletedProcess:
    """Extract the CSPs in `target`, evaluate them, write `sarif_path`. Returns a synthetic
    CompletedProcess so the runner's shared exit-code/SARIF handling applies unchanged:
    0 ok (SARIF written), 66 package missing, 127 no node interpreter, 1 evaluation failed."""
    driver = driver_path()
    if driver is None:
        return subprocess.CompletedProcess([], 66, "", f"{PACKAGE_DIR}/{DRIVER_NAME} missing under {tools_dir()}")
    node = node or node_exe()
    if not node:
        return subprocess.CompletedProcess([], 127, "", "node interpreter not found on PATH (node >= 18 required)")

    def _done(rc: int, stderr: str = "", note: str = "", truncated: bool = False,
              parse_errors: list[str] | None = None, results: list[ToolResult] | None = None,
              policies: list[CspPolicy] | None = None) -> subprocess.CompletedProcess:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(build_sarif(
            policies or [], results or [], version=version, note=note, truncated=truncated,
            parse_errors=parse_errors), indent=2) + "\n", encoding="utf-8")
        return subprocess.CompletedProcess([], rc, "", stderr)

    policies, truncated = extract_policies(target)
    if not policies:
        return _done(0, note="no Content-Security-Policy found in the target", truncated=truncated)
    evaluated, err = evaluate(policies, driver=driver, node=node)
    if evaluated is None:
        return _done(1, stderr=err)
    parse_errors = [f"{p.file}:{p.line}: the evaluator could not parse this policy: {evaluated[i].get('error', '?')}"
                    for i, p in enumerate(policies) if not evaluated.get(i, {}).get("parse_ok", True)]
    results = to_results(policies, evaluated)
    note = f"{len(policies)} policy(ies) evaluated"
    if truncated:
        note += "; policy extraction stopped at the MAX_POLICIES cap, later files were not read"
    return _done(0, note=note, truncated=truncated, parse_errors=parse_errors,
                 results=results, policies=policies)
