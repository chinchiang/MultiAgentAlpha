"""semgrep rule configuration and output normalisation.

The rules come from the semgrep/semgrep-rules checkout that scripts/install_tools.py pins by commit and
content digest (tools/versions.lock, tool `semgrep-rules`) under MARA_TOOLS_DIR/semgrep-rules; only the
security rulesets listed in the lock are passed to semgrep, so a scan never needs the semgrep.dev registry.

semgrep prefixes the id of every rule loaded from a local path with that path turned into dots
(`mara-tools.semgrep-rules.python.flask.security.injection.tainted-sql-string`), which would make
rule ids depend on where the tools happen to be installed. normalize_sarif() strips everything up to
and including the rules directory, giving the same ids the registry publishes
(`python.flask.security.injection.tainted-sql-string`), and drops the descriptors of rules that
produced no result (semgrep lists every loaded rule, several hundred, which dwarfs the results).
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .runner import installed_manifest_entry, tools_dir

RULES_DIR_NAME = "semgrep-rules"
REGISTRY_FALLBACK = "p/default"
_PREFIX_RE = re.compile(r"^.*?\b" + re.escape(RULES_DIR_NAME) + r"\.")
_TEXT_PREFIX_RE = re.compile(r"'[^'\s]*\b" + re.escape(RULES_DIR_NAME) + r"\.")


def rules_dir() -> Path:
    return tools_dir() / RULES_DIR_NAME


def installed_rule_paths() -> list[Path]:
    """The pinned rule directories the installer recorded in the manifest, if they exist on disk."""
    entry = installed_manifest_entry(RULES_DIR_NAME) or {}
    base = rules_dir()
    return [base / p for p in entry.get("paths", []) if (base / p).is_dir()]


def default_configs() -> list[str]:
    """MARA_SEMGREP_CONFIG (comma-separated) wins; otherwise the installed pinned rule directories; otherwise
    the registry ruleset p/default (needs network to semgrep.dev, still with --metrics=off)."""
    env = os.environ.get("MARA_SEMGREP_CONFIG", "")
    if env.strip():
        return [c.strip() for c in env.split(",") if c.strip()]
    paths = installed_rule_paths()
    return [str(p) for p in paths] if paths else [REGISTRY_FALLBACK]


def scan_env() -> dict[str, str]:
    """Environment for every semgrep invocation: no version check (the call to semgrep.dev hangs on networks
    that block it, even for `--version`) and no metrics, on top of the command-line flags."""
    return {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


def scan_args(exe: str, configs: list[str], sarif_out: Path) -> list[str]:
    """`semgrep scan` argv without the target: explicit rulesets (never --config auto, which turns metrics on
    and sends project identity to semgrep.dev), metrics off, no version check (that call hangs offline)."""
    args = [exe, "scan", "--metrics=off", "--disable-version-check", "--sarif", "--output", str(sarif_out)]
    for c in configs:
        args += ["--config", c]
    return args


def canonical_rule_id(rule_id: str) -> str:
    return _PREFIX_RE.sub("", rule_id, count=1)


def normalize_sarif(path: Path) -> dict:
    """Rewrite a semgrep SARIF file in place: canonical rule ids, unreferenced rule descriptors removed.
    Returns the document."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    for run in doc.get("runs", []):
        used = set()
        for res in run.get("results", []):
            if "ruleId" in res:
                res["ruleId"] = canonical_rule_id(res["ruleId"])
                used.add(res["ruleId"])
            if "rule" in res and "id" in res["rule"]:
                res["rule"]["id"] = canonical_rule_id(res["rule"]["id"])
        driver = run.get("tool", {}).get("driver", {})
        kept = []
        for rule in driver.get("rules", []):
            rule["id"] = canonical_rule_id(rule.get("id", ""))
            if "name" in rule:
                rule["name"] = canonical_rule_id(rule["name"])
            if rule["id"] in used:
                kept.append(rule)
        if "rules" in driver:
            driver["rules"] = kept
        for inv in run.get("invocations", []):
            for note in inv.get("toolExecutionNotifications", []):
                text = note.get("message", {}).get("text")
                if text:
                    note["message"]["text"] = _TEXT_PREFIX_RE.sub("'", text)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def result_keys(doc: dict) -> list[tuple[str, str, int]]:
    """(ruleId, uri, startLine) for every result, sorted: what drift checks compare."""
    keys = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            keys.append((res.get("ruleId", ""), loc.get("artifactLocation", {}).get("uri", ""), int(loc.get("region", {}).get("startLine", 0) or 0)))
    return sorted(keys)
