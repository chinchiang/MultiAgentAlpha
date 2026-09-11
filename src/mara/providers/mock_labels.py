"""Label-driven mock behaviour used for calibration dry runs.

When the target under review contains a labels.json (see scripts/gen_calib_samples.py),
each mock family synthesises reviewer findings from the labels with a deterministic,
family-specific profile, so the calibration loop (per-family precision/recall, judge
agreement, Dawid-Skene weights) can be exercised end to end without any live model.

Profiles (deliberately different, so the calibration report has something to say):
  anthropic  recall ~0.85, one fabricated-quote false positive per sample, never refuses
  deepseek   recall ~0.70, misses the csp dimension entirely, flips one judge vote on reverse
  nemotron   recall ~0.55, refuses the error_handling dimension, adds one hygiene FP
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

PROFILES = {
    "anthropic": {"recall": 0.85, "skip_dims": set(), "refuse_dims": set(), "fake_fp": True, "hygiene_fp": False},
    "deepseek": {"recall": 0.70, "skip_dims": {"csp"}, "refuse_dims": set(), "fake_fp": False, "hygiene_fp": False},
    "nemotron": {"recall": 0.55, "skip_dims": set(), "refuse_dims": {"error_handling"}, "fake_fp": False, "hygiene_fp": True},
}

VECTORS = {
    "CWE-89": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "CWE-78": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-94": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-502": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CWE-79": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "CWE-798": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "CWE-312": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "CWE-829": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    "CWE-22": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
}
DEFAULT_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
LOW_VECTOR = "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"


def _pick(seed: str, p: float) -> bool:
    h = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF
    return h < p


def load_labels(root: Path) -> list[dict] | None:
    p = Path(root) / "labels.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8")).get("labels", [])


def reviewer_response(family: str, dimension: str, labels: list[dict], sample: str) -> dict | None:
    """Return {"findings": [...]}, or None to signal a refusal."""
    prof = PROFILES.get(family, PROFILES["nemotron"])
    if dimension in prof["refuse_dims"]:
        return None
    findings = []
    if dimension not in prof["skip_dims"]:
        for lab in labels:
            if lab["dimension"] != dimension:
                continue
            if not _pick(f"{family}|{sample}|{lab['file']}|{lab['line']}|{lab['cwe']}", prof["recall"]):
                continue
            findings.append({
                "title": lab["title"],
                "cwe": lab["cwe"],
                "standard_refs": ["OWASP A05:2025"] if lab["cwe"] in ("CWE-89", "CWE-78", "CWE-79", "CWE-94") else [],
                "provenance": [{"file": lab["file"], "line": lab["line"], "quote": lab["quote"]}],
                "reachability": "reachable",
                "reachability_argument": "Public handler reachable without special preconditions (mock).",
                "exploit_sketch": "Supply crafted input to the endpoint (mock).",
                "cvss4_vector": VECTORS.get(lab["cwe"], DEFAULT_VECTOR),
                "model_confidence": 0.8,
            })
    if prof["fake_fp"] and dimension == "vulnerabilities":
        first = next((lab for lab in labels if lab["dimension"] == "vulnerabilities"), None)
        if first:
            findings.append({
                "title": "SQL injection in parameterised query (mock false positive)",
                "cwe": "CWE-89", "standard_refs": ["OWASP A05:2025"],
                "provenance": [{"file": first["file"], "line": max(1, first["line"] - 1),
                                "quote": "cursor.execute(\"SELECT * FROM nowhere WHERE id = '\" + x + \"'\")"}],
                "reachability": "reachable", "reachability_argument": "mock", "exploit_sketch": "mock",
                "cvss4_vector": VECTORS["CWE-89"], "model_confidence": 0.6,
            })
    if prof["hygiene_fp"] and dimension == "dependencies":
        dep = next((lab for lab in labels if lab["dimension"] == "dependencies"), None)
        if dep:
            findings.append({
                "title": "Unpinned dependency (hygiene, mock low-value finding)",
                "cwe": "CWE-1104", "standard_refs": ["ASVS 5.0 V15.2"],
                "provenance": [{"file": dep["file"], "line": 1, "quote": _first_line(sample, dep["file"])}],
                "reachability": "unknown", "reachability_argument": "mock", "exploit_sketch": "mock",
                "cvss4_vector": LOW_VECTOR, "model_confidence": 0.4,
            })
    return {"findings": findings}


_FIRST_LINE_CACHE: dict[str, str] = {}


def _first_line(sample: str, rel: str) -> str:
    return _FIRST_LINE_CACHE.get(f"{sample}/{rel}", "flask")


def remember_first_lines(root: Path) -> None:
    for p in Path(root).rglob("*"):
        if p.is_file() and p.suffix in (".txt", ".json"):
            try:
                first = p.read_text(encoding="utf-8").splitlines()[0].strip()
            except (OSError, IndexError):
                continue
            _FIRST_LINE_CACHE[f"{Path(root).name}/{p.relative_to(root).as_posix()}"] = first[:100]


def judge_rules(family: str) -> dict:
    """Judges agree with the labels; the fabricated and hygiene findings are rejected; deepseek flips one claim."""
    rules = {
        "default": {"verdict": "true_positive", "severity_band": "High", "reason": "Quoted code supports the claim (mock)."},
        "by_claim": {
            "mock false positive": {"verdict": "false_positive", "severity_band": "None", "reason": "Quote not found in file (mock)."},
            "hygiene": {"verdict": "false_positive" if family != "nemotron" else "needs_human", "severity_band": "Low",
                        "reason": "Hygiene only (mock)."},
            "XSS": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Outdated": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Suspicious package": {"verdict": "needs_human", "severity_band": "Medium", "reason": "Registry check required (mock)."},
            "Debug": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Traceback": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Stack trace": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Exception text": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "Prompt injection": {"verdict": "true_positive", "severity_band": "Low", "reason": "mock"},
            "Unpinned action": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
            "write-all": {"verdict": "true_positive", "severity_band": "Medium", "reason": "mock"},
        },
    }
    if family == "deepseek":
        rules["flip_on_reverse"] = ["Outdated"]
    return rules


SKEPTIC_RULES = {
    "default": {"verdict": "stands", "reason": "No control found (mock).", "sanitizer_or_control": ""},
    "by_claim": {"mock false positive": {"verdict": "refuted", "reason": "Cited line does not exist / query is parameterised (mock).",
                                         "sanitizer_or_control": "parameterised query"}},
}
REDTEAM_RULES = {
    "default": {"exploitable": "yes", "preconditions": "Network access (mock)."},
    "by_claim": {"IDOR": {"exploitable": "conditional", "preconditions": "Any valid session (mock)."},
                 "Outdated": {"exploitable": "unknown", "preconditions": "Scanner confirmation required (mock)."}},
}
