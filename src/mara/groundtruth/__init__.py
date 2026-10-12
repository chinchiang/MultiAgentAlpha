"""Pinned, machine-readable ground truth. Findings must cite ids that exist here."""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources

__all__ = ["cwe_known", "load", "validate_ref"]


@cache
def load(name: str) -> dict:
    with resources.files("mara.groundtruth").joinpath(f"{name}.json").open("r", encoding="utf-8") as fh:
        return json.load(fh)


_ASVS_RE = re.compile(r"^ASVS 5\.0 V(\d{1,2})(?:\.(\d{1,2}))?(?:\.(\d{1,2}))?$")
_TOP10_RE = re.compile(r"^OWASP A(\d{2}):2025$")
_API_RE = re.compile(r"^OWASP API(\d{1,2}):2023$")
_CWE_RE = re.compile(r"^CWE-(\d{1,5})$")
_LLM_RE = re.compile(r"^OWASP LLM(\d{2}):2025$")


def validate_ref(ref: str) -> tuple[bool, str]:
    """Return (ok, reason). Only ids present in the pinned artifacts are accepted."""
    if m := _ASVS_RE.match(ref):
        chapters = load("asvs_5_0")["chapters"]
        ch = m.group(1)
        if ch not in chapters:
            return False, f"ASVS 5.0 has no chapter V{ch}"
        sec, req = m.group(2), m.group(3)
        if sec and sec not in chapters[ch]["sections"]:
            return False, f"ASVS 5.0 V{ch} has no section V{ch}.{sec}"
        # a requirement id must exist too: `ASVS 5.0 V1.2.99` used to pass on its chapter and section alone
        if req and req not in chapters[ch]["requirements"][sec]:
            return False, f"ASVS 5.0 V{ch}.{sec} has no requirement V{ch}.{sec}.{req}"
        return True, "ok"
    if m := _TOP10_RE.match(ref):
        cats = load("owasp_top10_2025")["categories"]
        return (f"A{m.group(1)}" in cats, "ok" if f"A{m.group(1)}" in cats else "not an OWASP Top 10:2025 id")
    if m := _API_RE.match(ref):
        cats = load("owasp_api_top10_2023")["categories"]
        key = f"API{int(m.group(1))}"
        return (key in cats, "ok" if key in cats else "not an OWASP API Top 10 2023 id")
    if m := _LLM_RE.match(ref):
        cats = load("owasp_llm_top10_2025")["categories"]
        key = f"LLM{m.group(1)}"
        return (key in cats, "ok" if key in cats else "not an OWASP LLM Top 10 2025 id")
    if m := _CWE_RE.match(ref):
        known = load("cwe_known")["ids"]
        return (int(m.group(1)) in known, "ok" if int(m.group(1)) in known else "CWE id not in pinned catalogue subset")
    return False, "unrecognised reference format"


def cwe_known(cwe: str) -> bool:
    m = _CWE_RE.match(cwe)
    return m is not None and int(m.group(1)) in load("cwe_known")["ids"]
