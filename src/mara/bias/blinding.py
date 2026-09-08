"""Blinding transforms applied before anything reaches a judge.

Counters: self-preference (identity removed), anchoring (severity and confidence
removed), verbosity (fixed-width fields), position (deterministic shuffle plus a
reversed pass so every finding is judged in two positions).
"""

from __future__ import annotations

import hashlib
import random

from ..schemas import Finding, SkepticVerdict

MAX_FIELD = 300


def _clip(s: str, n: int = MAX_FIELD) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


def blind_finding(f: Finding, skeptic: SkepticVerdict | None) -> dict:
    """Return the only view of a finding a judge is allowed to see."""
    return {
        "finding_id": f.id,
        "dimension": f.dimension,
        "cwe": f.cwe,
        "standard_refs": f.standard_refs[:5],
        "claim": _clip(f.title, 120),
        "evidence": [{"file": p.file, "line": p.line, "quote": _clip(p.quote, 200)} for p in f.provenance[:3]],
        "reachability": f.reachability,
        "reachability_argument": _clip(f.reachability_argument),
        "exploit_sketch": _clip(f.exploit_sketch),
        # deliberately absent: source_family, source_model, model_confidence, cvss vector
        "skeptic": None
        if skeptic is None
        else {"verdict": skeptic.verdict, "reason": _clip(skeptic.reason), "control": _clip(skeptic.sanitizer_or_control, 150)},
    }


def blinded_batches(
    findings: list[Finding], skeptic_by_id: dict[str, SkepticVerdict], seed_material: str
) -> tuple[list[dict], list[dict]]:
    """Forward pass in a seeded random order; reverse pass is the exact mirror.

    Seeding on the target's content hash keeps runs reproducible while preventing
    the finder's emission order from leaking into judge position.
    """
    seed = int(hashlib.sha256(seed_material.encode("utf-8")).hexdigest()[:16], 16)
    order = list(range(len(findings)))
    random.Random(seed).shuffle(order)
    forward = [blind_finding(findings[i], skeptic_by_id.get(findings[i].id)) for i in order]
    reverse = list(reversed(forward))
    return forward, reverse
