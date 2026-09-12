"""Verify a six-layer gap assessment produced by Appendix E prompt 3.

Checks docs/assessment-<date>.md for: 60 numbered questions (1..60, no duplicates), a score in 0..4
and a non-empty evidence cell on every row, per-layer sums that match the summary table, and the
four CN rows. Exit 1 on any mismatch so the acceptance criteria of prompt 3 are machine-checked.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LAYERS = ["L0", "L1", "L2", "L3", "L4", "L5"]
PER_LAYER = 10
ROW = re.compile(r"^\|\s*(\d{1,2})\s*\|(.+?)\|\s*([0-4])\s*\|(.*)\|\s*$")
SUMMARY = re.compile(r"^\|\s*(L[0-5])\b[^|]*\|\s*(\d+)\s*\|\s*40\s*\|")
TOTAL = re.compile(r"^\|\s*合計\s*\|\s*(\d+)\s*\|\s*240\s*\|")
CN = re.compile(r"^\|\s*(CN-[1-4])\s*\|[^|]*\|\s*(是|否|不適用)\s*\|")


def check(path: Path) -> list[str]:
    errors: list[str] = []
    scores: dict[int, int] = {}
    summary: dict[str, int] = {}
    total: int | None = None
    cn: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            n, score, evidence = int(m.group(1)), int(m.group(3)), m.group(4).strip()
            if n in scores:
                errors.append(f"question {n} appears twice")
            scores[n] = score
            if not evidence:
                errors.append(f"question {n} has an empty evidence cell")
            continue
        m = SUMMARY.match(line)
        if m:
            summary[m.group(1)] = int(m.group(2))
            continue
        m = TOTAL.match(line)
        if m:
            total = int(m.group(1))
            continue
        m = CN.match(line)
        if m:
            cn[m.group(1)] = m.group(2)
    missing = [n for n in range(1, 61) if n not in scores]
    if missing:
        errors.append(f"missing questions: {missing}")
    extra = [n for n in scores if not 1 <= n <= 60]
    if extra:
        errors.append(f"unexpected question numbers: {extra}")
    for i, layer in enumerate(LAYERS):
        computed = sum(scores.get(n, 0) for n in range(i * PER_LAYER + 1, (i + 1) * PER_LAYER + 1))
        if layer not in summary:
            errors.append(f"summary table lacks {layer}")
        elif summary[layer] != computed:
            errors.append(f"{layer}: summary says {summary[layer]}, rows add up to {computed}")
    computed_total = sum(scores.values())
    if total is None:
        errors.append("summary table lacks the 合計 row")
    elif total != computed_total:
        errors.append(f"合計: summary says {total}, rows add up to {computed_total}")
    for k in ("CN-1", "CN-2", "CN-3", "CN-4"):
        if k not in cn:
            errors.append(f"CN table lacks {k}")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    args = ap.parse_args()
    errors = check(args.path)
    if errors:
        for e in errors:
            print(f"FAIL {e}")
        return 1
    print(f"OK {args.path}: 60 questions scored with evidence, layer sums match, CN-1..CN-4 present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
