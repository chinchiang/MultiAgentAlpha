"""Compare two semgrep SARIF files hit by hit: CI's semgrep.sarif (the l0-sarif artifact) or the one
scripts/check_local.py writes under out/check-local/<time>/, one against the other (docs/agents/pr-flow.md, step 6).

  .venv/bin/python scripts/semgrep_diff.py <a.sarif> <b.sarif>

A hit is its rule, file and start line (mara.tools.semgrep_rules.result_keys), the rule's id made canonical
(canonical_rule_id): semgrep_ci.py writes it so, and a SARIF semgrep wrote itself, its ids prefixed with where the rules
are installed, compares with it; a hit a file holds twice counts twice. It prints each file's count of hits, and how
many timeouts it records (a rule semgrep gave up on for a file, whose hits there are missing:
semgrep_rules.timeouts) when it records any, then each hit only in the second (`only in <b>: <rule>  <file>:<line>`),
each only in the first, and each timeout of either (`timeout in <a>: <rule> on <file>`); "no hit differs by rule,
file and line" when neither holds one the other does not. scripts/pr_checks.py compares a pull request's run with its
Reference run (GLOSSARY.md) by compare.

Exit 0 when both were read, whatever they hold; 2 when one cannot be read, is not JSON, is not shaped as SARIF
(mara.tools.sarif.shape_problem) or holds no run, named on stderr.

GLOSSARY.md terms: Reference run. It follows no ADR. Pure, except that it reads the two files.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mara.tools.sarif import shape_problem  # noqa: E402
from mara.tools.semgrep_rules import canonical_rule_id, result_keys, timeouts  # noqa: E402

Key = tuple[str, str, int]  # a hit: its rule's canonical id, its file and its start line
NO_DIFFERENCE = "no hit differs by rule, file and line"  # what differences says when no hit differs


class Comparison(NamedTuple):
    counts: tuple[int, int]  # the hits of each file
    only_a: list[Key]  # the hits the first holds more times than the second, once per time, sorted
    only_b: list[Key]
    timeouts_a: list[tuple[str, str]]  # (rule, file) of each timeout of the first, in its order
    timeouts_b: list[tuple[str, str]]


def hits(path: Path) -> Counter[Key]:
    """The hits of the SARIF at `path`; ValueError naming the path when it cannot be read, is not JSON, is not shaped
    as SARIF or holds no run."""
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"{path}: {e}") from e
    if (problem := shape_problem(doc)) is not None:
        raise ValueError(f"{path}: not shaped as SARIF: {problem}")
    if not doc.get("runs"):
        raise ValueError(f"{path}: holds no run")
    return Counter((canonical_rule_id(rule), uri, line) for rule, uri, line in result_keys(doc))


def compare(a: Path, b: Path) -> Comparison:
    """The comparison of the SARIF at `a` with the one at `b`; ValueError as hits raises it."""
    ha, hb = hits(a), hits(b)
    return Comparison((ha.total(), hb.total()), sorted((ha - hb).elements()), sorted((hb - ha).elements()), timeouts(a), timeouts(b))


def differences(c: Comparison, a: str, b: str) -> list[str]:
    """The lines that say what only one of the files `a` and `b` holds, the second's first, then the timeouts of each."""
    out = [f"only in {b}: {rule}  {uri}:{line}" for rule, uri, line in c.only_b]
    out += [f"only in {a}: {rule}  {uri}:{line}" for rule, uri, line in c.only_a]
    if not out:
        out.append(NO_DIFFERENCE)
    return out + [f"timeout in {name}: {rule} on {file}" for name, gave_up in ((a, c.timeouts_a), (b, c.timeouts_b))
                  for rule, file in gave_up]



def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("a", type=Path, help="a semgrep SARIF file")
    ap.add_argument("b", type=Path, help="the semgrep SARIF file to compare with it")
    args = ap.parse_args(argv)
    try:
        c = compare(args.a, args.b)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    for path, count, gave_up in ((args.a, c.counts[0], c.timeouts_a), (args.b, c.counts[1], c.timeouts_b)):
        print(f"{path}: {count} hit(s)" + (f", {len(gave_up)} timeout(s)" if gave_up else ""))
    for line in differences(c, str(args.a), str(args.b)):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
