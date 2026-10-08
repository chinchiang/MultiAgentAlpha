"""Live smoke test: one small structured call per model of a configuration, against the real endpoints.

  python3 scripts/live_smoke.py [--config config/mara.test.yaml]

Defaults to config/mara.test.yaml, the production panel with Claude Haiku 4.5 in Claude's seat ($AWS_MODEL
replaces it when set): a connectivity test never needs Opus 5.5's cost. Each model is called once through
MARA's own provider (Bedrock tool route or structured output, the gateway's CA bundle, Gemini's header key),
with the same JSON-schema contract the agents use, and must answer 2 + 3 = 5. Exit 1 when any model fails;
the line names the sanitised provider code or the outcome (refused, truncated, wrong answer), never a key.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.config import load_config  # noqa: E402
from mara.providers import make_provider  # noqa: E402

SCHEMA = {"type": "object", "additionalProperties": False, "required": ["answer", "note"],
          "properties": {"answer": {"type": "integer"}, "note": {"type": "string", "maxLength": 40}}}
SYSTEM = "You are a calculator. Reply with the JSON object the schema describes and nothing else."
USER = "What is 2 + 3? Put the number in `answer` and a short note in `note`."


def smoke(spec) -> tuple[bool, str]:
    """(ok, one-line outcome) for one model."""
    t = time.monotonic()
    try:
        c = make_provider(spec).complete(system=SYSTEM, user=USER, schema=SCHEMA, role="smoke")
    except RuntimeError as e:  # the providers' sanitised codes
        return False, f"{e} ({time.monotonic() - t:.1f} s)"
    took = f"{c.input_tokens}/{c.output_tokens} tokens, {time.monotonic() - t:.1f} s"
    served = f", served {c.served_model}" if c.served_model and c.served_model != spec.model else ""
    if c.refused or c.truncated or c.error or not isinstance(c.data, dict):
        outcome = "refused" if c.refused else "truncated" if c.truncated else c.error or "no JSON object"
        return False, f"{outcome} ({took})"
    if c.data.get("answer") != 5:
        return False, f"wrong answer {c.data.get('answer')!r} ({took})"
    return True, f"ok{served} ({took})"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "mara.test.yaml")
    a = ap.parse_args()
    cfg = load_config(a.config)
    failed = 0
    for spec in cfg.models:
        ok, outcome = smoke(spec)
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {spec.name:18s} {spec.provider:17s} {spec.model}: {outcome}")
    print(f"{len(cfg.models) - failed}/{len(cfg.models)} models answered ({a.config})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
