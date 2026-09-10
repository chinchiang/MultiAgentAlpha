"""Offline provider. Replays canned findings/verdicts from a fixtures directory so the
whole pipeline, including blinding, consensus and reporting, runs without any API.

Each mock family has slightly different behaviour on purpose:
  - anthropic-mock  : finds most seeded issues, one deliberate false positive
  - deepseek-mock   : misses the CSP issue, flips one vote between forward/reverse passes
  - nemotron-mock   : conservative, abstains (refuses) on one dimension
This gives the consensus layer something real to disagree about in tests.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..config import ModelSpec
from .base import Completion, Provider


class MockProvider(Provider):
    def __init__(self, spec: ModelSpec, fixtures_dir: str | None = None):
        super().__init__(spec)
        self.fixtures = Path(fixtures_dir) if fixtures_dir else Path(__file__).resolve().parents[3] / "fixtures" / "mock-responses"
        self.calls: list[str] = []

    def _load(self, name: str) -> dict | None:
        p = self.fixtures / f"{name}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        self.calls.append(role)
        fam = self.spec.family.value
        kind, _, arg = role.partition(":")
        data = self._load(f"{kind}_{arg}_{fam}") if arg else None
        if data is None:
            data = self._load(f"{kind}_{fam}")
        if data is None:
            data = self._load(f"{kind}_default")
        if data is None:
            return Completion(data={"findings": []} if kind == "reviewer" else {"items": []}, raw_text="{}")
        if data.get("_refuse"):
            return Completion(data=None, raw_text="", refused=True)
        # Judge mocks may specify verdicts keyed by finding title so they survive shuffling.
        if kind == "judge":
            data = _resolve_judge(data, user)
        if kind in ("skeptic", "redteam"):
            data = _resolve_by_title(data, user)
        return Completion(data=data, raw_text=json.dumps(data))


def _parse_batch(user: str) -> list[dict]:
    marker = "BEGIN_JSON_ARRAY\n"
    if marker not in user:
        return []
    try:
        return json.loads(user[user.rindex(marker) + len(marker):])
    except json.JSONDecodeError:
        return []


def _resolve_judge(data: dict, user: str) -> dict:
    batch = _parse_batch(user)
    rules: dict = data.get("by_claim", {})
    default = data.get("default", {"verdict": "needs_human", "severity_band": "Medium", "reason": "no rule"})
    flip_on_reverse: list[str] = data.get("flip_on_reverse", [])
    is_reverse = "pass_id: reverse" in user
    items = []
    for item in batch:
        rule = dict(_best_rule(rules, item.get("claim", ""), default))
        if is_reverse and any(k.lower() in item.get("claim", "").lower() for k in flip_on_reverse):
            rule["verdict"] = "false_positive" if rule["verdict"] == "true_positive" else "true_positive"
        items.append({"finding_id": item["finding_id"], **rule})
    return {"items": items}


def _resolve_by_title(data: dict, user: str) -> dict:
    batch = _parse_batch(user)
    rules: dict = data.get("by_claim", {})
    default = data.get("default", {})
    items = []
    for item in batch:
        rule = dict(_best_rule(rules, item.get("claim", ""), default))
        items.append({"finding_id": item["finding_id"], **rule})
    return {"items": items}


def _best_rule(rules: dict, claim: str, default: dict) -> dict:
    """Longest matching key wins, so 'SQL injection' beats 'order_id' for 'SQL injection ... order_id'."""
    best, best_len = default, -1
    for key, val in rules.items():
        if key.lower() in claim.lower() and len(key) > best_len:
            best, best_len = val, len(key)
    return best
