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
import re
from pathlib import Path

from ..config import ModelSpec
from .base import Completion, Provider

_FILE_BLOCK = re.compile(r'<file path="([^"]*)">\n(.*?)\n</file>', re.S)
_NUMBERED_LINE = re.compile(r"^\s*(\d+)\| (.*)$", re.M)
_MANIFEST_NAMES = {"requirements.txt", "package.json", "pyproject.toml", "poetry.lock", "go.mod", "pom.xml",
                   "build.gradle", "Gemfile", "composer.json", "Cargo.toml"}
_DB_HINTS = ("sqlite3.connect(", ".connect(", "create_engine(", "MongoClient(", "redis.Redis(")
_ROUTE_HINTS = ("@app.route(", "@app.get(", "@app.post(", "@router.", "app.get(", "app.post(")
# same citation pattern the skeptic harness verifies (assessment #33)
_CONTROL_REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_./\\-]*:\d+")


class MockProvider(Provider):
    def __init__(self, spec: ModelSpec, fixtures_dir: str | None = None):
        super().__init__(spec)
        self.fixtures = Path(fixtures_dir) if fixtures_dir else Path(__file__).resolve().parents[3] / "fixtures" / "mock-responses"
        self.calls: list[str] = []
        self.labels: list[dict] | None = None
        self.sample = ""

    def bind_target(self, root) -> None:
        from . import mock_labels

        self.labels = mock_labels.load_labels(root)
        self.sample = Path(root).name
        if self.labels is not None:
            mock_labels.remember_first_lines(root)

    def _load(self, name: str) -> dict | None:
        p = self.fixtures / f"{name}.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        self.calls.append(role)
        fam = self.spec.family.value
        kind, _, arg = role.partition(":")
        if kind == "context":
            return _context_response(user)
        if self.labels is not None:
            return _label_driven(self, kind, arg, fam, user)
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
            if kind == "skeptic":
                data = _fill_control_citation(data, user)
        return Completion(data=data, raw_text=json.dumps(data))


def _label_driven(self: MockProvider, kind: str, arg: str, fam: str, user: str) -> Completion:
    from . import mock_labels

    if kind == "reviewer":
        data = mock_labels.reviewer_response(fam, arg, self.labels or [], self.sample)
        if data is None:
            return Completion(data=None, raw_text="", refused=True)
        return Completion(data=data, raw_text=json.dumps(data))
    if kind == "judge":
        data = _resolve_judge(mock_labels.judge_rules(fam), user)
    elif kind == "skeptic":
        data = _fill_control_citation(_resolve_by_title(mock_labels.SKEPTIC_RULES, user), user)
    elif kind == "redteam":
        data = _resolve_by_title(mock_labels.REDTEAM_RULES, user)
    else:
        data = {"items": []}
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


def _fill_control_citation(data: dict, user: str) -> dict:
    """Label/fixture rules may cite a control by phrase only ('parameterised query'); the
    skeptic harness (#33) downgrades refuted verdicts whose citation has no verifiable
    path:line, so the mock pins such citations to the finding's own evidence location."""
    batch = {i.get("finding_id"): i for i in _parse_batch(user)}
    for it in data.get("items", []):
        if it.get("verdict") != "refuted" or _CONTROL_REF.search(it.get("sanitizer_or_control", "")):
            continue
        evidence = (batch.get(it.get("finding_id")) or {}).get("evidence") or []
        if evidence and evidence[0].get("file") and evidence[0].get("line"):
            phrase = (f"{evidence[0]['file']}:{evidence[0]['line']} " + it.get("sanitizer_or_control", "")).strip()
            it["sanitizer_or_control"] = phrase[:300]
    return data


def _context_response(user: str) -> Completion:
    """Deterministic C4-lite view parsed from the bundle itself: a container per application
    file, trust boundaries at HTTP entry points, data stores at connection lines, external
    systems from CI workflows and manifests. Every citation is an exact bundle line, so all
    the quote verifications the harness runs on context items pass."""
    files: dict[str, list[tuple[int, str]]] = {}
    for m in _FILE_BLOCK.finditer(user):
        files[m.group(1)] = [(int(n), t) for n, t in _NUMBERED_LINE.findall(m.group(2))]

    def first_non_empty(path: str) -> tuple[int, str] | None:
        return next(((n, t) for n, t in files.get(path, []) if t.strip()), None)

    def item(kind: str, name: str, path: str | None, quote: str | None = None, technology: str = "") -> dict | None:
        if path is None:
            return None
        if quote is not None:
            quote = quote[:400]
            # the citation must resolve to the exact line the quote came from, or the item
            # would fail the harness's quote verification
            line = next((n for n, t in files.get(path, []) if t == quote or t.startswith(quote)), None)
            if line is None:
                return None
        else:
            hit = first_non_empty(path)
            if not hit:
                return None
            line, quote = hit
        if not quote.strip():
            return None
        out = {"name": name[:80], "file": path, "line": line, "quote": quote}
        if technology:
            out["technology"] = technology[:80]
        return out

    py_files = [p for p in files if p.endswith(".py")]
    containers, external, boundaries, stores = [], [], [], []
    if py_files:
        first = py_files[0]
        hit = first_non_empty(first)
        if hit:
            containers.append(item("container", "application", first, quote=hit[1], technology="python"))
            for _, t in files[first]:
                if any(h in t for h in _ROUTE_HINTS):
                    boundaries.append(item("trust_boundary", f"HTTP entry point: {t.strip().strip('@')[:70]}", first, quote=t))
                    if len(boundaries) >= 6:
                        break
        for p in py_files:
            store = next((item("data_store", "database", p, quote=t) for _, t in files[p] if any(h in t for h in _DB_HINTS)), None)
            if store:
                stores.append(store)
                break
    workflows = [p for p in files if p.startswith(".github/workflows/")]
    if workflows:
        external.append(item("external_system", "CI/CD (GitHub Actions)", workflows[0]))
    manifests = [p for p in files if Path(p).name in _MANIFEST_NAMES]
    if manifests:
        external.append(item("external_system", "package registry", manifests[0]))
    data = {"containers": [c for c in containers if c], "external_systems": [e for e in external if e],
            "trust_boundaries": [b for b in boundaries if b], "data_stores": [s for s in stores if s]}
    return Completion(data=data, raw_text=json.dumps(data))
