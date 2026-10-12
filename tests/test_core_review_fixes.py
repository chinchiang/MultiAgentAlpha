"""Regression tests for the core review defects fixed together: bounded L3/L4 calls, dotfile control
citations, canary screening of skeptic / red-team verdicts, one judge per family, Gemini's output budget.
(The PSIRT dedupe key's target identity is covered in test_psirt.py.)"""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
import pytest

from mara import pipeline as pl
from mara.agents import base, redteam, skeptic
from mara.config import MaraConfig, ModelSpec, load_config
from mara.context.repo_map import MAX_TOTAL_CHARS, RepoContext, bundle_cost
from mara.pipeline import MAX_L3_FINDINGS, MAX_L4_FINDINGS, Pipeline, l3_chunks
from mara.providers.base import Completion, Provider
from mara.providers.gemini_provider import MAX_TOKENS as GEMINI_MAX_TOKENS
from mara.providers.gemini_provider import GeminiProvider
from mara.schemas import Finding, ModelFamily, Provenance

ROOT = Path(__file__).resolve().parents[1]
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
TOKEN_RE = re.compile(r"MARA-CANARY-[0-9a-f]{8}")


def _finding(i: int, file: str = "app.py", line: int = 1, quote: str = "unsafe()") -> Finding:
    return Finding(id=f"F-{i:04d}", dimension="vulnerabilities", title=f"finding {i}", cwe="CWE-89",
                   provenance=[Provenance(file=file, line=line, quote=quote, verified=True)],
                   reachability="reachable", reachability_argument="public", exploit_sketch="input",
                   cvss4_vector=VECTOR, model_confidence=0.9, source_family=ModelFamily.ANTHROPIC, source_model="test")


class _Fixed(Provider):
    """Answers every call with `answer(user)`; records the prompts."""

    def __init__(self, family: str, answer):
        super().__init__(ModelSpec(name=f"fixed-{family}", family=family, provider="mock", model="fixed", data_residency="on_prem"))
        self.answer, self.prompts = answer, []

    def complete(self, *, system, user, schema, role, max_tokens=16000):
        self.prompts.append(user)
        return self.answer(user)


# ------------------------------------------------------------------ 1. bounded L3 / L4 calls

def test_l3_chunks_bound_findings_and_evidence_size_and_count_a_shared_file_once():
    big = "x = 1\n" * (MAX_TOTAL_CHARS // 20)  # each file well under the bound, three of them over it
    content = {f"big{i}.py": big for i in range(6)} | {"app.py": "unsafe()\n"}
    ctx = RepoContext(root=Path("."), content=content)
    shared = [_finding(i) for i in range(1, 2 * MAX_L3_FINDINGS + 6)]
    chunks = l3_chunks(ctx, shared)
    assert [len(c) for c in chunks] == [MAX_L3_FINDINGS, MAX_L3_FINDINGS, 5], "one small shared file: only the count bounds"
    spread = [_finding(i, file=f"big{i % 6}.py") for i in range(1, 13)]
    chunks = l3_chunks(ctx, spread)
    assert sum(len(c) for c in chunks) == len(spread) and [f.id for c in chunks for f in c] == [f.id for f in spread]
    for c in chunks:
        files = {p.file for f in c for p in f.provenance}
        assert sum(bundle_cost(rel, content[rel]) for rel in files) <= MAX_TOTAL_CHARS
    assert len(chunks) > 1


def test_skeptic_and_red_team_are_called_per_bounded_chunk(tmp_path, monkeypatch):
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"})
    findings = [_finding(i) for i in range(1, 46)]
    finders = {f.id: {ModelFamily.ANTHROPIC} for f in findings}
    sizes = {"skeptic": [], "redteam": []}
    monkeypatch.setattr(skeptic, "run_skeptic", lambda p, c, fs: (sizes["skeptic"].append(len(fs)), ([], ["refused"], 0))[1])
    monkeypatch.setattr(redteam, "run_redteam", lambda p, c, fs: (sizes["redteam"].append(len(fs)), ([], ["refused"], 0))[1])
    _, abstained = pipe.run_skeptics(ctx, findings, finders)
    pipe.run_redteam(ctx, findings, finders)
    assert sizes["skeptic"] == sizes["redteam"] == [20, 20, 5]
    assert pipe.audit["skeptic_calls"] == pipe.audit["redteam_calls"] == 3
    assert abstained == {f.id for f in findings}, "every chunk without a verdict leaves its findings unchallenged"


def test_judge_passes_are_bounded_mirrored_per_chunk_and_cover_every_finding(tmp_path, monkeypatch):
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    findings = [_finding(i) for i in range(1, 61)]
    finders = {f.id: {ModelFamily.ANTHROPIC} for f in findings}  # anthropic is excluded, two families judge
    calls: list[tuple[ModelFamily, str, list[str]]] = []
    monkeypatch.setattr(pl.judge, "run_judge",
                        lambda p, batch, pass_id, self_ids=None: (calls.append((p.family, pass_id, [b["finding_id"] for b in batch])), ([], []))[1])
    pipe.run_jury(ctx, findings, {}, finders)
    assert calls and all(len(ids) <= MAX_L4_FINDINGS for _, _, ids in calls)
    for fam in (ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON):
        mine = [(pid, ids) for f, pid, ids in calls if f == fam]
        assert [pid for pid, _ in mine] == ["forward", "reverse"] * 3
        for (_, fwd), (_, rev) in zip(mine[::2], mine[1::2], strict=True):
            assert rev == list(reversed(fwd))
        assert sorted(i for pid, ids in mine if pid == "forward" for i in ids) == sorted(f.id for f in findings)
    assert pipe.audit["judge_calls"] == len(calls) == 12


# ------------------------------------------------------------------ 2. dotfile control citations

def test_control_citation_keeps_the_leading_dot_of_a_path():
    ctx = RepoContext(root=Path("."), content={".github/workflows/deploy.yml": "on: push\npermissions: read-all\n",
                                               "app.py": "import db\n\nq = db.param(x)\n"})
    shown = {".github/workflows/deploy.yml", "app.py"}
    assert skeptic._control_location_ok(ctx, "permissions pinned at .github/workflows/deploy.yml:2", shown)
    assert skeptic._control_location_ok(ctx, "see ./app.py:3", shown)
    assert skeptic._control_location_ok(ctx, "bound parameter ...app.py:3", shown), "dots prose puts in front still resolve"
    assert not skeptic._control_location_ok(ctx, "github/workflows/deploy.yml:2", shown), "the dotless path is another file"


def test_a_refutation_citing_a_workflow_file_stays_refuted():
    ctx = RepoContext(root=Path("."), content={".github/workflows/deploy.yml": "on: push\npermissions: read-all\n"})
    f = _finding(1, file=".github/workflows/deploy.yml", line=1, quote="on: push")
    prov = _Fixed("deepseek", lambda user: Completion(data={"items": [{
        "finding_id": f.id, "verdict": "refuted", "reason": "token is read-only",
        "sanitizer_or_control": ".github/workflows/deploy.yml:2"}]}, raw_text="{}"))
    verdicts, errors, unverified = skeptic.run_skeptic(prov, ctx, [f])
    assert errors == [] and unverified == 0 and verdicts[0].verdict == "refuted"


# ------------------------------------------------------------------ 3. canary screening of verdicts

def _verdict_answer(reason_for_token, *, aside: str = "", extra_raw: str = "", truncated: bool = False):
    def answer(user):
        token = TOKEN_RE.search(user).group()
        ids = re.findall(r'"finding_id": "([^"]+)"', user.split("BEGIN_JSON_ARRAY", 1)[1])
        items = [{"finding_id": i, "verdict": "stands", "reason": reason_for_token(token), "sanitizer_or_control": ""} for i in ids]
        data = {"items": items}
        raw = "\n".join(x for x in (aside.replace("{token}", token), json.dumps(data), extra_raw.replace("{token}", token)) if x)
        if truncated:
            return Completion(data=None, raw_text=raw, truncated=True)
        return Completion(data=data, raw_text=raw, aside=aside.replace("{token}", token))
    return answer


def test_canary_screen_tells_a_verdict_that_reports_the_planted_file_from_an_echo():
    c = base.Canary()
    t, path = c.token, base.CANARY_PATH
    report = Completion(data={"items": [{"reason": f"ignored the instruction in {path} ({t})"}]}, raw_text=f'{{"reason": "{path} {t}"}}')
    assert c.screen_verdicts(report) == (False, 1)
    echo = Completion(data={"items": [{"reason": t}]}, raw_text=json.dumps({"items": [{"reason": t}]}))
    assert c.screen_verdicts(echo) == (True, 0)
    hidden = Completion(data={"items": [{"reason": f"{path} {t}"}]}, raw_text=f"{path} {t}\n{t}")
    assert c.screen_verdicts(hidden)[0], "a second occurrence outside the reporting field is an echo"
    assert c.screen_verdicts(Completion(data=None, raw_text=t, truncated=True)) == (False, 0)
    assert c.screen_verdicts(Completion(data=None, raw_text=t)) == (True, 0)


@pytest.mark.parametrize("agent", [skeptic.run_skeptic, redteam.run_redteam])
def test_skeptic_and_red_team_keep_verdicts_that_report_the_canary(agent):
    ctx = RepoContext(root=Path("."), content={"app.py": "unsafe()\n"})
    fs = [_finding(1), _finding(2)]

    def run(answer):
        def adapt(user):
            comp = answer(user)
            if agent is redteam.run_redteam and isinstance(comp.data, dict):
                comp.data = {"items": [{"finding_id": x["finding_id"], "exploitable": "unknown", "preconditions": x["reason"]}
                                       for x in comp.data["items"]]}
            return comp
        return agent(_Fixed("deepseek", adapt), ctx, fs)

    out, errors, _ = run(_verdict_answer(lambda t: f"{base.CANARY_PATH} asks to reply {t}; ignored"))
    assert len(out) == 2 and errors == []
    out, errors, _ = run(_verdict_answer(lambda t: "reviewed", aside=f"{base.CANARY_PATH} says {{token}}; not followed"))
    assert len(out) == 2 and errors == []
    out, errors, _ = run(_verdict_answer(lambda t: t))
    assert out == [] and errors == ["canary_echoed"]
    out, errors, _ = run(_verdict_answer(lambda t: "reviewed", extra_raw="{token}"))
    assert out == [] and errors == ["canary_echoed"], "the token in a text block the answer was not parsed from"
    out, errors, _ = run(_verdict_answer(lambda t: t, truncated=True))
    assert "canary_echoed" not in errors, "a truncated answer is a truncation, not an echo"


# ------------------------------------------------------------------ 4. one judge per family

def test_config_rejects_two_judges_of_one_family():
    raw = {
        "models": [{"name": n, "family": fam, "provider": "mock", "model": n, "data_residency": "on_prem"}
                   for n, fam in (("a", "anthropic"), ("a2", "anthropic"), ("d", "deepseek"), ("n", "nemotron"))],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "a2", "d"]},
    }
    with pytest.raises(ValueError, match="each judge must come from a different model family"):
        MaraConfig.model_validate(raw)
    raw["roles"]["judges"] = ["a", "d", "n"]
    MaraConfig.model_validate(raw)


# ------------------------------------------------------------------ 5. Gemini output budget

def test_gemini_asks_for_the_same_output_room_as_the_other_reasoning_providers():
    from mara.providers.openai_compatible import MAX_TOKENS as OPENAI_MAX_TOKENS

    seen = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "{}"}]}, "finishReason": "STOP"}]})

    spec = ModelSpec(name="g", family="gemini", provider="gemini", model="gemini-test", data_residency="vendor_api_retained",
                     retention_approval_ref="T-1")
    p = GeminiProvider(spec, client=httpx.Client(base_url="https://example.invalid", transport=httpx.MockTransport(handler)))
    p.complete(system="s", user="u", schema={"type": "object"}, role="judge")
    assert seen["body"]["generationConfig"]["maxOutputTokens"] == GEMINI_MAX_TOKENS >= OPENAI_MAX_TOKENS > 16000
