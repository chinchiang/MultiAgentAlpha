"""The reviewer round (GLOSSARY.md: reviewer round; mara.reviewer_round, at its interface): ids given in content order,
so the blinded view the judges see carries no trace of which findings one reviewer exchange returned, and duplicates
merged at one place by the same rule the rest of the review uses (mara.identity.same_place: one file, one weakness,
lines at most NEAR_LINES apart), never an unverified finding into a verified one."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mara import reviewer_round
from mara.audit import Audit
from mara.config import load_config
from mara.context.repo_map import RepoContext
from mara.progress import Progress
from mara.providers.base import STOP_END, Provider, RawReply
from mara.schemas import Finding, ModelFamily, Provenance

ROOT = Path(__file__).resolve().parents[1]
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CONTENT = {"a.py": "query(user_input)\n" + "\n" * 7 + "exec(user_input)\n", "b.py": "\n" * 8 + "eval(user_input)\n"}


def _reply(*places: tuple[str, int, str]) -> dict:
    return {"findings": [{"title": f"injection at {file}:{line}", "cwe": "CWE-94", "standard_refs": [],
                          "provenance": [{"file": file, "line": line, "quote": quote}], "reachability": "reachable",
                          "reachability_argument": "user input reaches it", "exploit_sketch": "send code",
                          "cvss4_vector": VECTOR, "model_confidence": 0.8} for file, line, quote in places]}


def _answering(spec, data: dict) -> Provider:
    class Answering(Provider):
        def complete(self, **kwargs):
            return RawReply(STOP_END, answer_text=json.dumps(data))

    return Answering(spec)


def test_ids_follow_the_findings_place_not_the_order_the_reviewers_answered_in(tmp_path):
    """The first reviewer asked reports the last places in the file order, b.py before a.py; the ids still run a.py:1,
    a.py:9, b.py:9 (three places, none merged)."""
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    cfg = cfg.model_copy(update={"dimensions": ["vulnerabilities"]})
    first, second, third = cfg.roles.reviewers
    answers = {first: _reply(("b.py", 9, "eval(user_input)"), ("a.py", 9, "exec(user_input)")),
               second: _reply(("a.py", 1, "query(user_input)")), third: {"findings": []}}
    providers = {n: _answering(cfg.model_by_name(n), answers[n]) for n in cfg.roles.reviewers}
    said: list[str] = []
    audit = Audit()
    found = reviewer_round.run(RepoContext(root=tmp_path, content=CONTENT), None, cfg=cfg, providers=providers, audit=audit,
                               say=said.append, progress=Progress(), egress_blocked=False)
    assert [(f.id, f.provenance[0].file, f.provenance[0].line) for f in found.findings] == [
        ("F-0001", "a.py", 1), ("F-0002", "a.py", 9), ("F-0003", "b.py", 9)]
    assert found.raw_count == 3 and audit["findings_raw"] == 3 and audit["findings_deduped"] == 3 and len(said) == 3


def test_no_reviewer_is_asked_when_the_secret_preflight_blocked_source_egress(tmp_path):
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")

    asked: list[str] = []

    class Recording(Provider):
        # recorded, not raised: review_dimension counts a provider's exception as an error reply and goes on
        def complete(self, **kwargs):
            asked.append(self.spec.name)
            return RawReply(STOP_END, answer_text=json.dumps(_reply(("a.py", 1, "query(user_input)"))))

    providers = {n: Recording(cfg.model_by_name(n)) for n in cfg.roles.reviewers}
    audit = Audit()
    found = reviewer_round.run(RepoContext(root=tmp_path, content=CONTENT), None, cfg=cfg, providers=providers, audit=audit,
                               say=lambda _: None, progress=Progress(), egress_blocked=True)
    assert asked == [], "no reviewer is asked"
    assert found.findings == [] and found.raw_count == 0 and audit["findings_raw"] == 0 and audit["findings_deduped"] == 0


def _f(fid: str, file: str, line: int, cwe: str = "CWE-89", *, fam: ModelFamily = ModelFamily.ANTHROPIC,
       dimension: str = "vulnerabilities", verified: bool = True) -> Finding:
    return Finding(id=fid, dimension=dimension, title="t", cwe=cwe,
                   provenance=[Provenance(file=file, line=line, quote="unsafe()", verified=verified)],
                   reachability="reachable", reachability_argument="a", exploit_sketch="b", cvss4_vector=VECTOR,
                   model_confidence=0.5, source_family=fam, source_model="m")


@pytest.mark.parametrize("other, merged", [
    (_f("F-2", "app.py", 13, fam=ModelFamily.DEEPSEEK), True),            # 3 lines apart: one place
    (_f("F-2", "./app.py", 7, fam=ModelFamily.DEEPSEEK), True),           # the same file, spelled with ./
    (_f("F-2", "app.py", 14, fam=ModelFamily.DEEPSEEK), False),           # 4 lines apart
    (_f("F-2", "app.py", 10, "CWE-79", fam=ModelFamily.DEEPSEEK), False),  # another weakness
    (_f("F-2", "lib/app.py", 10, fam=ModelFamily.DEEPSEEK), False),       # another file
    (_f("F-2", "app.py", 10, fam=ModelFamily.DEEPSEEK, dimension="xss"), False),  # another dimension
    (_f("F-2", "app.py", 10, fam=ModelFamily.DEEPSEEK, verified=False), False),   # never unverified into verified
])
def test_two_findings_are_merged_exactly_when_they_are_at_one_place_in_one_dimension_and_equally_verified(other, merged):
    kept, finders = reviewer_round.dedupe([_f("F-1", "app.py", 10), other])
    assert [k.id for k in kept] == (["F-1"] if merged else ["F-1", "F-2"])
    assert finders["F-1"] == ({ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK} if merged else {ModelFamily.ANTHROPIC})


def test_a_finding_built_around_the_validation_is_merged_by_its_normalised_weakness():
    """A finding whose CWE was set without validation (model_copy does not validate) is still the same weakness as its
    normalised spelling, as it is to corroboration and calibration (mara.identity.same_place)."""
    spelled = _f("F-2", "app.py", 10, fam=ModelFamily.DEEPSEEK).model_copy(update={"cwe": " cwe-89 "})
    kept, finders = reviewer_round.dedupe([_f("F-1", "app.py", 10), spelled])
    assert [k.id for k in kept] == ["F-1"] and finders["F-1"] == {ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK}
