"""The gate severity (GLOSSARY.md; schemas.ConsensusResult.gate_severity) and what feeds it: one reviewer writes a
finding's CVSS vector and no judge sees it, so the vector alone must not decide whether an accepted finding blocks. A
reviewer's vector carries base metrics only (mara.agents.reviewer.base_vector_only), merged findings keep the highest
vector any finder gave (mara.reviewer_round.dedupe), and the tier C rule and the dimension score read the higher of the
vector's severity and the judges' bands, as the gate does (tests/test_review_status.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mara import reviewer_round
from mara.agents.reviewer import base_vector_only
from mara.audit import Audit
from mara.config import load_config
from mara.context.repo_map import RepoContext
from mara.progress import Progress
from mara.providers.base import STOP_END, Provider, RawReply
from mara.report.psirt_out import select_psirt_findings
from mara.report.sarif_out import to_sarif
from mara.schemas import Finding, JudgeVote, ModelFamily, Provenance, ReviewReport
from mara.scoring import cvss4
from mara.scoring.dimension_score import score_dimension
from mara.workspace import Workspace  # noqa: E402
from tests import scored_rows

ROOT = Path(__file__).resolve().parents[1]
BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3 Critical
LOW = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"  # Low


# ---------------------------------------------------------------- a reviewer's vector carries base metrics only


@pytest.mark.parametrize("suffix", ["/MVC:N/MVI:N/MVA:N", "/E:U", "/E:P", "/CR:L", "/MAV:P", "/MSI:S"])
def test_a_vector_with_a_threat_or_an_environmental_metric_is_refused(suffix):
    cvss4.score(BASE + suffix)  # it parses and scores: the refusal is the reviewer exchange's, not the scorer's
    with pytest.raises(ValueError, match="threat or environmental"):
        base_vector_only(BASE + suffix)


@pytest.mark.parametrize("suffix", ["", "/S:P", "/AU:Y/R:I", "/U:Red"])
def test_a_base_vector_with_or_without_supplemental_metrics_is_taken_as_given(suffix):
    assert base_vector_only(BASE + suffix) == BASE + suffix
    assert cvss4.score(BASE + suffix) == 9.3


def _reply(vector: str) -> dict:
    return {"findings": [{"title": "injection", "cwe": "CWE-94", "standard_refs": [],
                          "provenance": [{"file": "a.py", "line": 1, "quote": "exec(user_input)"}], "reachability": "reachable",
                          "reachability_argument": "user input reaches it", "exploit_sketch": "send code",
                          "cvss4_vector": vector, "model_confidence": 0.8}]}


def _review(tmp_path, answers: list[dict]):
    """A reviewer round of one dimension in which the config's reviewers give `answers`, in order."""
    cfg = load_config(ROOT / "config" / "mara.mock.yaml", Workspace(ROOT)).model_copy(update={"dimensions": ["vulnerabilities"]})

    def answering(spec, data):
        class Answering(Provider):
            def complete(self, **kwargs):
                return RawReply(STOP_END, answer_text=json.dumps(data))

        return Answering(spec)

    providers = {n: answering(cfg.model_by_name(n), a) for n, a in zip(cfg.roles.reviewers, answers, strict=True)}
    audit = Audit()
    found = reviewer_round.run(RepoContext(root=tmp_path, content={"a.py": "exec(user_input)\n"}), None, cfg=cfg, providers=providers,
                               audit=audit, say=lambda _m: None, progress=Progress(), egress_blocked=False)
    return found, audit


def test_a_reviewers_finding_whose_vector_zeroes_itself_is_an_invalid_item_not_a_finding_of_no_severity(tmp_path):
    """`/MVC:N/MVI:N/MVA:N` takes the 9.3 to 0.0 "None": taken as given, the finding could be accepted and never block."""
    zeroed = BASE + "/MVC:N/MVI:N/MVA:N"
    assert cvss4.score(zeroed) == 0.0
    found, audit = _review(tmp_path, [_reply(zeroed), {"findings": []}, {"findings": []}])
    assert found.findings == [] and audit["invalid_findings_dropped"] == 1
    assert "invalid_findings_dropped" in audit.incomplete_reasons(), "and the review is incomplete for it"


# ---------------------------------------------------------------- merged findings keep the highest vector


def _f(fid: str, vector: str, fam: ModelFamily, line: int = 10) -> Finding:
    return Finding(id=fid, dimension="vulnerabilities", title="t", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=line, quote="unsafe()", verified=True)],
                   reachability="reachable", reachability_argument="a", exploit_sketch="b", cvss4_vector=vector,
                   model_confidence=0.5, source_family=fam, source_model="m")


def test_merged_findings_keep_the_highest_vector_whichever_finder_comes_first():
    low_first = reviewer_round.dedupe([_f("F-1", LOW, ModelFamily.ANTHROPIC, 10), _f("F-2", BASE, ModelFamily.DEEPSEEK, 11),
                                       _f("F-3", BASE, ModelFamily.NEMOTRON, 12)])
    high_first = reviewer_round.dedupe([_f("F-1", BASE, ModelFamily.ANTHROPIC, 10), _f("F-2", LOW, ModelFamily.DEEPSEEK, 11)])
    assert [(k.id, k.cvss4_vector, len(k.finder_families)) for k in low_first] == [("F-1", BASE, 3)]
    assert [(k.id, k.cvss4_vector) for k in high_first] == [("F-1", BASE)]


def test_a_finding_that_is_not_merged_keeps_its_own_vector():
    kept = reviewer_round.dedupe([_f("F-1", LOW, ModelFamily.ANTHROPIC, 10), _f("F-2", BASE, ModelFamily.DEEPSEEK, 40)])
    assert [(k.id, k.cvss4_vector) for k in kept] == [("F-1", LOW), ("F-2", BASE)]


# ---------------------------------------------------------------- the tier C rule and the dimension score read it


def _votes(fid: str, band: str) -> list[JudgeVote]:
    return [v.model_copy(update={"severity_band": band}) for v in scored_rows.votes(fid, scored_rows.CONFIRMED)]


def test_a_tier_c_finding_the_judges_call_critical_goes_to_a_human_although_its_vector_is_medium():
    """The tier C floor (queue_tier_c_min_severity, High) read the vector's severity alone: a finder that wrote Medium
    kept its own unargued finding away from the human the rule sends it to."""
    f = scored_rows.finding(severity="Medium", reachability="unknown")
    (called_critical,) = scored_rows.score([f], _votes(f.id, "Critical")).rows
    (called_low,) = scored_rows.score([f], _votes(f.id, "Low")).rows
    assert (called_critical.tier.value, called_critical.cvss4_severity, called_critical.operational_severity,
            called_critical.gate_severity) == ("C", "Medium", "Critical", "Critical")
    assert called_critical.jury_outcome == "needs_human" and called_critical.human_reasons == ["tier_c_high"]
    assert (called_low.gate_severity, called_low.jury_outcome) == ("Medium", "accepted")


def test_the_dimension_score_counts_a_finding_at_its_gate_severity():
    f = scored_rows.finding(severity="Medium")
    (as_medium,) = scored_rows.score([f], _votes(f.id, "Medium")).rows
    (as_critical,) = scored_rows.score([f], _votes(f.id, "Critical")).rows
    assert as_medium.tier.value == as_critical.tier.value == "B" and as_medium.final_outcome == "accepted"
    assert score_dimension("vulnerabilities", [f], {f.id: as_medium}, tool_ran=True).score == 100 - 10 * 0.8
    assert score_dimension("vulnerabilities", [f], {f.id: as_critical}, tool_ran=True).score == 100 - 40 * 0.8


def test_the_dimension_score_counts_a_finding_a_human_confirmed_in_full_whatever_its_tier():
    f = scored_rows.finding(severity="Critical")
    dropped = scored_rows.row("dropped", severity="Critical")
    assert dropped.tier.value == "D"
    confirmed = dropped.model_copy(update={"human_decision": {"decision": "true_positive", "key": "k", "issue": 1, "decided_by": "a",
                                                               "decided_at": "2026-11-22"}})
    ruled_out = dropped.model_copy(update={"human_decision": {**confirmed.human_decision, "decision": "false_positive"}})
    assert score_dimension("vulnerabilities", [f], {f.id: confirmed}, tool_ran=True).score == 60.0  # 100 - 40, no tier D factor of 0
    assert score_dimension("vulnerabilities", [f], {f.id: ruled_out}, tool_ran=True).score == 100.0
    assert score_dimension("vulnerabilities", [f], {f.id: dropped}, tool_ran=True).score == 100.0


# ---------------------------------------------------------------- the PSIRT trigger and a code-scanning result's level read it


def _report(f: Finding, c) -> ReviewReport:
    d = score_dimension("vulnerabilities", [f], {f.id: c}, tool_ran=True)
    return ReviewReport(target="t", generated_at="now", provider_mode="mock", families_used=[], findings=[f], skeptic=[], redteam=[],
                        votes=[], consensus=[c], dimensions=[d], overall_score=None, gate_passed=False, bias_audit={})


def _accepted_medium_vector(band: str):
    f = scored_rows.finding(severity="Medium")
    (c,) = scored_rows.score([f], _votes(f.id, band)).rows
    assert (c.final_outcome, c.tier.value, c.cvss4_severity) == ("accepted", "B", "Medium")
    return f, c


def test_the_psirt_trigger_reads_the_gate_severity():
    cfg = load_config(ROOT / "config" / "mara.mock.yaml", Workspace(ROOT))
    cfg = cfg.model_copy(update={"psirt": cfg.psirt.model_copy(update={"enabled": True, "shipped": True, "trigger_tiers": ["A", "B"]})})
    assert cfg.psirt.trigger_severities == ["Critical"]
    f, called_critical = _accepted_medium_vector("Critical")
    _, called_medium = _accepted_medium_vector("Medium")
    assert [x[0].id for x in select_psirt_findings(_report(f, called_critical), cfg)] == [f.id]
    assert select_psirt_findings(_report(f, called_medium), cfg) == []


def test_a_code_scanning_results_level_is_that_of_its_gate_severity():
    f, called_critical = _accepted_medium_vector("Critical")
    _, called_medium = _accepted_medium_vector("Medium")
    level = {band: to_sarif(_report(f, c))["runs"][0]["results"][0]["level"]
             for band, c in (("Critical", called_critical), ("Medium", called_medium))}
    assert level == {"Critical": "error", "Medium": "warning"}
