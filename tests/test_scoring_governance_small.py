"""Small scoring, report and governance fixes from the 2026-10-12 deep review: the judge's own weight,
needs-human findings are not "rejected", a far-future review_by cannot skip the yearly re-approval,
red-team status per family across evaluations, exact CyberSecEval model keys, and a governance
config outside the scanned root."""

import datetime as dt
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mara import govdocs  # noqa: E402
from mara import model_eval as me  # noqa: E402
from mara.ballot_round import Ballots  # noqa: E402
from mara.config import MaraConfig  # noqa: E402
from mara.report.markdown_out import render_markdown  # noqa: E402
from mara.schemas import Finding, JudgeVote, ModelFamily, Provenance, ReviewReport  # noqa: E402
from mara.scoring import jury  # noqa: E402
from mara.scoring.consensus import weighted_consensus  # noqa: E402
from mara.scoring.dimension_score import score_dimension  # noqa: E402
from tests import scored_rows  # noqa: E402

VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
ANTHROPIC = {"provider": "anthropic", "model": "claude-opus-5", "data_residency": "vendor_api_zdr"}
DEEPSEEK = {"provider": "openai_compatible", "model": "deepseek-v3.2", "base_url": "https://vllm-deepseek.internal:8000/v1",
            "data_residency": "on_prem"}
NEMOTRON = {"provider": "openai_compatible", "model": "nvidia/nemotron-3-super", "base_url": "https://192.168.10.5:8000/v1",
            "data_residency": "on_prem"}


def _cfg(models, judges):
    return MaraConfig.model_validate({
        "models": models,
        "roles": {"reviewers": [m["name"] for m in models], "skeptic": "n", "redteam": "d", "judges": judges},
    })


def _finding(fid="F-1"):
    return Finding(id=fid, dimension="vulnerabilities", title="t", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=3, quote="abc", verified=True)],
                   reachability_argument="r", exploit_sketch="e", cvss4_vector=VEC, model_confidence=0.9,
                   source_family=ModelFamily.NEMOTRON, source_model="n", finder_families=[ModelFamily.NEMOTRON])


def _vote(fam, pass_id, verdict):
    return JudgeVote(finding_id="F-1", verdict=verdict, severity_band="High", reason="r", judge_family=fam, judge_model="m",
                     presentation_order=0, pass_id=pass_id)


# ---------------------------------------------------------------- weights


def test_a_judge_votes_with_its_own_weight_not_a_same_family_reviewers(tmp_path, monkeypatch):
    """weights were {family: weight} over every model: a reviewer-only model of the judge's family,
    listed later, replaced the judge's calibrated weight. (P3 already keeps judges to one per family.)"""
    monkeypatch.chdir(tmp_path)
    cfg = _cfg([{"name": "a", "family": "anthropic", "weight": 2.0, **ANTHROPIC},
                {"name": "d", "family": "deepseek", **DEEPSEEK},
                {"name": "n", "family": "nemotron", **NEMOTRON},
                {"name": "a2", "family": "anthropic", "weight": 0.1, **ANTHROPIC}],
               judges=["a", "d", "n"])
    votes = [_vote(ModelFamily.ANTHROPIC, p, "true_positive") for p in ("forward", "reverse")] + \
            [_vote(ModelFamily.DEEPSEEK, p, "false_positive") for p in ("forward", "reverse")] + \
            [_vote(ModelFamily.NEMOTRON, p, "true_positive") for p in ("forward", "reverse")]
    ballots = Ballots(skeptic={}, unchallenged=frozenset(), redteam={}, votes=votes)
    (c,) = jury.score([_finding()], {"F-1": {ModelFamily.NEMOTRON}}, ballots, [], jury=jury.Jury.from_config(cfg),
                      policy=scored_rows.policy(cfg)).rows
    flagged = [v.model_copy(update={"self_family": v.judge_family == ModelFamily.NEMOTRON}) for v in votes]
    expected = weighted_consensus(flagged, {ModelFamily.ANTHROPIC: 2.0, ModelFamily.DEEPSEEK: 1.0, ModelFamily.NEMOTRON: 1.0},
                                  cfg.gate.self_judge_discount)[0]
    assert c.weighted_score == expected


# ---------------------------------------------------------------- needs-human is not rejected


def _awaiting():
    # tier C: confirmed, but its reachability went unargued; at Critical it needs a human
    return scored_rows.row("tier_c", severity="Critical")


def test_a_finding_awaiting_a_human_is_not_counted_or_explained_as_rejected():
    d = score_dimension("vulnerabilities", [_finding()], {"F-1": _awaiting()}, tool_ran=True)
    assert (d.rejected_findings, d.human_queue) == (0, 1)
    report = ReviewReport(target="t", generated_at="now", provider_mode="mock", families_used=[], findings=[_finding()], skeptic=[],
                          redteam=[], votes=[], consensus=[_awaiting()], dimensions=[d], overall_score=None, gate_passed=False,
                          bias_audit={})
    line = next(x for x in render_markdown(report).splitlines() if x.startswith("- F-1 · t ·"))
    assert "below threshold" not in line and "awaiting human decision: tier_c_high" in line


def _under_rejection_review():
    """A rejected finding while policy P8 does not allow unsupervised rejection (docs/adr/0005-jury-outcome.md): tier A, a
    tool corroborates it and one of three independent judge families confirms it, so the jury needs a fourth judge."""
    return scored_rows.row("rejected")


def _report_of(c):
    d = score_dimension("vulnerabilities", [_finding()], {"F-1": c}, tool_ran=True)
    return d, ReviewReport(target="t", generated_at="now", provider_mode="mock", families_used=[], findings=[_finding()], skeptic=[],
                           redteam=[], votes=[], consensus=[c], dimensions=[d], overall_score=None, gate_passed=False, bias_audit={})


def test_a_rejection_under_review_counts_as_rejected_not_as_awaiting_a_decision():
    """ADR 0005: the jury decided it; rejection review is a human look, not an open outcome."""
    d, _ = _report_of(_under_rejection_review())
    assert (d.accepted_findings, d.rejected_findings, d.human_queue) == (0, 1, 0)


def test_the_report_says_a_rejection_is_under_review_until_a_human_rules_on_it():
    c = _under_rejection_review()
    _, report = _report_of(c)
    line = next(x for x in render_markdown(report).splitlines() if x.startswith("- F-1 · t ·"))
    assert line.endswith("· consensus 0.3333 below threshold · rejection review queued")
    ruled = c.model_copy(update={"human_decision": {"decision": "false_positive", "key": "k", "issue": 7, "decided_by": "alice",
                                                    "decided_at": "2026-10-14T00:00:00Z"}})
    _, report = _report_of(ruled)
    line = next(x for x in render_markdown(report).splitlines() if x.startswith("- F-1 · t ·"))
    assert "rejection review" not in line and "decided by human" in line


def test_the_dimension_table_counts_what_awaits_a_decision_under_that_name():
    """The third count is findings whose final outcome needs a human; the human queue also lists rejections under review."""
    _, report = _report_of(_awaiting())
    assert "| Dimension | Score | Accepted | Rejected | Awaiting decision | Tool ran |" in render_markdown(report).splitlines()


def test_the_cli_table_names_the_same_count_awaiting_decision(tmp_path):
    import re

    from typer.testing import CliRunner

    from mara.cli import app

    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock",
                                   "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(tmp_path / "out")],
                             env={"COLUMNS": "200"})  # wide enough that rich does not wrap the header
    header = next(x for x in re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", res.output).splitlines() if "Dimension" in x)
    assert [c.strip() for c in header.strip("┃│ ").split("┃")] == ["Dimension", "Score", "Accepted", "Rejected", "Awaiting decision", "Tool"]


# ---------------------------------------------------------------- G-1 review_by


def test_a_far_future_review_by_cannot_skip_the_yearly_re_approval(tmp_path):
    text = (ROOT / "docs" / "policy" / "mara-review-policy.md").read_text(encoding="utf-8")
    text = text.replace("status: draft ", "status: approved ").replace('approved_by: ""', 'approved_by: "pso-login"') \
        .replace('approved_on: ""', 'approved_on: "2026-09-01"').replace('review_by: ""', 'review_by: "2099-01-01"')
    p = tmp_path / "policy.md"
    p.write_text(text, encoding="utf-8")
    st = govdocs.policy_status(p, dt.date(2026, 10, 1))
    assert not st.ok and any("review_by" in x and "365" in x for x in st.problems)
    assert govdocs.policy_status(p, dt.date(2027, 9, 2)).state == "stale"


# ---------------------------------------------------------------- model eval


def _summary(root, date, families, mode="live"):
    (root / "calib").mkdir(exist_ok=True)
    (root / "calib" / f"model-eval-{date}.json").write_text(json.dumps(
        {"date": date, "mode": mode, "families": {f: {"verdict": {"overall": v}} for f, v in families.items()}}), encoding="utf-8")


def test_family_eval_status_reads_each_familys_latest_evaluation(tmp_path):
    """Only the newest summary was read: evaluating one family made every other family 'none', and a
    malformed newest file hid every earlier evaluation."""
    _summary(tmp_path, "2026-09-01", {"glm": "pass", "gemini": "fail"})
    _summary(tmp_path, "2026-09-12", {"gemini": "pass"})
    (tmp_path / "calib" / "model-eval-2026-09-20.json").write_text("{not json", encoding="utf-8")
    assert me.family_eval_status(tmp_path, ["gemini", "glm", "anthropic"]) == {
        "gemini": {"date": "2026-09-12", "mode": "live", "status": "pass"},
        "glm": {"date": "2026-09-01", "mode": "live", "status": "pass"},
        "anthropic": {"date": None, "mode": None, "status": "none"},
    }


def test_cyberseceval_stats_bind_to_the_exact_model_not_a_substring(tmp_path):
    stats = {"stat_per_model": {"gpt-4o-mini": {"total_count": 10, "injection_successful_count": 9}}}
    p = tmp_path / "pi.json"
    p.write_text(json.dumps(stats), encoding="utf-8")
    with pytest.raises(ValueError, match="no stat_per_model entry"):
        me.parse_cse_prompt_injection(p, "gpt-4o")
    stats["stat_per_model"]["OPENAI::gpt-4o"] = {"total_count": 10, "injection_successful_count": 1}
    p.write_text(json.dumps(stats), encoding="utf-8")
    assert me.parse_cse_prompt_injection(p, "gpt-4o")["model_key"] == "OPENAI::gpt-4o"


# ---------------------------------------------------------------- governance_check --config


def test_governance_check_takes_a_config_outside_the_scanned_root(tmp_path):
    from governance_check import run_all

    cfg = tmp_path / "mara.yaml"
    shutil.copy(ROOT / "config" / "mara.yaml", cfg)
    results = {r.id: r for r in run_all(ROOT, cfg, dt.date(2026, 9, 12))}
    assert cfg.as_posix() in results["G-2"].evidence and cfg.as_posix() in results["G-3"].evidence
