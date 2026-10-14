"""Human-resolved findings (docs/adr/0003-human-resolution.md): on a review of the same content, a usable
decision settles its finding - the human ruling outranks the jury in both directions - while the jury
outcome stays as the pipeline concluded it, for calibration."""

import json
from pathlib import Path

import pytest

from mara.config import load_config
from mara.pipeline import Pipeline

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
            "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n")


@pytest.fixture
def home(tmp_path, monkeypatch):
    """A MARA workspace with alice as a trained adjudicator; the working directory elsewhere."""
    h = tmp_path / "mara-home"
    (h / "training").mkdir(parents=True)
    (h / "training" / "records.yaml").write_text(REGISTER, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(h))
    monkeypatch.chdir(elsewhere)
    return h


def review(home, name="out", cfg=None):
    cfg = cfg or load_config(ROOT / "config" / "mara.mock.yaml")
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=home / name)
    return pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")


def decide(home, item, decision, *, by="alice", issue=1):
    """What `human_queue_issues.py --sync-decisions` writes for a closed ticket on this queue item."""
    rec = {k: getattr(item, k) for k in ("key", "target_id", "revision", "context_hash", "file", "line", "cwe")}
    rec.update(decision=decision, decision_event_id=1000 + issue, decided_by=by, decided_at="2026-10-01T08:00:00Z", issue=issue,
               finding_id=item.finding_id)
    d = home / "calib" / "decisions"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{item.key}.json").write_text(json.dumps(rec), encoding="utf-8")


def test_decided_findings_are_settled_on_a_review_of_the_same_content(home):
    first = review(home)
    assert "unresolved_human_review" in first.incomplete_reasons and first.human_queue
    for n, item in enumerate(first.human_queue, 1):
        decide(home, item, "false_positive", issue=n)
    second = review(home, "out2")
    assert second.human_queue == []
    assert "unresolved_human_review" not in second.incomplete_reasons
    cons = {c.finding_id: c for c in second.consensus}
    for item in first.human_queue:
        c = cons[item.finding_id]
        assert c.resolved_by_human and c.final_outcome == "rejected"
        assert c.needs_human, "the jury outcome stays as the pipeline concluded it"
    assert second.bias_audit["human_decisions_applied"] == len(first.human_queue)


def decide_finding(home, report, finding_id, decision, *, by="alice", issue=1):
    """A decision on any finding of `report`, queued or not (it may have been decided on an earlier review)."""
    from mara.report.human_queue_out import queue_key

    f = next(x for x in report.findings if x.id == finding_id)
    p = f.provenance[0]
    ctx = report.coverage["content_hash"]
    key = queue_key(p.file, p.line, f.cwe, target_id=report.target_id, revision=report.revision, context_hash=ctx)
    item = type("Item", (), {"key": key, "target_id": report.target_id, "revision": report.revision, "context_hash": ctx,
                             "file": p.file, "line": p.line, "cwe": f.cwe, "finding_id": finding_id})
    decide(home, item, decision, by=by, issue=issue)


def test_the_final_outcome_drives_the_gate_scores_and_report_in_both_directions(home):
    from mara.report.markdown_out import render_markdown

    first = review(home)
    jury = {c.finding_id: c for c in first.consensus}
    # F-0002: tier A Critical the jury could not settle; F-0001: tier A High the jury accepted; F-0029: tier D Critical
    assert jury["F-0002"].needs_human and jury["F-0001"].accepted and jury["F-0029"].tier.value == "D"
    decide_finding(home, first, "F-0002", "true_positive", issue=2)
    decide_finding(home, first, "F-0001", "false_positive", issue=1)
    decide_finding(home, first, "F-0029", "true_positive", issue=29)
    second = review(home, "out2")
    cons = {c.finding_id: c for c in second.consensus}
    assert cons["F-0002"].final_outcome == "accepted" and not cons["F-0002"].accepted, "jury outcome kept"
    assert cons["F-0001"].final_outcome == "rejected" and cons["F-0001"].accepted, "a human false positive outranks an accepting jury"
    assert cons["F-0029"].final_outcome == "accepted" and cons["F-0029"].tier.value == "D", "tier stays D"
    pipe = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), out_dir=home / "x")
    assert pipe.blocking_reason(cons["F-0002"]) == "blocking_tier_and_severity"
    assert pipe.blocking_reason(cons["F-0001"]) is None and pipe.blocking_reason(cons["F-0029"]) is None
    # two human true positives join the accepted findings, one human false positive leaves them
    assert sum(d.accepted_findings for d in second.dimensions) == sum(d.accepted_findings for d in first.dimensions) + 2 - 1
    md = render_markdown(second)
    accepted_part, rest = md.split("## Deterministic tool findings")
    assert "### F-0002 " in accepted_part and "decided by human (#2" in accepted_part
    assert "### F-0001 " not in accepted_part
    rejected_line = next(x for x in rest.splitlines() if x.startswith("- F-0001 "))
    assert "decided by human (#1" in rejected_line and "false positive" in rejected_line


def test_a_decision_that_is_not_usable_settles_nothing_and_says_why(home):
    first = review(home)
    item = first.human_queue[0]
    decide(home, item, "false_positive", by="mallory")  # no adjudicator training record
    second = review(home, "out2")
    queued = {i.finding_id: i for i in second.human_queue}
    assert item.finding_id in queued and "decision_not_usable:untrained" in queued[item.finding_id].reasons
    c = next(c for c in second.consensus if c.finding_id == item.finding_id)
    assert not c.resolved_by_human and c.final_outcome == "needs_human"
    assert "unresolved_human_review" in second.incomplete_reasons
    assert second.bias_audit["human_decisions_applied"] == 0
    assert second.bias_audit["human_decisions_not_usable[untrained]"] == 1


def test_code_scanning_shows_human_rulings_as_dismissals_and_confirmed_alerts(home):
    from mara.report.sarif_out import to_sarif

    first = review(home)
    decide_finding(home, first, "F-0001", "false_positive", issue=1)   # the jury accepted it
    decide_finding(home, first, "F-0002", "true_positive", issue=2)    # tier A Critical the jury left to a human
    results = {r["properties"]["findingId"]: r for r in to_sarif(review(home, "out2"))["runs"][0]["results"]}
    assert results["F-0001"]["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "human decision #1 by alice: false positive"}]
    assert results["F-0002"]["level"] == "error" and "suppressions" not in results["F-0002"]
    assert results["F-0002"]["properties"]["humanQueue"] is False


def test_a_human_confirmed_tier_a_critical_starts_the_psirt_clock(home):
    import yaml

    from mara.config import MaraConfig

    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {"enabled": True, "webhook_url": "https://psirt.example.internal/intake", "product": "IPC-7000 web console", "shipped": True}
    cfg = MaraConfig.model_validate(raw)
    first = review(home, cfg=cfg)
    assert first.psirt == [], "the jury accepted no tier A Critical"
    decide_finding(home, first, "F-0002", "true_positive", issue=2)
    second = review(home, "out2", cfg=cfg)
    assert [n["finding_id"] for n in second.psirt] == ["F-0002"]


def test_calibration_still_counts_a_jury_drop_that_a_human_confirmed_as_a_miss():
    """Guard for ADR 0003: the report keeps the jury outcome, so the AAT's rejection-safety check still sees the
    finding the pipeline would have dropped unsupervised although a human later confirmed it."""
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import calibrate

    from mara.decisions import Decision, TrainingRequirement
    from mara.report.human_queue_out import queue_key
    from mara.schemas import ConsensusResult, EvidenceTier

    key = queue_key("app.py", 10, "CWE-79", target_id="t", revision="r", context_hash="c")
    jury_drop = ConsensusResult(finding_id="F-1", weighted_score=0.2, votes_tp=0, votes_fp=4, votes_human=0, families_agreeing=[],
                                tool_corroborated=False, skeptic_refuted=False, position_consistent=True, tier=EvidenceTier.C,
                                cvss4_score=7.0, cvss4_severity="High", ssvc_decision="Track", accepted=False,
                                human_decision={"decision": "true_positive", "key": key, "issue": 1, "decided_by": "alice",
                                                "decided_at": "2026-10-01T08:00:00Z"})
    assert jury_drop.final_outcome == "accepted"
    report = {"target_id": "t", "revision": "r", "coverage": {"content_hash": "c"},
              "findings": [{"id": "F-1", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": 10}]}],
              "consensus": [json.loads(jury_drop.model_dump_json())]}
    decision = Decision.parse({"key": key, "target_id": "t", "revision": "r", "context_hash": "c", "file": "app.py", "line": 10,
                               "cwe": "CWE-79", "decision": "true_positive", "decision_event_id": 1, "decided_by": "alice",
                               "decided_at": "2026-10-01T08:00:00Z", "issue": 1})
    aat = calibrate.alternative_annotator_test([("s9", report, [])], [decision], {("s9", "F-1"): [0.1, 0.8, 0.1]},
                                               TrainingRequirement(required=False))
    assert aat["rejection"]["n"] == 1 and aat["rejection"]["misses"] == 1


def test_human_rulings_never_clear_a_tool_result(home):
    """A deterministic tool's error or warning is cleared only by that tool's triage, never by a ticket on a model
    finding at the same place."""
    first = review(home)
    tool_places = {(r["file"], r["line"]) for r in first.tool_results}
    on_tool_lines = [f.id for f in first.findings if (f.provenance[0].file, f.provenance[0].line) in tool_places]
    assert on_tool_lines, "the fixture has model findings where a tool also reported"
    for n, f in enumerate(first.findings, 1):
        decide_finding(home, first, f.id, "false_positive", issue=n)
    second = review(home, "out2")
    assert all(c.resolved_by_human for c in second.consensus)
    assert "unresolved_tool_findings" in second.incomplete_reasons and second.tool_results == first.tool_results
    assert "unresolved_human_review" not in second.incomplete_reasons
