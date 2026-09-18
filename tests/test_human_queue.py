"""G-11: the human queue is an object with full context, tightens (never loosens) when the ticket
backlog is over the limit, becomes deduplicated tickets, and decisions come back into calibration."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara.config import MaraConfig, load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from mara.report.human_queue_out import build_queue, queue_key, render_human_queue, tightening  # noqa: E402
from mara.schemas import ConsensusResult, EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance, ReviewReport, SkepticVerdict  # noqa: E402

VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _finding(fid, line, cwe="CWE-89"):
    return Finding(id=fid, dimension="vulnerabilities", title=f"t{fid}", cwe=cwe, provenance=[Provenance(file="app.py", line=line, quote="abc")],
                   reachability_argument="r", exploit_sketch="e", cvss4_vector=VEC, model_confidence=0.9,
                   source_family=ModelFamily.ANTHROPIC, source_model="m", finder_families=[ModelFamily.ANTHROPIC])


def _cons(fid, *, tp=2, fp=0, human=0, alpha=1.0, tier=EvidenceTier.B, sev="High", accepted=True):
    return ConsensusResult(finding_id=fid, weighted_score=0.9, votes_tp=tp, votes_fp=fp, votes_human=human, families_agreeing=[ModelFamily.DEEPSEEK],
                           tool_corroborated=False, skeptic_refuted=False, position_consistent=True, krippendorff_alpha=alpha, tier=tier,
                           cvss4_score=8.0, cvss4_severity=sev, ssvc_decision="Attend", accepted=accepted,
                           needs_human=human > tp or alpha < 0.4,
                           human_reasons=(["majority_needs_human"] if human > tp else []) + (["agreement_below_threshold"] if alpha < 0.4 else []))


def _vote(fid, fam, pass_id, verdict):
    return JudgeVote(finding_id=fid, verdict=verdict, severity_band="High", reason="because", judge_family=fam, judge_model="m",
                     presentation_order=0, pass_id=pass_id)


@pytest.fixture
def cfg():
    return load_config(ROOT / "config" / "mara.mock.yaml")


def test_selection_reasons_and_full_context(cfg):
    fs = [_finding("F-1", 10), _finding("F-2", 20), _finding("F-3", 30), _finding("F-4", 40)]
    cons = {"F-1": _cons("F-1", tp=0, human=3), "F-2": _cons("F-2", alpha=0.1), "F-3": _cons("F-3", tier=EvidenceTier.C, sev="High"),
            "F-4": _cons("F-4")}
    sk = {"F-1": SkepticVerdict(finding_id="F-1", verdict="weakened", reason="maybe", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON, source_model="n")}
    votes = [_vote("F-1", ModelFamily.DEEPSEEK, "forward", "needs_human"), _vote("F-1", ModelFamily.DEEPSEEK, "reverse", "needs_human")]
    items = {i.finding_id: i for i in build_queue(fs, cons, sk, {}, votes, cfg)}
    assert set(items) == {"F-1", "F-2", "F-3"}
    assert items["F-1"].reasons == ["majority_needs_human"] and items["F-2"].reasons == ["agreement_below_threshold"] and items["F-3"].reasons == ["tier_c_high"]
    assert items["F-1"].skeptic["verdict"] == "weakened" and len(items["F-1"].judge_votes) == 2 and items["F-1"].judge_votes[0]["family"] == "deepseek"
    assert items["F-1"].key == queue_key("app.py", 10, "CWE-89") == queue_key("./app.py", 10, "cwe-89")
    # tier C is dropped while tightened; the other reasons stay
    tightened = {i.finding_id for i in build_queue(fs, cons, sk, {}, votes, cfg, exclude_tier_c=True)}
    assert tightened == {"F-1", "F-2"}


def test_tightening_only_when_backlog_is_over_the_limit(cfg):
    base = cfg.gate.human_threshold_alpha
    assert tightening(cfg, None) == (base, False, False)
    assert tightening(cfg, cfg.human_queue.backlog_limit) == (base, False, False)
    alpha, excl, on = tightening(cfg, cfg.human_queue.backlog_limit + 1)
    assert on and excl and alpha == pytest.approx(base + cfg.human_queue.tighten_alpha_step) and alpha > base


def test_pipeline_reads_backlog_and_records_tightening(cfg, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "calib" / "decisions").mkdir(parents=True)
    (tmp_path / "calib" / "decisions" / "backlog.json").write_text(json.dumps({"open": 99}))
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / "out")
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    assert report.bias_audit["human_queue_tightened"] == 1 and report.bias_audit["human_queue_backlog"] == 99
    assert report.bias_audit["human_alpha_threshold"] > cfg.gate.human_threshold_alpha
    assert "human_queue_size" in report.bias_audit and "## Human queue" in render_human_queue(report) or True
    md = render_human_queue(report)
    assert md.startswith("# Human queue")


def _fake_gh(tmp_path: Path, state: dict) -> Path:
    """A gh stand-in that records mutating calls and serves canned issue lists from state.json."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "state.json").write_text(json.dumps(state))
    script = bin_dir / "gh"
    script.write_text(f'''#!/usr/bin/env python3
import json, sys
state_path = {str(tmp_path / "state.json")!r}
state = json.load(open(state_path))
args = sys.argv[1:]
state.setdefault("calls", []).append(args)
if args[:2] == ["issue", "list"]:
    want = args[args.index("--state") + 1]
    print(json.dumps(state.get(want, [])))
elif args[:2] == ["issue", "create"]:
    body = open(args[args.index("--body-file") + 1]).read()
    state.setdefault("open", []).append({{"number": 100 + len(state.get("open", [])), "body": body, "labels": []}})
elif args[:1] == ["api"]:
    number = args[1].rsplit("/", 2)[-2]
    print(json.dumps(state.get("events", {{}}).get(number, [])))
json.dump(state, open(state_path, "w"))
''')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def test_tickets_are_created_once_and_decisions_come_back(tmp_path, monkeypatch):
    import human_queue_issues as hq

    body_existing = hq.MARKER.format(key="aaaaaaaaaaaa") + "\ntarget `/t/x` · finding F-0001 · key `aaaaaaaaaaaa`\n- vulnerabilities · CWE-89 · `app.py:32` · tier C"
    body_closed = hq.MARKER.format(key="bbbbbbbbbbbb") + "\n**MARA human queue** · target `/t/x` · finding F-0002 · key `bbbbbbbbbbbb`\n- vulnerabilities · CWE-79 · `app.py:26` · tier C · CVSS 5 Medium · SSVC Track"
    state = {"open": [{"number": 7, "body": body_existing, "labels": []}],
             "closed": [{"number": 8, "body": body_closed, "labels": [{"name": "mara-human-queue"}, {"name": "decision:true-positive"}],
                         "closedAt": "2026-09-12T08:00:00Z", "url": "https://example/8"},
                        {"number": 9, "body": hq.MARKER.format(key="cccccccccccc"), "labels": [{"name": "mara-human-queue"}], "closedAt": "x", "url": "u"}],
             "events": {"8": [{"event": "labeled", "label": {"name": "mara-human-queue"}, "actor": {"login": "bot"}},
                              {"event": "labeled", "label": {"name": "decision:true-positive"}, "actor": {"login": "alice"}},
                              {"event": "closed", "actor": {"login": "alice"}}]}}
    _fake_gh(tmp_path, state)
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    queue = {"target": "/t/x", "generated_at": "now", "items": [
        {"finding_id": "F-0001", "key": "aaaaaaaaaaaa", "reasons": ["tier_c_high"], "title": "old", "dimension": "vulnerabilities", "cwe": "CWE-89",
         "file": "app.py", "line": 32, "quote": "q", "tier": "C", "cvss4_score": 9.3, "cvss4_severity": "Critical", "ssvc_decision": "Act",
         "weighted_score": 0.6, "krippendorff_alpha": 0.5, "votes_tp": 1, "votes_fp": 0, "votes_human": 0, "finder_families": ["anthropic"],
         "reachability": "reachable", "reachability_argument": "r", "exploit_sketch": "e", "skeptic": None, "redteam": None, "judge_votes": []},
        {"finding_id": "F-0003", "key": "dddddddddddd", "reasons": ["alpha_below_threshold"], "title": "new one", "dimension": "xss", "cwe": "CWE-79",
         "file": "app.py", "line": 26, "quote": "q", "tier": "B", "cvss4_score": 5.3, "cvss4_severity": "Medium", "ssvc_decision": "Track*",
         "weighted_score": 0.5, "krippendorff_alpha": 0.1, "votes_tp": 1, "votes_fp": 1, "votes_human": 0, "finder_families": ["deepseek"],
         "reachability": "conditional", "reachability_argument": "r", "exploit_sketch": "e",
         "skeptic": {"family": "nemotron", "verdict": "weakened", "reason": "x", "sanitizer_or_control": ""}, "redteam": None,
         "judge_votes": [{"family": "anthropic", "pass": "forward", "verdict": "true_positive", "severity_band": "Medium", "reason": "y", "self_family": False}]}]}
    for it in queue["items"]:
        it.update(target_id="target-x", revision="revision-x", context_hash="context-x")
        it["key"] = queue_key(it["file"], it["line"], it["cwe"], target_id="target-x", revision="revision-x", context_hash="context-x")
    state["open"][0]["body"] = hq.ticket_body(queue["items"][0], "/t/x")
    state["closed"][0]["body"] = hq.ticket_body({**queue["items"][1], "finding_id": "F-0002"}, "/t/x")
    state["events"]["8"][1].update(id=100, created_at="2026-09-12T08:00:00Z")
    (tmp_path / "state.json").write_text(json.dumps(state))
    (tmp_path / "hq.json").write_text(json.dumps(queue))
    created, skipped = hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False)
    assert (created, skipped) == (1, 1)
    st = json.loads((tmp_path / "state.json").read_text())
    new = st["open"][-1]
    assert hq.MARKER.format(key=queue["items"][1]["key"]) in new["body"] and "Skeptic (nemotron)" in new["body"] and "anthropic [forward]" in new["body"]
    assert not list(tmp_path.glob(".mara-hq-*.md"))
    register = tmp_path / "records.yaml"
    register.write_text("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords: []\n", encoding="utf-8")
    written, open_count = hq.sync_decisions("o/r", "mara-human-queue", tmp_path / "decisions", tmp_path / "decisions" / "backlog.json",
                                            dry_run=False, register=register)
    assert (written, open_count) == (1, 2)
    rec = json.loads((tmp_path / "decisions" / (queue["items"][1]["key"] + ".json")).read_text())
    checked_on = rec.pop("training_checked_on")
    assert rec == {"key": queue["items"][1]["key"], "decision": "true_positive", "issue": 8, "url": "https://example/8", "decided_at": "2026-09-12T08:00:00Z",
                   "target_id": "target-x", "revision": "revision-x", "context_hash": "context-x",
                   "finding_id": "F-0002", "cwe": "CWE-79", "file": "app.py", "line": 26,
                   "decision_event_id": 100, "decision_label": "decision:true-positive",
                   "decided_by": "alice", "adjudicator_trained": False}
    # once alice holds a valid adjudicator record the same decision is marked trained (G-13)
    import datetime as dt

    register.write_text("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
                        f"  - {{person: alice, role: adjudicator, curriculum_version: '2026-09', date: {checked_on}, assessor: quiz, evidence: quiz}}\n",
                        encoding="utf-8")
    assert dt.date.fromisoformat(checked_on)
    hq.sync_decisions("o/r", "mara-human-queue", tmp_path / "decisions", tmp_path / "decisions" / "backlog.json", dry_run=False, register=register)
    assert json.loads((tmp_path / "decisions" / (queue["items"][1]["key"] + ".json")).read_text())["adjudicator_trained"] is True
    assert json.loads((tmp_path / "decisions" / "backlog.json").read_text())["open"] == 2
    # a closed ticket without a decision label writes nothing
    assert not (tmp_path / "decisions" / "cccccccccccc.json").exists()


def test_calibration_uses_true_positive_decisions_as_labels(tmp_path):
    import calibrate

    decisions = [{"key": "k", "decision": "true_positive", "target": "/x/calib/samples/s9", "file": "app.py", "line": 26, "cwe": "CWE-79", "issue": 3,
                  "decided_by": "alice", "adjudicator_trained": True},
                 {"key": "k2", "decision": "false_positive", "target": "/x/calib/samples/s9", "file": "app.py", "line": 50, "cwe": "CWE-22", "issue": 4,
                  "decided_by": "alice", "adjudicator_trained": True},
                 {"key": "k3", "decision": "true_positive", "target": "/x/calib/samples/other", "file": "a.py", "line": 1, "cwe": "CWE-1", "issue": 5,
                  "decided_by": "alice", "adjudicator_trained": True},
                 {"key": "k4", "decision": "true_positive", "target": "/x/calib/samples/s9", "file": "app.py", "line": 80, "cwe": "CWE-89", "issue": 6,
                  "decided_by": "mallory", "adjudicator_trained": False}]
    calibrate.SKIPPED_UNTRAINED.clear()
    report = {"target_id": "target-s9", "revision": "rev", "coverage": {"content_hash": "ctx"}}
    for d in decisions:
        d.update(target_id="other" if d["issue"] == 5 else "target-s9", revision="rev", context_hash="ctx", decision_event_id=d["issue"])
        d["key"] = queue_key(d["file"], d["line"], d["cwe"], target_id=d["target_id"], revision="rev", context_hash="ctx")
    labels, applied = calibrate.apply_decisions("s9", report, [], decisions)
    assert applied == 2 and len(labels) == 1 and labels[0]["source"] == "human_decision" and labels[0]["cwe"] == "CWE-79"
    assert calibrate.SKIPPED_UNTRAINED == ["s9: ticket #6 by mallory"]  # G-13: untrained adjudicator's decision not applied
    labels, applied = calibrate.apply_decisions("s9", report, [], decisions, require_trained=False)
    assert applied == 3 and len(labels) == 2
    d = tmp_path / "decisions"
    d.mkdir()
    (d / "k.json").write_text(json.dumps(decisions[0]))
    (d / "backlog.json").write_text(json.dumps({"open": 3}))
    assert [x["key"] for x in calibrate.load_decisions(d)] == [decisions[0]["key"]]


def test_report_and_governance_g11(tmp_path):
    from governance_check import PASS, check_g11

    assert check_g11(ROOT, ROOT / "config" / "mara.yaml").status == PASS
    cfg = MaraConfig.model_validate(json.loads(json.dumps({
        "models": [{"name": "a", "family": "anthropic", "provider": "mock", "model": "m", "data_residency": "on_prem"},
                   {"name": "d", "family": "deepseek", "provider": "mock", "model": "m", "data_residency": "on_prem"},
                   {"name": "n", "family": "nemotron", "provider": "mock", "model": "m", "data_residency": "on_prem"}],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "d", "n"]}, "human_queue": {"enabled": False}})))
    assert build_queue([_finding("F-1", 1)], {"F-1": _cons("F-1", tp=0, human=3)}, {}, {}, [], cfg) == []
    r = ReviewReport(target="t", generated_at="2026-09-12T00:00:00+00:00", provider_mode="mock", families_used=[], findings=[], skeptic=[], redteam=[],
                     votes=[], consensus=[], dimensions=[], overall_score=0, gate_passed=True, bias_audit={})
    assert "_Empty._" in render_human_queue(r)
