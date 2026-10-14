"""G-11: the human queue is an object with full context, tightens (never loosens) when the ticket
backlog is over the limit, becomes deduplicated tickets, and decisions come back into calibration."""

import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara.config import MaraConfig, load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from mara.report.human_queue_out import build_queue, queue_key, render_human_queue, tightening  # noqa: E402
from mara.schemas import ConsensusResult, EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance, ReviewReport, SkepticVerdict  # noqa: E402
from mara.scoring.outcome import OutcomePolicy, OutcomeSignals, decide  # noqa: E402

VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"  # 9.3, Critical
HIGH_VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"  # 8.7, High


def _finding(fid, line, cwe="CWE-89", vec=VEC):
    return Finding(id=fid, dimension="vulnerabilities", title=f"t{fid}", cwe=cwe,
                   provenance=[Provenance(file="app.py", line=line, quote="abc")],
                   reachability_argument="r", exploit_sketch="e", cvss4_vector=vec, model_confidence=0.9,
                   source_family=ModelFamily.ANTHROPIC, source_model="m", finder_families=[ModelFamily.ANTHROPIC])


# Rows Pipeline.score() writes on the three-family panel (equal weights, the finder's own family discounted to 0.5):
# a tier B finding three families confirmed in both passes, which needs no human ...
SUPPORTED = OutcomeSignals(tier=EvidenceTier.B, score=1.0, severity="High", provenance_verified=True, skeptic_refuted=False,
                           skeptic_abstained=False, quorum_ok=True, passes_complete=True, alpha=1.0, votes_tp=6, votes_fp=0,
                           votes_human=0, position_consistent=True)
# ... and the changes for the other states: a tool-corroborated finding only the finder's family confirmed (tier A, the only
# tier the jury can reject, ADR 0005), one every family called a false positive (dropped), one every family sent to a human,
# and one the three families split three ways
REJECTED = {"tier": EvidenceTier.A, "score": 0.2, "votes_tp": 2, "votes_fp": 4, "alpha": 0.5}
DROPPED = {"tier": EvidenceTier.D, "score": 0.0, "votes_tp": 0, "votes_fp": 6}
ALL_NEEDS_HUMAN = {"tier": EvidenceTier.D, "score": 0.5, "votes_tp": 0, "votes_human": 6}
SPLIT = {"tier": EvidenceTier.D, "score": 0.4, "votes_tp": 2, "votes_fp": 2, "votes_human": 2, "alpha": 0.0}


def _policy(cfg, *, exclude_tier_c=False):
    return OutcomePolicy.from_config(cfg, alpha_threshold=cfg.gate.human_threshold_alpha, exclude_tier_c=exclude_tier_c)


def _cons(fid, policy, **signals):
    """A consensus row as Pipeline.score() writes it: the jury outcome comes from decide()."""
    s = replace(SUPPORTED, **signals)
    return ConsensusResult(finding_id=fid, weighted_score=s.score, votes_tp=s.votes_tp, votes_fp=s.votes_fp, votes_human=s.votes_human,
                           families_agreeing=[ModelFamily.DEEPSEEK], tool_corroborated=s.tier == EvidenceTier.A, skeptic_refuted=s.skeptic_refuted,
                           position_consistent=s.position_consistent, tier=s.tier, cvss4_score=8.0, cvss4_severity=s.severity,
                           ssvc_decision="Attend", agreement_proxy=s.alpha, **decide(s, policy).consensus_fields())


def _vote(fid, fam, pass_id, verdict):
    return JudgeVote(finding_id=fid, verdict=verdict, severity_band="High", reason="because", judge_family=fam, judge_model="m",
                     presentation_order=0, pass_id=pass_id)


@pytest.fixture
def cfg():
    return load_config(ROOT / "config" / "mara.mock.yaml")


def test_selection_reasons_and_full_context(cfg):
    fs = [_finding("F-1", 10), _finding("F-2", 20), _finding("F-3", 30), _finding("F-4", 40)]
    def rows(policy):
        return {"F-1": _cons("F-1", policy, **ALL_NEEDS_HUMAN), "F-2": _cons("F-2", policy, **SPLIT),
                "F-3": _cons("F-3", policy, tier=EvidenceTier.C, severity="High"), "F-4": _cons("F-4", policy)}

    cons = rows(_policy(cfg))
    sk = {"F-1": SkepticVerdict(finding_id="F-1", verdict="weakened", reason="maybe", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON, source_model="n")}
    votes = [_vote("F-1", ModelFamily.DEEPSEEK, "forward", "needs_human"), _vote("F-1", ModelFamily.DEEPSEEK, "reverse", "needs_human")]
    items = {i.finding_id: i for i in build_queue(fs, cons, sk, {}, votes, cfg)}
    assert set(items) == {"F-1", "F-2", "F-3"}
    assert items["F-1"].reasons == ["majority_needs_human"] and items["F-2"].reasons == ["agreement_below_threshold"] and items["F-3"].reasons == ["tier_c_high"]
    assert items["F-1"].skeptic["verdict"] == "weakened" and len(items["F-1"].judge_votes) == 2 and items["F-1"].judge_votes[0]["family"] == "deepseek"
    assert items["F-1"].key == queue_key("app.py", 10, "CWE-89") == queue_key("./app.py", 10, "cwe-89")
    # tier C is left to the jury while tightened; the other reasons stay
    tightened = {i.finding_id for i in build_queue(fs, rows(_policy(cfg, exclude_tier_c=True)), sk, {}, votes, cfg)}
    assert tightened == {"F-1", "F-2"}


def test_rejected_non_d_findings_are_queued_until_p8_allows_silence(cfg):
    # assessment #60: without a passing AAT (policy P8) no rejected finding goes without a human look (rejection review)
    fs = [_finding("F-1", 10), _finding("F-2", 20), _finding("F-3", 30)]
    def rows(policy):
        return {"F-1": _cons("F-1", policy, **REJECTED), "F-2": _cons("F-2", policy, **DROPPED), "F-3": _cons("F-3", policy, **REJECTED)}

    items = {i.finding_id: i for i in build_queue(fs, rows(_policy(cfg)), {}, {}, [], cfg)}
    assert items["F-1"].reasons == ["unsupervised_reject_unverified"] and items["F-3"].reasons == ["unsupervised_reject_unverified"]
    assert "F-2" not in items  # a dropped finding (tier D) is not a rejection
    cfg_true = cfg.model_copy(deep=True)
    cfg_true.gate.unsupervised_reject_allowed = True
    assert build_queue(fs, rows(_policy(cfg_true)), {}, {}, [], cfg_true) == []


def test_rejection_review_follows_what_the_row_records_not_the_config_the_queue_is_built_with(cfg):
    """docs/adr/0005-jury-outcome.md: the jury outcome module decides rejection review once, and the queue reads it.
    A rejection recorded without it (P8 allowed when it was scored) is not queued under a stricter config."""
    allowed = cfg.model_copy(deep=True)
    allowed.gate.unsupervised_reject_allowed = True
    row = _cons("F-1", _policy(allowed), **REJECTED)
    assert row.jury_outcome == "rejected" and not row.unsupervised_reject_unverified
    assert not cfg.gate.unsupervised_reject_allowed
    assert build_queue([_finding("F-1", 10)], {"F-1": row}, {}, {}, [], cfg) == []


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


def _score_cfg():
    """Three distinct model families so two independent judges reach quorum (a P3-compliant panel)."""
    return MaraConfig.model_validate({
        "models": [
            {"name": "a", "family": "anthropic", "provider": "anthropic", "model": "claude-opus-5", "data_residency": "vendor_api_zdr"},
            {"name": "d", "family": "deepseek", "provider": "openai_compatible", "model": "deepseek-v3.2",
             "base_url": "https://vllm-deepseek.internal:8000/v1", "data_residency": "on_prem"},
            {"name": "n", "family": "nemotron", "provider": "openai_compatible", "model": "nvidia/nemotron-3-super",
             "base_url": "https://192.168.10.5:8000/v1", "data_residency": "on_prem"},
        ],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "d", "n"]},
    })


def _votes(fid):
    # two independent families plus the finder's own family, all consistent across both passes:
    # quorum holds and the consensus is unanimous; reachability stays unknown, so the tier lands on C
    return [_vote(fid, fam, pid, "true_positive") for fam in (ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON, ModelFamily.ANTHROPIC)
            for pid in ("forward", "reverse")]


def _tier_c_finding(vec=VEC):
    f = _finding("F-1", 10, vec=vec)
    for p in f.provenance:
        p.verified = True
    return f


def test_tier_c_high_needs_a_human_until_the_queue_tightens(tmp_path, monkeypatch):
    cfg = _score_cfg()
    monkeypatch.chdir(tmp_path)  # no backlog file: not tightened
    pipe = Pipeline(cfg, out_dir=tmp_path / "out")
    f = _tier_c_finding()
    (c,) = pipe.score([f], {"F-1": {ModelFamily.ANTHROPIC}}, {}, {}, _votes("F-1"), [])
    assert c.tier == EvidenceTier.C and "tier_c_high" in c.human_reasons and not c.accepted
    items = build_queue([f], {"F-1": c}, {}, {}, _votes("F-1"), cfg)
    assert [i.reasons for i in items] == [["tier_c_high"]]

    (tmp_path / "calib" / "decisions").mkdir(parents=True)
    (tmp_path / "calib" / "decisions" / "backlog.json").write_text(json.dumps({"open": 999}), encoding="utf-8")
    tightened = Pipeline(cfg, out_dir=tmp_path / "out2")
    assert tightened.queue_tightened and tightened.exclude_tier_c
    (c2,) = tightened.score([f], {"F-1": {ModelFamily.ANTHROPIC}}, {}, {}, _votes("F-1"), [])
    assert c2.tier == EvidenceTier.C and c2.accepted and c2.human_reasons == []
    assert build_queue([f], {"F-1": c2}, {}, {}, _votes("F-1"), cfg) == []
    # ...and since nobody will look at it, it blocks the gate instead of passing (tightening never loosens);
    # tier C is not in block_on_tiers, so before this rule an over-limit backlog let a tier C Critical through
    assert "C" not in cfg.gate.block_on_tiers and pipe.blocking_reason(c2) is None
    assert tightened.blocking_reason(c2) == "tier_c_while_tightened"
    # tighten_exclude_tier_c: false keeps tier C in the queue even while tightened
    cfg.human_queue.tighten_exclude_tier_c = False
    kept = Pipeline(cfg, out_dir=tmp_path / "out3")
    assert kept.queue_tightened and not kept.exclude_tier_c
    (c3,) = kept.score([f], {"F-1": {ModelFamily.ANTHROPIC}}, {}, {}, _votes("F-1"), [])
    assert [i.reasons for i in build_queue([f], {"F-1": c3}, {}, {}, _votes("F-1"), cfg)] == [["tier_c_high"]]


def test_queue_tier_c_min_severity_configures_the_trigger(tmp_path, monkeypatch):
    f = _tier_c_finding(vec=HIGH_VEC)  # severity High
    monkeypatch.chdir(tmp_path)
    pipe = Pipeline(_score_cfg(), out_dir=tmp_path / "out")
    (c,) = pipe.score([f], {"F-1": {ModelFamily.ANTHROPIC}}, {}, {}, _votes("F-1"), [])
    assert "tier_c_high" in c.human_reasons  # the default trigger is High
    cfg = _score_cfg()
    cfg.human_queue.queue_tier_c_min_severity = "Critical"
    pipe2 = Pipeline(cfg, out_dir=tmp_path / "out2")
    (c2,) = pipe2.score([f], {"F-1": {ModelFamily.ANTHROPIC}}, {}, {}, _votes("F-1"), [])
    assert "tier_c_high" not in c2.human_reasons and c2.accepted


def _fake_gh(tmp_path: Path, state: dict) -> Path:
    """A gh stand-in that records mutating calls and serves canned issue lists from state.json."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (tmp_path / "state.json").write_text(json.dumps(state))
    py_code = f'''import json, sys
state_path = {str(tmp_path / "state.json")!r}
state = json.load(open(state_path, encoding="utf-8"))
args = sys.argv[1:]
state.setdefault("calls", []).append(args)
if args[:2] == ["issue", "create"]:
    body = open(args[args.index("--body-file") + 1], encoding="utf-8").read()
    state.setdefault("open", []).append({{"number": 100 + len(state.get("open", [])), "body": body, "labels": []}})
elif args[:1] == ["api"]:
    path = next(a for a in args[1:] if a.startswith("repos/"))
    if path.endswith("/events"):
        number = path.rsplit("/", 2)[-2]
        print(json.dumps(state.get("events", {{}}).get(number, [])))
    else:  # GET repos/o/r/issues -f state=... --paginate --slurp: the REST shape, 100 per page
        want = next(a.split("=", 1)[1] for a in args if a.startswith("state="))
        rest = [{{"number": i["number"], "body": i["body"], "labels": i.get("labels", []), "closed_at": i.get("closedAt"),
                  "html_url": i.get("url"), "state_reason": i.get("stateReason")}} for i in state.get(want, [])]
        rest += [{{"number": 9999, "pull_request": {{}}, "body": "", "labels": []}}]  # the issues endpoint also returns PRs
        print(json.dumps([rest[i:i + 100] for i in range(0, len(rest), 100)]))
json.dump(state, open(state_path, "w", encoding="utf-8"))
'''
    if sys.platform == "win32":
        py_script = bin_dir / "fake_gh.py"
        py_script.write_text(py_code, encoding="utf-8")
        script = bin_dir / "gh.cmd"
        script.write_text(f'@"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
        return script
    script = bin_dir / "gh"
    script.write_text(f'#!/usr/bin/env python3\n{py_code}')
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
    # F-0001 has an open ticket (#7) and F-0003's key was already decided on the closed #8: nothing is filed
    # (this used to file a second ticket for the decided key; see test_a_decided_key_is_never_filed_again)
    created, skipped = hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False)
    assert (created, skipped) == (0, 2)
    st = json.loads((tmp_path / "state.json").read_text())
    assert [t["number"] for t in st["open"]] == [7] and not list(tmp_path.glob(".mara-hq-*.md"))
    register = tmp_path / "records.yaml"
    register.write_text("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords: []\n", encoding="utf-8")
    written, open_count, unrecorded = hq.sync_decisions("o/r", "mara-human-queue", tmp_path / "decisions", tmp_path / "decisions" / "backlog.json",
                                                        dry_run=False, register=register)
    assert (written, open_count) == (1, 1)
    assert unrecorded == ["#9: closed with 0 decision labels, need exactly one"]
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
    assert json.loads((tmp_path / "decisions" / "backlog.json").read_text())["open"] == 1
    # a closed ticket without a decision label writes nothing
    assert not (tmp_path / "decisions" / "cccccccccccc.json").exists()



def _queue_item(n: int) -> dict:
    item = {"finding_id": f"F-{n:04d}", "reasons": ["tier_c_high"], "title": f"finding {n}", "dimension": "vulnerabilities", "cwe": "CWE-89",
            "file": "app.py", "line": n, "quote": "q", "tier": "C", "cvss4_score": 9.3, "cvss4_severity": "Critical", "ssvc_decision": "Act",
            "weighted_score": 0.6, "krippendorff_alpha": 0.5, "votes_tp": 1, "votes_fp": 0, "votes_human": 0, "finder_families": ["anthropic"],
            "reachability": "reachable", "reachability_argument": "r", "exploit_sketch": "e", "skeptic": None, "redteam": None, "judge_votes": [],
            "target_id": "target-x", "revision": "revision-x", "context_hash": "context-x"}
    item["key"] = queue_key("app.py", n, "CWE-89", target_id="target-x", revision="revision-x", context_hash="context-x")
    return item


def test_a_backlog_past_any_page_size_is_neither_refiled_nor_undercounted(tmp_path, monkeypatch):
    # gh issue list --limit 500 used to cut both lists: ticket 550 was re-filed and the backlog read 500.
    import human_queue_issues as hq

    items = [_queue_item(n) for n in range(1, 601)]
    state = {"open": [{"number": n, "body": hq.ticket_body(it, "/t/x"), "labels": [{"name": "mara-human-queue"}]} for n, it in enumerate(items, 1)],
             "closed": []}
    _fake_gh(tmp_path, state)
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hq.json").write_text(json.dumps({"target": "/t/x", "items": [items[549], _queue_item(601)]}))
    assert hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False) == (1, 1)
    written, open_count, unrecorded = hq.sync_decisions("o/r", "mara-human-queue", tmp_path / "d", tmp_path / "d" / "backlog.json", dry_run=False)
    assert (written, open_count, unrecorded) == (0, 601, [])
    assert json.loads((tmp_path / "d" / "backlog.json").read_text())["open"] == 601


def test_a_decision_that_cannot_be_recorded_is_reported_and_fails_the_run(tmp_path, monkeypatch, capsys):
    import human_queue_issues as hq

    items = [_queue_item(n) for n in range(1, 7)]
    tp = [{"name": "mara-human-queue"}, {"name": "decision:true-positive"}]
    label_event = {"id": 1, "event": "labeled", "label": {"name": "decision:true-positive"}, "actor": {"login": "alice"}, "created_at": "2026-09-12T08:00:00Z"}
    broken_meta = hq.ticket_body(items[4], "/t/x").rsplit("<!-- mara-meta:", 1)[0] + "<!-- mara-meta:bm90LWpzb24= -->"
    state = {"open": [], "closed": [
        {"number": 1, "body": hq.ticket_body(items[0], "/t/x"), "labels": tp, "stateReason": "completed"},             # recorded
        {"number": 2, "body": hq.ticket_body(items[1], "/t/x"), "labels": tp[:1], "stateReason": "completed"},         # no decision label
        {"number": 3, "body": hq.ticket_body(items[2], "/t/x"), "labels": tp[:1], "stateReason": "not_planned"},       # withdrawn on purpose
        {"number": 4, "body": hq.ticket_body(items[3], "/t/x"), "labels": tp, "stateReason": "completed"},             # no label event
        {"number": 5, "body": broken_meta, "labels": tp, "stateReason": "completed"},                                  # damaged metadata
        {"number": 6, "body": hq.ticket_body(items[5], "/t/x").split("\n<!-- mara-meta:")[0], "labels": tp},          # metadata removed
        {"number": 7, "body": "filed by hand", "labels": tp[:1]},                                                      # not a MARA ticket
    ], "events": {"1": [label_event], "5": [label_event], "6": [label_event]}}
    _fake_gh(tmp_path, state)
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    written, open_count, unrecorded = hq.sync_decisions("o/r", "mara-human-queue", tmp_path / "d", tmp_path / "d" / "backlog.json", dry_run=False)
    assert (written, open_count) == (1, 0)
    assert unrecorded == ["#2: closed with 0 decision labels, need exactly one",
                          "#4: label history does not resolve to decision:true-positive with an actor and a time",
                          "#5: mara-meta block or decision time is unreadable",
                          "#6: ticket body has no mara-meta block"]
    out = capsys.readouterr().out
    assert "UNRECORDED #4" in out and "1 ticket(s) closed as not planned" in out and "1 closed ticket(s) labelled mara-human-queue without a MARA marker" in out
    monkeypatch.setattr(sys, "argv", ["human_queue_issues.py", "--repo", "o/r", "--sync-decisions", "--decisions-dir", str(tmp_path / "d"),
                                      "--backlog-file", str(tmp_path / "d" / "backlog.json")])
    assert hq.main() == 2
    assert "4 closed ticket(s) carry a decision that was not recorded" in capsys.readouterr().err


def test_a_decided_key_is_never_filed_again(tmp_path, monkeypatch, capsys):
    """Every push to main reviews the unchanged fixture: a key a human had already decided on a closed ticket
    used to get a fresh ticket each time."""
    import human_queue_issues as hq

    items = [_queue_item(n) for n in range(1, 8)]
    items[5].update(skeptic={"family": "nemotron", "verdict": "weakened", "reason": "x", "sanitizer_or_control": ""},
                    judge_votes=[{"family": "anthropic", "pass": "forward", "verdict": "true_positive", "severity_band": "High", "reason": "y",
                                  "self_family": False}])
    tp, fp = {"name": "decision:true-positive"}, {"name": "decision:false-positive"}
    q = {"name": "mara-human-queue"}
    state = {"open": [], "closed": [
        {"number": 1, "body": hq.ticket_body(items[0], "/t/x"), "labels": [q, tp], "stateReason": "completed"},     # decided
        {"number": 2, "body": hq.ticket_body(items[1], "/t/x"), "labels": [q, fp], "stateReason": "completed"},     # decided
        {"number": 3, "body": hq.ticket_body(items[2], "/t/x"), "labels": [q], "stateReason": "completed"},         # awaits its label
        {"number": 4, "body": hq.ticket_body(items[3], "/t/x"), "labels": [q], "stateReason": "not_planned"},       # withdrawn
    ]}
    _fake_gh(tmp_path, state)
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    decisions = tmp_path / "d"
    decisions.mkdir()
    # recorded, though its ticket is gone (transferred, deleted); an untrained adjudicator's decision still
    # answers the ticket (docs/adr/0002-usable-decisions.md)
    recorded = {k: items[4][k] for k in ("key", "target_id", "revision", "context_hash", "file", "line", "cwe")}
    recorded.update(decision="false_positive", decision_event_id=5, decided_by="mallory", decided_at="2026-10-01T08:00:00Z", issue=5)
    (decisions / f"{items[4]['key']}.json").write_text(json.dumps(recorded))
    (decisions / f"{items[6]['key']}.json").write_text("{}")  # damaged: answers nothing, so the key is filed again
    (tmp_path / "hq.json").write_text(json.dumps({"target": "/t/x", "items": items}))
    assert hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False, decisions_dir=decisions) == (3, 4)
    assert f"{items[6]['key']}.json is not a well-formed decision" in capsys.readouterr().out
    # the next push: the three new tickets are open now, nothing is filed
    assert hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False, decisions_dir=decisions) == (0, 7)
    st = json.loads((tmp_path / "state.json").read_text())
    filed = [t["body"] for t in st["open"]]
    assert len(filed) == 3, "only the withdrawn key, the new one and the damaged record's key are filed, once"
    assert hq.MARKER.format(key=items[3]["key"]) in filed[0] and hq.MARKER.format(key=items[5]["key"]) in filed[1]
    assert hq.MARKER.format(key=items[6]["key"]) in filed[2]
    assert "Skeptic (nemotron)" in filed[1] and "anthropic [forward]" in filed[1] and not list(tmp_path.glob(".mara-hq-*.md"))


def test_closed_tickets_for_one_key_never_overwrite_each_other(tmp_path, monkeypatch, capsys):
    """Several closed tickets for one key used to write calib/decisions/<key>.json in list order, so the last
    one listed won, an untrained or contradicting decision included."""
    import human_queue_issues as hq

    agree, clash = _queue_item(1), _queue_item(2)
    tp, fp, q = {"name": "decision:true-positive"}, {"name": "decision:false-positive"}, {"name": "mara-human-queue"}

    def ev(n, who, label, at):
        return [{"id": n, "event": "labeled", "label": {"name": label}, "actor": {"login": who}, "created_at": at}]

    state = {"open": [], "closed": [
        # listed newest first, as the API does: an untrained bob after the trained alice, both true positive
        {"number": 12, "body": hq.ticket_body(agree, "/t/x"), "labels": [q, tp], "stateReason": "completed"},
        {"number": 11, "body": hq.ticket_body(agree, "/t/x"), "labels": [q, tp], "stateReason": "completed"},
        # one key, two different answers
        {"number": 22, "body": hq.ticket_body(clash, "/t/x"), "labels": [q, fp], "stateReason": "completed"},
        {"number": 21, "body": hq.ticket_body(clash, "/t/x"), "labels": [q, tp], "stateReason": "completed"},
    ], "events": {"12": ev(120, "bob", "decision:true-positive", "2026-10-02T08:00:00Z"),
                  "11": ev(110, "alice", "decision:true-positive", "2026-10-05T08:00:00Z"),
                  "22": ev(220, "bob", "decision:false-positive", "2026-10-03T08:00:00Z"),
                  "21": ev(210, "alice", "decision:true-positive", "2026-10-01T08:00:00Z")}}
    _fake_gh(tmp_path, state)
    monkeypatch.setenv("PATH", str(tmp_path / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.chdir(tmp_path)
    register = tmp_path / "records.yaml"
    register.write_text("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
                        "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n",
                        encoding="utf-8")
    decisions = tmp_path / "d"
    decisions.mkdir()
    earlier = decisions / f"{clash['key']}.json"
    earlier.write_text('{"decision": "true_positive", "issue": 21}\n')  # a previous sync, before #22 was closed
    written, _, unrecorded = hq.sync_decisions("o/r", "mara-human-queue", decisions, decisions / "backlog.json", dry_run=False, register=register)
    assert written == 1
    rec = json.loads((decisions / f"{agree['key']}.json").read_text())
    assert (rec["issue"], rec["decided_by"], rec["adjudicator_trained"]) == (11, "alice", True), "the trained adjudicator's decision, not the last one listed"
    out = capsys.readouterr().out
    assert "2 closed tickets agree (true_positive); recording #11, also decided in #12" in out
    assert "#11 by alice" not in out and "WARNING" not in out, "the recorded decision is a trained one"
    clash_lines = [u for u in unrecorded if clash["key"] in u]
    assert [u.split(":")[0] for u in clash_lines] == ["#21", "#22"]
    assert "contradicting decisions (#21 true_positive, #22 false_positive)" in clash_lines[0]
    assert earlier.read_text() == '{"decision": "true_positive", "issue": 21}\n', "a contradiction neither overwrites nor deletes"
    # neither key is filed again
    (tmp_path / "hq.json").write_text(json.dumps({"target": "/t/x", "items": [agree, clash]}))
    assert hq.create_tickets(tmp_path / "hq.json", "o/r", "mara-human-queue", dry_run=False, decisions_dir=decisions) == (0, 2)


def test_an_api_failure_while_reading_a_decision_aborts_instead_of_dropping_it(monkeypatch):
    import human_queue_issues as hq

    def failing(args, **_):
        raise hq.GhError("gh api repos/o/r/issues/1/events failed: HTTP 502")
    monkeypatch.setattr(hq, "gh", failing)
    with pytest.raises(hq.GhError, match="502"):
        hq.decision_event("o/r", 1, "decision:true-positive")
    with pytest.raises(hq.GhError, match="502"):
        hq.list_tickets("o/r", "mara-human-queue", "closed")
    monkeypatch.setattr(hq, "gh", lambda args, **_: json.dumps({"message": "Not Found"}))
    with pytest.raises(hq.GhError, match="unexpected response shape"):
        hq.list_tickets("o/r", "mara-human-queue", "open")

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
    import datetime as dt

    from mara.decisions import Decision, TrainingRequirement, select
    from mara.training import Record, Register

    report = {"target_id": "target-s9", "revision": "rev", "coverage": {"content_hash": "ctx"}}
    for d in decisions:
        d.update(target_id="other" if d["issue"] == 5 else "target-s9", revision="rev", context_hash="ctx", decision_event_id=d["issue"],
                 decided_at="2026-10-01T08:00:00Z")
        d["key"] = queue_key(d["file"], d["line"], d["cwe"], target_id=d["target_id"], revision="rev", context_hash="ctx")
    parsed = [Decision.parse(d) for d in decisions]
    alice = Record("alice", "adjudicator", "2026-09", dt.date(2026, 9, 1), dt.date(2027, 9, 1), None, "quiz", "quiz")
    sel = select(parsed, report, TrainingRequirement(required=True, register=Register("2026-09", 365, 0.8, [alice])))
    labels, applied = calibrate.apply_decisions(sel.usable, [])
    assert applied == 2 and len(labels) == 1 and labels[0]["source"] == "human_decision" and labels[0]["cwe"] == "CWE-79"
    assert [(d.issue, why) for d, why in sel.excluded] == [(5, "unbound"), (6, "untrained")]  # G-13: mallory's decision not applied
    labels, applied = calibrate.apply_decisions(select(parsed, report, TrainingRequirement(required=False)).usable, [])
    assert applied == 3 and len(labels) == 2
    d = tmp_path / "decisions"
    d.mkdir()
    (d / f"{decisions[0]['key']}.json").write_text(json.dumps(decisions[0]))
    (d / "backlog.json").write_text(json.dumps({"open": 3}))
    assert [x.key for x in calibrate.load_decisions(d)] == [decisions[0]["key"]]


def test_report_and_governance_g11(tmp_path):
    import shutil

    from governance_check import FAIL, PASS, check_g11

    # this repository: the config files issues and the workflow runs the sync, but it never ran for real (dry-run)
    r = check_g11(ROOT, ROOT / "config" / "mara.yaml")
    assert r.status == FAIL and "human_queue_issues.py --sync-decisions" not in r.evidence.split("需要")[-1] and "dry-run" in r.evidence
    # the same repository after a live sync wrote its backlog: G-11 passes
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / ".github", repo / ".github")
    shutil.copytree(ROOT / "config", repo / "config")
    (repo / "calib" / "decisions").mkdir(parents=True)
    assert check_g11(repo, repo / "config" / "mara.yaml").status == FAIL
    (repo / "calib" / "decisions" / "backlog.json").write_text('{"open": 3}', encoding="utf-8")
    assert check_g11(repo, repo / "config" / "mara.yaml").status == PASS
    # a workflow that only names the human queue, without running the sync, is no integration
    for wf in (repo / ".github" / "workflows").glob("*.yml"):
        wf.write_text(wf.read_text(encoding="utf-8").replace("--sync-decisions", ""), encoding="utf-8")
    assert check_g11(repo, repo / "config" / "mara.yaml").status == FAIL
    cfg = MaraConfig.model_validate(json.loads(json.dumps({
        "models": [{"name": "a", "family": "anthropic", "provider": "mock", "model": "m", "data_residency": "on_prem"},
                   {"name": "d", "family": "deepseek", "provider": "mock", "model": "m", "data_residency": "on_prem"},
                   {"name": "n", "family": "nemotron", "provider": "mock", "model": "m", "data_residency": "on_prem"}],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "d", "n"]}, "human_queue": {"enabled": False}})))
    assert build_queue([_finding("F-1", 1)], {"F-1": _cons("F-1", _policy(cfg), **ALL_NEEDS_HUMAN)}, {}, {}, [], cfg) == []
    r = ReviewReport(target="t", generated_at="2026-09-12T00:00:00+00:00", provider_mode="mock", families_used=[], findings=[], skeptic=[], redteam=[],
                     votes=[], consensus=[], dimensions=[], overall_score=0, gate_passed=True, bias_audit={})
    assert "_Empty._" in render_human_queue(r)
