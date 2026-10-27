"""The calibration loop runs end to end on a labelled sample with label-driven mock families."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mara.config import load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from tests import scored_rows  # noqa: E402


def test_label_driven_mock_and_calibrate(root, tmp_path):
    cfg = load_config(root / "config" / "mara.mock.yaml")
    sample = root / "calib" / "samples" / "s1-fastapi-inventory"
    out = tmp_path / "calib-out" / sample.name
    pipe = Pipeline(cfg, out_dir=out)
    report = pipe.run(sample, mode="mock")
    labels = json.loads((sample / "labels.json").read_text())["labels"]
    assert report.findings, "label-driven mock produced no findings"
    assert all(f.finder_families for f in report.findings)
    assert report.bias_audit["reviewer_refusals[nemotron]"] == 1  # nemotron profile refuses error_handling
    fake = [f for f in report.findings if "mock false positive" in f.title]
    assert fake and not any(p.verified for p in fake[0].provenance)
    hit = sum(1 for lab in labels for f in report.findings
              if f.provenance[0].file == lab["file"] and abs(f.provenance[0].line - lab["line"]) <= 3 and f.cwe == lab["cwe"])
    assert hit >= len(labels) * 0.6
    (out / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    rep_md = tmp_path / "calibration.md"
    cp = subprocess.run(
        [sys.executable, str(root / "scripts" / "calibrate.py"), "--out-dir", str(tmp_path / "calib-out"),
         "--samples-dir", str(root / "calib" / "samples"), "--report", str(rep_md)],
        capture_output=True, text=True, cwd=root,
    )
    assert cp.returncode == 0, cp.stderr
    text = rep_md.read_text(encoding="utf-8")
    assert "anthropic" in text and "建議家族權重" in text
    assert "weight=" in cp.stdout


def test_calibration_run_never_takes_an_exit_2_without_a_report_for_a_review(tmp_path):
    """Exit 2 is a blocked gate (a completed review) but also any typer usage error; the loop took both as
    success and calibrated on whatever report.json an earlier run had left in calib-out."""
    import os
    import shutil

    sample = tmp_path / "samples" / "s1"
    shutil.copytree(ROOT / "calib" / "samples" / "s1-fastapi-inventory", sample)
    stale = tmp_path / "out" / "s1" / "report.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"stale": true}', encoding="utf-8")
    # MARA_HOME inside the sample: `mara review` refuses it with a usage error (exit 2) and writes no report
    env = {**os.environ, "MARA_HOME": str(sample / "home"), "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "calibration_run.py"), "--mode", "mock", "--samples-dir", str(tmp_path / "samples"),
                        "--out-dir", str(tmp_path / "out"), "--report", str(tmp_path / "r.md")],
                       capture_output=True, text=True, encoding="utf-8", env=env, cwd=ROOT)
    assert r.returncode == 1 and "review of s1 failed (exit 2, no report written)" in r.stderr, r.stdout + r.stderr
    assert not stale.exists() and not (tmp_path / "r.md").exists()


# ------------------------------------------------------------------ the answer key never reaches a model

def test_calibration_answer_key_is_excluded_from_the_bundle(root, tmp_path):
    from mara.context.repo_map import build_context
    from tests.tracked import tracked_files

    samples = sorted({f.split("/")[2] for f in tracked_files(root) if f.startswith("calib/samples/") and f.count("/") >= 3})
    assert samples
    for sample in (root / "calib" / "samples" / name for name in samples):
        ctx = build_context(sample)
        assert "labels.json" not in ctx.content, sample.name
        assert ctx.excluded["labels.json"] == "calibration_answer_key" and ctx.complete, sample.name
        assert "labels.json" not in ctx.bundle()
    # recognised by content: an unrelated labels.json (e.g. a GitHub label set) is still reviewed
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "labels.json").write_text(json.dumps([{"name": "bug", "color": "d73a4a"}]), encoding="utf-8")
    assert "labels.json" in build_context(tmp_path).content
    (tmp_path / "labels.json").write_text(json.dumps({"labels": [{"name": "bug"}]}), encoding="utf-8")
    assert "labels.json" in build_context(tmp_path).content


def test_live_calibration_refuses_runs_that_bundled_the_answer_key(tmp_path, monkeypatch):
    import calibrate

    run = {"provider_mode": "live", "provider_manifest": [{"type": "anthropic", "family": "anthropic", "model": "claude-opus-5"}],
           "config_hash": "hash", "revision": "rev", "coverage": {"included": ["main.py", "labels.json"]}}
    monkeypatch.setattr(sys, "argv", ["calibrate", "--mode", "live", "--out-dir", str(tmp_path)])
    monkeypatch.setattr(calibrate, "load_runs", lambda *_, **__: [("s1", run, [])])
    import pytest
    with pytest.raises(SystemExit, match="answer key labels.json was in the reviewed bundle of \\['s1'\\]"):
        calibrate.main()


def test_runs_without_their_own_labels_are_skipped_not_scored_against_nothing(tmp_path, capsys):
    import calibrate

    (tmp_path / "out" / "unlabelled-corpus").mkdir(parents=True)
    (tmp_path / "out" / "unlabelled-corpus" / "report.json").write_text(json.dumps({"findings": []}), encoding="utf-8")
    (tmp_path / "samples").mkdir()
    assert calibrate.load_runs(tmp_path / "out", tmp_path / "samples", decisions_dir=tmp_path / "none") == []
    assert "unlabelled-corpus: SKIPPED" in capsys.readouterr().err


# ------------------------------------------------------------------ per-role refusals, refutation and weight discounts (#30/#38)

def test_audit_rates_reports_per_role_refusals_and_invalid_output():
    import calibrate

    rep = {"bias_audit": {
        "reviewer_calls[anthropic]": 10, "reviewer_refusals[anthropic]": 2, "invalid_findings_dropped[anthropic]": 3,
        "skeptic_calls[anthropic]": 5, "skeptic_refusals[anthropic]": 1, "skeptic_invalid_items[anthropic]": 1,
        "skeptic_refuted[anthropic]": 2, "skeptic_unverified_controls[anthropic]": 1,
        "redteam_calls[anthropic]": 4, "redteam_refusals[anthropic]": 1, "redteam_invalid_items[anthropic]": 1,
        "judge_calls[anthropic]": 8, "judge_refusals[anthropic]": 2, "judge_invalid_items[anthropic]": 1,
    }}
    r = calibrate.audit_rates([("s", rep, [])], ["anthropic"])["anthropic"]
    assert r["refusal_rate"] == 0.2 and r["invalid_rate"] == 0.3
    assert r["skeptic_refusal_rate"] == 0.2 and r["skeptic_invalid_rate"] == 0.2 and r["skeptic_refuted"] == 2
    assert r["redteam_refusal_rate"] == 0.25 and r["redteam_invalid_rate"] == 0.25
    assert r["judge_refusal_rate"] == 0.25 and r["judge_invalid_rate"] == 0.125
    assert r["skeptic_unverified_controls"] == 1


def test_a_context_canary_echo_does_not_reach_the_reviewer_canary_rate():
    """The context agent's echoes used to be written into the reviewers' canary_echoes, so calibration charged a
    context echo to that family's reviewers (docs/adr/0008-reply-accounting.md)."""
    import calibrate

    from mara.audit import Audit
    from tests.reply_records import extraction

    a = Audit()
    a.record(extraction("context", "anthropic", canary_echoes=1))
    a.record(extraction("reviewer", "anthropic"))
    r = calibrate.audit_rates([("s", {"bias_audit": dict(a)}, [])], ["anthropic"])["anthropic"]
    assert r["calls"] == 1 and r["canary_rate"] == 0
    assert a["context_canary_echoes[anthropic]"] == 1 and "context_canary_echoes" in a.incomplete_reasons()


def test_the_families_measured_are_the_ones_that_reviewed():
    """Calibration reads the per-family counters through mara.audit.by_family: a family that only ran the context agent
    or judged, or a pair of families, is not a reviewer that missed every label."""
    import calibrate

    rep = {"findings": [], "bias_audit": {"reviewer_calls[anthropic]": 3, "reviewer_calls[glm]": 0, "context_calls[gemini]": 1,
                                          "judge_calls[deepseek]": 2, "judge_agreement[anthropic~deepseek]": 0.5}}
    stats, families = calibrate.family_metrics([("s", rep, [{"file": "a.py", "line": 1, "cwe": "CWE-89"}])])
    assert families == ["anthropic"] and set(stats) == {"anthropic"}


def test_family_metrics_pairs_overlapping_labels_independently_of_order():
    import calibrate

    labels = [{"file": "a.py", "line": n, "cwe": "CWE-89"} for n in (12, 10)]
    findings = [{"provenance": [{"file": "a.py", "line": n}], "cwe": "CWE-89", "finder_families": ["anthropic"]}
                for n in (10, 14)]
    for ordered_labels in (labels, labels[::-1]):
        for ordered_findings in (findings, findings[::-1]):
            rep = {"findings": ordered_findings, "bias_audit": {}}
            stats, _ = calibrate.family_metrics([("s", rep, ordered_labels)])
            assert stats["anthropic"]["CWE-89"] == {"tp": 2, "fp": 0, "fn": 0}


def test_family_metrics_counts_duplicates_and_unmatched_findings_per_family():
    import calibrate

    labels = [{"file": "a.py", "line": 10, "cwe": "CWE-89"}, {"file": "a.py", "line": 30, "cwe": "CWE-79"}]
    findings = [
        {"provenance": [{"file": "a.py", "line": 10}], "cwe": "CWE-89", "finder_families": ["anthropic", "glm"]},
        {"provenance": [{"file": "a.py", "line": 11}], "cwe": "CWE-89", "finder_families": ["anthropic"]},
        {"provenance": [{"file": "other.py", "line": 10}], "cwe": "CWE-89", "finder_families": ["anthropic"]},
    ]
    rep = {"findings": findings, "bias_audit": {}}
    stats, _ = calibrate.family_metrics([("s", rep, labels)])
    assert stats["anthropic"]["CWE-89"] == {"tp": 1, "fp": 1, "fn": 0}
    assert stats["glm"]["CWE-89"] == {"tp": 1, "fp": 0, "fn": 0}
    assert stats["anthropic"]["CWE-79"] == stats["glm"]["CWE-79"] == {"tp": 0, "fp": 0, "fn": 1}


def test_refutation_rates_are_per_finder_family():
    import calibrate

    rep = {"findings": [
        {"id": "F-1", "finder_families": ["anthropic"]},
        {"id": "F-2", "finder_families": ["anthropic", "deepseek"]},
        {"id": "F-3", "finder_families": ["deepseek"]},
    ], "skeptic": [{"finding_id": "F-1", "verdict": "refuted"}, {"finding_id": "F-3", "verdict": "refuted"}]}
    rates = calibrate.refutation_rates([("s", rep, [])], ["anthropic", "deepseek"])
    assert rates["anthropic"] == 0.5 and rates["deepseek"] == 0.5


def test_suggested_weights_discount_refutations_and_invalid_output():
    import calibrate

    stats = {f: {"CWE-79": {"tp": 9, "fp": 1, "fn": 1}} for f in ("a", "b", "c")}
    rel = {f: 0.9 for f in ("a", "b", "c")}
    base = calibrate.suggest_weights(stats, rel, ["a", "b", "c"])
    disc = calibrate.suggest_weights(stats, rel, ["a", "b", "c"],
                                     refuted_rates={"a": 0.5}, rates={"b": {"invalid_rate": 0.2}})
    assert disc["a"]["weight"] == round(base["a"]["weight"] * 0.5, 2)  # over-reporting family
    assert disc["b"]["weight"] == round(base["b"]["weight"] * 0.8, 2) and disc["b"]["invalid_discounted"]
    assert disc["c"]["weight"] == base["c"]["weight"]  # no discount without cause
    assert disc["a"]["skeptic_refuted_rate"] == 0.5 and disc["b"]["invalid_output_rate"] == 0.2


# ------------------------------------------------------------------ assessment #60: Alternative Annotator Test

def _aat_run(sample, findings, consensus=()):
    return (sample, {"target_id": "target-s9", "revision": "rev", "coverage": {"content_hash": "ctx"}, "findings": findings,
                     "consensus": list(consensus)}, [])


def _dec(file, line, cwe, decision, trained=True):
    from mara.decisions import Decision
    from mara.human_queue import queue_key

    return Decision.parse({"key": queue_key(file, line, cwe, target_id="target-s9", revision="rev", context_hash="ctx"),
                           "decision": decision, "file": file, "line": line, "cwe": cwe, "issue": line,
                           "decided_by": "alice" if trained else "mallory", "decided_at": "2026-10-01T08:00:00Z",
                           "target_id": "target-s9", "revision": "rev", "context_hash": "ctx", "decision_event_id": line})


def _trained():
    """G-13: alice holds a valid adjudicator record; mallory has none."""
    import datetime as dt

    from mara.decisions import TrainingRequirement
    from mara.training import Record, Register

    alice = Record("alice", "adjudicator", "2026-09", dt.date(2026, 9, 1), dt.date(2027, 9, 1), None, "quiz", "quiz")
    return TrainingRequirement(required=True, register=Register("2026-09", 365, 0.8, [alice]))


def _post(sample, fid, argmax):
    p = [0.1, 0.1, 0.1]
    p[argmax] = 0.7
    return (sample, fid), p


def _finding(i, cwe="CWE-79"):
    return {"id": f"F-{i}", "cwe": cwe, "provenance": [{"file": "app.py", "line": i * 10}]}


def _row(i, state):
    """The consensus row jury scoring writes for F-i in `state` (tests/scored_rows.py), as report.json holds it."""
    return scored_rows.row(state, f"F-{i}").model_dump(mode="json")


def _rejected(i):
    """A rejected finding, the rejection P8 unlocks: a tool corroborates it (tier A) and one of three independent judge
    families confirmed it. Only tier A can be rejected, and only with a fourth judge family on the mock panel
    (docs/adr/0005-jury-outcome.md)."""
    return _row(i, "rejected")


def _accepted(i):
    return _row(i, "accepted")


def _dropped(i):
    """A dropped finding: every family called it a false positive, so it is tier D, out on the evidence rather than the vote."""
    return _row(i, "dropped")


def test_aat_agreement_is_tested_against_chance_and_needs_ten_items():
    import calibrate

    findings = [_finding(i) for i in range(1, 13)]
    decisions = [_dec("app.py", i * 10, "CWE-79", "true_positive" if i % 2 else "false_positive") for i in range(1, 12)]
    post = dict([_post("s9", f"F-{i}", 0 if i % 2 else 1) for i in range(1, 11)])
    post[_post("s9", "F-11", 2)[0]] = _post("s9", "F-11", 2)[1]   # pipeline abstains: excluded, not tested
    post[_post("s9", "F-12", 1)[0]] = _post("s9", "F-12", 1)[1]   # no human decision: not tested
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], decisions, post, _trained())
    assert aat["n"] == 10 and aat["agreement"] == 1.0 and aat["chance_agreement"] == 0.5 and aat["kappa"] == 1.0
    assert aat["p_value"] == 0.001 and aat["agreement_passed"] and aat["excluded"] == 1  # one-sided: 0.5 ** 10
    # agreement alone is not enough: none of these was a rejection the pipeline would make unsupervised
    assert aat["rejection"]["n"] == 0 and not aat["passed"] and "不採納安全性未達" in aat["why"]
    weak = calibrate.alternative_annotator_test([_aat_run("s9", findings[:2])], decisions[:2],
                                                {_post("s9", "F-1", 0)[0]: _post("s9", "F-1", 0)[1],
                                                 _post("s9", "F-2", 1)[0]: _post("s9", "F-2", 1)[1]}, _trained())
    assert weak["n"] == 2 and weak["agreement"] == 1.0 and not weak["agreement_passed"]  # significant needs n >= 10


def test_aat_constant_labeller_agrees_only_at_chance_and_fails():
    """Humans confirm 18 of 20 queued findings as false positives. A pipeline that calls everything a
    false positive agrees 90% of the time, which the old fixed-0.5 baseline read as p = 0.0004."""
    import calibrate

    findings = [_finding(i) for i in range(1, 21)]
    decisions = [_dec("app.py", i * 10, "CWE-79", "true_positive" if i <= 2 else "false_positive") for i in range(1, 21)]
    post = dict(_post("s9", f"F-{i}", 1) for i in range(1, 21))
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], decisions, post, _trained())
    assert aat["n"] == 20 and aat["agreement"] == 0.9 and aat["chance_agreement"] == 0.9 and aat["kappa"] == 0.0
    assert aat["p_value"] > 0.5 and not aat["agreement_passed"] and not aat["passed"]


def test_aat_rejection_safety_bounds_the_miss_rate_of_unsupervised_rejections():
    import calibrate

    def run(n_rejected, misses=0):
        rej = range(1, n_rejected + 1)
        acc = range(100, 120)
        findings = [_finding(i) for i in [*rej, *acc]]
        decisions = ([_dec("app.py", i * 10, "CWE-79", "true_positive" if i <= misses else "false_positive") for i in rej]
                     + [_dec("app.py", i * 10, "CWE-79", "true_positive") for i in acc])
        post = dict([_post("s9", f"F-{i}", 1) for i in rej] + [_post("s9", f"F-{i}", 0) for i in acc])
        consensus = [_rejected(i) for i in rej] + [_accepted(i) for i in acc]
        return calibrate.alternative_annotator_test([_aat_run("s9", findings, consensus)], decisions, post, _trained())

    ok = run(59)  # zero misses in 59: the 95% upper bound 1 - 0.05 ** (1/59) = 0.0495 <= 0.05
    from mara.policy import AAT_METHOD
    assert ok["passed"] and ok["method"] == AAT_METHOD and ok["agreement_passed"]
    assert ok["rejection"] == {"n": 59, "misses": 0, "miss_rate_upper": 0.0495, "max_miss_rate": 0.05, "confidence": 0.95, "passed": True}
    short = run(58)  # one decided rejection short: 0.0503 > 0.05
    assert short["agreement_passed"] and not short["rejection"]["passed"] and not short["passed"]
    missed = run(59, misses=1)  # one real vulnerability among the would-be rejections
    assert missed["rejection"]["misses"] == 1 and missed["rejection"]["miss_rate_upper"] > 0.05 and not missed["passed"]
    assert abs(calibrate.clopper_pearson_upper(0, 59) - (1 - 0.05 ** (1 / 59))) < 1e-9
    assert abs(calibrate.clopper_pearson_upper(1, 59) - 0.07790) < 1e-4  # P(X <= 1 | 59, p) = 0.05 at p = 0.0779


def test_aat_rejection_safety_counts_rejected_findings_not_dropped_ones():
    """docs/adr/0005-jury-outcome.md: the rejections P8 unlocks are the jury's own; a dropped finding (tier D) is out
    on the evidence, so a human confirming one is not a miss of unsupervised rejection."""
    import calibrate

    findings = [_finding(1), _finding(2)]
    decisions = [_dec("app.py", 10, "CWE-79", "true_positive"), _dec("app.py", 20, "CWE-79", "true_positive")]
    post = dict([_post("s9", "F-1", 1), _post("s9", "F-2", 1)])
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings, [_rejected(1), _dropped(2)])], decisions, post, _trained())
    assert (aat["rejection"]["n"], aat["rejection"]["misses"]) == (1, 1)


def test_aat_stops_on_a_consensus_row_that_does_not_validate():
    """Fail closed: a row that is not a ConsensusResult (hand-edited, truncated) is never guessed into the rejection count."""
    import calibrate
    import pytest

    broken = {k: v for k, v in _rejected(1).items() if k != "tier"}
    with pytest.raises(ValueError):
        calibrate.alternative_annotator_test([_aat_run("s9", [_finding(1)], [broken])], [_dec("app.py", 10, "CWE-79", "true_positive")],
                                             dict([_post("s9", "F-1", 1)]), _trained())


def test_aat_stops_on_an_invalid_consensus_row_even_where_no_decision_is_bound():
    """Every row is validated before anything is counted, not only the rows a decision happens to bind to."""
    import calibrate
    import pytest

    broken = {k: v for k, v in _rejected(2).items() if k != "tier"}
    with pytest.raises(ValueError):
        calibrate.alternative_annotator_test([_aat_run("s9", [_finding(1), _finding(2)], [_rejected(1), broken])],
                                             [_dec("app.py", 10, "CWE-79", "true_positive")], dict([_post("s9", "F-1", 1)]), _trained())


def test_aat_binds_one_decision_to_one_finding_by_key():
    import calibrate

    # the old +-3-line match let the line-10 decision count for the line-12 finding as well
    findings = [{"id": "F-1", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": 10}]},
                {"id": "F-2", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": 12}]}]
    post = dict([_post("s9", "F-1", 0), _post("s9", "F-2", 0)])
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], [_dec("app.py", 10, "CWE-79", "true_positive")], post, _trained())
    assert aat["n"] == 1
    contradictory = [_dec("app.py", 10, "CWE-79", "true_positive"), _dec("app.py", 10, "CWE-79", "false_positive")]
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], contradictory, post, _trained())
    assert aat["n"] == 0 and aat["excluded"] == 1


def test_aat_ignores_untrained_adjudicators():
    import calibrate

    findings = [{"id": "F-1", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": 26}]}]
    untrained = _dec("app.py", 26, "CWE-79", "true_positive", trained=False)
    post = {_post("s9", "F-1", 1)[0]: _post("s9", "F-1", 1)[1]}
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], [untrained], post, _trained())
    assert aat["n"] == 0 and not aat["passed"] and aat["why"]  # G-13: the decision is not bound at all
    from mara.decisions import TrainingRequirement

    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], [untrained], post, TrainingRequirement(required=False))
    assert aat["n"] == 1 and aat["agreement"] == 0.0 and not aat["passed"]


def test_aat_disagreement_fails_and_empty_decisions_report_why():
    import calibrate

    findings = [{"id": "F-1", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": 26}]}]
    decisions = [_dec("app.py", 26, "CWE-79", "true_positive")]
    post = {_post("s9", "F-1", 1)[0]: _post("s9", "F-1", 1)[1]}  # pipeline says false_positive, human said tp
    aat = calibrate.alternative_annotator_test([_aat_run("s9", findings)], decisions, post, _trained())
    assert aat["n"] == 1 and aat["agreement"] == 0.0 and not aat["passed"]
    empty = calibrate.alternative_annotator_test([_aat_run("s9", findings)], [], post, _trained())
    assert empty["n"] == 0 and not empty["passed"] and empty["why"]


# ------------------------------------------------------------------ assessment #49: alpha history

def test_history_is_live_only_deduplicated_and_comparable(tmp_path):
    import calibrate

    path = tmp_path / "calib" / "history.json"
    calibrate.append_history(path, "2026-10-01", "mock", 0.5, {"anthropic-deepseek": 0.9})
    assert not path.exists()  # mock numbers never enter the time series
    calibrate.append_history(path, "2026-10-01", "live", 0.5, {"anthropic-deepseek": 0.9})
    calibrate.append_history(path, "2026-10-01", "live", 0.6, {"anthropic-deepseek": 0.8})  # same date+mode: replace
    calibrate.append_history(path, "2026-10-02", "live", 0.45, {"anthropic-deepseek": 0.75})
    hist = calibrate.load_history(path)
    assert [h["global_alpha"] for h in hist] == [0.6, 0.45]
    assert hist[0]["judge_agreement"] == {"anthropic-deepseek": 0.8}
    assert calibrate.load_history(tmp_path / "missing.json") == []


# ------------------------------------------------------------------ assessment #10: tools as a second reference label set

_SEMGREP_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [{"id": "python.django_sql", "properties": {"tags": ["CWE-89: sql"]}}]}},
              "results": [
                  {"ruleId": "python.django_sql", "level": "error", "message": {"text": "sql"},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 33}}}]},
                  {"ruleId": "python.django_sql", "level": "error", "message": {"text": "sql elsewhere"},
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 100}}}]},
                  {"ruleId": "python.django_sql", "message": {"text": "suppressed"},
                   "suppressions": [{"status": "accepted"}],
                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 5}}}]}]}],
}


def test_load_tool_labels_reads_calib_out_tools(tmp_path):
    import calibrate

    tools_dir = tmp_path / "s1" / "tools"
    tools_dir.mkdir(parents=True)
    (tools_dir / "semgrep.sarif").write_text(json.dumps(_SEMGREP_SARIF), encoding="utf-8")
    labels = calibrate.load_tool_labels(tmp_path)
    assert set(labels) == {"s1"} and set(labels["s1"]) == {"semgrep"}
    rs = labels["s1"]["semgrep"]
    assert len(rs) == 2 and rs[0].line == 33 and rs[0].cwe == "CWE-89" and rs[0].tool == "semgrep"  # suppression skipped
    assert calibrate.load_tool_labels(tmp_path / "nope") == {}


def test_tool_recall_matches_by_location_within_three_lines():
    import calibrate

    runs = [("s1", {"findings": [{"provenance": [{"file": "./app.py", "line": 30}], "finder_families": ["anthropic"]},
                                 {"provenance": [{"file": "app.py", "line": 60}], "finder_families": ["deepseek"]}]}, [])]
    tool_labels = {"s1": {"semgrep": []}}
    from mara.tools.sarif import ToolResult

    hits = [ToolResult(tool="semgrep", rule_id="r", level="error", message="m", file="app.py", line=33),
            ToolResult(tool="semgrep", rule_id="r", level="error", message="m", file="app.py", line=100)]
    tool_labels["s1"]["semgrep"] = hits
    rows = calibrate.tool_recall(runs, tool_labels)
    assert rows["anthropic"]["semgrep"] == {"found": 1, "total": 2}   # line 33 is within 3 of 30; 100 is not
    assert rows["deepseek"]["semgrep"] == {"found": 0, "total": 2}
    assert calibrate.tool_recall(runs, {}) == {"anthropic": {}, "deepseek": {}}  # no tool labels: nothing to report
