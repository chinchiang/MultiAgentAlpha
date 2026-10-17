"""mara.decisions: one rule for when a human decision counts (docs/adr/0002-usable-decisions.md).
A well-formed decision answers its ticket; only a usable one - bound to the report, uncontradicted,
by an adjudicator trained on the decision day when training is required - is ground truth."""

import datetime as dt
import json

import pytest

from mara import decisions as dec
from mara.human_queue import queue_key
from mara.training import load_register

TARGET, REVISION, CONTEXT = "target-s9", "rev", "ctx"
REPORT = {"target_id": TARGET, "revision": REVISION, "coverage": {"content_hash": CONTEXT}}


def record(line=10, decision="true_positive", by="alice", at="2026-10-01T08:00:00Z", **over):
    r = {"file": "app.py", "line": line, "cwe": "CWE-79", "target_id": TARGET, "revision": REVISION, "context_hash": CONTEXT,
         "decision": decision, "decision_event_id": 100 + line, "decided_by": by, "decided_at": at, "issue": line,
         "url": f"https://example/{line}", "adjudicator_trained": True}
    r.update(over)
    r.setdefault("key", queue_key(r["file"], int(r["line"]), r["cwe"], target_id=r["target_id"], revision=r["revision"],
                                  context_hash=r["context_hash"]))
    return r


def write(directory, rec, name=None):
    directory.mkdir(exist_ok=True)
    (directory / (name or f"{rec['key']}.json")).write_text(json.dumps(rec), encoding="utf-8")


@pytest.fixture
def register(tmp_path):
    p = tmp_path / "records.yaml"
    p.write_text("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
                 "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n",
                 encoding="utf-8")
    return load_register(p)


def trained(register):
    return dec.TrainingRequirement(required=True, register=register)


# ---------------------------------------------------------------- well-formed


def test_load_separates_well_formed_decisions_from_damaged_records(tmp_path):
    d = tmp_path / "decisions"
    good = record()
    write(d, good)
    write(d, record(line=20, key="v2-" + "0" * 24))                       # key is not its own fields' key
    write(d, record(line=30), name="v2-renamed.json")                    # file name is not its key
    write(d, record(line=40, decision="needs_human"))                    # not a ruling
    write(d, {k: v for k, v in record(line=50).items() if k != "decision_event_id"})  # no decision event
    (d / "broken.json").write_text("{not json", encoding="utf-8")
    (d / "backlog.json").write_text(json.dumps({"open": 3}), encoding="utf-8")
    loaded = dec.load(d)
    assert [x.key for x in loaded.decisions] == [good["key"]]
    assert loaded.decisions[0].decision == "true_positive" and loaded.decisions[0].issue == 10
    reasons = {p.name: why for p, why in loaded.malformed}
    assert set(reasons) == {f"{record(line=20, key='v2-' + '0' * 24)['key']}.json", "v2-renamed.json",
                            f"{record(line=40)['key']}.json", f"{record(line=50)['key']}.json", "broken.json"}
    assert "backlog.json" not in reasons
    assert all(why for why in reasons.values())


def test_a_record_round_trips_through_its_decision(tmp_path):
    rec = record()
    parsed = dec.Decision.parse(rec)
    assert isinstance(parsed, dec.Decision) and parsed.to_record() == rec


def test_a_missing_directory_holds_no_decisions(tmp_path):
    loaded = dec.load(tmp_path / "absent")
    assert loaded.decisions == [] and loaded.malformed == []


# ---------------------------------------------------------------- usable


def parsed(*records):
    return [dec.Decision.parse(r) for r in records]


def test_only_decisions_bound_to_the_report_are_usable(register):
    ours = record()
    other = record(line=20, target_id="target-other")
    stale = record(line=30, revision="older")
    sel = dec.select(parsed(ours, other, stale), REPORT, trained(register))
    assert [d.key for d in sel.usable] == [ours["key"]]
    assert sel.by_reason() == {"unbound": 2}


@pytest.mark.parametrize("report", [{}, {"target_id": TARGET, "revision": REVISION}, {**REPORT, "coverage": {"content_hash": ""}}])
def test_a_report_without_its_full_identity_binds_nothing(register, report):
    sel = dec.select(parsed(record()), report, trained(register))
    assert sel.usable == [] and sel.by_reason() == {"unbound": 1}


def test_training_is_judged_from_the_register_on_the_decision_day_not_from_the_record(register):
    """The sync's adjudicator_trained flag is a copy anyone can edit: setting it to true used to make an
    untrained ruling ground truth."""
    forged = record(line=20, by="mallory", adjudicator_trained=True)
    honest_but_stale_flag = record(line=30, by="alice", adjudicator_trained=False)
    before_training = record(line=40, by="alice", at="2026-09-01T08:00:00Z")  # alice trained on 2026-09-20
    sel = dec.select(parsed(forged, honest_but_stale_flag, before_training), REPORT, trained(register))
    assert [d.key for d in sel.usable] == [honest_but_stale_flag["key"]]
    assert sel.by_reason() == {"untrained": 2}
    anyone = dec.select(parsed(forged, honest_but_stale_flag, before_training), REPORT, dec.TrainingRequirement(required=False))
    assert len(anyone.usable) == 3 and anyone.excluded == []


def test_without_a_readable_register_no_decision_is_trained():
    sel = dec.select(parsed(record()), REPORT, dec.TrainingRequirement(required=True, register=None, problem="no training/records.yaml"))
    assert sel.usable == [] and sel.by_reason() == {"untrained": 1}


def test_contradicting_decisions_on_one_key_are_all_excluded(register):
    tp, fp = record(), record(decision="false_positive", decision_event_id=999)
    agreeing = [record(line=20), record(line=20, decision_event_id=998)]
    sel = dec.select(parsed(tp, fp, *agreeing), REPORT, trained(register))
    assert [d.key for d in sel.usable] == [agreeing[0]["key"]], "agreeing records of one key count once"
    assert sel.by_reason() == {"contradictory": 1}, "one contradicted key, however many records"


def test_an_untrained_ruling_does_not_contradict_a_trained_one(register):
    trained_tp, untrained_fp = record(), record(decision="false_positive", by="mallory", decision_event_id=999)
    sel = dec.select(parsed(trained_tp, untrained_fp), REPORT, trained(register))
    assert [d.decision for d in sel.usable] == ["true_positive"] and sel.by_reason() == {"untrained": 1}


def test_training_requirement_from_the_config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    cfg = tmp_path / "mara.yaml"
    cfg.write_text("training: {require_trained_adjudicator: false}\n", encoding="utf-8")
    assert dec.TrainingRequirement.from_config_file(cfg).required is False
    cfg.write_text("models: []\n", encoding="utf-8")
    req = dec.TrainingRequirement.from_config_file(cfg)
    assert req.required and req.register is None and "training/records.yaml" in req.problem
    (tmp_path / "training").mkdir()
    (tmp_path / "training" / "records.yaml").write_text("curriculum_version: '2026-09'\nrecords: []\n", encoding="utf-8")
    req = dec.TrainingRequirement.from_config_file(cfg)
    assert req.register is not None and req.problem == ""
    missing = dec.TrainingRequirement.from_config_file(tmp_path / "absent.yaml")
    assert missing.required, "no config: training stays required (fail closed)"


# ---------------------------------------------------------------- calibration


def _calib():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    import calibrate

    return calibrate


def _sample(tmp_path, decisions):
    out, samples, ddir = tmp_path / "calib-out", tmp_path / "samples", tmp_path / "decisions"
    (out / "s9").mkdir(parents=True)
    (samples / "s9").mkdir(parents=True)
    (out / "s9" / "report.json").write_text(json.dumps({**REPORT, "findings": [], "consensus": []}), encoding="utf-8")
    (samples / "s9" / "labels.json").write_text(json.dumps({"labels": []}), encoding="utf-8")
    for r in decisions:
        write(ddir, r)
    return out, samples, ddir


def test_calibration_labels_come_from_usable_decisions_only(tmp_path, register, capsys):
    """Calibration labels used to apply both of two contradicting decisions, and trusted the record's
    training flag; skipped decisions went into a module-level list that leaked across runs."""
    calibrate = _calib()
    usable = record(line=10)
    forged = record(line=20, by="mallory", adjudicator_trained=True)
    out, samples, ddir = _sample(tmp_path, [usable, forged])
    ddir.joinpath(f"{record(line=30)['key']}.json").write_text(json.dumps(record(line=30)), encoding="utf-8")
    contradicted = record(line=30, decision="false_positive", decision_event_id=999)
    ddir.joinpath("copy.json").write_text(json.dumps(contradicted), encoding="utf-8")  # a hand-made copy: not well-formed
    runs = calibrate.load_runs(out, samples, ddir, training=trained(register))
    (_, _, labels), = runs
    assert sorted(lab["line"] for lab in labels) == [10, 30]
    captured = capsys.readouterr()
    printed = captured.out + captured.err
    assert "untrained" in printed and "#20 by mallory" in printed and "copy.json" in printed
    assert not hasattr(calibrate, "SKIPPED_UNTRAINED")


def test_two_well_formed_contradicting_decisions_give_no_label(tmp_path, register):
    calibrate = _calib()
    tp = record()
    fp = record(decision="false_positive", decision_event_id=999)
    decisions = [dec.Decision.parse(tp), dec.Decision.parse(fp)]
    sel = dec.select(decisions, REPORT, trained(register))
    labels, applied = calibrate.apply_decisions(sel.usable, [])
    assert labels == [] and applied == 0


def test_the_aat_reports_why_items_were_left_out(register):
    calibrate = _calib()
    findings = [{"id": f"F-{i}", "cwe": "CWE-79", "provenance": [{"file": "app.py", "line": i}]} for i in (10, 20, 30, 40)]
    run = ("s9", {**REPORT, "findings": findings, "consensus": []}, [])
    decisions = parsed(record(line=10), record(line=20, by="mallory"), record(line=30),
                       record(line=30, decision="false_positive", decision_event_id=999), record(line=40))
    post = {("s9", "F-10"): [0.7, 0.1, 0.1], ("s9", "F-40"): [0.1, 0.1, 0.7]}  # F-40: the pipeline abstains
    aat = calibrate.alternative_annotator_test([run], decisions, post, trained(register))
    assert aat["n"] == 1
    assert aat["excluded_by_reason"] == {"contradictory": 1, "pipeline_abstained": 1, "untrained": 1}
    assert aat["excluded"] == 3


# ---------------------------------------------------------------- shadow-phase baseline


def test_the_baseline_false_positive_rate_counts_usable_decisions_on_its_reviews(tmp_path, register):
    """baseline_metrics counted every file in calib/decisions: another revision's, an untrained
    adjudicator's, a hand-written one."""
    from mara import govdocs

    rep = tmp_path / "run" / "report.json"
    rep.parent.mkdir()
    rep.write_text(json.dumps({**REPORT, "consensus": [], "gate_passed": True, "provider_mode": "live"}), encoding="utf-8")
    ddir = tmp_path / "decisions"
    write(ddir, record(line=10, decision="false_positive"))
    write(ddir, record(line=20, decision="true_positive"))
    write(ddir, record(line=30, decision="false_positive", revision="older"))
    write(ddir, record(line=40, decision="false_positive", by="mallory"))
    (ddir / "hand.json").write_text(json.dumps({"decision": "false_positive"}), encoding="utf-8")
    m = govdocs.baseline_metrics([rep], ddir, trained(register))
    assert m["decisions"] == {"true_positive": 1, "false_positive": 1}
    assert m["false_positive_rate_from_decisions"] == 0.5
    assert m["decisions_excluded"] == {"malformed": 1, "unbound": 1, "untrained": 1}


# ---------------------------------------------------------------- G-13


def test_g13_names_the_decisions_that_wait_for_a_trained_adjudicator(tmp_path):
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from governance_check import check_g13

    (tmp_path / "training").mkdir()
    (tmp_path / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    (tmp_path / "training" / "records.yaml").write_text(
        "curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
        "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n",
        encoding="utf-8")
    ddir = tmp_path / "calib" / "decisions"
    ddir.mkdir(parents=True)
    write(ddir, record(line=10))
    write(ddir, record(line=20, by="mallory", adjudicator_trained=True))
    r = check_g13(tmp_path, dt.date(2026, 10, 13))
    assert "#20 by mallory" in r.evidence and "#10" not in r.evidence
