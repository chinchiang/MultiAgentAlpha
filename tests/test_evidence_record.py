"""mara.evidence: when an Evidence record stands (GLOSSARY.md). The table is read at a fixed `today`, never at the real
date, and every expected value is a literal."""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import pytest
import yaml

from mara import evidence, govdocs
from mara import model_eval as me
from mara.audit import Audit
from mara.config import MaraConfig
from mara.evidence import MAX_AGE_DAYS, Future, Header, MissingFamilies, NoDate, NotLive, Stale, standing
from mara.govdocs import read_front_matter
from mara.policy import p8_unsupervised_reject
from tests.aat_records import (
    aat_decision,
    aat_finding,
    aat_posterior,
    aat_run,
    accepted_row,
    rejected_row,
    trained_register,
)
from tests.reply_records import extraction
from tests.test_governance_config import _config, _models

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

TODAY = dt.date(2026, 11, 4)
PRODUCTION = ("anthropic", "gemini", "glm")


def _header(days_ago: int | None = 0, mode: str | None = "live", families: tuple[str, ...] | None = PRODUCTION) -> Header:
    when = None if days_ago is None else TODAY - dt.timedelta(days=days_ago)
    return Header(date=when, mode=mode, families=families)


def test_a_record_stands_for_ninety_days():
    assert MAX_AGE_DAYS == 90


@pytest.mark.parametrize(
    ("header", "required", "problems"),
    [
        pytest.param(_header(0), PRODUCTION, [], id="dated-today-stands"),
        pytest.param(_header(90), PRODUCTION, [], id="ninety-days-old-still-stands"),
        pytest.param(_header(91), PRODUCTION, [Stale(age_days=91, limit=90)], id="ninety-one-days-old-is-stale"),
        pytest.param(_header(-1), PRODUCTION, [Future(date=dt.date(2026, 11, 5))], id="dated-tomorrow-is-in-the-future"),
        pytest.param(_header(None), PRODUCTION, [NoDate()], id="no-date"),
        pytest.param(_header(0, mode="mock"), PRODUCTION, [NotLive(mode="mock")], id="mock-is-not-live"),
        pytest.param(_header(0, mode="dry-run"), PRODUCTION, [NotLive(mode="dry-run")], id="dry-run-is-not-live"),
        pytest.param(_header(0, mode="Live"), PRODUCTION, [NotLive(mode="Live")], id="the-mode-is-lower-case-live-and-nothing-else"),
        pytest.param(_header(0, mode=None), PRODUCTION, [NotLive(mode=None)], id="no-mode-is-not-live"),
        pytest.param(_header(0, families=("anthropic", "gemini")), PRODUCTION, [MissingFamilies(families=("glm",))],
                     id="a-family-not-covered-is-named"),
        pytest.param(_header(0, families=("glm",)), PRODUCTION, [MissingFamilies(families=("anthropic", "gemini"))],
                     id="missing-families-keep-the-order-asked-for"),
        pytest.param(_header(0, families=("deepseek",)), ("glm", "anthropic", "deepseek"), [MissingFamilies(families=("glm", "anthropic"))],
                     id="missing-families-keep-the-order-asked-for-not-the-alphabet"),
        pytest.param(_header(0, families=PRODUCTION + ("deepseek",)), PRODUCTION, [], id="a-family-more-than-asked-for-is-fine"),
        pytest.param(_header(0, families=None), PRODUCTION, [MissingFamilies(families=PRODUCTION)],
                     id="a-record-that-names-no-families-covers-none"),
        pytest.param(_header(0, families=None), None, [], id="no-families-asked-for-none-checked"),
        pytest.param(_header(0, families=None), (), [], id="an-empty-list-of-families-asked-for-misses-none"),
        pytest.param(_header(91, mode="mock", families=("glm",)), PRODUCTION,
                     [Stale(age_days=91, limit=90), NotLive(mode="mock"), MissingFamilies(families=("anthropic", "gemini"))],
                     id="every-problem-is-reported-date-first-then-mode-then-families"),
    ],
)
def test_standing_reports_what_keeps_a_record_from_standing(header, required, problems):
    assert standing(header, TODAY, required) == problems


def test_a_record_with_no_families_asked_for_is_not_checked_for_them():
    assert standing(_header(0, families=None), TODAY) == []


# ------------------------------------------------------------------ reading a record's header


def test_a_latest_json_is_read_into_its_header_and_its_other_keys_are_not_the_headers_business():
    record = {"date": "2026-10-08", "mode": "live", "families": ["anthropic", "glm"], "aat": {"passed": True}, "global_alpha": 0.61}
    assert evidence.Header.from_json(record) == Header(dt.date(2026, 10, 8), "live", ("anthropic", "glm"))


def test_a_latest_json_written_before_it_named_families_names_none():
    record = {"date": "2026-10-08", "mode": "live", "aat": {}, "global_alpha": 0.61}
    assert evidence.Header.from_json(record) == Header(dt.date(2026, 10, 8), "live", None)


@pytest.mark.parametrize("date", ["2026-13-01", "yesterday", "", None, 20261008, 20261008.5, ["2026-10-08"],
                                  "20261008", "2026W41", "2026-W41-4", "2026-10-8", " 2026-10-08", "2026-10-08 ", "2026-10-08T10:00"])
def test_a_date_that_is_not_one_reads_as_no_date(date):
    assert evidence.Header.from_json({"date": date, "mode": "live"}).date is None


def test_a_latest_json_with_no_date_key_reads_as_no_date():
    assert evidence.Header.from_json({"mode": "live"}).date is None


@pytest.mark.parametrize("record", [[], None, "live", 3, [{"date": "2026-10-08"}]])
def test_a_latest_json_that_is_not_an_object_reads_as_a_header_that_says_nothing(record):
    assert evidence.Header.from_json(record) == Header(None, None, None)


@pytest.mark.parametrize("mode", [5, ["live"], {"live": True}, None, True])
def test_a_mode_that_is_not_text_reads_as_no_mode(mode):
    assert evidence.Header.from_json({"date": "2026-10-08", "mode": mode}).mode is None


@pytest.mark.parametrize(("families", "read"), [
    (["glm", 3, None, "gemini"], ("glm", "gemini")), ([], ()), ("anthropic", None), (5, None), ({"glm": 1}, None)])
def test_families_read_as_the_strings_of_a_list_and_as_none_otherwise(families, read):
    assert evidence.Header.from_json({"date": "2026-10-08", "mode": "live", "families": families}).families == read


def test_a_front_matter_is_read_into_its_header_with_the_date_the_caller_gives():
    meta = {"report": "calibration", "mode": "live", "families": ["anthropic", "gemini", "glm"], "provider_modes": ["live"], "labels": 51}
    assert evidence.Header.from_front_matter(meta, dt.date(2026, 10, 8)) == Header(dt.date(2026, 10, 8), "live", ("anthropic", "gemini", "glm"))


def test_a_front_matter_dated_by_no_one_has_no_date():
    assert evidence.Header.from_front_matter({"mode": "live"}, None).date is None


def test_a_front_matter_mode_is_kept_as_written_not_lower_cased():
    assert evidence.Header.from_front_matter({"mode": "Live"}, dt.date(2026, 10, 8)).mode == "Live"


def test_a_front_matter_that_says_no_mode_and_no_families_names_neither():
    assert evidence.Header.from_front_matter({}, dt.date(2026, 10, 8)) == Header(dt.date(2026, 10, 8), None, None)


# ------------------------------------------------------------------ writing a record's header


def test_the_fields_of_a_header_come_in_the_order_date_mode_families():
    assert list(evidence.header_fields("2026-10-08", "live", ["glm", "anthropic"])) == ["date", "mode", "families"]


def test_the_families_of_a_header_are_written_as_a_sorted_list():
    fields = evidence.header_fields("2026-10-08", "live", ("glm", "anthropic", "gemini"))
    assert fields == {"date": "2026-10-08", "mode": "live", "families": ["anthropic", "gemini", "glm"]}
    assert evidence.header_fields("2026-10-08", "mock", [])["families"] == []


@pytest.mark.parametrize("mode", ["live", "mock", "dry-run"])
def test_the_modes_a_run_has_are_written(mode):
    assert evidence.header_fields("2026-10-08", mode, [])["mode"] == mode


@pytest.mark.parametrize("mode", ["Live", "LIVE", "dry_run", "", "production", None])
def test_a_mode_no_run_has_is_refused_when_it_is_written(mode):
    with pytest.raises(ValueError, match="mode"):
        evidence.header_fields("2026-10-08", mode, [])


def test_a_header_written_reads_back_as_the_header_it_was_written_from():
    fields = evidence.header_fields("2026-10-08", "live", ["glm", "anthropic"])
    assert evidence.Header.from_json(fields) == Header(dt.date(2026, 10, 8), "live", ("anthropic", "glm"))
    assert evidence.Header.from_front_matter(fields, dt.date(2026, 10, 8)) == Header(dt.date(2026, 10, 8), "live", ("anthropic", "glm"))


# ------------------------------------------------------------------ the writers put the header first, and the readers read it back

DAY = dt.date(2026, 9, 5)
A_WEEK_LATER = dt.date(2026, 9, 12)
EXAMPLE = ROOT / "config" / "examples" / "ml-bom-required.yaml"  # the example config: production families anthropic and deepseek


def _eval_results(families):
    return [me.FamilyResult(me.EvalTarget(f, f"{f}-reviewer", f"{f}-model", "openai_compatible", "https://llm.internal/v1", "KEY"))
            for f in families]


def _eval_summary(results, mode):
    return me.summarize(results, date=DAY, mode=mode, th=me.Thresholds(), garak_version="0.17.1", cse_ref="4be64c3a2444",
                        probes=["promptinject"])


def _front_matter_of(text: str, tmp_path: Path) -> dict:
    path = tmp_path / "report.md"
    path.write_text(text, encoding="utf-8")
    return read_front_matter(path)[0]


def _live_run(families):
    audit = Audit()
    for family in families:
        audit.record(extraction("reviewer", family))
    return ("s9", {"provider_mode": "live", "provider_manifest": [{"type": "bedrock"}], "config_hash": "h", "revision": "r",
                   "coverage": {}, "findings": [], "votes": [], "consensus": [], "bias_audit": dict(audit)}, [])


def _passing_aat():
    """The Alternative Annotator Test as calibrate computes it, passing: 59 rejections the humans all upheld."""
    import calibrate

    rejected, accepted = range(1, 60), range(100, 120)
    findings = [aat_finding(i) for i in [*rejected, *accepted]]
    decisions = ([aat_decision("app.py", i * 10, "CWE-79", "false_positive") for i in rejected]
                 + [aat_decision("app.py", i * 10, "CWE-79", "true_positive") for i in accepted])
    post = dict([aat_posterior("s9", f"F-{i}", 1) for i in rejected] + [aat_posterior("s9", f"F-{i}", 0) for i in accepted])
    consensus = [rejected_row(i) for i in rejected] + [accepted_row(i) for i in accepted]
    aat = calibrate.alternative_annotator_test([aat_run("s9", findings, consensus)], decisions, post, trained_register())
    assert aat["passed"], aat["why"]
    return aat


@pytest.mark.parametrize("render", [me.render_garak_report, me.render_cyberseceval_report], ids=["garak", "cyberseceval"])
def test_an_evaluation_report_puts_the_header_first_in_its_front_matter(tmp_path, render):
    results = _eval_results(["glm", "anthropic"])
    meta = _front_matter_of(render(_eval_summary(results, "live"), results, {}), tmp_path)
    assert list(meta)[:4] == ["report", "date", "mode", "families"]
    assert (meta["date"], meta["mode"], meta["families"]) == ("2026-09-05", "live", ["anthropic", "glm"])


@pytest.mark.parametrize("render", [me.render_garak_report, me.render_cyberseceval_report], ids=["garak", "cyberseceval"])
def test_an_evaluation_report_of_a_mode_no_run_has_is_not_written(render):
    results = _eval_results(["glm"])
    with pytest.raises(ValueError, match="mode"):
        render(_eval_summary(results, "production"), results, {})


def test_a_calibration_report_puts_the_header_first_in_its_front_matter(tmp_path):
    import calibrate

    runs = [("s1", {"provider_mode": "live"}, ["a", "b"]), ("s2", {"provider_mode": "live"}, ["c"])]
    meta = _front_matter_of(calibrate.front_matter("live", "2026-09-05", ["glm", "anthropic"], runs, None) + "# x\n", tmp_path)
    assert list(meta)[:4] == ["report", "date", "mode", "families"]
    assert (meta["report"], meta["date"], meta["mode"], meta["families"]) == ("calibration", "2026-09-05", "live", ["anthropic", "glm"])
    assert (meta["samples"], meta["labels"], meta["provider_modes"], meta["governance"]) == (["s1", "s2"], 3, ["live"], "G-9")


def test_a_calibration_report_of_a_mode_no_run_has_is_not_written():
    import calibrate

    with pytest.raises(ValueError, match="mode"):
        calibrate.front_matter("production", "2026-09-05", ["glm"], [("s1", {"provider_mode": "live"}, [])], None)


def test_the_latest_json_of_a_calibration_puts_the_header_first():
    import calibrate

    record = calibrate.latest_record("2026-09-05", "live", ["glm", "anthropic"], {"passed": True}, 0.61)
    assert list(record) == ["date", "mode", "families", "aat", "global_alpha"]
    assert record == {"date": "2026-09-05", "mode": "live", "families": ["anthropic", "glm"], "aat": {"passed": True}, "global_alpha": 0.61}


def test_a_latest_json_the_calibration_writes_is_one_policy_p8_accepts(tmp_path, monkeypatch):
    import calibrate

    record = calibrate.latest_record("2026-09-05", "live", ["anthropic", "deepseek"], _passing_aat(), 0.61)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "calib").mkdir()
    (tmp_path / "calib" / "latest.json").write_text(json.dumps(record), encoding="utf-8")
    cfg = MaraConfig.model_validate({**yaml.safe_load(EXAMPLE.read_text(encoding="utf-8")), "gate": {"unsupervised_reject_allowed": True}},
                                    context={"skip_policies": True})
    result = p8_unsupervised_reject(cfg, today=A_WEEK_LATER)
    assert result.passed, result.reason
    record["aat"]["passed"] = False  # the writer's key for the result is the one the reader reads
    (tmp_path / "calib" / "latest.json").write_text(json.dumps(record), encoding="utf-8")
    assert "did not pass" in p8_unsupervised_reject(cfg, today=A_WEEK_LATER).reason


def test_a_live_calibration_leaves_a_latest_json_and_a_report_that_say_what_it_covered(tmp_path, monkeypatch):
    import calibrate
    import governance_check as gc

    root = tmp_path / "repo"
    cfg = _config(root, models=_models())
    monkeypatch.chdir(root)
    monkeypatch.delenv("MARA_HOME", raising=False)
    report = root / "docs" / "calibration-2026-09-05.md"
    report.parent.mkdir()
    (root / "calib").mkdir()
    monkeypatch.setattr(calibrate, "load_runs", lambda *_, **__: [_live_run(["deepseek", "anthropic"])])
    monkeypatch.setattr(calibrate, "training_requirement", lambda *_: trained_register())
    monkeypatch.setattr(sys, "argv", ["calibrate", "--mode", "live", "--date", "2026-09-05", "--report", str(report),
                                      "--out-dir", str(root / "calib-out")])
    calibrate.main()
    latest = json.loads((root / "calib" / "latest.json").read_text(encoding="utf-8"))
    assert Header.from_json(latest) == Header(DAY, "live", ("anthropic", "deepseek"))
    assert Header.from_front_matter(read_front_matter(report)[0], DAY) == Header(DAY, "live", ("anthropic", "deepseek"))
    assert gc.check_g9(root, A_WEEK_LATER, cfg).status == gc.PASS


def test_the_evaluation_reports_the_script_writes_stand_for_check_g8(tmp_path):
    import governance_check as gc

    root = tmp_path / "repo"
    cfg = _config(root, models=_models())
    (root / "docs").mkdir()

    def write(families, mode):
        results = _eval_results(families)
        summary = _eval_summary(results, mode)
        (root / "docs" / "garak-2026-09-05.md").write_text(me.render_garak_report(summary, results, {}), encoding="utf-8")
        (root / "docs" / "cyberseceval-2026-09-05.md").write_text(me.render_cyberseceval_report(summary, results, {}), encoding="utf-8")

    write(["deepseek", "anthropic"], "live")
    assert gc.check_g8(root, A_WEEK_LATER, cfg).status == gc.PASS
    write(["anthropic"], "live")
    assert "未涵蓋家族 ['deepseek']" in gc.check_g8(root, A_WEEK_LATER, cfg).evidence
    write(["deepseek", "anthropic"], "dry-run")
    assert "mode 為 dry-run，不是 live" in gc.check_g8(root, A_WEEK_LATER, cfg).evidence


# ------------------------------------------------------------------ the front matter of a Markdown report


def _read(tmp_path: Path, text: str):
    path = tmp_path / "report.md"
    path.write_text(text, encoding="utf-8")
    return evidence.read_front_matter(path)


def test_the_front_matter_of_a_markdown_report_is_read_apart_from_its_body(tmp_path):
    assert _read(tmp_path, "---\nmode: live\nfamilies: [glm]\n---\n# x\n\ntext\n") == ({"mode": "live", "families": ["glm"]}, "# x\n\ntext\n")


@pytest.mark.parametrize("text", ["# x\n", "", "mode: live\n", "--- not a fence\nmode: live\n---\n", "---\nmode: live\n# never closed\n"])
def test_a_report_without_a_closed_front_matter_has_none_and_is_all_body(tmp_path, text):
    assert _read(tmp_path, text) == ({}, text)


def test_a_front_matter_that_is_not_a_mapping_is_none_and_the_body_is_what_follows_it(tmp_path):
    assert _read(tmp_path, "---\n- glm\n- anthropic\n---\nbody\n") == ({}, "body\n")


def test_the_front_matter_reader_is_the_one_govdocs_and_the_checks_import():
    assert govdocs.read_front_matter is evidence.read_front_matter
