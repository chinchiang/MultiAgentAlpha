"""The names of the audit's counters (GLOSSARY.md: Bias audit; docs/adr/0008-reply-accounting.md,
docs/adr/0009-report-metadata.md): `mara.audit` holds every name a report's `bias_audit` carries, each with one shape
(a plain count, a count per model family, per pair of families or per reason), writes and reads them through named
entries, and refuses a name it does not hold. The persisted names themselves do not change; the tests pin them.
The cases of the last group describe behaviour that was already there (marked "characterization"): they passed on their
first run and hold the rewrite of the readers to it."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mara import audit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

# the names the roles' table persists, and the others the pipeline and the rounds write, as reports hold them
ROLE_NAMES = (
    "canary_echoes", "canary_reports", "context_calls", "context_canary_echoes", "context_canary_reports", "context_errors",
    "context_invalid_items", "context_refusals", "context_truncations", "context_unparseable_replies", "context_unverified_items",
    "findings_with_unverified_quotes", "invalid_findings_dropped", "judge_calls", "judge_errors", "judge_invalid_items", "judge_items",
    "judge_refusals", "judge_retries", "judge_truncations", "judge_unparseable_replies", "redteam_calls", "redteam_canary_echoes",
    "redteam_canary_reports", "redteam_errors", "redteam_exploit_code_stripped", "redteam_invalid_items", "redteam_items",
    "redteam_refusals", "redteam_retries", "redteam_truncations", "redteam_unparseable_replies", "reviewer_calls", "reviewer_errors",
    "reviewer_refusals", "reviewer_truncations", "reviewer_unparseable_replies", "skeptic_calls", "skeptic_canary_echoes",
    "skeptic_canary_reports", "skeptic_errors", "skeptic_invalid_items", "skeptic_items", "skeptic_refusals", "skeptic_refuted",
    "skeptic_retries", "skeptic_truncations", "skeptic_unparseable_replies", "skeptic_unverified_controls",
)
OTHER_NAMES = (
    "bundle_files_changed", "bundle_files_related", "context_view_items", "exchange_version", "findings_deduped", "findings_raw",
    "global_krippendorff_alpha", "human_decisions_applied", "human_decisions_not_usable", "input_tokens", "judge_agreement",
    "output_tokens", "position_flips", "redteam_same_family", "secret_preflight_calibration_exempted", "self_family_fallback_votes",
    "self_preference_exclusions", "skeptic_same_family", "standard_refs_stripped", "tier_c_blocked_while_tightened", "unknown_cwe",
)


def test_the_persisted_names_are_the_ones_the_reports_hold():
    assert sorted(audit.COUNTER_NAMES) == sorted(ROLE_NAMES + OTHER_NAMES)
    assert len(set(audit.COUNTER_NAMES)) == len(audit.COUNTER_NAMES), "no name twice"


def test_every_name_outside_the_roles_table_is_a_count_member_with_its_persisted_name_as_value():
    assert sorted(str(m) for m in audit.Count) == sorted(OTHER_NAMES)
    assert audit.Count.POSITION_FLIPS == "position_flips" and audit.Count("findings_raw") is audit.Count.FINDINGS_RAW


def test_every_incomplete_counter_is_a_name_the_audit_holds():
    assert set(audit.INCOMPLETE_COUNTERS) <= set(audit.COUNTER_NAMES)


def test_every_name_a_mock_review_writes_is_one_the_audit_holds(mock_report):
    written = {key.partition("[")[0] for key in mock_report[1].bias_audit}
    assert written <= set(audit.COUNTER_NAMES), sorted(written - set(audit.COUNTER_NAMES))


@pytest.mark.parametrize("use", [
    lambda a: a.add("reviewer_calsl", "anthropic"),
    lambda a: a.__setitem__("positon_flips", 1),
    lambda a: a["positon_flips"],
    lambda a: a["reviewer_calsl[anthropic]"],
], ids=["add", "set", "read", "read-per-family"])
def test_a_name_the_audit_does_not_hold_is_refused_on_write_and_on_read(use):
    with pytest.raises(KeyError):
        use(audit.Audit())


def test_a_report_read_by_a_name_the_audit_does_not_hold_is_refused():
    with pytest.raises(KeyError):
        audit.read({"position_flips": 2}, "positon_flips")


def test_a_report_written_before_a_counter_existed_reads_zero_for_it():
    assert audit.read({}, "reviewer_calls") == 0 and audit.read({}, audit.Count.POSITION_FLIPS) == 0
    assert audit.read({"position_flips": 2.5}, audit.Count.POSITION_FLIPS) == 2.5


@pytest.mark.parametrize("value", ["n/a", None, True, [1]], ids=["text", "null", "bool", "list"])
def test_a_report_value_that_is_no_number_reads_zero(value):
    assert audit.read({"position_flips": value}, audit.Count.POSITION_FLIPS) == 0


def test_the_named_entries_write_the_persisted_keys():
    a = audit.Audit()
    a.set(audit.Count.FINDINGS_RAW, 61)
    a.count(audit.Count.SKEPTIC_SAME_FAMILY)
    a.count(audit.Count.SKEPTIC_SAME_FAMILY, 2)
    a.set_reason(audit.Count.HUMAN_DECISIONS_NOT_USABLE, "untrained", 3)
    a.set_pair(audit.Count.JUDGE_AGREEMENT, "anthropic~gemini", 0.92)
    a.set_alpha(0.4872)
    assert dict(a) == {"findings_raw": 61, "skeptic_same_family": 3, "human_decisions_not_usable[untrained]": 3,
                       "judge_agreement[anthropic~gemini]": 0.92, "global_krippendorff_alpha": 0.4872}


def test_a_name_is_written_in_its_own_shape_only():
    a = audit.Audit()
    with pytest.raises(ValueError, match="judge_agreement"):
        a.set(audit.Count.JUDGE_AGREEMENT, 1)
    with pytest.raises(ValueError, match="position_flips"):
        a.set_pair(audit.Count.POSITION_FLIPS, "a~b", 1.0)
    with pytest.raises(ValueError, match="position_flips"):
        a.set_reason(audit.Count.POSITION_FLIPS, "why", 1)


def test_a_reason_is_not_a_family():
    doc = {"human_decisions_not_usable[untrained]": 2, "human_decisions_not_usable[stale]": 1,
           "reviewer_calls[anthropic]": 3, "judge_agreement[anthropic~gemini]": 0.5}
    assert audit.by_family(doc) == {"anthropic": {"reviewer_calls": 3}}
    assert audit.by_reason(doc, audit.Count.HUMAN_DECISIONS_NOT_USABLE) == {"untrained": 2, "stale": 1}


def test_the_pairs_of_the_jury_agreement_are_read_back_by_pair():
    doc = {"judge_agreement[a~b]": 0.5, "judge_agreement[a~c]": 0.25, "judge_calls[a]": 4, "global_krippendorff_alpha": 0.3}
    assert audit.by_pair(doc, audit.Count.JUDGE_AGREEMENT) == {"a~b": 0.5, "a~c": 0.25}
    assert audit.by_pair({}, audit.Count.JUDGE_AGREEMENT) == {}


@pytest.mark.parametrize(("doc", "expected"), [
    ({"global_krippendorff_alpha": 0.4872}, 0.4872),
    ({"global_krippendorff_alpha": 0}, 0.0),
    ({"global_krippendorff_alpha": "n/a"}, None),
    ({}, None),
    ({"global_krippendorff_alpha": True}, None),
], ids=["a number", "zero", "n/a", "absent", "a bool is no number"])
def test_the_global_alpha_is_a_number_or_none(doc, expected):
    assert audit.alpha(doc) == expected
    assert (audit.alpha(doc) is None) == (expected is None)


def test_a_missing_alpha_is_written_as_n_a():
    a = audit.Audit()
    a.set_alpha(None)
    assert dict(a) == {"global_krippendorff_alpha": "n/a"}


# characterization: calibration's rates, as scripts/calibrate.py computed them before it read through mara.audit.
# Every number below is different, so a name read from the wrong counter changes a rate.
CALIBRATION_DOC = {
    "reviewer_calls[f]": 10, "reviewer_refusals[f]": 2, "reviewer_errors[f]": 1, "canary_echoes[f]": 3,
    "findings_with_unverified_quotes[f]": 4, "invalid_findings_dropped[f]": 5,
    "skeptic_calls[f]": 4, "skeptic_refusals[f]": 1, "skeptic_invalid_items[f]": 2, "skeptic_refuted[f]": 6,
    "skeptic_unverified_controls[f]": 7,
    "redteam_calls[f]": 5, "redteam_refusals[f]": 2, "redteam_invalid_items[f]": 1,
    "judge_calls[f]": 8, "judge_refusals[f]": 4, "judge_invalid_items[f]": 2,
}


def test_characterization_calibration_rates_follow_the_counters_of_each_role():
    import calibrate

    rates = calibrate.audit_rates([("s", {"bias_audit": dict(CALIBRATION_DOC)}, [])], ["f", "absent"])
    assert rates["f"] == {
        "calls": 10, "refusal_rate": 0.2, "error_rate": 0.1, "canary_rate": 0.3, "unverified_quotes": 4, "invalid": 5,
        "invalid_rate": 0.5, "skeptic_calls": 4, "skeptic_refusal_rate": 0.25, "skeptic_invalid_rate": 0.5,
        "redteam_calls": 5, "redteam_refusal_rate": 0.4, "redteam_invalid_rate": 0.2,
        "judge_calls": 8, "judge_refusal_rate": 0.5, "judge_invalid_rate": 0.25,
        "skeptic_refuted": 6, "skeptic_unverified_controls": 7}
    assert rates["absent"]["calls"] == 0 and rates["absent"]["refusal_rate"] == 0


def test_characterization_calibration_averages_the_pairs_and_the_alpha_of_the_runs_that_have_one():
    import calibrate

    one = {"bias_audit": {"judge_agreement[a~b]": 0.5, "judge_agreement[a~c]": 1.0, "global_krippendorff_alpha": 0.4}}
    two = {"bias_audit": {"judge_agreement[a~b]": 1.0, "global_krippendorff_alpha": "n/a"}}
    assert calibrate.judge_agreement([("s", one, []), ("t", two, [])]) == ({"a~b": 0.75, "a~c": 1.0}, 0.4)
    assert calibrate.judge_agreement([("t", two, [])]) == ({"a~b": 1.0}, None)
