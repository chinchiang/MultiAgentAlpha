"""Tool triage (GLOSSARY.md: tool triage, triaged alert; docs/adr/0010-tool-triage.md; mara.tool_triage at its
interface, and the three places that read a ruling: mara.tools.evidence, mara.review_status and a review's report). A
ruling counts only while it is usable, clears nothing but the alert it names on the target it names, and never a
secret."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import yaml

from mara import tool_triage
from mara.config import ToolTriageConfig, TrainingConfig, load_config
from mara.decisions import TrainingRequirement
from mara.pipeline import Pipeline
from mara.review_status import UNRESOLVED_TOOL_FINDINGS, _incomplete_reasons
from mara.schemas import Finding, ModelFamily, Provenance
from mara.tools.evidence import blocks, corroborates
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult
from mara.training import load_register
from mara.workspace import Workspace
from tests.review_facts import FACTS

ROOT = Path(__file__).resolve().parents[1]
TODAY = dt.date(2026, 11, 23)
TARGET = "t" * 64
NO_TRAINING = TrainingRequirement(required=False)
REGISTER = ("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
            "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n")


def _raw(**kw) -> dict:
    d = {"target_id": TARGET, "tool": "semgrep", "rule": "python.sqli", "file": "app.py", "verdict": "false_positive",
         "reason": "the query is built from a constant table name", "decided_by": "alice", "decided_on": "2026-11-20",
         "expires": "2026-12-20"}
    d.update(kw)
    return {k: v for k, v in d.items() if v is not None}


def _entry(**kw) -> tool_triage.Entry:
    parsed = tool_triage.parse(_raw(**kw))
    assert isinstance(parsed, tool_triage.Entry), parsed
    return parsed


def _alert(tool: str = "semgrep", rule: str = "python.sqli", file: str = "app.py", level: str = "error", line: int = 11) -> ToolResult:
    return ToolResult(tool=tool, rule_id=rule, level=level, message="m", file=file, line=line, cwe="CWE-89", cwes=["CWE-89"])


def _apply(results, *entries, target=TARGET, today=TODAY, max_days=90, training=NO_TRAINING, malformed=()):
    return tool_triage.apply(results, tool_triage.Loaded(list(entries), list(malformed)), target_id=target, today=today,
                             max_days=max_days, training=training)


# ---------------------------------------------------------------- an entry's shape

@pytest.mark.parametrize("change, problem", [
    ({"tool": None}, "tool is missing or not text"),
    ({"rule": 7}, "rule is missing or not text"),
    ({"file": "  "}, "file is missing or not text"),
    ({"verdict": "wontfix"}, "verdict is not one of false_positive, accepted_risk"),
    ({"reason": "fp"}, "reason is shorter than 20 characters"),
    ({"decided_on": "soon"}, "decided_on and expires are dates (YYYY-MM-DD)"),
    ({"expires": None}, "decided_on and expires are dates (YYYY-MM-DD)"),
    ({"expires": "2026-11-19"}, "expires is before decided_on"),
    ({"verdict": "accepted_risk"}, "an accepted risk names its approval_ref"),
    ({"verdict": "accepted_risk", "approval_ref": 12}, "approval_ref is not text"),
    ({"paths": ["*"]}, "unknown key(s) paths"),
])
def test_an_entry_that_is_not_well_formed_says_what_is_wrong_with_it(change, problem):
    assert tool_triage.parse(_raw(**change)) == problem
    assert tool_triage.parse(["semgrep"]) == "an entry is a mapping"


def test_an_accepted_risk_with_its_approval_is_an_entry_and_carries_it_into_the_report():
    e = _entry(verdict="accepted_risk", approval_ref="RISK-2026-014")
    assert e.record() == {"verdict": "accepted_risk", "reason": "the query is built from a constant table name", "decided_by": "alice",
                          "decided_on": "2026-11-20", "expires": "2026-12-20", "approval_ref": "RISK-2026-014"}
    assert "approval_ref" not in _entry().record()


def test_a_triage_file_is_read_entry_by_entry_and_a_file_of_another_shape_triages_nothing(tmp_path):
    assert tool_triage.load(tmp_path / "none.yaml") == tool_triage.Loaded()
    path = tmp_path / "tool-triage.yaml"
    path.write_text(yaml.safe_dump({"entries": [_raw(), _raw(reason="no"), _raw(decided_on=dt.date(2026, 11, 20))]}), encoding="utf-8")
    loaded = tool_triage.load(path)
    assert [e.rule for e in loaded.entries] == ["python.sqli", "python.sqli"]
    assert loaded.malformed == ["entry 2: reason is shorter than 20 characters"]
    for text in ("- just a list\n", "entries: {}\n", "entries: []\nother: 1\n", "entries: [\n"):
        path.write_text(text, encoding="utf-8")
        bad = tool_triage.load(path)
        assert bad.entries == [] and len(bad.malformed) == 1 and bad.malformed[0].startswith("tool-triage.yaml: "), text


# ---------------------------------------------------------------- when an entry is usable

@pytest.mark.parametrize("change, kw, why", [
    ({}, {}, ""),
    ({"tool": "gitleaks"}, {}, "untriageable_tool"),
    ({"decided_on": "2026-11-24", "expires": "2026-12-20"}, {}, "decided_in_future"),
    ({"decided_on": "2026-10-01", "expires": "2026-11-22"}, {}, "expired"),
    ({"expires": "2026-11-23"}, {}, ""),                         # the day it expires still counts
    ({"decided_on": "2026-11-20", "expires": "2027-02-19"}, {}, "window_too_long"),   # 91 days
    ({"decided_on": "2026-11-20", "expires": "2027-02-18"}, {}, ""),                  # 90 days
    ({"decided_on": "2026-11-20", "expires": "2026-12-01"}, {"max_days": 10}, "window_too_long"),
])
def test_an_entry_is_usable_only_inside_its_window_and_for_a_tool_that_may_be_triaged(change, kw, why):
    assert tool_triage.usable(_entry(**change), today=TODAY, max_days=kw.get("max_days", 90), training=NO_TRAINING) == why


def test_where_training_is_required_only_a_trained_adjudicators_ruling_is_usable(tmp_path):
    (tmp_path / "records.yaml").write_text(REGISTER, encoding="utf-8")
    required = TrainingRequirement(required=True, register=load_register(tmp_path / "records.yaml"))
    assert tool_triage.usable(_entry(), today=TODAY, max_days=90, training=required) == ""
    assert tool_triage.usable(_entry(decided_by="mallory"), today=TODAY, max_days=90, training=required) == "untrained"
    # required, and no register to say who is trained: nobody is
    assert tool_triage.usable(_entry(), today=TODAY, max_days=90, training=TrainingRequirement(required=True)) == "untrained"


# ---------------------------------------------------------------- what applying does

def test_a_usable_entry_rules_on_the_alert_it_names_and_on_nothing_else():
    named, other_rule, other_file, other_tool, note = (_alert(), _alert(rule="python.xss"), _alert(file="lib/app.py"),
                                                       _alert(tool="trivy"), _alert(level="note"))
    done = _apply([named, other_rule, other_file, other_tool, note], _entry())
    assert named.triage == _entry().record()
    assert [t.triage for t in (other_rule, other_file, other_tool, note)] == [None] * 4
    assert (done.triaged, done.not_usable, done.stale) == (1, {}, 0)
    assert [blocks(t) for t in (named, other_rule, note)] == [False, True, False]


def test_a_file_spelled_with_a_leading_dot_slash_is_the_same_file():
    alert = _alert(file="./src/app.py")
    assert _apply([alert], _entry(file="src/app.py")).triaged == 1 and alert.triage


def test_an_entry_for_another_target_is_not_this_reviews_and_is_not_counted():
    alert = _alert()
    done = _apply([alert], _entry(target_id="o" * 64))
    assert alert.triage is None and (done.triaged, done.not_usable, done.stale) == (0, {}, 0)


def test_an_entry_that_is_not_usable_leaves_its_alert_blocking_and_is_counted_by_why():
    alert, secret = _alert(), _alert(tool="gitleaks", rule="generic-api-key")
    done = _apply([alert, secret], _entry(decided_on="2026-08-01", expires="2026-09-01"),
                  _entry(tool="gitleaks", rule="generic-api-key"), malformed=["entry 3: reason is shorter than 20 characters"])
    assert alert.triage is None and secret.triage is None and blocks(alert) and blocks(secret)
    assert done.triaged == 0 and done.not_usable == {"expired": 1, "malformed": 1, "untriageable_tool": 1}


def test_two_usable_entries_that_disagree_on_one_alert_are_both_set_aside():
    alert = _alert()
    done = _apply([alert], _entry(), _entry(verdict="accepted_risk", approval_ref="RISK-1"))
    assert alert.triage is None and done.not_usable == {"contradicted": 2}
    agree = _alert()
    later = _entry(decided_on="2026-11-22", reason="re-read on the 22nd: still a constant")
    assert _apply([agree], _entry(), later).triaged == 1 and agree.triage["decided_on"] == "2026-11-22"


def test_a_usable_entry_that_matches_no_alert_is_stale():
    done = _apply([_alert()], _entry(), _entry(rule="python.gone"))
    assert (done.triaged, done.stale) == (1, 1)


# ---------------------------------------------------------------- who reads a ruling

def _finding() -> Finding:
    return Finding(id="F-1", dimension="vulnerabilities", title="SQL injection", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=11, quote="query(uid)", verified=True)], reachability="reachable",
                   reachability_argument="a", exploit_sketch="b",
                   cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", model_confidence=0.5,
                   source_family=ModelFamily.ANTHROPIC, source_model="m")


def test_an_alert_ruled_a_false_positive_corroborates_nothing_and_an_accepted_risk_still_does():
    plain, false_positive, accepted = _alert(), _alert(), _alert()
    _apply([false_positive], _entry())
    _apply([accepted], _entry(verdict="accepted_risk", approval_ref="RISK-1"))
    assert corroborates(_finding(), [plain]) and corroborates(_finding(), [accepted])
    assert not corroborates(_finding(), [false_positive])


def test_a_review_whose_every_alert_is_triaged_has_no_unresolved_tool_finding_and_one_left_keeps_it():
    triaged, left = _alert(), _alert(rule="python.xss")
    _apply([triaged, left], _entry())
    assert UNRESOLVED_TOOL_FINDINGS not in _incomplete_reasons(FACTS, [], [triaged])
    assert UNRESOLVED_TOOL_FINDINGS in _incomplete_reasons(FACTS, [], [triaged, left])


# ---------------------------------------------------------------- the config

def test_tool_triage_is_off_unless_the_config_turns_it_on_and_its_file_stays_below_the_workspace():
    assert load_config(ROOT / "config" / "mara.yaml", Workspace(ROOT)).tool_triage.enabled is False
    assert ToolTriageConfig() == ToolTriageConfig(enabled=False, file="calib/tool-triage.yaml", max_days=90)
    for bad in ("/etc/triage.yaml", "../target/triage.yaml", "calib/../../x.yaml", "C:\\x.yaml", " "):
        with pytest.raises(ValueError, match="relative to the MARA workspace"):
            ToolTriageConfig(file=bad)
    with pytest.raises(ValueError):
        ToolTriageConfig(max_days=181)


# ---------------------------------------------------------------- a review

TOOLS = ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy", "csp-evaluator")


def _review(tmp_path: Path, *, enabled: bool, entries: list[dict] | None = None, results=None):
    """A mock review of a one-file target in a workspace of its own, its tools a runner that reports `results` (one
    semgrep alert unless given). `entries` are written to the workspace's triage file first."""
    ws, target = tmp_path / "ws", tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "app.py").write_text("unsafe()\n", encoding="utf-8")
    (ws / "calib").mkdir(parents=True, exist_ok=True)
    if entries is not None:
        (ws / "calib" / "tool-triage.yaml").write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")
    cfg = load_config(ROOT / "config" / "mara.mock.yaml", Workspace(ROOT))
    cfg = cfg.model_copy(update={"tool_triage": ToolTriageConfig(enabled=enabled),
                                 "training": TrainingConfig(require_trained_adjudicator=False)})
    found = results if results is not None else [_alert(file="app.py", line=1)]
    runs = [ToolRun(t, True, results=[r for r in found if r.tool == t]) for t in TOOLS]
    return Pipeline(cfg, out_dir=tmp_path / "out", root=ws, run_tools=lambda *_a, **_k: runs).run(target, provider_mode="mock")


def _ruling(report, **kw) -> dict:
    today = dt.date.today()
    return _raw(**{"target_id": report.target_id, "decided_on": today.isoformat(),
                   "expires": (today + dt.timedelta(days=30)).isoformat(), **kw})


def test_a_review_with_triage_off_is_as_it_was_whatever_the_file_says(tmp_path):
    first = _review(tmp_path, enabled=False)
    again = _review(tmp_path, enabled=False, entries=[_ruling(first)])
    assert UNRESOLVED_TOOL_FINDINGS in again.incomplete_reasons and not again.gate_passed
    assert "triage" not in again.tool_results[0] and again.bias_audit.get("tool_alerts_triaged", 0) == 0
    assert again.tool_results == first.tool_results


def test_a_review_with_triage_on_keeps_the_triaged_alert_in_its_report_and_is_no_longer_incomplete_for_it(tmp_path):
    first = _review(tmp_path, enabled=True)
    assert UNRESOLVED_TOOL_FINDINGS in first.incomplete_reasons, "on, and nothing ruled on: the alert blocks"
    report = _review(tmp_path, enabled=True, entries=[_ruling(first)])
    assert UNRESOLVED_TOOL_FINDINGS not in report.incomplete_reasons
    [result] = report.tool_results
    assert (result["rule_id"], result["level"], result["triage"]["verdict"], result["triage"]["decided_by"]) \
        == ("python.sqli", "error", "false_positive", "alice")
    assert report.bias_audit["tool_alerts_triaged"] == 1 and report.bias_audit.get("tool_triage_stale", 0) == 0
    from mara.report.markdown_out import render_markdown
    [line] = [x for x in render_markdown(report).splitlines() if "python.sqli" in x]
    assert "triaged:" in line and "by alice" in line and "the query is built from a constant table name" in line


def test_a_review_does_not_let_an_expired_ruling_or_a_ruling_on_a_secret_clear_anything(tmp_path):
    secret = _alert(tool="gitleaks", rule="generic-api-key", file="app.py", line=1)
    first = _review(tmp_path, enabled=True, results=[_alert(file="app.py", line=1), secret])
    today = dt.date.today()
    expired = _ruling(first, decided_on=(today - dt.timedelta(days=40)).isoformat(), expires=(today - dt.timedelta(days=1)).isoformat())
    report = _review(tmp_path, enabled=True, results=[_alert(file="app.py", line=1), secret],
                     entries=[expired, _ruling(first, tool="gitleaks", rule="generic-api-key")])
    assert UNRESOLVED_TOOL_FINDINGS in report.incomplete_reasons and not report.gate_passed
    assert all("triage" not in t for t in report.tool_results)
    assert report.bias_audit["tool_triage_not_usable[expired]"] == 1
    assert report.bias_audit["tool_triage_not_usable[untriageable_tool]"] == 1
