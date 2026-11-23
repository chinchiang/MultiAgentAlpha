"""scripts/tool_triage.py (GLOSSARY.md: tool triage; docs/adr/0010-tool-triage.md): `draft` prints an entry draft for
each untriaged alert of a report that may be triaged, never a ruling; `check` says which entries of a triage file are
malformed or not usable today. Driven through `main`, in a workspace of the test's own named by MARA_HOME."""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import tool_triage as script  # noqa: E402

from mara import tool_triage  # noqa: E402

TARGET = "t" * 64
TODAY = dt.date.today()


def _result(tool="semgrep", rule="python.sqli", file="app.py", level="error", fingerprint: str | None = "a" * 16, **more) -> dict:
    """A tool result with a fingerprint unless None is given (a review gives one to its alerts only; the note here
    has one so that the script's own level check is what leaves it out)."""
    out = {"tool": tool, "rule_id": rule, "level": level, "message": "m", "file": file, "line": 3, **more}
    if fingerprint:
        out["fingerprint"] = fingerprint
    return out


def _report(tmp_path: Path, results: list[dict], target: str | None = TARGET) -> Path:
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"target_id": target, "tool_results": results}), encoding="utf-8")
    return path


def test_a_draft_is_printed_for_each_untriaged_alert_that_may_be_triaged_once(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    report = _report(tmp_path, [_result(), _result(), _result(file="./app.py", fingerprint="b" * 16),
                                _result(rule="python.xss", level="warning"),
                                _result(rule="python.info", level="note"), _result(tool="gitleaks", rule="generic-api-key"),
                                _result(rule="generic.secrets.security.detected-key"),
                                _result(rule="python.done", triage={"verdict": "false_positive"})])
    assert script.main(["draft", "--report", str(report), "--days", "14", "--decided-by", "alice"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("# 2 draft(s): ")
    entries = yaml.safe_load(out)["entries"]
    assert [(e["tool"], e["rule"], e["file"]) for e in entries] == [("semgrep", "python.sqli", "app.py"), ("semgrep", "python.xss", "app.py")]
    assert entries[0] == {"target_id": TARGET, "tool": "semgrep", "rule": "python.sqli", "file": "app.py",
                          "fingerprints": ["a" * 16, "b" * 16], "verdict": "TODO",
                          "reason": "TODO", "decided_by": "alice", "decided_on": TODAY.isoformat(),
                          "expires": (TODAY + dt.timedelta(days=14)).isoformat()}


def test_a_draft_is_not_an_entry_until_a_person_has_ruled(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    assert script.main(["draft", "--report", str(_report(tmp_path, [_result()]))]) == 0
    [draft] = yaml.safe_load(capsys.readouterr().out)["entries"]
    assert tool_triage.parse(draft) == "verdict is not one of false_positive, accepted_risk"
    ruled = {**draft, "verdict": "false_positive", "reason": "the table name is a constant of the module", "decided_by": "alice"}
    assert isinstance(tool_triage.parse(ruled), tool_triage.Entry)


def test_a_report_of_a_review_without_tool_triage_drafts_nothing_and_says_how_to_get_one(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    report = _report(tmp_path, [_result(fingerprint=None), _result(rule="python.xss", fingerprint=None)])
    assert script.main(["draft", "--report", str(report)]) == 0
    out = capsys.readouterr().out
    assert yaml.safe_load(out)["entries"] == []
    assert out.splitlines()[0].startswith("# 2 alert(s) carry no fingerprint and are left out: ")
    assert "tool_triage.enabled: true" in out.splitlines()[0]


def test_a_report_with_no_target_or_that_cannot_be_read_drafts_nothing(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    assert script.main(["draft", "--report", str(_report(tmp_path, [_result()], target=None))]) == 0
    assert yaml.safe_load(capsys.readouterr().out)["entries"] == []
    (tmp_path / "bad.json").write_text("[1]", encoding="utf-8")
    assert script.main(["draft", "--report", str(tmp_path / "bad.json")]) == 2
    assert script.main(["draft", "--report", str(tmp_path / "none.json")]) == 2
    assert capsys.readouterr().err.splitlines() == [f"ERROR: {tmp_path / 'bad.json'}: not a report",
                                                    f"ERROR: {tmp_path / 'none.json'}: not a readable report (FileNotFoundError)"]


def _entry(**kw) -> dict:
    d = {"target_id": TARGET, "tool": "semgrep", "rule": "python.sqli", "file": "app.py", "verdict": "false_positive",
         "reason": "the table name is a constant of the module", "decided_by": "alice", "decided_on": TODAY.isoformat(),
         "expires": (TODAY + dt.timedelta(days=30)).isoformat(), "fingerprints": ["a" * 16]}
    d.update(kw)
    return d


def _check(tmp_path: Path, entries: list[dict], capsys) -> tuple[int, list[str]]:
    """`check` on a triage file holding `entries`, with the mock config (training not required there is not assumed:
    the config is the repository's mock config with training switched off, written beside the file)."""
    cfg = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    cfg["training"] = {"require_trained_adjudicator": False}
    (tmp_path / "mara.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    file = tmp_path / "triage.yaml"
    file.write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")
    code = script.main(["check", "--file", str(file), "--config", str(tmp_path / "mara.yaml")])
    return code, capsys.readouterr().out.splitlines()


def test_check_passes_a_file_whose_every_entry_is_usable_and_says_when_no_review_applies_it(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    code, lines = _check(tmp_path, [_entry()], capsys)
    assert code == 0
    assert lines == [f"{tmp_path / 'triage.yaml'}: 1 entr(ies), 0 not usable or malformed; tool_triage.enabled is false, "
                     "so no review applies this file"]


def test_check_lists_each_entry_that_is_malformed_or_not_usable_and_exits_1(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    old = _entry(decided_on=(TODAY - dt.timedelta(days=60)).isoformat(), expires=(TODAY - dt.timedelta(days=1)).isoformat())
    code, lines = _check(tmp_path, [_entry(), old, _entry(tool="gitleaks", rule="key"), _entry(reason="fp")], capsys)
    assert code == 1
    assert lines[:3] == ["NOT USABLE entry 4: reason is shorter than 20 characters",
                         f"NOT USABLE semgrep python.sqli app.py (target {TARGET[:12]}): expired",
                         f"NOT USABLE gitleaks key app.py (target {TARGET[:12]}): secret_alert"]
    assert lines[3].startswith(f"{tmp_path / 'triage.yaml'}: 3 entr(ies), 3 not usable or malformed")


def test_check_lists_two_usable_entries_that_disagree_on_one_alert(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    other = _entry(verdict="accepted_risk", approval_ref="RISK-1")
    code, lines = _check(tmp_path, [_entry(), other, _entry(rule="python.xss")], capsys)
    assert code == 1
    assert lines[:2] == [f"NOT USABLE semgrep python.sqli app.py (target {TARGET[:12]}): contradicted"] * 2
