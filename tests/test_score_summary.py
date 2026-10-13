"""Score summary (docs/adr/0004-score-summary.md): `mara export-summary` derives an allowlisted summary of a written
review report for a team outside the country, and every report records its review scope."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mara.cli import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def mock_review(tmp_path_factory) -> Path:
    """The out directory of one real mock review of the seeded fixture."""
    out = tmp_path_factory.mktemp("review")
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock",
                                   "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(out)])
    assert res.exit_code in (0, 2), res.output
    return out


def test_a_full_review_records_its_scope_in_the_report(mock_review):
    report = json.loads((mock_review / "report.json").read_text(encoding="utf-8"))
    assert report["review_scope"] == "full"
    header = (mock_review / "report.md").read_text(encoding="utf-8").split("\n## ")[0]
    assert "Review scope: full" in header


def test_an_incremental_review_records_its_scope_in_the_report(tmp_path):
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "test")
    (repo / "app.py").write_text("def main():\n    return 1\n")
    git("add", "-A")
    git("commit", "-m", "init")
    (repo / "app.py").write_text("def main():\n    return 2\n")
    git("commit", "-am", "change app")
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(repo), "--provider", "mock", "--base", "HEAD~1",
                                   "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(out)])
    assert res.exit_code in (0, 2), res.output
    assert json.loads((out / "report.json").read_text(encoding="utf-8"))["review_scope"] == "incremental"


SUMMARY_KEYS = {"schema", "source_report_sha256", "exported_at", "label", "target_id", "revision", "review_scope",
                "generated_at", "provider_mode", "families_used", "config_hash", "review_status", "incomplete_reasons",
                "gate_passed", "overall_score", "dimensions"}
DIMENSION_KEYS = {"dimension", "score", "accepted_findings", "rejected_findings", "human_queue", "tool_ran", "notes"}


def export(report: Path, out: Path, *extra: str):
    return CliRunner().invoke(app, ["export-summary", str(report), "--out", str(out), *extra])


def plain(output: str) -> str:
    """The CLI output without the error panel's box drawing and line wrapping."""
    return " ".join(output.translate({ord(c): " " for c in "│╭╮╰╯─"}).split())


def test_the_summary_holds_exactly_the_allowlisted_fields(mock_review, tmp_path):
    res = export(mock_review / "report.json", tmp_path / "summary.json", "--allow-mock")
    assert res.exit_code == 0, res.output
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert set(summary) == SUMMARY_KEYS
    assert summary["schema"] == "mara-score-summary/1" and summary["label"] is None
    assert summary["dimensions"] and all(set(d) == DIMENSION_KEYS for d in summary["dimensions"])


def test_the_summary_carries_no_finding_detail_and_no_target_path(mock_review, tmp_path):
    report = json.loads((mock_review / "report.json").read_text(encoding="utf-8"))
    assert report["findings"], "the seeded fixture must yield findings for this test to mean anything"
    detail = {report["target"]}
    for f in report["findings"]:
        detail |= {f["id"], f["title"], f["cwe"], f["cvss4_vector"], f["reachability_argument"], f["exploit_sketch"]}
        detail |= {p["file"] for p in f["provenance"]} | {p["quote"] for p in f["provenance"]}
    detail |= {h["key"] for h in report["human_queue"]}
    assert export(mock_review / "report.json", tmp_path / "summary.json", "--allow-mock").exit_code == 0
    text = (tmp_path / "summary.json").read_text(encoding="utf-8")
    assert not [d for d in detail if d and json.dumps(d)[1:-1] in text]


def test_a_mock_report_is_refused_without_allow_mock(mock_review, tmp_path):
    res = export(mock_review / "report.json", tmp_path / "summary.json")
    assert res.exit_code != 0 and "--allow-mock" in res.output
    assert not (tmp_path / "summary.json").exists()


def live_copy(mock_review: Path, tmp_path: Path, drop: tuple[str, ...] = (), **changes) -> Path:
    """The mock review's report as a live-mode report, with `changes` applied and the keys in `drop` removed."""
    report = json.loads((mock_review / "report.json").read_text(encoding="utf-8"))
    report["provider_mode"] = "live"
    report.update(changes)
    for k in drop:
        del report[k]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def test_a_report_that_does_not_validate_is_refused(mock_review, tmp_path):
    truncated = tmp_path / "truncated.json"
    truncated.write_bytes((mock_review / "report.json").read_bytes()[:500])
    missing = live_copy(mock_review, tmp_path, drop=("gate_passed",))
    for bad in (truncated, missing):
        res = export(bad, tmp_path / "summary.json")
        assert res.exit_code != 0, res.output
        assert isinstance(res.exception, SystemExit), res.exception  # a usage error, not a traceback
        assert "not a valid MARA review report" in res.output
        assert not (tmp_path / "summary.json").exists()


@pytest.mark.parametrize("label", ["重慶廠 MES", "x" * 80])
def test_a_label_is_exported_as_given(mock_review, tmp_path, label):
    res = export(live_copy(mock_review, tmp_path), tmp_path / "summary.json", "--label", label)
    assert res.exit_code == 0, res.output
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))["label"] == label


@pytest.mark.parametrize("label", ["", "x" * 81, "MES\nlogin.py", "MES\x1b[31m"])
def test_a_label_that_is_not_one_short_line_is_refused(mock_review, tmp_path, label):
    res = export(live_copy(mock_review, tmp_path), tmp_path / "summary.json", "--label", label)
    assert res.exit_code != 0 and "--label" in res.output
    assert not (tmp_path / "summary.json").exists()


def test_the_summary_names_the_exact_report_it_came_from(mock_review, tmp_path):
    import hashlib

    source = live_copy(mock_review, tmp_path)
    assert export(source, tmp_path / "summary.json").exit_code == 0
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["source_report_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_an_incomplete_review_is_exported_with_no_overall_score_and_its_reasons(mock_review, tmp_path):
    source = live_copy(mock_review, tmp_path, review_status="incomplete", overall_score=None,
                       incomplete_reasons=["required_tool_incomplete", "reviewer_refusals"])
    assert export(source, tmp_path / "summary.json").exit_code == 0
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["review_status"] == "incomplete" and summary["overall_score"] is None
    assert summary["incomplete_reasons"] == ["required_tool_incomplete", "reviewer_refusals"]


def test_a_report_written_before_review_scope_existed_reads_as_unknown(mock_review, tmp_path):
    source = live_copy(mock_review, tmp_path, drop=("review_scope",))
    assert export(source, tmp_path / "summary.json").exit_code == 0
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))["review_scope"] == "unknown"


def test_the_summary_is_not_written_into_the_reviewed_target(mock_review, tmp_path):
    target = tmp_path / "repo"
    target.mkdir()
    source = live_copy(mock_review, tmp_path, target=str(target))
    res = export(source, target / "score-summary.json")
    assert res.exit_code != 0 and "--out" in res.output
    assert "may not be written inside the reviewed target" in plain(res.output) and "refusing to review" not in plain(res.output)
    assert not (target / "score-summary.json").exists()


def test_only_the_output_file_is_kept_out_of_the_target(mock_review, tmp_path, monkeypatch):
    # the export reads no config and runs no tool, so a workspace inside the target does not matter to it
    target = tmp_path / "repo"
    target.mkdir()
    source = live_copy(mock_review, tmp_path, target=str(target))
    monkeypatch.delenv("MARA_HOME", raising=False)
    monkeypatch.chdir(target)
    res = export(source, tmp_path / "summary.json")
    assert res.exit_code == 0, res.output


def test_the_summary_never_overwrites_the_report_it_came_from(mock_review, tmp_path):
    source = live_copy(mock_review, tmp_path)
    (tmp_path / "sub").mkdir()
    before = source.read_bytes()
    for out in (source, tmp_path / "sub" / ".." / "report.json"):
        res = export(source, out)
        assert res.exit_code != 0 and "--out" in res.output
        assert source.read_bytes() == before  # the retained report source_report_sha256 names stays intact


def test_an_unreadable_report_is_a_usage_error_not_a_traceback(mock_review, tmp_path):
    import os

    if os.geteuid() == 0:
        pytest.skip("root reads files regardless of their mode")
    source = live_copy(mock_review, tmp_path)
    source.chmod(0)
    try:
        res = export(source, tmp_path / "summary.json")
    finally:
        source.chmod(0o600)
    assert res.exit_code != 0 and isinstance(res.exception, SystemExit), res.exception
    assert "report.json" in plain(res.output) and "readable" in plain(res.output)
    assert not (tmp_path / "summary.json").exists()
