"""Score summary (docs/adr/0004-score-summary.md): `mara export-summary` derives an allowlisted summary of a written
review report for a team outside the country, and every report records its review scope."""
from __future__ import annotations

import json
import re
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


SUMMARY_KEYS = {"schema", "source_report_sha256", "exported_at", "label", "target_pseudonym", "revision_pseudonym",
                "pseudonym_key_id", "review_scope", "generated_at", "provider_mode", "families_used", "config_hash",
                "review_status", "incomplete_reasons", "gate_passed", "overall_score", "dimensions"}
DIMENSION_KEYS = {"dimension", "score", "accepted_findings", "rejected_findings", "human_queue", "tool_ran"}
KEY = "k" * 32  # the shortest key MARA_SUMMARY_KEY may hold; plainly fake, so gitleaks does not take it for a secret


def export(report: Path, out: Path, *extra: str, key: str | None = KEY):
    env = {"MARA_SUMMARY_KEY": key} if key is not None else {}
    runner = CliRunner(env=env)
    if key is None:
        runner.env["MARA_SUMMARY_KEY"] = None  # CliRunner unsets a variable mapped to None
    return runner.invoke(app, ["export-summary", str(report), "--out", str(out), *extra])


def plain(output: str) -> str:
    """The CLI output without colour codes (rich colours it on CI), the error panel's box drawing and line wrapping."""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", output)
    return " ".join(text.translate({ord(c): " " for c in "│╭╮╰╯─"}).split())


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
    assert res.exit_code != 0 and "--allow-mock" in plain(res.output)
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
        assert "not a valid MARA review report" in plain(res.output)
        assert not (tmp_path / "summary.json").exists()


@pytest.mark.parametrize("label", ["重慶廠 MES", "x" * 80, "重慶廠\u3000MES", "Cafe\u0301 MES"])
def test_a_label_is_exported_as_given(mock_review, tmp_path, label):
    res = export(live_copy(mock_review, tmp_path), tmp_path / "summary.json", "--label", label)
    assert res.exit_code == 0, res.output
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))["label"] == label


@pytest.mark.parametrize("label", ["", "x" * 81, "MES\nlogin.py", "MES\x1b[31m", "   ", " MES", "MES\u3000",
                                   "MES\u202egnp.nigol", "MES \U0001f468\u200d\U0001f4bb"])
def test_a_label_that_is_not_one_short_line_is_refused(mock_review, tmp_path, label):
    res = export(live_copy(mock_review, tmp_path), tmp_path / "summary.json", "--label", label)
    assert res.exit_code != 0 and "--label" in plain(res.output)
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
    assert res.exit_code != 0 and "--out" in plain(res.output)
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
        assert res.exit_code != 0 and "--out" in plain(res.output)
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
    # the panel can wrap the long tmp path inside a word ("report.jso n"), so compare without whitespace
    squeezed = "".join(plain(res.output).split())
    assert "report.json" in squeezed and "readable" in squeezed
    assert not (tmp_path / "summary.json").exists()


TARGET_ID = "1" * 64
REVISION = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"


def test_the_pseudonyms_are_hmac_sha256_under_the_key(mock_review, tmp_path):
    # expected values computed outside Python:
    #   printf 'target\0%s' "$TARGET_ID" | openssl dgst -sha256 -hmac "$KEY"
    #   printf 'revision\0%s\0%s' "$TARGET_ID" "$REVISION" | openssl dgst -sha256 -hmac "$KEY"
    #   printf '%s' "$KEY" | sha256sum | cut -c1-16
    source = live_copy(mock_review, tmp_path, target_id=TARGET_ID, revision=REVISION)
    assert export(source, tmp_path / "summary.json").exit_code == 0
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["target_pseudonym"] == "e39ebb6b1cb4c2833d1829ff06b37194b96c1f04656b63f39d401929cdf48444"
    assert summary["revision_pseudonym"] == "9db7a4dcfe194cca192a6190bfacff6ad6b82549fb865f5acbf1757bc442c4aa"
    assert summary["pseudonym_key_id"] == "5e318f8cf9cbe249"


def summary_of(mock_review: Path, tmp_path: Path, name: str, key: str = KEY, **changes) -> dict:
    sub = tmp_path / name
    sub.mkdir()
    res = export(live_copy(mock_review, sub, **changes), sub / "summary.json", key=key)
    assert res.exit_code == 0, plain(res.output)
    return json.loads((sub / "summary.json").read_text(encoding="utf-8"))


def test_the_pseudonyms_follow_a_target_under_one_key_and_reveal_nothing_without_it(mock_review, tmp_path):
    first = summary_of(mock_review, tmp_path, "a", target_id=TARGET_ID, revision=REVISION)
    again = summary_of(mock_review, tmp_path, "b", target_id=TARGET_ID, revision=REVISION)
    rekeyed = summary_of(mock_review, tmp_path, "c", key="f" * 32, target_id=TARGET_ID, revision=REVISION)
    fork = summary_of(mock_review, tmp_path, "d", target_id="2" * 64, revision=REVISION)
    assert (first["target_pseudonym"], first["revision_pseudonym"]) == (again["target_pseudonym"], again["revision_pseudonym"])
    assert rekeyed["target_pseudonym"] != first["target_pseudonym"] and rekeyed["pseudonym_key_id"] != first["pseudonym_key_id"]
    # the same commit under another target (a fork) gets another pseudonym: printf 'revision\0%s\0%s' 222…2 "$REVISION" | openssl …
    assert fork["revision_pseudonym"] == "a3eb7fe21af9be57370de1b533ce9f29c044836ba12dc64d9a6d92786758f613"
    text = (tmp_path / "a" / "summary.json").read_text(encoding="utf-8")
    assert TARGET_ID not in text and REVISION not in text


def test_a_report_without_a_revision_has_no_revision_pseudonym(mock_review, tmp_path):
    summary = summary_of(mock_review, tmp_path, "a", target_id=TARGET_ID, revision="")
    assert summary["revision_pseudonym"] is None and summary["target_pseudonym"]


@pytest.mark.parametrize("key", [None, "", "x" * 31, KEY + "\n", " " + KEY])
def test_no_summary_without_a_usable_key_even_for_a_mock_report(mock_review, tmp_path, key):
    res = export(mock_review / "report.json", tmp_path / "summary.json", "--allow-mock", key=key)
    assert res.exit_code != 0 and "MARA_SUMMARY_KEY" in plain(res.output)
    assert not (tmp_path / "summary.json").exists()


@pytest.mark.parametrize(("change", "says"), [({"target_id": ""}, "target_id"), ({"target": "fixtures/vuln-sample"}, "relative")])
def test_a_report_that_cannot_name_or_place_its_target_is_refused(mock_review, tmp_path, change, says):
    res = export(live_copy(mock_review, tmp_path, **change), tmp_path / "summary.json")
    assert res.exit_code != 0 and says in plain(res.output)
    assert not (tmp_path / "summary.json").exists()


def with_dimension_named(mock_review: Path, name: str) -> list[dict]:
    dims = json.loads((mock_review / "report.json").read_text(encoding="utf-8"))["dimensions"]
    return [dict(dims[0], dimension=name), *dims[1:]]


@pytest.mark.parametrize("field", ["incomplete_reasons", "families_used", "provider_mode", "generated_at", "config_hash", "dimension"])
def test_an_allowlisted_field_carrying_free_text_is_refused(mock_review, tmp_path, field):
    text = "login.py:42 SQL injection in build_query"  # finding detail smuggled into a field that never holds text
    change = {"incomplete_reasons": {"incomplete_reasons": ["reviewer_refusals", text]},
              "families_used": {"families_used": ["anthropic", text]},
              "provider_mode": {"provider_mode": text},
              "generated_at": {"generated_at": text},
              "config_hash": {"config_hash": text},
              "dimension": {"dimensions": with_dimension_named(mock_review, text)}}[field]
    source = live_copy(mock_review, tmp_path, **change)
    if field == "provider_mode":  # live_copy sets live; put the free text back
        report = json.loads(source.read_text(encoding="utf-8"))
        report["provider_mode"] = text
        source.write_text(json.dumps(report), encoding="utf-8")
    res = export(source, tmp_path / "summary.json")
    assert res.exit_code != 0 and field in plain(res.output), plain(res.output)
    assert not (tmp_path / "summary.json").exists()


def test_every_incomplete_reason_a_review_can_write_can_be_exported(mock_review, tmp_path):
    """The reasons come from the writers, not from the allowlist: every completeness counter counted in an Audit, and
    what assess() writes with every fact wrong and the evidence that brings the last two reasons (a finding waiting for
    a human, an untriaged tool result), once with egress blocked and once without (a blocked egress makes no context
    call, so the context view cannot be missing then). Whatever a review can write, the summary exports.

    The review status's own codes are written out below on purpose, from the ADR rather than from
    OWN_INCOMPLETE_REASONS: a reason added to the writer must be added there and here."""
    from dataclasses import replace

    from mara.audit import INCOMPLETE_COUNTERS, Audit
    from mara.review_status import assess
    from mara.tools.sarif import ToolResult
    from tests.review_facts import FACTS, GATE, OUTCOME, dim, row

    audit = Audit()
    for counter in INCOMPLETE_COUNTERS:
        audit.add(counter, "glm")
    wrong = replace(FACTS, context_complete=False, required_tools_ran=False, ml_bom_signature=False, context_view_missing=True,
                    incomplete_counters=tuple(audit.incomplete_reasons()))
    evidence = ([row("F-1", "B", "Medium", "needs_human")], [ToolResult("semgrep", "r", "warning", "m", "app.py", 1)],
                [dim("xss", 80.0)], OUTCOME, GATE)
    written: list[str] = []
    for facts in (replace(wrong, egress_blocked=True), wrong):
        written += [r for r in assess(facts, *evidence).incomplete_reasons if r not in written]
    # every code the review status writes itself (docs/adr/0007-review-status-and-gate.md), and every counter
    assert set(written) - set(INCOMPLETE_COUNTERS) == {
        "context_coverage_incomplete", "source_egress_blocked_by_secret_preflight", "required_tool_incomplete",
        "ml_bom_signature_unverified", "context_view_incomplete", "unresolved_human_review", "unresolved_tool_findings"}
    assert set(INCOMPLETE_COUNTERS) <= set(written)
    summary = summary_of(mock_review, tmp_path, "a", review_status="incomplete", overall_score=None, incomplete_reasons=written)
    assert summary["incomplete_reasons"] == written
