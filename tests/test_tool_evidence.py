"""mara.tools.evidence (GLOSSARY.md: tool evidence, required tool, tool alert, corroboration): what the deterministic
tools reported on a review's target, and the rules that read it."""

from pathlib import Path

import pytest

from mara.config import load_config
from mara.pipeline import Pipeline
from mara.schemas import Provenance
from mara.tools.evidence import ToolEvidence, corroborates, is_alert, required_tools, scans
from mara.tools.runner import TOOL_DIMENSIONS, ToolRun
from mara.tools.sarif import ToolResult
from tests.scored_rows import finding

ROOT = Path(__file__).resolve().parents[1]
SQL = ToolResult("semgrep", "sql", "error", "SQL injection", "app.py", 2, "CWE-89")
OUTDATED = ToolResult("trivy", "CVE-1", "warning", "outdated", "requirements.txt", 1, "CWE-1104")


def test_an_error_or_a_warning_is_a_tool_alert_and_a_note_is_not():
    assert is_alert("error") and is_alert("warning")
    assert not is_alert("note") and not is_alert("none") and not is_alert(None), "information, or a result without a level"


def test_the_results_and_the_tools_that_ran_are_read_from_the_runs():
    """A scan that did not complete did not run, but what it reported is still part of the evidence."""
    evidence = ToolEvidence(runs=[ToolRun("semgrep", True, [SQL], "pinned"), ToolRun("trivy", False, [OUTDATED], "scanner_incomplete"),
                                  ToolRun("gitleaks", False, [], "not installed")])
    assert evidence.results == [SQL, OUTDATED]
    assert evidence.ran == frozenset({"semgrep"})


def test_a_dimension_has_a_tool_only_when_a_tool_that_scans_it_ran():
    evidence = ToolEvidence(runs=[ToolRun("semgrep", True), ToolRun("trivy", False, [OUTDATED], "scanner_incomplete")])
    assert evidence.ran_for("xss") and evidence.ran_for("vulnerabilities")
    assert not evidence.ran_for("dependencies"), "trivy's scan did not complete"
    assert not evidence.ran_for("architecture"), "no tool scans it"


def test_a_tool_scans_the_dimensions_tool_dimensions_names_for_it():
    assert scans("semgrep", "xss") and scans("trivy", "supply_chain")
    assert not scans("csp-evaluator", "vulnerabilities") and not scans("unknown", "xss")


def test_the_required_tools_are_those_that_scan_a_reviewed_dimension():
    assert required_tools(["vulnerabilities", "secrets"]) == {"semgrep", "gitleaks"}
    assert required_tools(["dependencies"]) == {"osv-scanner", "trivy"}
    assert required_tools(["architecture"]) == frozenset()


def test_the_evidence_is_incomplete_without_a_required_tool():
    dims = ["vulnerabilities", "secrets"]
    assert not ToolEvidence(runs=[ToolRun("semgrep", True)]).complete_for(dims), "gitleaks has no run"
    assert not ToolEvidence(runs=[ToolRun("semgrep", True), ToolRun("gitleaks", False)]).complete_for(dims), "gitleaks did not run"
    assert ToolEvidence(runs=[ToolRun("semgrep", True), ToolRun("gitleaks", True)]).complete_for(dims)
    assert ToolEvidence(runs=[]).complete_for(["architecture"]), "no dimension here needs a tool"


def test_today_a_failed_tool_that_is_not_required_still_makes_the_evidence_incomplete():
    """Stricter than the glossary's required tool: trivy scans no dimension of this review, yet its failed run makes
    the evidence incomplete. A follow-up of the tool evidence rework decides whether only required tools count; this
    test pins today's rule until then."""
    runs = [ToolRun("semgrep", True), ToolRun("gitleaks", True), ToolRun("trivy", False, [], "failed: timeout")]
    assert "trivy" not in required_tools(["vulnerabilities", "secrets"])
    assert not ToolEvidence(runs=runs).complete_for(["vulnerabilities", "secrets"])


def test_the_runs_of_a_tool_keep_their_order():
    first, second = ToolRun("gitleaks", False, [], "not installed"), ToolRun("gitleaks", True)
    evidence = ToolEvidence(runs=[first, ToolRun("semgrep", True), second])
    assert evidence.runs_of("gitleaks") == [first, second]
    assert evidence.runs_of("zizmor") == []


def test_an_alert_corroborates_at_the_same_place_for_the_same_weakness_from_a_tool_of_the_dimension():
    f = finding()  # vulnerabilities, CWE-89, app.py:1

    def hit(**changes):
        base = {"tool": "semgrep", "rule_id": "sql", "level": "error", "message": "SQL injection", "file": "app.py", "line": 4,
                "cwe": "CWE-89", "cwes": []}
        return [ToolResult(**{**base, **changes})]

    assert corroborates(f, hit()) and corroborates(f, hit(level="warning")), "three lines away, an alert"
    assert not corroborates(f, hit(line=5)), "four lines away"
    assert not corroborates(f, hit(level="note")), "a note is information"
    assert not corroborates(f, hit(cwe="CWE-79")), "another weakness"
    assert corroborates(f, hit(cwe="", cwes=["CWE-79", "CWE-89"])), "one of the result's weaknesses"
    assert corroborates(f, hit(cwe="")), "a result without a weakness"
    assert not corroborates(f, hit(tool="csp-evaluator", cwe="")), "csp-evaluator does not scan vulnerabilities"
    assert not corroborates(f, hit(file="lib/app.py")), "another file"
    assert corroborates(f, hit(file="svc/app.py"), "svc"), "the target's own path below the repository top level"
    assert not corroborates(f, hit(file="svc/app.py"), "other")
    moved = f.model_copy(update={"provenance": [Provenance(file="other.py", line=9, quote="other()", verified=True),
                                                Provenance(file="./app.py", line=1, quote="unsafe()", verified=True)]})
    assert corroborates(moved, hit()), "any of the finding's places"


def test_today_an_incomplete_scan_can_still_corroborate():
    """semgrep's scan did not complete, so the vulnerabilities dimension has no tier A - yet its alert still
    corroborates a finding there. A follow-up of the tool evidence rework decides whether it should; this test pins
    today's rule until then."""
    evidence = ToolEvidence(runs=[ToolRun("semgrep", False, [SQL], "scanner_incomplete")])
    assert not evidence.ran_for("vulnerabilities")
    assert corroborates(finding(), evidence.results)


@pytest.mark.parametrize("sarif_dir", [None, ROOT / "fixtures" / "vuln-sample-sarif"],
                         ids=["no pre-recorded SARIF", "pre-recorded SARIF, mock mode"])
def test_a_review_takes_its_tool_runs_from_the_runner_it_is_given(tmp_path, sarif_dir):
    """Without pre-recorded SARIF the tools are run once, into out/tools; with it, in mock mode, they are not run."""
    (tmp_path / "app.py").write_text("print(1)\n")
    calls = []

    def runner(target, out_dir, enabled=None):
        calls.append((target, out_dir, enabled))
        return [ToolRun("semgrep", True, [], "from the runner")]

    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out", run_tools=runner)
    report = pipe.run(tmp_path, mode="mock", sarif_dir=sarif_dir)
    if sarif_dir is None:
        assert calls == [(tmp_path.resolve(), tmp_path / "out" / "tools", None)]
        assert report.tool_health == [{"tool": "semgrep", "ran": True, "note": "from the runner"}]
    else:
        assert calls == []
        assert {t["note"] for t in report.tool_health} == {"prerecorded"}


def test_a_review_reads_its_required_tools_and_each_dimension_s_tool_from_the_evidence(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("print(1)\n")

    def review(runs):
        pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")
        monkeypatch.setattr(pipe, "run_tools", lambda *_: runs)
        return pipe.run(tmp_path, mode="mock")

    every = [ToolRun(t, True) for t in TOOL_DIMENSIONS]
    complete = review(every)
    assert "required_tool_incomplete" not in complete.incomplete_reasons
    assert all(d.tool_ran == (d.dimension != "architecture") for d in complete.dimensions)
    without_trivy = review([r for r in every if r.tool != "trivy"] + [ToolRun("trivy", False, [], "failed: timeout")])
    assert "required_tool_incomplete" in without_trivy.incomplete_reasons
    without_semgrep = review([r for r in every if r.tool != "semgrep"])
    assert "required_tool_incomplete" in without_semgrep.incomplete_reasons
    assert {d.dimension for d in without_semgrep.dimensions if not d.tool_ran} == {"architecture", *TOOL_DIMENSIONS["semgrep"]}
