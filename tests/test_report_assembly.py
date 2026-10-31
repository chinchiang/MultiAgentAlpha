"""mara.report.assembly: the review report built from what the stages handed in, its assessment and its report
metadata, with the human queue and the PSIRT payloads that follow from them; pure."""

from __future__ import annotations

from pathlib import Path

import pytest

from mara.ballot_round import Ballots
from mara.context.repo_map import RepoContext
from mara.pipeline import ReviewerFindings, Stages
from mara.report.assembly import ReportMetadata, assemble
from mara.review_status import GatePolicy, SecretPreflight, assess
from mara.reviewed_content import ReviewedContent
from mara.schemas import MlBomEntry, ModelEvalStatus, ModelFamily, QueueTightening, RedTeamNote, SkepticVerdict
from mara.scoring.dimension_score import score_dimension
from mara.tools.evidence import ToolEvidence
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult
from tests import scored_rows
from tests.review_facts import FACTS

METADATA = ReportMetadata(
    rollout_phase="shadow",
    human_queue_tightening=QueueTightening(backlog=99, tightened=True, alpha_threshold=0.5),
    ml_bom={"glm-reviewer": MlBomEntry(model_id="glm-4.7", status="pending")},
    ml_bom_signature="verified",
    model_eval={"glm": ModelEvalStatus(date="2026-10-01", mode="live", status="pass")},
)
MANIFEST = [{"name": "mock-a", "type": "mock", "family": "anthropic", "model": "mock-anthropic", "served_models": []}]


def _stages(tmp_path: Path, base_ref: str | None = None) -> Stages:
    """Two findings: F-2 confirmed by both judge families, F-1 split between them (so it needs a human). The skeptic and
    the red team ruled on F-2 before F-1."""
    finders = {"F-1": {ModelFamily.ANTHROPIC}, "F-2": {ModelFamily.ANTHROPIC}}
    findings = [scored_rows.finding("F-1"), scored_rows.finding("F-2")]
    votes = (scored_rows.votes("F-1", {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "false_positive"})
             + scored_rows.votes("F-2", scored_rows.CONFIRMED))
    skeptic = {fid: SkepticVerdict(finding_id=fid, verdict="stands", reason="r", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON,
                                   source_model="m") for fid in ("F-2", "F-1")}
    redteam = {fid: RedTeamNote(finding_id=fid, exploitable="yes", preconditions="none", source_family=ModelFamily.DEEPSEEK,
                                source_model="m") for fid in ("F-2", "F-1")}
    ballots = Ballots(skeptic=skeptic, unchallenged=frozenset(), redteam=redteam, votes=votes)
    result = ToolResult("semgrep", "sql", "warning", "SQL injection", "other.py", 9, "CWE-89")
    tools = ToolEvidence(runs=[ToolRun("semgrep", True, [result], "pinned 1.0"), ToolRun("gitleaks", False, [], "missing")])
    scoring = scored_rows.score(findings, finders, votes, skeptic=skeptic, redteam=redteam, tool_results=tools.results)
    dims = [score_dimension("vulnerabilities", findings, {c.finding_id: c for c in scoring.rows}, True)]
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h", revision="r1")
    return Stages(ctx=ctx, tools=tools, egress=SecretPreflight(blocked=False), context_view=None, reviewed=ReviewerFindings(raw_count=3, findings=findings, finders=finders),
                  ballots=ballots, scoring=scoring, dimensions=dims, content=ReviewedContent("t" * 64, "r1", "h"),
                  base_ref=base_ref)


def _assembled(tmp_path: Path, *, base_ref: str | None = None, psirt_event: dict | None = None):
    stages = _stages(tmp_path, base_ref)
    assessment = assess(FACTS, stages.scoring.rows, stages.tools.results, stages.dimensions, scored_rows.policy(),
                        GatePolicy.from_config(scored_rows.MOCK))
    return assemble(stages, assessment, METADATA, cfg=scored_rows.MOCK, target=tmp_path, provider_mode="mock",
                    generated_at="2026-10-17T00:00:00+00:00", provider_manifest=MANIFEST, bias_audit={"skeptic_calls": 1},
                    psirt_event=psirt_event)


def test_the_report_metadata_land_in_their_fields_and_not_in_the_bias_audit(tmp_path):
    report = _assembled(tmp_path)
    assert (report.rollout_phase, report.human_queue_tightening, report.ml_bom, report.ml_bom_signature, report.model_eval) == (
        METADATA.rollout_phase, METADATA.human_queue_tightening, METADATA.ml_bom, METADATA.ml_bom_signature, METADATA.model_eval)
    assert report.bias_audit == {"skeptic_calls": 1}


@pytest.mark.parametrize("base_ref, scope", [(None, "full"), ("origin/main", "incremental")])
def test_the_review_scope_follows_the_base_of_an_incremental_review(tmp_path, base_ref, scope):
    assert _assembled(tmp_path, base_ref=base_ref).review_scope == scope


def test_the_skeptic_and_red_team_keep_their_order_and_the_queue_holds_what_needs_a_human(tmp_path):
    report = _assembled(tmp_path)
    assert [v.finding_id for v in report.skeptic] == [n.finding_id for n in report.redteam] == ["F-2", "F-1"]
    assert [c.finding_id for c in report.consensus] == ["F-1", "F-2"] and report.consensus[0].jury_outcome == "needs_human"
    assert [i.finding_id for i in report.human_queue] == ["F-1"]


def test_the_tool_health_lists_every_run_and_the_manifest_is_the_pipelines(tmp_path):
    report = _assembled(tmp_path)
    assert report.tool_health == [{"tool": "semgrep", "ran": True, "note": "pinned 1.0"}, {"tool": "gitleaks", "ran": False, "note": "missing"}]
    assert report.tool_results == [{"tool": "semgrep", "rule_id": "sql", "level": "warning", "message": "SQL injection", "file": "other.py",
                                    "line": 9, "cwe": "CWE-89", "cwes": []}]
    assert report.provider_manifest == MANIFEST and report.target_id == "t" * 64 and report.revision == "r1"


def test_the_psirt_event_reaches_the_hand_off(tmp_path):
    """build_notifications reads the event's legal deadlines and refuses one without them (mara.report.psirt_out)."""
    _assembled(tmp_path, psirt_event=None)
    with pytest.raises(ValueError):
        _assembled(tmp_path, psirt_event={"not": "an event"})


def test_the_same_stages_assemble_into_the_same_report(tmp_path):
    assert _assembled(tmp_path).model_dump(mode="json") == _assembled(tmp_path).model_dump(mode="json")
