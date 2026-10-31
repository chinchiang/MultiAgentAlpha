"""Reviewed content (GLOSSARY.md: reviewed content; mara.reviewed_content): the target, revision and content bundle a
review examined, one value from the bundle to the report, the human queue and the decisions bound to it
(docs/adr/0002-usable-decisions.md)."""

import hashlib
import json
from pathlib import Path

import pytest

from mara.config import load_config
from mara.context.repo_map import RepoContext
from mara.decisions import Decision
from mara.human_queue import queue_key
from mara.pipeline import Pipeline
from mara.reviewed_content import ReviewedContent

ROOT = Path(__file__).resolve().parents[1]
REPORT = {"target_id": "t" * 64, "revision": "r1", "coverage": {"content_hash": "h1"}}


def test_a_bundle_is_reviewed_as_its_targets_hashed_identity_its_revision_and_its_content_hash(tmp_path):
    identity = json.dumps(["git", "github.com/o/r", "svc"])
    ctx = RepoContext(root=tmp_path, identity=identity, revision="tree:abc", content_hash="h1")
    assert ReviewedContent.of_bundle(ctx) == ReviewedContent(hashlib.sha256(identity.encode()).hexdigest(), "tree:abc", "h1")


def test_a_report_gives_its_reviewed_content_from_its_target_id_revision_and_coverage():
    assert ReviewedContent.of_report(REPORT) == ReviewedContent("t" * 64, "r1", "h1")


@pytest.mark.parametrize("report", [{}, {"target_id": "t", "revision": "r"}, {**REPORT, "coverage": None},
                                    {**REPORT, "coverage": {"content_hash": ""}}, {**REPORT, "target_id": ""},
                                    {**REPORT, "revision": 7}])
def test_a_report_missing_a_part_of_it_has_no_reviewed_content(report):
    assert ReviewedContent.of_report(report) is None


def test_a_record_names_its_content_hash_context_hash_and_without_every_part_its_key_is_the_legacy_one():
    record = {"target_id": "t", "revision": "r", "context_hash": "c", "file": "app.py", "line": 3, "cwe": "CWE-79"}
    content = ReviewedContent.of_record(record)
    assert content == ReviewedContent("t", "r", "c") and content.known
    assert queue_key("app.py", 3, "CWE-79", content).startswith("v2-")
    for part in ("target_id", "revision", "context_hash"):
        partial = ReviewedContent.of_record({**record, part: ""})
        assert not partial.known
        assert queue_key("app.py", 3, "CWE-79", partial) == queue_key("app.py", 3, "CWE-79")


def test_a_decision_binds_to_the_reviewed_content_its_record_names():
    content = ReviewedContent("t", "r", "c")
    d = Decision.parse({"key": queue_key("app.py", 3, "CWE-79", content), "target_id": "t", "revision": "r", "context_hash": "c",
                        "file": "app.py", "line": 3, "cwe": "CWE-79", "decision": "true_positive", "decision_event_id": 1,
                        "decided_by": "alice", "decided_at": "2026-10-01T08:00:00Z"})
    assert isinstance(d, Decision) and d.content == content


def test_a_reviews_report_and_every_queue_item_name_one_reviewed_content(tmp_path, monkeypatch):
    """What the report records, what each human queue item carries and the key it is queued under come from one value:
    a decision synced from the item binds to the report's reviewed content."""
    monkeypatch.setenv("MARA_HOME", str(tmp_path / "home"))
    pipe = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"),
                    out_dir=tmp_path / "out")
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    content = ReviewedContent.of_report(json.loads(report.model_dump_json()))
    assert content is not None and content.known and report.human_queue
    for item in report.human_queue:
        assert ReviewedContent.of_record(item.model_dump()) == content
        assert item.key == queue_key(item.file, item.line, item.cwe, content)
