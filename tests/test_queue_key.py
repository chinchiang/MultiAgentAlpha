"""The queue key (GLOSSARY.md: queue key) never changes its value: a decision file is named by the key and binds to the
finding through it, so a key computed differently for the same finding would unbind every decision already made
(docs/adr/0002-usable-decisions.md). The values here were computed before the human queue's rework moved the key."""

import importlib.util
from pathlib import Path

from mara.human_queue import queue_key

ROOT = Path(__file__).resolve().parents[1]
TARGET, REVISION, CONTEXT = "a" * 64, "0123456789abcdef0123456789abcdef01234567", "c" * 64


def test_a_v2_key_keeps_its_value_whatever_spelling_the_path_and_the_weakness_have():
    key = queue_key("src/app.py", 10, "CWE-89", target_id=TARGET, revision=REVISION, context_hash=CONTEXT)
    assert key == "v2-4a38f11b31ae424e6a51733b"
    assert queue_key(".\\src\\app.py", 10, " cwe-89 ", target_id=TARGET, revision=REVISION, context_hash=CONTEXT) == key


def test_a_key_without_the_reviewed_content_is_the_legacy_key():
    """A legacy key is never synced; it is what a finding gets when the target, revision or content is unknown."""
    assert queue_key("src/app.py", 10, "CWE-89", target_id=TARGET, revision=REVISION) == "efa446c75c92"
    assert queue_key("./src/app.py", 10, "cwe-89") == "efa446c75c92"


def test_another_revision_or_another_line_is_another_key():
    assert queue_key("src/app.py", 10, "CWE-89", target_id=TARGET, revision="f" * 40, context_hash=CONTEXT) == "v2-a7c1fa676531ee915b949765"
    assert queue_key("src/app.py", 11, "CWE-89", target_id=TARGET, revision=REVISION, context_hash=CONTEXT) == "v2-a1a347e0516662a510793da2"


def test_every_key_in_the_published_workbench_demo_recomputes_from_its_item():
    spec = importlib.util.spec_from_file_location("build_workbench_demo", ROOT / "scripts" / "build_workbench_demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    items = [i for page in demo.committed_data()["api"].values() if isinstance(page, dict) for i in page.get("human_queue", [])]
    assert len(items) >= 20
    for i in items:
        assert queue_key(i["file"], i["line"], i["cwe"], target_id=i["target_id"], revision=i["revision"],
                         context_hash=i["context_hash"]) == i["key"]
