"""scripts/compare_reviews.py: mock reviews in three scenarios, recorded before and after a change, differ only where
the comparison is told they may."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import compare_reviews  # noqa: E402


@pytest.fixture(scope="module")
def recorded(tmp_path_factory) -> Path:
    """One recording of every scenario, copied as a second label: what a change that changes nothing would give."""
    out = tmp_path_factory.mktemp("compare")
    compare_reviews.record("before", out)
    return out


@pytest.fixture
def out(recorded, tmp_path) -> Path:
    out = tmp_path / "out"
    shutil.copytree(recorded / "before", out / "before")
    shutil.copytree(recorded / "before", out / "after")
    return out


def test_each_scenario_reaches_what_it_is_there_for(recorded):
    reports = {s: json.loads((recorded / "before" / s / "report.json").read_text(encoding="utf-8")) for s in compare_reviews.SCENARIOS}
    assert not reports["default"]["human_queue_tightening"]["tightened"]
    assert reports["tightened"]["human_queue_tightening"]["tightened"]
    audit = reports["decisions"]["bias_audit"]
    assert audit["human_decisions_applied"] == 1 and audit["human_decisions_not_usable[untrained]"] == 1
    assert len(json.loads((recorded / "before" / "decisions" / "decided-keys.json").read_text(encoding="utf-8"))) == 2


def test_two_recordings_of_one_source_are_the_same_apart_from_their_timestamps(recorded, tmp_path, capsys):
    compare_reviews.record("again", recorded, ("default",))
    assert compare_reviews.main(["--out", str(recorded), "compare", "before", "again"]) == 0
    assert "default: the same" in capsys.readouterr().out


def test_a_difference_fails_the_comparison_unless_it_is_allowed(out, capsys):
    report = out / "after" / "default" / "report.json"
    data = json.loads(report.read_text(encoding="utf-8"))
    data["bias_audit"]["exchange_version"] += 1
    report.write_text(json.dumps(data), encoding="utf-8")
    log = out / "after" / "tightened" / "pipeline.log"
    log.write_text(log.read_text(encoding="utf-8") + "L5: a line of its own\n", encoding="utf-8")
    assert compare_reviews.main(["--out", str(out), "compare", "before", "after"]) == 1
    printed = capsys.readouterr().out
    assert "default: DIFFERENT" in printed and "report.json: bias_audit differs" in printed
    assert "pipeline.log: 1 line(s) differ" in printed and "decisions: the same" in printed
    assert compare_reviews.main(["--out", str(out), "compare", "before", "after", "--allow", "bias_audit.exchange_version",
                                 "--ignore", "a line of its own"]) == 0


def test_a_key_moved_in_the_report_is_a_difference(out, capsys):
    report = out / "after" / "default" / "report.json"
    data = json.loads(report.read_text(encoding="utf-8"))
    report.write_text(json.dumps(dict(reversed(list(data.items())))), encoding="utf-8")
    assert compare_reviews.main(["--out", str(out), "compare", "before", "after"]) == 1
    assert "the top-level key order differs" in capsys.readouterr().out
