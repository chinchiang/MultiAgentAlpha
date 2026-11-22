"""Two failures at MARA's own edges that a review must survive: a pre-recorded SARIF file that is not JSON
(mara.tools.runner.load_prerecorded), and a PSIRT ledger write that stops half-way (mara.psirt_ledger.save_ledger)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mara import psirt_ledger
from mara.tools.runner import load_prerecorded

ROOT = Path(__file__).resolve().parents[1]
RECORDED = ROOT / "fixtures" / "vuln-sample-sarif"


@pytest.mark.parametrize("content", [b"{not json", b"", b"\xff\xfe\x00not utf-8"])
def test_a_prerecorded_file_that_is_not_json_is_a_tool_that_did_not_run(tmp_path, content):
    """It raised out of the review (json.JSONDecodeError, UnicodeDecodeError) instead of leaving the review incomplete
    for the tool, as a scan the runner starts itself does."""
    good = sorted(RECORDED.glob("*.sarif"))[0]
    (tmp_path / good.name).write_bytes(good.read_bytes())
    (tmp_path / "semgrep-broken.sarif").write_bytes(content)
    runs = {r.tool: r for r in load_prerecorded(tmp_path)}
    broken = runs["semgrep-broken"]
    assert not broken.ran and broken.results == [] and broken.note.startswith("prerecorded, ")
    assert runs[good.stem].note == "prerecorded", "the other files are still read"


def test_a_ledger_write_that_fails_leaves_the_ledger_as_it_was(tmp_path, monkeypatch):
    """Written in place, a write cut short left half a ledger, which load_ledger refuses: every delivery it recorded was
    lost with it and each finding was notified again."""
    path = tmp_path / "ops" / "ledger.json"
    first = {"schema": psirt_ledger.LEDGER_SCHEMA, "items": {"k1": {"key": "k1", "state": "delivered"}}}
    psirt_ledger.save_ledger(first, path)
    assert psirt_ledger.load_ledger(path) == first

    def refused(tmp: Path, target: Path) -> None:
        assert json.loads(tmp.read_text(encoding="utf-8"))["items"].keys() == {"k1", "k2"}, "the new ledger is whole before it is moved"
        raise OSError("disk full")

    monkeypatch.setattr(psirt_ledger, "replace", refused)
    second = {"schema": psirt_ledger.LEDGER_SCHEMA, "items": {**first["items"], "k2": {"key": "k2", "state": "delivered"}}}
    with pytest.raises(OSError, match="disk full"):
        psirt_ledger.save_ledger(second, path)
    assert psirt_ledger.load_ledger(path) == first
    assert [p.name for p in path.parent.iterdir()] == ["ledger.json"], "no temporary file is left beside it"
