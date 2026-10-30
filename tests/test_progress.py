"""The live progress file (mara.progress) that `mara serve` draws its pipeline stepper from: the pipeline reports
its nine stages in order, the CLI marks the end of the review only after the reports are written, and a failure
leaves a failed record instead of one that reads as a blocked gate."""

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mara import progress as prog
from mara.cli import app

ROOT = Path(__file__).resolve().parents[1]


def plain(text: str) -> str:
    """CLI output without rich's colour codes and panel borders (CI forces colour)."""
    return " ".join(re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text).replace("│", " ").split())


def test_without_a_path_nothing_is_written_but_stage_names_are_still_checked(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    p = prog.Progress()
    p.begin("bundle")
    p.log("L1: x")
    p.done("bundle")
    p.finish(ok=True)
    assert not list(tmp_path.iterdir())
    with pytest.raises(ValueError, match="unknown progress stage"):
        p.begin("l2")


def test_stages_are_recorded_in_order_and_the_file_is_replaced_atomically(tmp_path):
    path = tmp_path / "progress.json"
    p = prog.Progress(path)
    first = prog.read(path)
    assert first and first["status"] == "running" and [s["id"] for s in first["stages"]] == list(prog.STAGES)
    assert all(s["status"] == "pending" for s in first["stages"])
    p.begin("bundle")
    assert prog.read(path)["current"] == "bundle"
    p.done("bundle", "7 file(s)")
    p.skip("context", "no context role configured")
    p.finish(ok=True)
    d = prog.read(path)
    stages = {s["id"]: s for s in d["stages"]}
    assert d["status"] == "finished" and d["current"] is None and d["finished_at"]
    assert stages["bundle"]["status"] == "done" and stages["bundle"]["note"] == "7 file(s)"
    assert stages["bundle"]["started_at"] <= stages["bundle"]["finished_at"]
    assert stages["context"]["status"] == "skipped" and stages["tools"]["status"] == "pending"
    assert [f.name for f in tmp_path.iterdir()] == ["progress.json"], "no temporary file is left behind"


def test_a_failure_marks_the_running_stage_failed(tmp_path):
    path = tmp_path / "progress.json"
    p = prog.Progress(path)
    p.begin("bundle")
    p.done("bundle")
    p.begin("tools")
    p.finish(ok=False, error="ValueError")
    d = prog.read(path)
    assert d["status"] == "failed" and d["error"] == "ValueError"
    assert [s["status"] for s in d["stages"][:3]] == ["done", "failed", "pending"]


def test_the_log_keeps_only_the_newest_lines_and_notes_are_bounded(tmp_path):
    path = tmp_path / "progress.json"
    p = prog.Progress(path)
    for i in range(prog.LOG_LINES + 25):
        p.log(f"L2: line {i}")
    p.done("bundle", "x" * 1000)
    d = prog.read(path)
    assert len(d["log"]) == prog.LOG_LINES and d["log"][-1] == f"L2: line {prog.LOG_LINES + 24}"
    assert len(d["stages"][0]["note"]) == prog.NOTE_CHARS


@pytest.mark.parametrize("content", ["", "not json", "[]", json.dumps({"version": 99, "stages": []}), json.dumps({"version": 1})])
def test_read_refuses_what_is_not_a_progress_record(tmp_path, content):
    path = tmp_path / "progress.json"
    path.write_text(content, encoding="utf-8")
    assert prog.read(path) is None
    assert prog.read(tmp_path / "missing.json") is None


def test_the_mock_pipeline_reports_all_nine_stages_in_order(root, tmp_path):
    from mara.config import load_config
    from mara.pipeline import Pipeline

    path = tmp_path / "progress.json"
    cfg = load_config(root / "config" / "mara.mock.yaml")
    pipe = Pipeline(cfg, mock_fixtures=str(root / "fixtures" / "mock-responses"), out_dir=tmp_path / "out", progress=prog.Progress(path))
    pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=root / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    d = prog.read(path)
    assert d["status"] == "running", "the pipeline leaves finishing to whoever writes the reports"
    assert [s["status"] for s in d["stages"]] == ["done"] * len(prog.STAGES)
    times = [t for s in d["stages"] for t in (s["started_at"], s["finished_at"])]
    assert times == sorted(times), "stages run one after another, in the order of STAGES"
    assert any(line.startswith("L2: ") for line in d["log"]) and d["log"] == pipe.log[-prog.LOG_LINES:]
    notes = {s["id"]: s["note"] for s in d["stages"]}
    assert "after deduplication" in notes["reviewers"] and "gate blocked" in notes["scoring"]


def test_the_cli_finishes_the_record_only_after_writing_the_reports(root, tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(root))
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(root / "fixtures" / "vuln-sample"), "--provider", "mock",
                                   "--sarif-dir", str(root / "fixtures" / "vuln-sample-sarif"), "--out", str(out),
                                   "--progress-file", str(out / "progress.json")])
    assert res.exit_code == 0, res.output
    d = prog.read(out / "progress.json")
    assert d["status"] == "finished" and (out / "report.json").is_file()


def test_a_usage_error_leaves_a_failed_record_not_a_finished_one(root, tmp_path, monkeypatch):
    """exit 2 is both a blocked gate (with --fail-on-gate) and a usage error; the progress record tells them apart"""
    monkeypatch.setenv("MARA_HOME", str(root))
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(root / "fixtures" / "vuln-sample"), "--provider", "mock",
                                   "--config", str(root / "config" / "mara.yaml"), "--out", str(out),
                                   "--progress-file", str(out / "progress.json")])
    assert res.exit_code == 2
    d = prog.read(out / "progress.json")
    assert d["status"] == "failed" and d["error"] == "BadParameter" and not (out / "report.json").exists()


def test_a_progress_file_inside_the_target_is_refused(root, tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_HOME", str(root))
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print(1)\n")
    res = CliRunner().invoke(app, ["review", str(target), "--provider", "mock", "--out", str(tmp_path / "out"),
                                   "--progress-file", str(target / "progress.json")])
    assert res.exit_code == 2 and "--progress-file" in plain(res.output) and not (target / "progress.json").exists()
