"""A run's gate_enforced and psirt_failed (GLOSSARY.md: Run, Progress record; docs/adr/0007-review-status-and-gate.md): read
from the files of the run when it is read, by one rule (mara.invocation.outcome), never stored beside them. The tests
build a run directory by hand, as its files hold it after a review, a stopped server or an older version of the
workbench, and read it through `RunRegistry.get`: no child is started."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mara.progress import Progress
from mara.web import procs
from mara.web.runs import IMPORTED_ID, RunRegistry

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = "20261101-000000-abcdef"


def _build(base: Path, report, *, status: str, exit_code: int | None, progress: str | None, recorded: bool | None = True,
           validates: bool = True, stale: dict | None = None) -> RunRegistry:
    """A registry over `base`, whose one run has the files a review leaves: run.json as the waiter (or a stopped server)
    left it (with the two values the launch record held, False and False, unless `stale` gives others), progress.json
    as the review left it (finished, failed, running or none), and report.json recording gate_enforced as `recorded`,
    with a gate code the report model does not know unless `validates`."""
    run_dir = base / "out" / "runs" / RUN_ID
    run_dir.mkdir(parents=True)
    procs.write_json(run_dir / "run.json", {
        "id": RUN_ID, "title": "t", "target": str(ROOT), "status": status, "started_at": procs.now(), "finished_at": None,
        "exit_code": exit_code, "pid": None, "request": {}, "argv": [], "roles": {}, "models": [],
        "gate_enforced": False, "psirt_failed": False, **(stale or {})})
    if progress in ("finished", "failed"):
        Progress(run_dir / "progress.json").finish(ok=progress == "finished", error="" if progress == "finished" else "boom")
    elif progress == "running":
        Progress(run_dir / "progress.json").begin("bundle")
    if report is not None:
        doc = json.loads(report.model_copy(update={"gate_enforced": recorded}).model_dump_json())
        if not validates:
            doc["gate_reasons"] = ["review_incomplete", "blocked_by_the_owner"]
        (run_dir / "report.json").write_text(json.dumps(doc), encoding="utf-8")
    return RunRegistry(ROOT, base / "out")


def _read(reg: RunRegistry) -> dict:
    run = reg.get(RUN_ID)
    assert run is not None
    return run


@pytest.mark.parametrize(("status", "exit_code", "recorded", "gate_enforced", "psirt_failed"), [
    ("finished", 2, True, True, False),    # the waiter recorded the exit of a review whose gate was enforced
    ("finished", 3, True, True, True),     # a failed PSIRT hand-off exits 3, which outranks the gate's 2
    ("finished", 0, False, False, False),
    ("running", None, True, True, None),   # the server stopped before the exit was recorded: the report still says
    ("running", None, False, False, None),
    ("running", None, None, None, None),   # a report written before the field, and no exit code: unknown
], ids=["exit-2", "exit-3", "exit-0", "no-exit-enforced", "no-exit-not-enforced", "no-exit-old-report"])
def test_a_finished_run_reads_whether_its_gate_was_enforced_and_its_psirt_hand_off_failed(tmp_path, mock_report, status, exit_code,
                                                                                         recorded, gate_enforced, psirt_failed):
    reg = _build(tmp_path, mock_report[1], status=status, exit_code=exit_code, progress="finished", recorded=recorded)
    run = _read(reg)
    assert run["status"] == "finished"
    assert (run["gate_enforced"], run["psirt_failed"]) == (gate_enforced, psirt_failed)


def test_the_gate_is_read_from_a_report_the_run_view_cannot_validate(tmp_path, mock_report):
    reg = _build(tmp_path, mock_report[1], status="finished", exit_code=3, progress="finished", recorded=True, validates=False)
    assert reg.report(RUN_ID) is None, "the report does not validate, so the run has no report view"
    run = _read(reg)
    assert (run["gate_enforced"], run["psirt_failed"]) == (True, True)


@pytest.mark.parametrize(("status", "exit_code", "progress", "expected"), [
    ("failed", 1, "failed", "failed"),
    ("cancelled", -15, "running", "cancelled"),
    ("running", None, None, "interrupted"),
], ids=["failed", "cancelled", "interrupted"])
def test_a_run_that_did_not_finish_has_enforced_nothing_and_failed_nothing(tmp_path, mock_report, status, exit_code, progress, expected):
    reg = _build(tmp_path, mock_report[1], status=status, exit_code=exit_code, progress=progress, recorded=True)
    run = _read(reg)
    assert run["status"] == expected
    assert (run["gate_enforced"], run["psirt_failed"]) == (False, False)


def test_what_an_older_workbench_stored_in_run_json_is_not_read(tmp_path, mock_report):
    """The launch record held both as False and the exit overwrote them: neither is the run's to keep."""
    reg = _build(tmp_path, mock_report[1], status="running", exit_code=None, progress="finished", recorded=True,
                 stale={"gate_enforced": False, "psirt_failed": True})
    run = _read(reg)
    assert (run["gate_enforced"], run["psirt_failed"]) == (True, None)


def test_a_run_reads_the_same_whether_or_not_its_exit_was_recorded(tmp_path, mock_report):
    report = mock_report[1]
    recorded = _read(_build(tmp_path / "recorded", report, status="finished", exit_code=2, progress="finished"))
    stopped = _read(_build(tmp_path / "stopped", report, status="running", exit_code=None, progress="finished"))
    assert recorded["status"] == stopped["status"] == "finished"
    assert recorded["gate_enforced"] is stopped["gate_enforced"] is True
    assert (recorded["psirt_failed"], stopped["psirt_failed"]) == (False, None), "only the exit code tells a PSIRT hand-off"


def test_a_review_the_workbench_did_not_start_reads_its_gate_from_its_report(tmp_path, mock_report):
    """`out/report.json` of the workspace, shown read-only as the imported run."""
    workspace = tmp_path / "ws"
    (workspace / "out").mkdir(parents=True)
    (workspace / "out" / "report.json").write_text(mock_report[1].model_copy(update={"gate_enforced": True}).model_dump_json(),
                                                   encoding="utf-8")
    run = RunRegistry(workspace, tmp_path / "out").get(IMPORTED_ID)
    assert run is not None and (run["gate_enforced"], run["psirt_failed"]) == (True, None)


def test_a_report_that_changes_is_read_again_even_when_its_modified_time_does_not(tmp_path, mock_report):
    """The gate read from report.json is cached by the file's modified time and size; two reports of the same time and
    different sizes (`false`, `true`) are two files."""
    reg = _build(tmp_path, mock_report[1], status="finished", exit_code=None, progress="finished", recorded=False)
    path = tmp_path / "out" / "runs" / RUN_ID / "report.json"
    before = path.stat()
    assert _read(reg)["gate_enforced"] is False
    path.write_text(path.read_text(encoding="utf-8").replace('"gate_enforced": false', '"gate_enforced": true'), encoding="utf-8")
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size != before.st_size and path.stat().st_mtime_ns == before.st_mtime_ns
    assert _read(reg)["gate_enforced"] is True
