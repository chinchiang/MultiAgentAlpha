"""`scripts/rollout_phase.py` `status` and `advance` look for a relative `rollout.baseline_report` below the MARA
workspace, as governance check G-10 does, not below this checkout; an absolute one is read as given."""

from __future__ import annotations

import datetime as dt
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from mara.workspace import Workspace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance_check as gc  # noqa: E402

SCRIPT = ROOT / "scripts" / "rollout_phase.py"
TODAY = dt.date(2026, 11, 26)
IN_CHECKOUT = "LICENSE"  # a file of this checkout whose text no change rewrites; a workspace holds one only where a test writes it


def _config(path: Path, **rollout: str) -> Path:
    """The mock config with its rollout block replaced, written to `path`."""
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = rollout
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def _run(ws: Path, config: Path, *args: str) -> subprocess.CompletedProcess:
    """rollout_phase.py with the workspace `ws` (MARA_HOME), run from a directory that is neither it nor this checkout."""
    elsewhere = ws.parent / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    return subprocess.run([sys.executable, str(SCRIPT), "--config", str(config), "--today", TODAY.isoformat(), *args],
                          capture_output=True, text=True, encoding="utf-8", cwd=elsewhere,
                          env={**os.environ, "MARA_HOME": str(ws), "PYTHONIOENCODING": "utf-8"})


def _workspace(tmp_path: Path, baseline: str = "# baseline\n") -> Path:
    """A workspace holding `pilot/baseline.md`."""
    ws = tmp_path / "workspace"
    (ws / "pilot").mkdir(parents=True)
    (ws / "pilot" / "baseline.md").write_text(baseline, encoding="utf-8")
    return ws


def test_status_passes_g10_on_a_relative_baseline_report_in_the_workspace_and_fails_on_one_only_in_the_checkout(tmp_path):
    ws = _workspace(tmp_path)
    r = _run(ws, _config(tmp_path / "in-workspace.yaml", phase="advisory", started_on="2026-11-01",
                         baseline_report="pilot/baseline.md"), "status")
    assert r.returncode == 0 and r.stdout.splitlines()[-1] == "G-10: PASS", r.stdout + r.stderr
    r = _run(ws, _config(tmp_path / "in-checkout.yaml", phase="advisory", started_on="2026-11-01",
                         baseline_report=IN_CHECKOUT), "status")
    assert r.returncode == 1 and f"problem: baseline report {IN_CHECKOUT} not found" in r.stdout, r.stdout + r.stderr
    assert r.stdout.splitlines()[-1] == "G-10: FAIL"


def test_advance_finds_a_relative_baseline_report_in_the_workspace_and_misses_one_only_in_the_checkout(tmp_path):
    ws = _workspace(tmp_path)
    r = _run(ws, _config(tmp_path / "in-workspace.yaml", phase="shadow", started_on="2026-08-01",
                         baseline_report="pilot/baseline.md"), "advance", "--to", "advisory")
    assert r.returncode == 0 and "preconditions met" in r.stdout and "blocked" not in r.stdout, r.stdout + r.stderr
    r = _run(ws, _config(tmp_path / "in-checkout.yaml", phase="shadow", started_on="2026-08-01",
                         baseline_report=IN_CHECKOUT), "advance", "--to", "advisory")
    assert r.returncode == 1 and r.stdout.splitlines() == [
        "blocked: baseline report missing: run `rollout_phase.py baseline` and set rollout.baseline_report"], r.stdout + r.stderr


def test_advance_reads_a_mock_baseline_report_found_in_the_workspace_as_built_from_mock_mode_reviews(tmp_path):
    """The workspace's report has the name of a file of this checkout that is not mock, so a reading of the checkout's
    file passes where the workspace's blocks."""
    assert "Mock mode reports are included" not in (ROOT / IN_CHECKOUT).read_text(encoding="utf-8")
    ws = _workspace(tmp_path)
    (ws / IN_CHECKOUT).write_text("# baseline\n\nMock mode reports are included.\n", encoding="utf-8")
    r = _run(ws, _config(tmp_path / "mock.yaml", phase="shadow", started_on="2026-08-01", baseline_report=IN_CHECKOUT),
             "advance", "--to", "advisory")
    assert r.returncode == 1 and r.stdout.splitlines() == [
        f"blocked: baseline report {IN_CHECKOUT} is built from mock-mode reviews"], r.stdout + r.stderr


@pytest.mark.parametrize("report_at", ["workspace", "checkout", "absolute"])
def test_status_prints_the_g10_status_the_governance_check_gives_for_the_same_config_and_workspace(tmp_path, report_at):
    ws = _workspace(tmp_path)
    report = {"workspace": "pilot/baseline.md", "checkout": IN_CHECKOUT, "absolute": str(ws / "pilot" / "baseline.md")}[report_at]
    config = _config(tmp_path / "config.yaml", phase="advisory", started_on="2026-11-01", baseline_report=report)
    printed = _run(ws, config, "status").stdout.splitlines()[-1]
    assert printed == f"G-10: {gc.check_g10(ROOT, config, TODAY, workspace=Workspace(ws)).status}"
