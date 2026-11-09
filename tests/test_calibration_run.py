"""scripts/calibration_run.py: the processes it starts run this checkout's mara."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("calibration_run", ROOT / "scripts" / "calibration_run.py")
assert spec and spec.loader
calibration_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calibration_run)


def test_the_cli_it_starts_is_the_mara_of_its_own_checkout(tmp_path, monkeypatch, capsys):
    """The dev environment's `mara` is an editable install of one checkout; from a git worktree `python -m mara.cli` would read
    that checkout's code. A `mara` that refuses to be imported on the PYTHONPATH stands for the other checkout: the config check
    the script runs first must not reach it, and so goes on to the samples (there are none here)."""
    other = tmp_path / "other-checkout" / "mara"
    other.mkdir(parents=True)
    (other / "__init__.py").write_text("raise ImportError('the cli imported the mara of another checkout')\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "other-checkout"))
    samples = tmp_path / "samples"
    samples.mkdir()
    monkeypatch.setattr(sys, "argv", ["calibration_run.py", "--mode", "mock", "--samples-dir", str(samples),
                                      "--out-dir", str(tmp_path / "out")])
    assert calibration_run.main() == 2
    err = capsys.readouterr().err
    assert "no samples under" in err and "check-config failed" not in err
