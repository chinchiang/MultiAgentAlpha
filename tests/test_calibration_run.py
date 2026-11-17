"""scripts/calibration_run.py: the processes it starts run this checkout's mara."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

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


SAID = tuple(f"the cli said {n:02}, a line long enough that forty of them pass 800 characters" for n in range(1, 41))


def _children(monkeypatch, fails: str | None) -> None:
    """The script's subprocess, standing in for the children it starts: `check-config` says SAID on stdout and `boom` on
    stderr, and the command named `fails` exits 1 (writing no report), the other 0."""
    def run(cmd, **kw):
        command = next(c for c in ("check-config", "review") if c in cmd)
        return subprocess.CompletedProcess(cmd, 1 if command == fails else 0, stdout="".join(f"{line}\n" for line in SAID),
                                           stderr="boom\n")
    monkeypatch.setattr(calibration_run, "subprocess", SimpleNamespace(run=run, CompletedProcess=subprocess.CompletedProcess))


def _calibrate(tmp_path: Path, monkeypatch, *samples: str) -> int:
    root = tmp_path / "samples"
    for s in samples:
        (root / s).mkdir(parents=True)
    root.mkdir(exist_ok=True)
    monkeypatch.setattr(sys, "argv", ["calibration_run.py", "--mode", "mock", "--samples-dir", str(root), "--out-dir", str(tmp_path / "out")])
    return calibration_run.main()


def _shown(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith(("the cli said", "boom"))]


def test_a_failed_config_check_prints_every_line_it_said(tmp_path, monkeypatch, capsys):
    """The policy that failed, and why, is in check-config's table, above its summary line: a failure shows all of it."""
    _children(monkeypatch, fails="check-config")
    assert _calibrate(tmp_path, monkeypatch) == 2
    out, err = capsys.readouterr()
    assert "check-config failed" in err and _shown(out) == [*SAID, "boom"]


def test_a_config_check_that_passes_still_prints_its_last_line_alone(tmp_path, monkeypatch, capsys):
    _children(monkeypatch, fails=None)
    assert _calibrate(tmp_path, monkeypatch) == 2  # no samples: it stops after the check
    out, err = capsys.readouterr()
    assert "no samples under" in err and _shown(out) == [SAID[-1]]


def test_a_failed_review_of_a_sample_prints_every_line_it_said(tmp_path, monkeypatch, capsys):
    _children(monkeypatch, fails="review")
    assert _calibrate(tmp_path, monkeypatch, "s1") == 1
    out, err = capsys.readouterr()
    assert "review of s1 failed (exit 1)" in err and _shown(err) == [*SAID, "boom"]
