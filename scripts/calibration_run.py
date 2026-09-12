"""G-9: run the calibration loop end to end and write docs/calibration-<date>.md.

  python3 scripts/calibration_run.py --mode mock [--date YYYY-MM-DD] [--report <path>]
      reproducible locally: the label-driven mock families review every calib/samples/* target.
  python3 scripts/calibration_run.py --mode live --config config/mara.yaml [--date ...]
      on a host that reaches the three families' endpoints: `mara check-config`, then `mara review`
      on every sample with the live config, then scripts/calibrate.py --mode live. Refused when the
      config contains a mock provider, so a mock run can never be labelled live.

The report carries YAML front matter (mode, date, families, samples, labels, model_eval) that
governance check G-9 reads; calibrate.py also refuses --mode live when any run's provider_mode is
not live.
"""

from __future__ import annotations

import argparse
import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.config import load_config  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=["mock", "live"], required=True)
    ap.add_argument("--config", type=Path, default=None, help="default: config/mara.mock.yaml for mock, config/mara.yaml for live")
    ap.add_argument("--samples-dir", type=Path, default=ROOT / "calib" / "samples")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "calib-out")
    ap.add_argument("--date", type=dt.date.fromisoformat, default=dt.date.today())
    ap.add_argument("--report", type=Path, default=None, help="default: docs/calibration-<date>.md")
    a = ap.parse_args()
    config = a.config or (ROOT / "config" / ("mara.mock.yaml" if a.mode == "mock" else "mara.yaml"))
    cfg = load_config(config)
    mock_models = [m.name for m in cfg.models if m.provider == "mock"]
    if a.mode == "live" and mock_models:
        print(f"ERROR: --mode live but {config} has mock providers: {mock_models}", file=sys.stderr)
        return 2
    if a.mode == "mock" and len(mock_models) != len(cfg.models):
        print(f"ERROR: --mode mock needs a config whose models all use provider: mock ({config})", file=sys.stderr)
        return 2
    mara = shutil.which("mara") or [sys.executable, "-m", "mara.cli"]
    base = [mara] if isinstance(mara, str) else mara
    r = subprocess.run([*base, "check-config", str(config)], capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr.strip()[-200:])
    if r.returncode != 0:
        print("ERROR: check-config failed; fix the policies before calibrating", file=sys.stderr)
        return 2
    samples = sorted(p for p in a.samples_dir.iterdir() if p.is_dir())
    if not samples:
        print(f"ERROR: no samples under {a.samples_dir}", file=sys.stderr)
        return 2
    for s in samples:
        out = a.out_dir / s.name
        cmd = [*base, "review", str(s), "--config", str(config), "--provider", a.mode, "--out", str(out)]
        print(f"+ {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode not in (0, 2):  # 2 = gate blocked in blocking phase, still a completed review
            print(r.stdout[-800:] + r.stderr[-800:], file=sys.stderr)
            print(f"ERROR: review of {s.name} failed (exit {r.returncode})", file=sys.stderr)
            return 1
    report = a.report or ROOT / "docs" / f"calibration-{a.date}.md"
    cmd = [sys.executable, str(ROOT / "scripts" / "calibrate.py"), "--mode", a.mode, "--out-dir", str(a.out_dir), "--samples-dir", str(a.samples_dir),
           "--report", str(report), "--date", a.date.isoformat()]
    print(f"+ {' '.join(cmd)}")
    r = subprocess.run(cmd, text=True)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
