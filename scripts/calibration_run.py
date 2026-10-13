"""G-9: run the calibration loop end to end and write docs/calibration-<date>.md.

  python3 scripts/calibration_run.py --mode mock [--date YYYY-MM-DD] [--report <path>]
      reproducible locally: the label-driven mock families review every calib/samples/* target.
  python3 scripts/calibration_run.py --mode live --config config/mara.yaml [--date ...]
      on a host that reaches the three families' endpoints: `mara check-config`, then `mara review`
      on every sample with the live config, then scripts/calibrate.py --mode live. Refused when the
      config contains a mock provider, so a mock run can never be labelled live.

The report carries YAML front matter (mode, date, families, samples, labels, tool_labels,
model_eval) that governance check G-9 reads; calibrate.py also refuses --mode live when any run's
provider_mode is not live. After the reviews, the locked deterministic tools (semgrep, osv-scanner,
gitleaks) scan every sample and their SARIF is stored under calib-out/<sample>/tools/ as a second
reference label set for calibrate.py (assessment #10). After a live run, commit calib/history.json and calib/latest.json together with the report: policy P8 verifies calib/latest.json from the repository.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mara.config import load_config  # noqa: E402
from mara.workspace import resolve  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--mode", choices=["mock", "live"], required=True)
    ap.add_argument("--config", type=Path, default=None, help="default: config/mara.mock.yaml for mock, config/mara.yaml for live")
    ap.add_argument("--samples-dir", type=Path, default=None, help="default: <workspace>/calib/samples")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "calib-out")
    ap.add_argument("--date", type=dt.date.fromisoformat, default=dt.date.today())
    ap.add_argument("--report", type=Path, default=None, help="default: docs/calibration-<date>.md")
    a = ap.parse_args()
    a.samples_dir = a.samples_dir or resolve("calib/samples")
    config = a.config or (ROOT / "config" / ("mara.mock.yaml" if a.mode == "mock" else "mara.yaml"))
    cfg = load_config(config)
    mock_models = [m.name for m in cfg.models if m.provider == "mock"]
    if a.mode == "live" and mock_models:
        print(f"ERROR: --mode live but {config} has mock providers: {mock_models}", file=sys.stderr)
        return 2
    if a.mode == "mock" and len(mock_models) != len(cfg.models):
        print(f"ERROR: --mode mock needs a config whose models all use provider: mock ({config})", file=sys.stderr)
        return 2
    # this interpreter and this checkout's code, never whatever `mara` an older install left on PATH
    base = [sys.executable, "-m", "mara.cli"]
    # the CLI prints Unicode (rich tables): make the child write UTF-8 and read it back as UTF-8, or a
    # Windows console code page (cp950, cp1252) fails the decode and leaves stdout None
    io = {"capture_output": True, "text": True, "encoding": "utf-8", "errors": "replace",
          "env": {**os.environ, "PYTHONIOENCODING": "utf-8"}}
    r = subprocess.run([*base, "check-config", str(config)], **io)
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
        # a previous run's report must never stand in for this one
        (out / "report.json").unlink(missing_ok=True)
        # --calibration-sample: the seeded secrets the sample's answer key declares must not block live egress.
        # Only for the labelled samples under calib/samples/; anything else (calib/corpora/...) keeps the strict preflight.
        seeded = resolve("calib/samples").resolve() in s.resolve().parents
        cmd = [*base, "review", str(s), "--config", str(config), "--provider", a.mode, "--out", str(out)] + (["--calibration-sample"] if seeded else [])
        print(f"+ {' '.join(cmd)}")
        r = subprocess.run(cmd, **io)
        # exit 2 is a blocked gate in the blocking phase, still a completed review - but a usage error
        # (typer/click) is exit 2 too, and writes no report: only a fresh report.json makes it a review
        if r.returncode not in (0, 2) or not (out / "report.json").is_file():
            print(r.stdout[-800:] + r.stderr[-800:], file=sys.stderr)
            print(f"ERROR: review of {s.name} failed (exit {r.returncode}{', no report written' if r.returncode in (0, 2) else ''})",
                  file=sys.stderr)
            return 1

    # assessment #10: the calibration reference set must not rely on human labels alone. Run the
    # locked deterministic tools on every sample; calibrate.py uses their SARIF as a second
    # reference label set and reports each family's recall against it. The SARIF lives under
    # calib-out/<sample>/tools/ — never inside the sample directory, so the reference labels cannot
    # leak into a later review's bundle. A tool that cannot run is reported and skipped.
    from mara.tools.runner import run_all

    for s in samples:
        for t in run_all(s, a.out_dir / s.name / "tools", enabled=["semgrep", "osv-scanner", "gitleaks"]):
            print(f"  {s.name} · {t.tool}: {'ok' if t.ran else t.note}")
    report = a.report or ROOT / "docs" / f"calibration-{a.date}.md"
    cmd = [sys.executable, str(ROOT / "scripts" / "calibrate.py"), "--mode", a.mode, "--out-dir", str(a.out_dir), "--samples-dir", str(a.samples_dir),
           "--report", str(report), "--date", a.date.isoformat()]
    print(f"+ {' '.join(cmd)}")
    r = subprocess.run(cmd, text=True)
    if a.mode == "live" and r.returncode == 0:
        # the docstring's commit policy, enforced as a reminder: policy P8 later verifies
        # calib/latest.json from the repository, and an uncommitted run wastes its AAT evidence
        # with a confusing check-config failure long after the run itself.
        evidence = [p for p in (resolve("calib/history.json"), resolve("calib/latest.json"), report) if p.is_file()]
        print("\nLIVE RUN COMMIT POLICY: commit together with the report:")
        for p in evidence:
            print(f"  git add {p.relative_to(ROOT) if p.resolve().is_relative_to(ROOT) else p}")
        if not resolve("calib/latest.json").is_file():
            print("  WARNING: calib/latest.json was not written; policy P8 will refuse unsupervised_reject_allowed until a live run records it")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
