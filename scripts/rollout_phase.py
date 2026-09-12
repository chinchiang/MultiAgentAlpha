"""G-10: the three-phase rollout (shadow → advisory → blocking), report section 15.4.

  python3 scripts/rollout_phase.py status [--config config/mara.yaml] [--today YYYY-MM-DD]
      current phase, days in phase, due date, what governance check G-10 sees; exit 1 when it fails.
  python3 scripts/rollout_phase.py baseline --runs out/ [out2/ ...] --out docs/rollout-baseline-<date>.md
      aggregate every report.json under the given directories into the shadow-phase baseline report
      (findings per review, tier mix, gate would-block rate, human-queue size, token cost, and the
      false-positive rate from calib/decisions when decisions exist).
  python3 scripts/rollout_phase.py advance --to advisory|blocking
      check the preconditions for the next phase (time in phase, baseline report, and for blocking a
      non-mock calibration report) and print the config change; it never edits config/mara.yaml.
"""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import govdocs  # noqa: E402
from mara.config import load_config  # noqa: E402


def cmd_status(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    st = govdocs.rollout_status(cfg, ROOT, a.today)
    print(f"phase: {st.phase}" + (f" since {cfg.rollout.started_on} ({st.days_in_phase} days)" if st.days_in_phase is not None else ""))
    if st.due:
        print(f"next phase due by: {st.due}")
    for n in st.notes:
        print(f"  {n}")
    for p in st.problems:
        print(f"  problem: {p}")
    print("G-10: " + ("PASS" if st.ok else "FAIL"))
    return 0 if st.ok else 1


def cmd_baseline(a: argparse.Namespace) -> int:
    paths = sorted({p for d in a.runs for p in Path(d).rglob("report.json")})
    if not paths:
        print("ERROR: no report.json under the given directories", file=sys.stderr)
        return 2
    cfg = load_config(a.config)
    metrics = govdocs.baseline_metrics(paths, a.decisions)
    out = a.out or ROOT / "docs" / f"rollout-baseline-{a.today}.md"
    out.write_text(govdocs.render_baseline(metrics, date=a.today, phase_started=cfg.rollout.started_on,
                                          sources=[str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p) for p in paths]), encoding="utf-8")
    print(f"wrote {out}: {metrics['reviews']} review(s), {metrics['findings_per_review']} findings/review, "
          f"gate would-block rate {metrics['gate_would_block_rate']}, modes {metrics['modes']}")
    if "mock" in metrics["modes"]:
        print("note: mock-mode reports included; the rollout decision needs live reviews")
    return 0


def _calibration_is_live(root: Path) -> bool:
    for p in (root / "docs").glob("calibration-*.md"):
        head = p.read_text(encoding="utf-8")[:2000]
        if re.search(r"執行模式[:：]\s*mock|mode[:：]\s*mock", head, re.I):
            continue
        return True
    return False


def cmd_advance(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    r = cfg.rollout
    order = ["not_started", "shadow", "advisory", "blocking"]
    if order.index(a.to) != order.index(r.phase) + 1:
        print(f"ERROR: cannot advance from {r.phase} to {a.to}; next phase is {order[min(order.index(r.phase) + 1, 3)]}", file=sys.stderr)
        return 2
    problems = []
    st = govdocs.rollout_status(cfg, ROOT, a.today)
    if a.to == "shadow":
        pass
    else:
        planned = r.shadow_months if r.phase == "shadow" else r.advisory_months
        if st.days_in_phase is None or st.days_in_phase < 30 * planned:
            problems.append(f"{r.phase} phase planned {planned} months; only {st.days_in_phase} days so far")
        baseline = ROOT / r.baseline_report if r.baseline_report else None
        if baseline is None or not baseline.exists():
            problems.append("baseline report missing: run `rollout_phase.py baseline` and set rollout.baseline_report")
        elif "Mock mode reports are included" in baseline.read_text(encoding="utf-8"):
            problems.append(f"baseline report {r.baseline_report} is built from mock-mode reviews")
        if a.to == "blocking" and not _calibration_is_live(ROOT):
            problems.append("no non-mock calibration report in docs/ (G-9): blocking needs calibrated weights")
    for p in problems:
        print(f"blocked: {p}")
    if problems:
        return 1
    print(f"preconditions met. In config/mara.yaml set:\n  rollout:\n    phase: {a.to}\n    started_on: {a.today}"
          + ("\n    baseline_report: " + r.baseline_report if r.baseline_report else ""))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "mara.yaml")
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    s = sub.add_parser("baseline")
    s.add_argument("--runs", nargs="+", required=True, help="directories containing report.json files")
    s.add_argument("--out", type=Path)
    s.add_argument("--decisions", type=Path, default=ROOT / "calib" / "decisions")
    s = sub.add_parser("advance")
    s.add_argument("--to", required=True, choices=["shadow", "advisory", "blocking"])
    a = ap.parse_args()
    try:
        return {"status": cmd_status, "baseline": cmd_baseline, "advance": cmd_advance}[a.cmd](a)
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
