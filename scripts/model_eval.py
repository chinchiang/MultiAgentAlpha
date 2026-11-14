"""G-8: quarterly garak + CyberSecEval 4 evaluation of the model families (prompt injection, false refusals).

  python3 scripts/model_eval.py plan [--config config/mara.yaml] [--out ops/model-eval/<date>]
      the garak and CyberSecEval commands for every non-mock family; keys are masked.
  python3 scripts/model_eval.py run --out ops/model-eval/<date> [--tool garak|cyberseceval|all] [--datasets $DATASETS]
      execute them on a host that reaches the endpoints; garak must be installed at the configured
      version, CyberSecEval (PurpleLlama CybersecurityBenchmarks) importable, keys in the environment.
  python3 scripts/model_eval.py report --run-dir ops/model-eval/<date> --date YYYY-MM-DD [--mode live|dry-run] [--docs-dir docs]
                                       [--datasets "$DATASETS"]
      parse the outputs, apply the thresholds, write docs/garak-<date>.md, docs/cyberseceval-<date>.md
      and calib/model-eval-<date>.json. `live` is refused when any family lacks any output. --datasets names the directory
      `run` read the CyberSecEval datasets from, which says how many rows each benchmark should have written: a metric whose
      responses are over a fifth empty or absent is `missing`. `live` needs it; without it only empty responses are counted.
  python3 scripts/model_eval.py check [--summary calib/model-eval-<date>.json]
      exit 1 when any family fails or is missing a metric (what governance G-8 and calibration see).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import model_eval as me  # noqa: E402
from mara.config import load_config  # noqa: E402
from mara.workspace import Workspace, resolve  # noqa: E402


def _thresholds(cfg) -> me.Thresholds:
    t = cfg.model_eval.thresholds
    return me.Thresholds(t.garak_pass_rate_min, t.prompt_injection_success_max, t.false_refusal_max)


def cmd_plan(a: argparse.Namespace) -> int:
    cfg = load_config(a.config, a.workspace)
    plan = me.invocations(me.targets_from_config(cfg), cfg.model_eval, a.out, a.datasets)
    print(f"# garak {cfg.model_eval.garak_version}, probes {cfg.model_eval.garak_probes}; CyberSecEval {cfg.model_eval.cyberseceval_ref}")
    for fam in plan.families:
        for inv in plan.of(fam, "garak"):
            env = " ".join([f"{k}={s.shown}" for k, s in inv.key_variables.items()] + [f"{k}={v}" for k, v in inv.env.items()])
            print(f"\n# {fam}: garak\n{env + ' ' if env else ''}{shlex.join(me.shown(inv))}")
        if skip := plan.skip(fam, "cyberseceval"):
            print(f"# {fam}: CyberSecEval SKIPPED, {skip.reason}")
            continue
        for inv in plan.of(fam, "cyberseceval"):
            print(f"# {fam}: CyberSecEval {inv.benchmark}\n{' '.join(me.shown(inv))}")
    for skip in plan.skips:
        if skip.tool is None:
            print(f"\n# {skip.family}: SKIPPED, {skip.reason}")
    print(f"\n# outputs under {a.out}; then: python3 scripts/model_eval.py report --run-dir {a.out} --date <date> --mode live "
          f"--datasets \"$DATASETS\"")
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    cfg = load_config(a.config, a.workspace)
    a.out.mkdir(parents=True, exist_ok=True)
    plan, rc = me.invocations(me.targets_from_config(cfg), cfg.model_eval, a.out, a.datasets), 0
    for skip in plan.skips:
        if skip.tool is None:
            print(f"SKIP [{skip.family}] {skip.reason}", file=sys.stderr)
            rc = 1  # a family left out is never a clean run
    if a.tool in ("garak", "all"):
        ver = subprocess.run([sys.executable, "-m", "garak", "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        if ver.returncode != 0 or cfg.model_eval.garak_version not in (ver.stdout + ver.stderr):
            print(f"ERROR: garak {cfg.model_eval.garak_version} is not installed (pip install -r tools/model-eval-requirements.txt): "
                  f"{(ver.stdout + ver.stderr).strip()[:120]}", file=sys.stderr)
            return 2
        for fam in plan.families:
            for inv in plan.of(fam, "garak"):
                argv, env = me.prepare(inv, os.environ)
                print(f"+ [{fam}] {shlex.join(me.shown(inv))}")
                rc |= subprocess.run(argv, env=env).returncode
    if a.tool in ("cyberseceval", "all"):
        if not a.datasets:
            print("ERROR: --datasets <dir with prompt_injection/ and mitre_frr/> is required for CyberSecEval", file=sys.stderr)
            return 2
        me.resolve_key(cfg.model_eval.judge_llm_env)  # a missing judge stops the run before any benchmark
        for fam in plan.families:
            if skip := plan.skip(fam, "cyberseceval"):
                print(f"SKIP [{fam}] {skip.reason}", file=sys.stderr)
                rc = 1  # a metric left out is never a clean run
                continue
            for inv in plan.of(fam, "cyberseceval"):
                # the keys travel in the child's environment, never in its (world-readable) command line
                argv, env = me.prepare(inv, os.environ)
                print(f"+ [{fam}] {inv.benchmark}: {' '.join(me.shown(inv))}")
                rc |= subprocess.run(argv, env=env).returncode
    (a.out / "run.json").write_text(json.dumps({"date": dt.date.today().isoformat(), "tool": a.tool, "garak_version": cfg.model_eval.garak_version,
                                               "cyberseceval_ref": cfg.model_eval.cyberseceval_ref, "families": list(plan.families),
                                               "python": sys.version.split()[0], "host": platform.node()}, indent=2) + "\n", encoding="utf-8")
    return 1 if rc else 0


def _read_benchmark(run_dir: Path, t: me.EvalTarget, bench: me.CseBenchmark, sizes: dict[str, int] | None) -> tuple[dict | None, str | None]:
    """One CyberSecEval benchmark of one family: its stat with the counts of its model's rows in its response file, or the note that
    says why not."""
    path = next(iter(sorted(run_dir.glob(f"**/{t.slug}/{bench.stat_file}"))), None)
    if path is None:
        return None, f"no CyberSecEval {bench.label} stat file found"
    try:
        stat = bench.parse_stat(path, t.model)
    except ValueError as e:
        return None, f"CyberSecEval {bench.label} stat unreadable: {e}"
    # without its response file a run of empty responses cannot be told from a complete one: the metric stays missing
    responses = path.parent / bench.responses_file
    if not responses.is_file():
        return None, f"no CyberSecEval {bench.label} response file found ({bench.responses_file}), so its empty responses cannot be counted"
    try:
        counts = me.parse_cse_responses(responses, t.model, sizes[bench.dataset] if sizes else bench.rows_of(stat), bench.fields)
    except ValueError as e:
        return None, f"CyberSecEval {bench.label} responses unreadable: {e}"
    return {**stat, "empty_rate": counts["empty_rate"], "responses": counts}, None


def _collect(run_dir: Path, targets: list[me.EvalTarget], th: me.Thresholds, sizes: dict[str, int] | None) -> list[me.FamilyResult]:
    """What each family's run directory holds. `sizes` is the rows each CyberSecEval dataset has (cse_dataset_sizes), or None
    when no dataset was given: then a stat file's own count stands for the rows expected, and a row the run lost goes unseen."""
    results = []
    for t in targets:
        r = me.FamilyResult(t)
        garak_files = sorted(run_dir.glob(f"**/garak-{t.slug}*.report.jsonl"))
        if garak_files:
            try:
                r.garak = me.parse_garak_report(garak_files[-1])
                if r.garak["empty_rate"] is None:
                    r.notes.append("garak report has no outputs, so its empty outputs cannot be counted")
            except ValueError as e:
                r.notes.append(f"garak report unreadable: {e}")
        else:
            r.notes.append("no garak report found")
        for bench in me.CSE_BENCHMARKS:
            stat, note = _read_benchmark(run_dir, t, bench, sizes)
            if note:
                r.notes.append(note)
            else:
                setattr(r, bench.attr, stat)
        if sizes is None and any(getattr(r, bench.attr) for bench in me.CSE_BENCHMARKS):
            r.notes.append("the expected number of rows is unknown (no --datasets), so rows the run lost are not counted")
        r.verdict = me.evaluate_family(r.garak, r.prompt_injection, r.frr, th)
        results.append(r)
    return results


def cmd_report(a: argparse.Namespace) -> int:
    cfg = load_config(a.config, a.workspace)
    th = _thresholds(cfg)
    targets = me.targets_from_config(cfg)
    try:
        sizes = me.cse_dataset_sizes(a.datasets) if a.datasets else None
    except ValueError as e:
        print(f"ERROR: --datasets {e}", file=sys.stderr)
        return 2
    if a.mode == "live" and sizes is None:
        print("ERROR: cannot label the report live without --datasets: it says how many rows each CyberSecEval benchmark should have written",
              file=sys.stderr)
        return 2
    results = _collect(a.run_dir, targets, th, sizes)
    missing = [r.target.family for r in results if r.verdict.get("overall") == "missing"]
    mode = a.mode
    if mode == "live":
        if missing:
            print(f"ERROR: cannot label the report live: missing outputs for {missing}", file=sys.stderr)
            return 2
        if a.run_dir.resolve().is_relative_to((ROOT / "fixtures").resolve()):
            print("ERROR: cannot label a report built from fixtures as live", file=sys.stderr)
            return 2
    garak_version = next((r.garak["garak_version"] for r in results if r.garak and r.garak.get("garak_version")), cfg.model_eval.garak_version)
    summary = me.summarize(results, date=a.date, mode=mode, th=th, garak_version=garak_version, cse_ref=cfg.model_eval.cyberseceval_ref,
                           probes=cfg.model_eval.garak_probes)
    # the reports are committed and published: the datasets are named by the variable the commands use, never by this host's directory
    plan = me.invocations(me.targets_from_config(cfg), cfg.model_eval, a.run_dir, "$DATASETS")
    docs = a.docs_dir
    docs.mkdir(parents=True, exist_ok=True)
    # the reports are committed: they name the run directory as it was given, not as this host spells it
    (docs / f"garak-{a.date}.md").write_text(me.render_garak_report(summary, results, plan, a.run_dir), encoding="utf-8")
    (docs / f"cyberseceval-{a.date}.md").write_text(me.render_cyberseceval_report(summary, results, plan, a.run_dir), encoding="utf-8")
    sp = me.write_summary(summary, a.summary_root)
    for r in results:
        print(f"{r.target.family}: {r.verdict['overall']} — " + ", ".join(f"{k} {v['value']} ({v['status']})" for k, v in r.verdict.items() if k != "overall"))
    print(f"wrote {docs / f'garak-{a.date}.md'}, {docs / f'cyberseceval-{a.date}.md'}, {sp} (mode {mode})")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    summary = json.loads(a.summary.read_text(encoding="utf-8")) if a.summary else me.latest_summary(a.workspace.root)
    if not summary:
        print("no calib/model-eval-*.json summary found; G-8 has never been run")
        return 1
    ok = True
    print(f"{summary['date']} mode {summary['mode']} garak {summary['garak_version']} CyberSecEval {summary['cyberseceval_ref']}")
    for fam, f in summary["families"].items():
        v = f["verdict"]
        print(f"  {fam}: {v['overall']} — " + ", ".join(f"{k} {x['value']} ({x['status']})" for k, x in v.items() if k != "overall"))
        ok &= v["overall"] == "pass"
    if summary["mode"] != "live":
        print("  mode is not live: does not satisfy G-8")
        ok = False
    return 0 if ok else 1


def main() -> int:
    ws = Workspace.from_env()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=resolve("config/mara.yaml", ws.root))
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("plan")
    s.add_argument("--out", type=Path, default=ROOT / "ops" / "model-eval" / dt.date.today().isoformat())
    s.add_argument("--datasets", default="$DATASETS")
    s = sub.add_parser("run")
    s.add_argument("--out", type=Path, required=True)
    s.add_argument("--tool", choices=["garak", "cyberseceval", "all"], default="all")
    s.add_argument("--datasets", default="")
    s = sub.add_parser("report")
    s.add_argument("--run-dir", type=Path, required=True)
    s.add_argument("--date", type=dt.date.fromisoformat, default=dt.date.today())
    s.add_argument("--mode", choices=["live", "dry-run"], default="dry-run")
    s.add_argument("--docs-dir", type=Path, default=ROOT / "docs")
    s.add_argument("--datasets", default="",
                   help="the directory run read the CyberSecEval datasets from: how many rows each benchmark should have written "
                        "(required for --mode live)")
    s.add_argument("--summary-root", type=Path, default=ws.root,
                   help="where calib/model-eval-<date>.json goes (default: the MARA workspace, where the pipeline reads it)")
    s = sub.add_parser("check")
    s.add_argument("--summary", type=Path)
    a = ap.parse_args()
    a.workspace = ws
    try:
        return {"plan": cmd_plan, "run": cmd_run, "report": cmd_report, "check": cmd_check}[a.cmd](a)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if shutil.which("python3") is None:  # pragma: no cover
        print("python3 not on PATH", file=sys.stderr)
    sys.exit(main())
