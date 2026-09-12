"""G-8: quarterly garak + CyberSecEval 4 evaluation of the model families (prompt injection, false refusals).

  python3 scripts/model_eval.py plan [--config config/mara.yaml] [--out ops/model-eval/<date>]
      the garak and CyberSecEval commands for every non-mock family; keys are masked.
  python3 scripts/model_eval.py run --out ops/model-eval/<date> [--tool garak|cyberseceval|all] [--datasets $DATASETS]
      execute them on a host that reaches the endpoints; garak must be installed at the configured
      version, CyberSecEval (PurpleLlama CybersecurityBenchmarks) importable, keys in the environment.
  python3 scripts/model_eval.py report --run-dir ops/model-eval/<date> --date YYYY-MM-DD [--mode live|dry-run] [--docs-dir docs]
      parse the outputs, apply the thresholds, write docs/garak-<date>.md, docs/cyberseceval-<date>.md
      and calib/model-eval-<date>.json. `live` is refused when any family lacks any output.
  python3 scripts/model_eval.py check [--summary calib/model-eval-<date>.json]
      exit 1 when any family fails or is missing a metric (what governance G-8 and calibration see).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import model_eval as me  # noqa: E402
from mara.config import load_config  # noqa: E402


def _thresholds(cfg) -> me.Thresholds:
    t = cfg.model_eval.thresholds
    return me.Thresholds(t.garak_pass_rate_min, t.prompt_injection_success_max, t.false_refusal_max)


def _plan(cfg, out_dir: Path, datasets: str, judge: str) -> tuple[dict, dict, dict]:
    garak_cmds, cse_cmds, envs = {}, {}, {}
    for t in me.targets_from_config(cfg):
        argv, env = me.garak_command(t, cfg.model_eval.garak_probes, out_dir)
        garak_cmds[t.family], envs[t.family] = argv, env
        cse_cmds[t.family] = me.cyberseceval_commands(t, datasets, out_dir, judge)
    return garak_cmds, cse_cmds, envs


def cmd_plan(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    judge = f"${cfg.model_eval.judge_llm_env}"
    garak_cmds, cse_cmds, envs = _plan(cfg, a.out, a.datasets, judge)
    print(f"# garak {cfg.model_eval.garak_version}, probes {cfg.model_eval.garak_probes}; CyberSecEval {cfg.model_eval.cyberseceval_ref}")
    for fam, argv in garak_cmds.items():
        env = " ".join(f"{k}={v}" for k, v in envs[fam].items())
        print(f"\n# {fam}: garak\n{env + ' ' if env else ''}{' '.join(argv)}")
        for bench, c in cse_cmds[fam].items():
            print(f"# {fam}: CyberSecEval {bench}\n{' '.join(c)}")
    print(f"\n# outputs under {a.out}; then: python3 scripts/model_eval.py report --run-dir {a.out} --date <date> --mode live")
    return 0


def cmd_run(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    a.out.mkdir(parents=True, exist_ok=True)
    targets = me.targets_from_config(cfg)
    rc = 0
    if a.tool in ("garak", "all"):
        ver = subprocess.run([sys.executable, "-m", "garak", "--version"], capture_output=True, text=True)
        if ver.returncode != 0 or cfg.model_eval.garak_version not in (ver.stdout + ver.stderr):
            print(f"ERROR: garak {cfg.model_eval.garak_version} is not installed (pip install -r tools/model-eval-requirements.txt): "
                  f"{(ver.stdout + ver.stderr).strip()[:120]}", file=sys.stderr)
            return 2
        for t in targets:
            opts = me.garak_generator_options(t)
            option_file = a.out / f"garak-{t.slug}.generator.json"
            if opts:
                option_file.write_text(json.dumps(opts, indent=2) + "\n", encoding="utf-8")
            argv, env_map = me.garak_command(t, cfg.model_eval.garak_probes, a.out, option_file)
            env = dict(os.environ)
            for k, v in env_map.items():
                env[k] = me.resolve_key(v.lstrip("$"))
            print(f"+ [{t.family}] {' '.join(argv)}")
            r = subprocess.run(argv, env=env)
            rc |= r.returncode
    if a.tool in ("cyberseceval", "all"):
        if not a.datasets:
            print("ERROR: --datasets <dir with prompt_injection/ and mitre_frr/> is required for CyberSecEval", file=sys.stderr)
            return 2
        judge = me.resolve_key(cfg.model_eval.judge_llm_env)
        for t in targets:
            key = me.resolve_key(t.api_key_env or me.ANTHROPIC_KEY_ENV)
            for bench, argv in me.cyberseceval_commands(t, a.datasets, a.out, judge, key).items():
                shown = [x.replace(key, me.MASK).replace(judge, "$" + cfg.model_eval.judge_llm_env) for x in argv]
                print(f"+ [{t.family}] {bench}: {' '.join(shown)}")
                (a.out / t.slug).mkdir(parents=True, exist_ok=True)
                r = subprocess.run(argv)
                rc |= r.returncode
    (a.out / "run.json").write_text(json.dumps({"date": dt.date.today().isoformat(), "tool": a.tool, "garak_version": cfg.model_eval.garak_version,
                                               "cyberseceval_ref": cfg.model_eval.cyberseceval_ref, "families": [t.family for t in targets],
                                               "python": sys.version.split()[0], "host": os.uname().nodename}, indent=2) + "\n", encoding="utf-8")
    return 1 if rc else 0


def _collect(run_dir: Path, targets: list[me.EvalTarget], th: me.Thresholds) -> list[me.FamilyResult]:
    results = []
    for t in targets:
        r = me.FamilyResult(t)
        garak_files = sorted(run_dir.glob(f"**/garak-{t.slug}*.report.jsonl"))
        if garak_files:
            try:
                r.garak = me.parse_garak_report(garak_files[-1])
            except ValueError as e:
                r.notes.append(f"garak report unreadable: {e}")
        else:
            r.notes.append("no garak report found")
        pi = next(iter(sorted(run_dir.glob(f"**/{t.slug}/prompt_injection_stat.json"))), None)
        fr = next(iter(sorted(run_dir.glob(f"**/{t.slug}/mitre_frr_stat.json"))), None)
        for label, path, fn, attr in (("prompt-injection", pi, me.parse_cse_prompt_injection, "prompt_injection"),
                                      ("mitre-frr", fr, me.parse_cse_frr, "frr")):
            if path is None:
                r.notes.append(f"no CyberSecEval {label} stat file found")
                continue
            try:
                setattr(r, attr, fn(path, t.model))
            except ValueError as e:
                r.notes.append(f"CyberSecEval {label} stat unreadable: {e}")
        r.verdict = me.evaluate_family(r.garak, r.prompt_injection, r.frr, th)
        results.append(r)
    return results


def cmd_report(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    th = _thresholds(cfg)
    targets = me.targets_from_config(cfg)
    results = _collect(a.run_dir, targets, th)
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
    garak_cmds, cse_cmds, _ = _plan(cfg, a.run_dir, a.datasets, f"${cfg.model_eval.judge_llm_env}")
    docs = a.docs_dir
    docs.mkdir(parents=True, exist_ok=True)
    (docs / f"garak-{a.date}.md").write_text(me.render_garak_report(summary, results, garak_cmds), encoding="utf-8")
    (docs / f"cyberseceval-{a.date}.md").write_text(me.render_cyberseceval_report(summary, results, cse_cmds), encoding="utf-8")
    sp = me.write_summary(summary, a.summary_root)
    for r in results:
        print(f"{r.target.family}: {r.verdict['overall']} — " + ", ".join(f"{k} {v['value']} ({v['status']})" for k, v in r.verdict.items() if k != "overall"))
    print(f"wrote {docs / f'garak-{a.date}.md'}, {docs / f'cyberseceval-{a.date}.md'}, {sp} (mode {mode})")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    summary = json.loads(a.summary.read_text(encoding="utf-8")) if a.summary else me.latest_summary(ROOT)
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
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "mara.yaml")
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
    s.add_argument("--summary-root", type=Path, default=ROOT)
    s.add_argument("--datasets", default="$DATASETS")
    s = sub.add_parser("check")
    s.add_argument("--summary", type=Path)
    a = ap.parse_args()
    try:
        return {"plan": cmd_plan, "run": cmd_run, "report": cmd_report, "check": cmd_check}[a.cmd](a)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    if shutil.which("python3") is None:  # pragma: no cover
        print("python3 not on PATH", file=sys.stderr)
    sys.exit(main())
