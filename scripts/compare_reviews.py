"""Mock reviews of the seeded fixture, recorded before and after a change and compared, in three scenarios.

  .venv/bin/python scripts/compare_reviews.py record before      # with the source as it is now
  .venv/bin/python scripts/compare_reviews.py record after       # after the change
  .venv/bin/python scripts/compare_reviews.py compare before after [--allow bias_audit.exchange_version] [--ignore REGEX]

`record <label>` runs `mara review fixtures/vuln-sample --provider mock` against the pre-recorded SARIF in each scenario,
each in a workspace (MARA_HOME) of its own holding the MARA workspace's calib/latest.json and history.json and a
training register with one trained adjudicator, alice:
  default    no ticket backlog and no human decisions
  tightened  a ticket backlog one over the limit, so the human queue tightens
  decisions  two keys of a first run's human queue decided, one by alice (usable) and one by bob (untrained)
Each review writes to one fixed directory and is moved under <out>/<label>/<scenario> afterwards, so the console
output of two labels can be compared as it is.

`compare <before> <after>` passes when both labels hold the same scenarios and, in every scenario, the reports are the
same apart from what the reviews cannot keep the same and what is allowed: report.json apart from generated_at and
every --allow key (a dotted path); the other files and the console apart from timestamps and lines matching an
--ignore regex; the progress record apart from its timestamps; and in the decisions scenario the same keys decided,
recorded under both labels. It prints what differs and exits 1 when anything does.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ("default", "tightened", "decisions")
TEXT_FILES = ("pipeline.log", "report.sarif", "context.json", "report.md", "human_queue.md", "human_queue.json")
REGISTER = ("curriculum_version: '2026-09'\nvalidity_days: 365\npass_mark: 0.8\nrecords:\n"
            "  - {person: alice, role: adjudicator, curriculum_version: '2026-09', date: 2026-09-20, assessor: quiz, evidence: quiz}\n")
CONFIG = ROOT / "config" / "mara.mock.yaml"
TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})")
PROGRESS_TIMES = {"started_at", "finished_at", "at", "updated_at"}


def _workspace(path: Path, scenario: str) -> Path:
    shutil.rmtree(path, ignore_errors=True)
    (path / "calib" / "decisions").mkdir(parents=True)
    for name in ("latest.json", "history.json"):
        if (ROOT / "calib" / name).is_file():
            shutil.copy(ROOT / "calib" / name, path / "calib" / name)
    (path / "training").mkdir()
    (path / "training" / "records.yaml").write_text(REGISTER, encoding="utf-8")
    if scenario == "tightened":
        sys.path.insert(0, str(ROOT / "src"))
        from mara.config import load_config

        limit = load_config(CONFIG).human_queue.backlog_limit
        (path / "calib" / "decisions" / "backlog.json").write_text(json.dumps({"open": limit + 1}), encoding="utf-8")
    return path


def _review(ws: Path, out: Path, *, progress: Path | None = None, console: Path | None = None) -> None:
    mara = Path(sys.executable).with_name("mara")
    argv = [str(mara), "review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(CONFIG),
            "--mock-fixtures", str(ROOT / "fixtures" / "mock-responses"), "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"),
            "--out", str(out)] + (["--progress-file", str(progress)] if progress else [])
    env = {**os.environ, "MARA_HOME": str(ws), "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    cp = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True)
    if console is not None:
        console.write_text(cp.stdout + cp.stderr, encoding="utf-8")
    if cp.returncode != 0:
        raise RuntimeError(f"mara review failed ({cp.returncode}): {(cp.stdout + cp.stderr)[-2000:]}")


def _decide(ws: Path, item: dict, decision: str, by: str, issue: int) -> None:
    """The decision file the ticket sync writes for a closed ticket on `item`."""
    rec = {k: item[k] for k in ("key", "target_id", "revision", "context_hash", "file", "line", "cwe")}
    rec.update(decision=decision, decision_event_id=1000 + issue, decided_by=by, decided_at="2026-10-01T08:00:00Z", issue=issue,
               finding_id=item["finding_id"])
    (ws / "calib" / "decisions" / f"{item['key']}.json").write_text(json.dumps(rec), encoding="utf-8")


def record(label: str, out: Path, scenarios: tuple[str, ...] = SCENARIOS) -> None:
    """Record every scenario of `scenarios` under <out>/<label>."""
    run = out / "run"  # every review writes here first, so two labels' console output names the same paths
    for scenario in scenarios:
        ws = _workspace(out / "ws" / scenario, scenario)
        if scenario == "decisions":
            shutil.rmtree(run, ignore_errors=True)
            _review(ws, run)
            items = json.loads((run / "human_queue.json").read_text(encoding="utf-8"))["items"]
            if len(items) < 2:
                raise RuntimeError("the first run queued fewer than two findings to decide")
            _decide(ws, items[0], "false_positive", "alice", 1)  # usable: alice is a trained adjudicator
            _decide(ws, items[1], "true_positive", "bob", 2)  # not usable: bob is not
        shutil.rmtree(run, ignore_errors=True)
        _review(ws, run, progress=run.with_name("run.progress.json"), console=run.with_name("run.console"))
        dest = out / label / scenario
        shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        run.rename(dest)
        run.with_name("run.progress.json").rename(dest / "progress.json")
        run.with_name("run.console").rename(dest / "console.txt")
        if scenario == "decisions":
            decided = sorted(p.stem for p in (ws / "calib" / "decisions").glob("v2-*.json"))
            (dest / "decided-keys.json").write_text(json.dumps(decided) + "\n", encoding="utf-8")
        print(f"recorded {label} {scenario}", flush=True)


def _drop(data: dict, dotted: str) -> None:
    *parents, last = dotted.split(".")
    for key in parents:
        data = data.get(key) if isinstance(data, dict) else None  # type: ignore[assignment]
        if not isinstance(data, dict):
            return
    data.pop(last, None)


def _strip_times(x):
    if isinstance(x, dict):
        return {k: _strip_times(v) for k, v in x.items() if k not in PROGRESS_TIMES}
    if isinstance(x, list):
        return [_strip_times(v) for v in x]
    return x


def _lines(path: Path, ignore: list[re.Pattern]) -> list[str]:
    text = TIMESTAMP.sub("<time>", path.read_text(encoding="utf-8")) if path.is_file() else "<missing>"
    return [line for line in text.splitlines() if not any(p.search(line) for p in ignore)]


def compare_scenario(before: Path, after: Path, allow: list[str], ignore: list[re.Pattern]) -> list[str]:
    """What differs between two recordings of one scenario, beyond what is allowed; empty when nothing does."""
    diffs = []
    rb, ra = (json.loads((d / "report.json").read_text(encoding="utf-8")) for d in (before, after))
    if list(rb) != list(ra):
        diffs.append("report.json: the top-level key order differs")
    if list(rb.get("bias_audit", {})) != list(ra.get("bias_audit", {})):
        diffs.append("report.json: the bias_audit key order differs")
    for r in (rb, ra):
        for key in ("generated_at", *allow):
            _drop(r, key)
    diffs += [f"report.json: {k} differs" for k in sorted(set(rb) | set(ra)) if rb.get(k) != ra.get(k)]
    for name in (*TEXT_FILES, "console.txt"):
        lb, la = _lines(before / name, ignore), _lines(after / name, ignore)
        if lb != la:
            n = sum(x != y for x, y in zip(lb, la, strict=False)) + abs(len(lb) - len(la))
            diffs.append(f"{name}: {n} line(s) differ")
    pb, pa = (_strip_times(json.loads((d / "progress.json").read_text(encoding="utf-8"))) for d in (before, after))
    if pb != pa:
        diffs.append("progress record differs (timestamps aside)")
    kb, ka = before / "decided-keys.json", after / "decided-keys.json"
    missing = [k.parent.parent.name for k in (kb, ka) if not k.is_file()]
    if missing and (before.name == "decisions" or len(missing) == 1):
        diffs.append(f"decided-keys.json: not recorded under {', '.join(missing)}")
    elif not missing and kb.read_text(encoding="utf-8") != ka.read_text(encoding="utf-8"):
        diffs.append("the decided keys differ")
    return diffs


def compare(before: Path, after: Path, allow: list[str], ignore: list[str]) -> int:
    patterns = [re.compile(p) for p in ignore]
    recorded = {d: {p.name for p in d.iterdir() if p.is_dir()} for d in (before, after)}
    order = {s: i for i, s in enumerate(SCENARIOS)}
    scenarios = sorted(recorded[before] & recorded[after], key=lambda s: order.get(s, len(SCENARIOS)))
    if not scenarios:
        print(f"no scenario recorded under both {before} and {after}")
        return 1
    failed = False
    for d, other in ((before, after), (after, before)):
        for scenario in sorted(recorded[d] - recorded[other], key=lambda s: order.get(s, len(SCENARIOS))):
            print(f"{scenario}: recorded under {d.name} only")
            failed = True
    for scenario in scenarios:
        diffs = compare_scenario(before / scenario, after / scenario, allow, patterns)
        print(f"{scenario}: " + ("the same" if not diffs else "DIFFERENT"))
        for d in diffs:
            print(f"  {d}")
        failed |= bool(diffs)
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "out" / "compare-reviews", help="default: out/compare-reviews")
    sub = ap.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record", help="record the scenarios with the source as it is now")
    rec.add_argument("label")
    rec.add_argument("--scenario", nargs="+", choices=SCENARIOS, default=list(SCENARIOS))
    cmp = sub.add_parser("compare", help="compare two recordings")
    cmp.add_argument("before")
    cmp.add_argument("after")
    cmp.add_argument("--allow", action="append", default=[], help="a report.json key (dotted path) that may differ")
    cmp.add_argument("--ignore", action="append", default=[], help="a regex: lines of the other files matching it are not compared")
    a = ap.parse_args(argv)
    if a.command == "record":
        record(a.label, a.out, tuple(a.scenario))
        return 0
    return compare(a.out / a.before, a.out / a.after, a.allow, a.ignore)


if __name__ == "__main__":
    sys.exit(main())
