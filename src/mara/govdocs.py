"""Governance evidence that used to be "needs a human" (G-1, G-4, G-10) made machine-decidable.

- G-1: the review policy document (docs/policy/mara-review-policy.md) carries YAML front matter
  (status, approver, dates) and mandatory statements marked `<!-- policy:S1 -->` … ; `policy_status`
  decides whether it is approved, current and complete.
- G-4: cold-standby configurations (config/examples/standby-for-<family>.yaml) and the model-swap
  drill register (ops/model-swap-drills.yaml); `drill_status` decides, per production family,
  whether a standby config exists and a live drill finished within a week in the last year.
- G-10: the rollout phase in the config (`rollout:`), its dates and the shadow-phase baseline
  report; `rollout_status` decides whether the declared phase is consistent with the report's
  schedule and `baseline_metrics` aggregates review outputs into that report.

Nothing here reads the network; every decision is a function of files in the repository.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import MaraConfig

POLICY_STATEMENTS = {
    "S1": "自動審查是 ISO/IEC 27001 A.8.29 安全測試的一部分",
    "S2": "審查通過不等於免除人工安全測試",
    "S3": "阻擋級 finding 的處理義務",
    "S4": "人工裁決與裁決者資格",
    "S5": "資料駐留與模型使用限制",
    "S6": "例外與風險接受",
}
POLICY_REQUIRED = ("S1", "S2", "S3", "S4", "S5", "S6")
POLICY_MAX_AGE_DAYS = 365
DRILL_MAX_HOURS = 7 * 24
DRILL_MAX_AGE_DAYS = 365
ROLLOUT_PHASES = ("not_started", "shadow", "advisory", "blocking")


# ---------------------------------------------------------------- front matter

def read_front_matter(path: Path | str) -> tuple[dict, str]:
    """(front matter dict, body) for a Markdown file starting with a `---` YAML block."""
    import yaml

    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    meta = yaml.safe_load(text[4:end]) or {}
    return (meta if isinstance(meta, dict) else {}), text[end + 5:]


def _date(v) -> dt.date | None:
    if not v:
        return None
    if isinstance(v, dt.date):
        return v
    try:
        return dt.date.fromisoformat(str(v))
    except ValueError:
        return None


# ---------------------------------------------------------------- G-1 policy

@dataclass(frozen=True)
class PolicyStatus:
    ok: bool
    state: str                 # approved | draft | missing | stale | incomplete
    problems: tuple[str, ...]
    meta: dict
    statements: dict[str, bool]


def policy_status(path: Path | str, today: dt.date) -> PolicyStatus:
    p = Path(path)
    if not p.exists():
        return PolicyStatus(False, "missing", (f"{p} does not exist",), {}, {})
    meta, body = read_front_matter(p)
    statements = {}
    for sid in POLICY_REQUIRED:
        marker = f"<!-- policy:{sid} -->"
        idx = body.find(marker)
        after = body[idx + len(marker):].strip() if idx >= 0 else ""
        # the statement is the first non-heading paragraph after the marker
        para = next((blk.strip() for blk in after.split("\n\n") if blk.strip() and not blk.strip().startswith("#")), "") if idx >= 0 else ""
        statements[sid] = bool(para)
    problems = [f"statement {sid} ({POLICY_STATEMENTS[sid]}) missing or empty" for sid, ok in statements.items() if not ok]
    status = str(meta.get("status", "draft")).lower()
    approved_on = _date(meta.get("approved_on"))
    review_by = _date(meta.get("review_by"))
    if status != "approved":
        problems.append("status is not `approved` (PSO approval pending)")
    if not str(meta.get("approved_by", "")).strip():
        problems.append("approved_by is empty")
    if approved_on is None:
        problems.append("approved_on is empty or not a date")
    elif approved_on > today:
        problems.append(f"approved_on {approved_on} is in the future")
    if review_by is not None and review_by < today:
        problems.append(f"review_by {review_by} has passed")
    if approved_on is not None and (today - approved_on).days > POLICY_MAX_AGE_DAYS and (review_by is None or review_by < today):
        problems.append(f"approved more than {POLICY_MAX_AGE_DAYS} days ago and not re-reviewed")
    if problems:
        state = "incomplete" if any("statement" in x for x in problems) else ("draft" if status != "approved" else "stale")
        return PolicyStatus(False, state, tuple(problems), meta, statements)
    return PolicyStatus(True, "approved", (), meta, statements)


# ---------------------------------------------------------------- G-4 standby and drills

@dataclass(frozen=True)
class Drill:
    date: dt.date
    kind: str                  # live | rehearsal
    replaced_family: str
    standby_family: str
    config: str
    duration_hours: float
    outcome: str               # pass | fail
    performed_by: str
    evidence: str


def load_drills(path: Path | str) -> list[Drill]:
    import yaml

    p = Path(path)
    if not p.exists():
        return []
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out = []
    for d in raw.get("drills", []) or []:
        date = _date(d.get("date"))
        if date is None:
            raise ValueError(f"drill without a valid date: {d}")
        out.append(Drill(date, str(d.get("kind", "live")), str(d.get("replaced_family", "")), str(d.get("standby_family", "")),
                         str(d.get("config", "")), float(d.get("duration_hours", 0) or 0), str(d.get("outcome", "")),
                         str(d.get("performed_by", "")), str(d.get("evidence", ""))))
    return out


def append_drill(path: Path | str, drill: Drill) -> None:
    import yaml

    p = Path(path)
    text = p.read_text(encoding="utf-8") if p.exists() else ""
    head = text.split("drills:")[0].rstrip("\n") if "drills:" in text else "# model-swap drills (G-4)"
    drills = load_drills(p) + [drill]
    body = yaml.safe_dump({"drills": [{
        "date": d.date.isoformat(), "kind": d.kind, "replaced_family": d.replaced_family, "standby_family": d.standby_family,
        "config": d.config, "duration_hours": d.duration_hours, "outcome": d.outcome, "performed_by": d.performed_by, "evidence": d.evidence}
        for d in drills]}, sort_keys=False, allow_unicode=True)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(head + "\n" + body, encoding="utf-8")


def production_families(cfg: MaraConfig) -> list[str]:
    fams = []
    for m in cfg.models:
        f = m.family.value
        if m.provider != "mock" and f not in fams:
            fams.append(f)
    return fams


def standby_configs(root: Path | str) -> dict[str, Path]:
    """replaced family -> standby config path, from config/examples/standby-for-<family>.yaml."""
    out = {}
    for p in sorted((Path(root) / "config" / "examples").glob("standby-for-*.y*ml")):
        fam = p.stem[len("standby-for-"):]
        out[fam] = p
    return out


@dataclass(frozen=True)
class FamilyDrillStatus:
    family: str
    standby_config: str
    standby_family: str
    config_ok: bool
    config_problem: str
    drill: Drill | None
    drill_ok: bool
    drill_problem: str

    @property
    def ok(self) -> bool:
        return self.config_ok and self.drill_ok


def _standby_family_of(prod: list[str], cfg_path: Path, replaced: str) -> tuple[str, str]:
    """(standby family, problem) after loading the standby config through the policies."""
    from .config import load_config

    try:
        sb = load_config(cfg_path)
    except Exception as e:  # policy or structure failure
        return "", f"does not load: {str(e).splitlines()[0][:160]}"
    fams = production_families(sb)
    if replaced in fams:
        return "", f"still contains the {replaced} family"
    new = [f for f in fams if f not in prod]
    missing = [f for f in prod if f != replaced and f not in fams]
    if missing:
        return "", f"drops other production families too: {missing}"
    if not new:
        return "", "adds no standby family"
    return new[0], ""


def drill_status(cfg: MaraConfig, root: Path | str, today: dt.date, drills_path: Path | str | None = None) -> list[FamilyDrillStatus]:
    root = Path(root)
    prod = production_families(cfg)
    standbys = standby_configs(root)
    drills = load_drills(drills_path or (root / "ops" / "model-swap-drills.yaml"))
    out = []
    for fam in prod:
        sb = standbys.get(fam)
        if sb is None:
            out.append(FamilyDrillStatus(fam, "", "", False, f"no config/examples/standby-for-{fam}.yaml", None, False, "no drill"))
            continue
        sb_fam, problem = _standby_family_of(prod, sb, fam)
        live = [d for d in drills if d.kind == "live" and d.replaced_family == fam]
        recent = [d for d in live
                  if (today - d.date).days <= DRILL_MAX_AGE_DAYS and d.outcome == "pass" and 0 < d.duration_hours <= DRILL_MAX_HOURS]
        best = max(recent, key=lambda d: d.date) if recent else (max(live, key=lambda d: d.date) if live else None)
        if recent:
            dp = ""
        elif live:
            dp = (f"last live drill {best.date} outcome {best.outcome}, {best.duration_hours:g} h; "
                  f"need pass within {DRILL_MAX_HOURS} h in the last {DRILL_MAX_AGE_DAYS} days")
        else:
            dp = "no live drill recorded"
        out.append(FamilyDrillStatus(fam, str(sb.relative_to(root)), sb_fam, not problem, problem, best, bool(recent), dp))
    return out


# ---------------------------------------------------------------- G-10 rollout

@dataclass(frozen=True)
class RolloutStatus:
    ok: bool
    phase: str
    days_in_phase: int | None
    due: dt.date | None
    problems: tuple[str, ...]
    notes: tuple[str, ...] = ()


def rollout_status(cfg: MaraConfig, root: Path | str, today: dt.date) -> RolloutStatus:
    r = cfg.rollout
    root = Path(root)
    problems, notes = [], []
    if r.phase == "not_started":
        msg = "rollout.phase is not_started: set phase: shadow and started_on on the day the pipeline first runs on real pull requests"
        return RolloutStatus(False, r.phase, None, None, (msg,))
    started = _date(r.started_on)
    if started is None:
        return RolloutStatus(False, r.phase, None, None, (f"rollout.started_on is empty or not a date (phase {r.phase})",))
    if started > today:
        return RolloutStatus(False, r.phase, None, None, (f"rollout.started_on {started} is in the future",))
    days = (today - started).days
    months = {"shadow": r.shadow_months, "advisory": r.advisory_months}.get(r.phase)
    due = started + dt.timedelta(days=30 * months) if months else None
    baseline = root / r.baseline_report if r.baseline_report else None
    if r.phase == "shadow":
        if due and today > due + dt.timedelta(days=30):
            problems.append(f"shadow phase started {started}, planned {r.shadow_months} months, now {days} days: "
                            "produce the baseline report and advance to advisory")
        notes.append("gate results are recorded, never enforced")
    if r.phase in ("advisory", "blocking"):
        if baseline is None:
            problems.append("rollout.baseline_report is empty: the shadow phase must end with a baseline report (rollout_phase.py baseline)")
        elif not baseline.exists():
            problems.append(f"baseline report {r.baseline_report} not found")
        if r.phase == "advisory":
            notes.append("gate results are advisory; blocking findings are marked, not enforced")
            if due and today > due + dt.timedelta(days=30):
                problems.append(f"advisory phase started {started}, planned {r.advisory_months} months, now {days} days: decide on blocking")
        else:
            notes.append("gate blocks on accepted tier A/B High+ findings")
    return RolloutStatus(not problems, r.phase, days, due, tuple(problems), tuple(notes))


def baseline_metrics(report_paths: list[Path], decisions_dir: Path | str | None = None) -> dict:
    """Aggregate review outputs (report.json files) into the shadow-phase baseline the report asks for:
    findings per review, tier mix, gate would-block rate, human-queue size, token cost, and the
    false-positive rate from human decisions when any exist."""
    reports = [json.loads(Path(p).read_text(encoding="utf-8")) for p in report_paths]
    n = len(reports)
    if not n:
        raise ValueError("no report.json files given")
    tiers = {"A": 0, "B": 0, "C": 0, "D": 0}
    accepted = rejected = queued = blocked = 0
    tokens_in = tokens_out = 0
    for r in reports:
        for c in r.get("consensus", []):
            tiers[c["tier"]] = tiers.get(c["tier"], 0) + 1
            accepted += int(c.get("accepted", False))
            rejected += int(not c.get("accepted", False))
        queued += len(r.get("human_queue", []))
        blocked += int(not r.get("gate_passed", True))
        audit = r.get("bias_audit", {})
        tokens_in += int(audit.get("input_tokens", 0) or 0)
        tokens_out += int(audit.get("output_tokens", 0) or 0)
    decisions = {"true_positive": 0, "false_positive": 0}
    if decisions_dir and Path(decisions_dir).is_dir():
        for p in Path(decisions_dir).glob("*.json"):
            if p.name == "backlog.json":
                continue
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if d.get("decision") in decisions:
                decisions[d["decision"]] += 1
    decided = decisions["true_positive"] + decisions["false_positive"]
    return {
        "reviews": n,
        "findings_per_review": round((accepted + rejected) / n, 2),
        "accepted_per_review": round(accepted / n, 2),
        "tiers": tiers,
        "gate_would_block_rate": round(blocked / n, 3),
        "human_queue_per_review": round(queued / n, 2),
        "tokens_in": tokens_in, "tokens_out": tokens_out,
        "decisions": decisions,
        "false_positive_rate_from_decisions": None if not decided else round(decisions["false_positive"] / decided, 3),
        "modes": sorted({r.get("provider_mode", "?") for r in reports}),
    }


def render_baseline(metrics: dict, *, date: dt.date, phase_started: str, sources: list[str]) -> str:
    fp = metrics["false_positive_rate_from_decisions"]
    L = [f"# Rollout baseline report ({date})", "",
         f"Shadow phase started {phase_started or 'unknown'}; {metrics['reviews']} review(s) aggregated; "
         f"provider mode(s): {', '.join(metrics['modes'])}.",
         "", "| metric | value |", "|---|---:|",
         f"| findings per review (accepted + rejected) | {metrics['findings_per_review']} |",
         f"| accepted findings per review | {metrics['accepted_per_review']} |",
         f"| evidence tiers A / B / C / D | {metrics['tiers']['A']} / {metrics['tiers']['B']} / {metrics['tiers']['C']} / {metrics['tiers']['D']} |",
         f"| gate would-block rate | {metrics['gate_would_block_rate']} |",
         f"| human-queue items per review | {metrics['human_queue_per_review']} |",
         f"| tokens in / out | {metrics['tokens_in']} / {metrics['tokens_out']} |",
         f"| human decisions (tp / fp) | {metrics['decisions']['true_positive']} / {metrics['decisions']['false_positive']} |",
         f"| false-positive rate from decisions | {'not available (no decisions yet)' if fp is None else fp} |",
         "", "Sources:", ""] + [f"- `{s}`" for s in sources] + [""]
    if "mock" in metrics["modes"]:
        L += ["**Mock mode reports are included; a baseline for the rollout decision must come from live reviews of real pull requests.**", ""]
    return "\n".join(L)
