"""Tool triage (GLOSSARY.md; docs/adr/0010-tool-triage.md): draft entries from a report, and check a triage file.

  python scripts/tool_triage.py draft --report out/report.json [--days 30] [--decided-by NAME]
      prints, as YAML, one entry for each tool, rule and file of the report with a tool alert that no triage rules on
      and that may be triaged (never a secret), listing the fingerprints of those alerts: a ruling covers the alerts a
      person read and no other. The report must be of a review with tool_triage.enabled, which is what gives an alert
      its fingerprint. Each draft has the report's target, today as its decision day and an expiry --days later, and
      `TODO` for the verdict and the reason, so a draft is not an entry until a person has ruled: read each alert,
      drop a fingerprint you do not rule on, choose false_positive or accepted_risk, say why (an accepted risk also
      names its approval_ref), and add it under `entries:` of <workspace>/calib/tool-triage.yaml.
  python scripts/tool_triage.py check [--file FILE] [--config CONFIG]
      reads the triage file (default: the one the config names, below the workspace) and prints each entry that is
      malformed or not usable today, with why; exit 1 when there is one, 0 when every entry is usable.

Nothing here rules on an alert: a person writes the verdict and the reason.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import tool_triage  # noqa: E402
from mara.identity import norm_path  # noqa: E402
from mara.tools.evidence import is_alert  # noqa: E402
from mara.workspace import Workspace, resolve  # noqa: E402

TODO = "TODO"


def drafts(report: dict, today: dt.date, days: int, decided_by: str) -> list[dict]:
    """One draft entry for each tool, rule and file of `report` with an untriaged alert that may be triaged, in the
    report's order, listing the fingerprints of those alerts. An alert with no fingerprint is left out: the report is
    of a review that did not apply tool triage. A report with no target_id drafts nothing: an entry binds to its
    target."""
    target = report.get("target_id")
    if not isinstance(target, str) or not target:
        return []
    out: dict[tuple[str, str, str], dict] = {}
    for t in report.get("tool_results") or []:
        if not isinstance(t, dict) or not is_alert(t.get("level")) or t.get("triage"):
            continue
        tool, rule, file = str(t.get("tool") or ""), str(t.get("rule_id") or ""), str(t.get("file") or "")
        fp = t.get("fingerprint")
        if not tool or not rule or not norm_path(file) or not isinstance(fp, str) or tool_triage.secret_alert(tool, rule):
            continue
        entry = out.setdefault((tool, rule, norm_path(file)), {
            "target_id": target, "tool": tool, "rule": rule, "file": file, "fingerprints": [], "verdict": TODO, "reason": TODO,
            "decided_by": decided_by or TODO, "decided_on": today.isoformat(), "expires": (today + dt.timedelta(days=days)).isoformat()})
        if fp not in entry["fingerprints"]:
            entry["fingerprints"].append(fp)
    return list(out.values())


def unstamped(report: dict) -> int:
    """How many alerts of `report` carry no fingerprint: those of a review that did not apply tool triage."""
    return sum(1 for t in report.get("tool_results") or []
               if isinstance(t, dict) and is_alert(t.get("level")) and not isinstance(t.get("fingerprint"), str))


def problems(loaded: tool_triage.Loaded, *, today: dt.date, max_days: int, training) -> list[str]:
    """What is wrong with the triage file `loaded` today: each malformed entry, each well-formed one that is not
    usable, with why, and each usable one that another contradicts. Whether a target has a name of its own is known
    only to a review of it, and is not checked here."""
    out = list(loaded.malformed)
    held = []
    for e in loaded.entries:
        why = tool_triage.usable(e, today=today, max_days=max_days, training=training)
        if why:
            out.append(f"{e.tool} {e.rule} {e.file} (target {e.target_id[:12]}): {why}")
        else:
            held.append(e)
    out += [f"{e.tool} {e.rule} {e.file} (target {e.target_id[:12]}): {tool_triage.CONTRADICTED}" for e in tool_triage.contradicted(held)]
    return out


def main(argv: list[str] | None = None) -> int:
    import yaml

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("draft")
    d.add_argument("--report", type=Path, required=True)
    d.add_argument("--days", type=int, default=30)
    d.add_argument("--decided-by", default="")
    c = sub.add_parser("check")
    c.add_argument("--file", type=Path)
    c.add_argument("--config", type=Path)
    a = ap.parse_args(argv)
    workspace = Workspace.from_env()
    today = dt.date.today()
    if a.cmd == "draft":
        try:
            report = json.loads(a.report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"ERROR: {a.report}: not a readable report ({type(e).__name__})", file=sys.stderr)
            return 2
        if not isinstance(report, dict):
            print(f"ERROR: {a.report}: not a report", file=sys.stderr)
            return 2
        found = drafts(report, today, a.days, a.decided_by)
        if missing := unstamped(report):
            print(f"# {missing} alert(s) carry no fingerprint and are left out: the report is of a review that did not apply tool "
                  "triage. Set tool_triage.enabled: true, review again, and draft from that report.")
        print(f"# {len(found)} draft(s): each needs a verdict (false_positive or accepted_risk) and a reason before it is an entry")
        print(yaml.safe_dump({"entries": found}, sort_keys=False, allow_unicode=True), end="")
        return 0
    from mara.config import load_config
    from mara.decisions import TrainingRequirement

    try:
        cfg = load_config(a.config or workspace.root / "config" / "mara.yaml", workspace)
    except (OSError, ValueError) as e:
        print(f"ERROR: config: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    path = a.file or resolve(cfg.tool_triage.file, workspace.root)
    loaded = tool_triage.load(path)
    found = problems(loaded, today=today, max_days=cfg.tool_triage.max_days,
                     training=TrainingRequirement.from_config(cfg.training, workspace.root))
    for line in found:
        print(f"NOT USABLE {line}")
    print(f"{path}: {len(loaded.entries)} entr(ies), {len(found)} not usable or malformed"
          + ("" if cfg.tool_triage.enabled else "; tool_triage.enabled is false, so no review applies this file"))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
