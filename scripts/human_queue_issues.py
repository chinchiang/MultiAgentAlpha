"""G-11: turn the human queue into tickets and bring decisions back.

  python scripts/human_queue_issues.py --queue out/human_queue.json --repo owner/repo [--dry-run]
      one GitHub issue per queue item (label from --label, deduplicated by the item's stable key
      carried as an HTML marker in the body); existing open tickets are left alone.
  python scripts/human_queue_issues.py --repo owner/repo --sync-decisions [--dry-run]
      closed tickets carrying decision:true-positive or decision:false-positive become
      calib/decisions/<key>.json, and calib/decisions/backlog.json records the open count so the
      pipeline can tighten when the backlog is over the limit.

Uses the `gh` CLI (present on GitHub runners; needs GH_TOKEN with issues: write). Nothing here
ever approves a finding; humans decide on the ticket, the pipeline only reads the outcome.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mara.report.escaping import literal  # noqa: E402

MARKER = "<!-- mara-hq:{key} -->"
MARKER_RE = re.compile(r"<!-- mara-hq:(v2-[0-9a-f]{24}|[0-9a-f]{12}) -->")
DECISION_LABELS = {"decision:true-positive": "true_positive", "decision:false-positive": "false_positive"}


class GhError(RuntimeError):
    pass


def gh(args: list[str], *, dry_run: bool = False, mutating: bool = False) -> str:
    exe = shutil.which("gh")
    if not exe:
        raise GhError("gh CLI not found on PATH")
    if dry_run and mutating:
        print("  [dry-run] gh " + " ".join(args))
        return ""
    cp = subprocess.run([exe, *args], capture_output=True, text=True, check=False)
    if cp.returncode != 0:
        raise GhError(f"gh {' '.join(args[:3])} failed: {cp.stderr.strip()[-500:]}")
    return cp.stdout


def ensure_labels(repo: str, label: str, dry_run: bool) -> None:
    for name, color, desc in ((label, "d93f0b", "MARA finding waiting for a human decision"),
                              ("decision:true-positive", "0e8a16", "Human decision: real vulnerability"),
                              ("decision:false-positive", "6a737d", "Human decision: not a vulnerability")):
        gh(["label", "create", name, "--force", "--color", color, "--description", desc, "--repo", repo], dry_run=dry_run, mutating=True)


def open_tickets(repo: str, label: str) -> dict[str, int]:
    out = gh(["issue", "list", "--repo", repo, "--label", label, "--state", "open", "--limit", "500", "--json", "number,body"])
    keys: dict[str, int] = {}
    for issue in json.loads(out or "[]"):
        m = MARKER_RE.search(issue.get("body") or "")
        if m:
            keys[m.group(1)] = issue["number"]
    return keys


def ticket_body(item: dict, target: str) -> str:
    meta = {k: item.get(k) for k in ("key", "target_id", "revision", "context_hash", "finding_id", "file", "line", "cwe")}
    encoded = base64.urlsafe_b64encode(json.dumps(meta, ensure_ascii=False).encode()).decode()
    marker = MARKER.format(key=item["key"])
    def safe(value):
        if isinstance(value, str):
            return literal(value)
        if isinstance(value, list):
            return [safe(v) for v in value]
        if isinstance(value, dict):
            return {k: safe(v) for k, v in value.items()}
        return value
    item = safe(item)
    L = [marker, f"**MARA human queue** · target `{literal(target)}` · finding {item['finding_id']} · key `{item['key']}`", "",
         f"- Why: {', '.join(item['reasons'])}",
         f"- {item['dimension']} · {item['cwe']} · `{item['file']}:{item['line']}` · tier {item['tier']} · CVSS {item['cvss4_score']} {item['cvss4_severity']} · SSVC {item['ssvc_decision']}",
         f"- Consensus {item['weighted_score']} (tp {item['votes_tp']} / fp {item['votes_fp']} / human {item['votes_human']}) · agreement proxy {item.get('agreement_proxy')}",
         f"- Found by {', '.join(item['finder_families'])} · reachability {item['reachability']}: {item['reachability_argument']}",
         f"- Attacker path: {item['exploit_sketch']}", f"- Quote: `{item['quote']}`"]
    if item.get("skeptic"):
        s = item["skeptic"]
        L.append(f"- Skeptic ({s['family']}): **{s['verdict']}** — {s['reason']}" + (f" · control: {s['sanitizer_or_control']}" if s.get("sanitizer_or_control") else ""))
    if item.get("redteam"):
        r = item["redteam"]
        L.append(f"- Red team ({r['family']}): exploitable **{r['exploitable']}** — {r['preconditions']}")
    if item.get("judge_votes"):
        L += ["- Judges:"] + [f"  - {v['family']} [{v['pass']}]{' (self-family)' if v.get('self_family') else ''}: **{v['verdict']}** {v['severity_band']} — {v['reason']}"
                              for v in item["judge_votes"]]
    L += ["", "**Decide:** add label `decision:true-positive` or `decision:false-positive`, then close. "
          "The decision is written to `calib/decisions/` on the next sync and feeds calibration. Do not close without a decision label.",
          "", "---", "_Generated by MARA; model text is untrusted evidence._"]
    return "\n".join(L) + f"\n<!-- mara-meta:{encoded} -->"


def create_tickets(queue_path: Path, repo: str, label: str, dry_run: bool) -> tuple[int, int]:
    q = json.loads(queue_path.read_text(encoding="utf-8"))
    items, target = q.get("items", []), q.get("target", "")
    if not items:
        print("human queue is empty; nothing to file")
        return 0, 0
    if any(not valid_identity(it) for it in items):
        raise ValueError("legacy or invalid queue identity: regenerate the review before creating tickets")
    ensure_labels(repo, label, dry_run)
    existing = {} if dry_run else open_tickets(repo, label)
    created = skipped = 0
    for it in items:
        if it["key"] in existing:
            print(f"  {it['finding_id']} key {it['key']}: open ticket #{existing[it['key']]} exists, skipping")
            skipped += 1
            continue
        body_file = Path(f".mara-hq-{it['key']}.md")
        body_file.write_text(ticket_body(it, target), encoding="utf-8")
        try:
            gh(["issue", "create", "--repo", repo, "--label", label, "--title", f"[MARA human queue] {it['finding_id']} · {it['title'][:80]}",
                "--body-file", str(body_file)], dry_run=dry_run, mutating=True)
        finally:
            body_file.unlink(missing_ok=True)
        created += 1
    return created, skipped


def valid_identity(item: dict) -> bool:
    sys.path.insert(0, str(ROOT / "src"))
    from mara.report.human_queue_out import queue_key
    if not all(item.get(k) for k in ("target_id", "revision", "context_hash", "file", "line", "cwe")):
        return False
    return item.get("key") == queue_key(item["file"], int(item["line"]), item["cwe"], target_id=item["target_id"],
                                       revision=item["revision"], context_hash=item["context_hash"])


def decision_event(repo: str, number: int, label: str) -> dict | None:
    """Replay adds/removes; bind the surviving exact label to its own actor and event time."""
    try:
        pages = json.loads(gh(["api", f"repos/{repo}/issues/{number}/events", "--paginate", "--slurp"]) or "[]")
        events = [e for page in pages for e in page] if pages and isinstance(pages[0], list) else pages
    except (GhError, ValueError, TypeError):
        return None
    active = {}
    for ev in events:
        name = (ev.get("label") or {}).get("name", "")
        if name not in DECISION_LABELS:
            continue
        if ev.get("event") == "labeled":
            active[name] = ev
        elif ev.get("event") == "unlabeled":
            active.pop(name, None)
    if set(active) != {label}:
        return None
    event = active[label]
    if not event.get("id") or not event.get("created_at") or not (event.get("actor") or {}).get("login"):
        return None
    return event


def decision_actor(repo: str, number: int, label: str = "decision:true-positive") -> str:
    event = decision_event(repo, number, label)
    return event["actor"]["login"] if event else ""


def _load_register(register: Path | None):
    if register is None or not register.exists():
        return None
    sys.path.insert(0, str(ROOT / "src"))
    from mara.training import load_register

    try:
        return load_register(register)
    except (OSError, ValueError):
        return None


def sync_decisions(repo: str, label: str, decisions_dir: Path, backlog_file: Path, dry_run: bool,
                   register: Path | None = None) -> tuple[int, int]:
    """Closed tickets with a decision label become calib/decisions/<key>.json. Each record names who
    applied the label and whether that person holds a valid adjudicator training record (G-13);
    calibration applies only trained adjudicators' decisions when the config requires it."""
    sys.path.insert(0, str(ROOT / "src"))
    from mara.training import is_trained

    closed = json.loads(gh(["issue", "list", "--repo", repo, "--label", label, "--state", "closed", "--limit", "500",
                            "--json", "number,body,labels,closedAt,url"]) or "[]")
    decisions_dir.mkdir(parents=True, exist_ok=True)
    reg = _load_register(register)
    written = 0
    untrained = []
    for issue in closed:
        m = MARKER_RE.search(issue.get("body") or "")
        if not m:
            continue
        labels = {lab["name"] for lab in issue.get("labels", [])}
        decisions = labels & DECISION_LABELS.keys()
        if len(decisions) != 1:
            print(f"  issue #{issue['number']} closed without a decision label; ignored")
            continue
        decision_label = next(iter(decisions))
        event = decision_event(repo, issue["number"], decision_label)
        metadata = re.search(r"<!-- mara-meta:([A-Za-z0-9_=-]+) -->", issue.get("body") or "")
        if not event or not metadata:
            continue
        try:
            meta = json.loads(base64.urlsafe_b64decode(metadata.group(1)))
            decision_day = dt.datetime.fromisoformat(event["created_at"].replace("Z", "+00:00")).date()
            if not valid_identity(meta) or meta["key"] != m.group(1):
                continue
        except (ValueError, TypeError, KeyError):
            continue
        key = meta["key"]
        decision = DECISION_LABELS[decision_label]
        actor = event["actor"]["login"]
        trained = is_trained(reg, actor, "adjudicator", decision_day)
        if not trained:
            untrained.append(f"#{issue['number']} by {actor}")
        record = {**meta, "decision": decision, "issue": issue["number"], "url": issue.get("url"),
                  "decided_at": event["created_at"], "decision_event_id": event["id"], "decision_label": decision_label,
                  "decided_by": actor, "adjudicator_trained": trained, "training_checked_on": decision_day.isoformat()}
        path = decisions_dir / f"{key}.json"
        if dry_run:
            print(f"  [dry-run] would write {path}: {decision}")
        else:
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written += 1
    if untrained:
        print(f"  WARNING: {len(untrained)} decision(s) by adjudicators without a valid training record (G-13): {', '.join(untrained)}; "
              "calibration will not apply them while training.require_trained_adjudicator is true")
    open_count = len(open_tickets(repo, label))
    backlog = {"open": open_count, "updated_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "label": label, "repo": repo}
    if dry_run:
        print(f"  [dry-run] backlog: {backlog}")
    else:
        backlog_file.parent.mkdir(parents=True, exist_ok=True)
        backlog_file.write_text(json.dumps(backlog, indent=2) + "\n", encoding="utf-8")
    return written, open_count


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--queue", type=Path, help="out/human_queue.json from a review; omit with --sync-decisions only")
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument("--label", default="mara-human-queue")
    ap.add_argument("--decisions-dir", type=Path, default=ROOT / "calib" / "decisions")
    ap.add_argument("--backlog-file", type=Path, default=ROOT / "calib" / "decisions" / "backlog.json")
    ap.add_argument("--sync-decisions", action="store_true")
    ap.add_argument("--register", type=Path, default=ROOT / "training" / "records.yaml",
                    help="AI-literacy register (G-13); decisions by people without a valid adjudicator record are flagged")
    ap.add_argument("--dry-run", action="store_true", help="print the gh commands instead of running the mutating ones")
    args = ap.parse_args()
    try:
        if args.queue:
            created, skipped = create_tickets(args.queue, args.repo, args.label, args.dry_run)
            print(f"tickets: {created} created, {skipped} already open")
        if args.sync_decisions:
            written, open_count = sync_decisions(args.repo, args.label, args.decisions_dir, args.backlog_file, args.dry_run, args.register)
            print(f"decisions: {written} written to {args.decisions_dir}; open backlog {open_count}")
        if not args.queue and not args.sync_decisions:
            ap.error("give --queue and/or --sync-decisions")
    except (GhError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
