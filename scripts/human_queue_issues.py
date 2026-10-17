"""G-11: turn the human queue into tickets and bring decisions back.

  python scripts/human_queue_issues.py --queue out/human_queue.json --repo owner/repo [--dry-run]
      one GitHub issue per queue item (label from --label, deduplicated by the item's stable key
      carried as an HTML marker in the body). A key is filed once: an open ticket, a closed one (decided,
      or awaiting a fixed decision label) or a decision already in --decisions-dir means no new ticket.
      Only a key whose every earlier ticket was withdrawn (closed as not planned, no decision label) is
      filed again.
  python scripts/human_queue_issues.py --repo owner/repo --sync-decisions [--dry-run]
      closed tickets carrying decision:true-positive or decision:false-positive become
      calib/decisions/<key>.json, and calib/decisions/backlog.json records the open count so the
      pipeline can tighten when the backlog is over the limit. A closed ticket whose decision cannot
      be recorded (no or two decision labels, unresolvable label history, damaged metadata) is listed
      with its reason and the run exits 2, so no decision is lost without anyone noticing; closing
      as "not planned" without a decision label withdraws a ticket on purpose and is only logged.
      Several closed tickets for one key are recorded once: when they agree, the decision of a trained
      adjudicator (else the earliest) is written; when they disagree, none is written and every one of
      them is listed, so a later ticket never silently replaces an earlier decision.

Tickets are listed through the REST API with every page followed: no count limit, so a backlog past
any page size is neither undercounted nor re-filed.

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
from mara.decisions import Decision  # noqa: E402
from mara.decisions import read as read_decision  # noqa: E402
from mara.human_queue import queue_key  # noqa: E402
from mara.report.escaping import code, literal  # noqa: E402
from mara.training import is_trained, load_register  # noqa: E402
from mara.workspace import resolve  # noqa: E402

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


def list_tickets(repo: str, label: str, state: str) -> list[dict]:
    """Every issue (pull requests excluded) carrying `label` in `state`, all pages."""
    out = gh(["api", "--method", "GET", f"repos/{repo}/issues", "-f", f"labels={label}", "-f", f"state={state}",
              "-f", "per_page=100", "--paginate", "--slurp"])
    try:
        pages = json.loads(out or "[]")
    except ValueError as e:
        raise GhError(f"issue list for {repo}: unreadable response ({e})") from None
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise GhError(f"issue list for {repo}: unexpected response shape")
    return [{"number": i["number"], "body": i.get("body") or "", "labels": i.get("labels") or [],
             "closedAt": i.get("closed_at"), "url": i.get("html_url"), "stateReason": i.get("state_reason")}
            for page in pages for i in page if "pull_request" not in i]


def open_tickets(repo: str, label: str) -> dict[str, int]:
    keys: dict[str, int] = {}
    for issue in list_tickets(repo, label, "open"):
        m = MARKER_RE.search(issue.get("body") or "")
        if m:
            keys[m.group(1)] = issue["number"]
    return keys


def closed_keys(repo: str, label: str) -> dict[str, int]:
    """Key -> number of a closed MARA ticket that was not withdrawn (closed as not planned without a
    decision label): decided, or waiting for its decision label to be fixed. Either way the key has its
    ticket, and filing another one would ask the same question twice."""
    keys: dict[str, int] = {}
    for issue in list_tickets(repo, label, "closed"):
        m = MARKER_RE.search(issue.get("body") or "")
        if not m:
            continue
        decided = {lab.get("name") for lab in issue.get("labels") or []} & DECISION_LABELS.keys()
        if not decided and issue.get("stateReason") == "not_planned":
            continue
        keys.setdefault(m.group(1), issue["number"])
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
    raw, item = item, safe(item)  # running text goes through literal(); code spans take the raw text through code()
    L = [marker, f"**MARA human queue** · target {code(target)} · finding {item['finding_id']} · key `{item['key']}`", "",
         f"- Why: {', '.join(item['reasons'])}",
         f"- {item['dimension']} · {item['cwe']} · {code(str(raw['file']) + ':' + str(raw['line']))} · tier {item['tier']} · CVSS {item['cvss4_score']} {item['cvss4_severity']} · SSVC {item['ssvc_decision']}",
         f"- Consensus {item['weighted_score']} (tp {item['votes_tp']} / fp {item['votes_fp']} / human {item['votes_human']}) · agreement proxy {item.get('agreement_proxy')}",
         f"- Found by {', '.join(item['finder_families'])} · reachability {item['reachability']}: {item['reachability_argument']}",
         f"- Attacker path: {item['exploit_sketch']}", f"- Quote: {code(raw['quote'])}"]
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


def create_tickets(queue_path: Path, repo: str, label: str, dry_run: bool, decisions_dir: Path | None = None) -> tuple[int, int]:
    q = json.loads(queue_path.read_text(encoding="utf-8"))
    items, target = q.get("items", []), q.get("target", "")
    if not items:
        print("human queue is empty; nothing to file")
        return 0, 0
    if any(not valid_identity(it) for it in items):
        raise ValueError("legacy or invalid queue identity: regenerate the review before creating tickets")
    ensure_labels(repo, label, dry_run)
    existing = open_tickets(repo, label)  # read-only, so a dry run shows what would really be filed
    closed = closed_keys(repo, label)
    created = skipped = 0
    for it in items:
        if it["key"] in existing:
            print(f"  {it['finding_id']} key {it['key']}: open ticket #{existing[it['key']]} exists, skipping")
            skipped += 1
            continue
        if it["key"] in closed:
            print(f"  {it['finding_id']} key {it['key']}: closed ticket #{closed[it['key']]} holds its decision, skipping")
            skipped += 1
            continue
        recorded = decisions_dir / f"{it['key']}.json" if decisions_dir is not None else None
        if recorded is not None and recorded.is_file():
            # any well-formed decision answers the ticket, a usable one or not (docs/adr/0002-usable-decisions.md);
            # a damaged record answers nothing, so a human decides again
            parsed = read_decision(recorded)
            if isinstance(parsed, Decision):
                print(f"  {it['finding_id']} key {it['key']}: decision already recorded in {decisions_dir}, skipping")
                skipped += 1
                continue
            print(f"  WARNING {it['finding_id']}: {recorded.name} is not a well-formed decision ({parsed}); filing the key again")
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
    if not all(item.get(k) for k in ("target_id", "revision", "context_hash", "file", "line", "cwe")):
        return False
    return item.get("key") == queue_key(item["file"], int(item["line"]), item["cwe"], target_id=item["target_id"],
                                       revision=item["revision"], context_hash=item["context_hash"])


def decision_event(repo: str, number: int, label: str) -> dict | None:
    """Replay adds/removes; bind the surviving exact label to its own actor and event time.

    None when the history does not resolve to exactly `label` with an actor and a time. A failed API
    call raises GhError instead: an outage must not read as "no decision".
    """
    try:
        pages = json.loads(gh(["api", f"repos/{repo}/issues/{number}/events", "--paginate", "--slurp"]) or "[]")
        events = [e for page in pages for e in page] if pages and isinstance(pages[0], list) else pages
    except (ValueError, TypeError):
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
    try:
        return load_register(register)
    except (OSError, ValueError):
        return None


def sync_decisions(repo: str, label: str, decisions_dir: Path, backlog_file: Path, dry_run: bool,
                   register: Path | None = None) -> tuple[int, int, list[str]]:
    """Closed tickets with a decision label become calib/decisions/<key>.json. Each record names who
    applied the label and whether that person holds a valid adjudicator training record (G-13);
    calibration applies only trained adjudicators' decisions when the config requires it.

    Returns (written, open backlog, unrecorded): one "#<number>: <reason>" per closed MARA ticket
    whose decision could not be recorded. Closed tickets without the MARA marker are not ours and
    are only counted in the log."""
    closed = list_tickets(repo, label, "closed")
    decisions_dir.mkdir(parents=True, exist_ok=True)
    reg = _load_register(register)
    written = foreign = withdrawn = 0
    untrained = []
    unrecorded: list[str] = []
    candidates: dict[str, list[dict]] = {}
    for issue in closed:
        m = MARKER_RE.search(issue.get("body") or "")
        if not m:
            foreign += 1
            continue
        labels = {lab["name"] for lab in issue.get("labels", [])}
        decisions = labels & DECISION_LABELS.keys()
        if not decisions and issue.get("stateReason") == "not_planned":
            withdrawn += 1  # closed as not planned (e.g. the code changed): deliberately no decision
            continue
        if len(decisions) != 1:
            unrecorded.append(f"#{issue['number']}: closed with {len(decisions)} decision labels, need exactly one")
            continue
        decision_label = next(iter(decisions))
        event = decision_event(repo, issue["number"], decision_label)
        if not event:
            unrecorded.append(f"#{issue['number']}: label history does not resolve to {decision_label} with an actor and a time")
            continue
        metadata = re.search(r"<!-- mara-meta:([A-Za-z0-9_=-]+) -->", issue.get("body") or "")
        if not metadata:
            unrecorded.append(f"#{issue['number']}: ticket body has no mara-meta block")
            continue
        try:
            meta = json.loads(base64.urlsafe_b64decode(metadata.group(1)))
            decision_day = dt.datetime.fromisoformat(event["created_at"].replace("Z", "+00:00")).date()
            if not valid_identity(meta) or meta["key"] != m.group(1):
                unrecorded.append(f"#{issue['number']}: mara-meta identity does not match the ticket key")
                continue
        except (ValueError, TypeError, KeyError, AttributeError):
            unrecorded.append(f"#{issue['number']}: mara-meta block or decision time is unreadable")
            continue
        key = meta["key"]
        decision = DECISION_LABELS[decision_label]
        actor = event["actor"]["login"]
        # a snapshot for the log and the record's reader; whoever uses the decision judges training again (mara.decisions)
        trained = is_trained(reg, actor, "adjudicator", decision_day)
        record = {**meta, "decision": decision, "issue": issue["number"], "url": issue.get("url"),
                  "decided_at": event["created_at"], "decision_event_id": event["id"], "decision_label": decision_label,
                  "decided_by": actor, "adjudicator_trained": trained, "training_checked_on": decision_day.isoformat()}
        parsed = Decision.parse(record)
        if not isinstance(parsed, Decision):
            unrecorded.append(f"#{issue['number']}: the decision record would not be well-formed ({parsed})")
            continue
        candidates.setdefault(key, []).append(parsed.to_record())
    # one file per key: the tickets used to be written in list order, so the last one listed replaced any
    # earlier decision for the same key, an untrained or contradicting one included
    for key, records in sorted(candidates.items()):
        records.sort(key=lambda r: r["issue"])
        if len({r["decision"] for r in records}) > 1:
            listed = ", ".join(f"#{r['issue']} {r['decision']}" for r in records)
            unrecorded += [f"#{r['issue']}: key {key} has contradicting decisions ({listed}); reopen or relabel all but one" for r in records]
            continue
        record = min(records, key=lambda r: (not r["adjudicator_trained"], r["decided_at"], r["issue"]))
        if len(records) > 1:
            others = ", ".join(f"#{r['issue']}" for r in records if r is not record)
            print(f"  key {key}: {len(records)} closed tickets agree ({record['decision']}); recording #{record['issue']}, also decided in {others}")
        if not record["adjudicator_trained"]:
            untrained.append(f"#{record['issue']} by {record['decided_by']}")
        path = decisions_dir / f"{key}.json"
        if dry_run:
            print(f"  [dry-run] would write {path}: {record['decision']}")
        else:
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written += 1
    if foreign:
        print(f"  {foreign} closed ticket(s) labelled {label} without a MARA marker; not MARA tickets, ignored")
    if withdrawn:
        print(f"  {withdrawn} ticket(s) closed as not planned without a decision label; no decision to record")
    for line in unrecorded:
        print(f"  UNRECORDED {line}")
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
    return written, open_count, unrecorded


def queue_settings(config: Path):
    """The config's human_queue block (structure only: the policies are check-config's job)."""
    import yaml

    from mara.config import HumanQueueConfig, MaraConfig

    if not config.is_file():
        return HumanQueueConfig()
    raw = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    return MaraConfig.model_validate(raw, context={"skip_policies": True}).human_queue


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--queue", type=Path, help="out/human_queue.json from a review; omit with --sync-decisions only")
    ap.add_argument("--repo", required=True, help="owner/repo")
    ap.add_argument("--config", type=Path, default=resolve("config/mara.yaml"),
                    help="human_queue.ticketing, .label and .backlog_file come from here (default: <workspace>/config/mara.yaml)")
    ap.add_argument("--label", default=None, help="default: human_queue.label")
    # MARA's own state, in the workspace the pipeline reads it from (MARA_HOME, else the working directory)
    ap.add_argument("--decisions-dir", type=Path, default=resolve("calib/decisions"))
    ap.add_argument("--backlog-file", type=Path, default=None, help="default: <workspace>/<human_queue.backlog_file>")
    ap.add_argument("--sync-decisions", action="store_true")
    ap.add_argument("--register", type=Path, default=resolve("training/records.yaml"),
                    help="AI-literacy register (G-13); decisions by people without a valid adjudicator record are flagged")
    ap.add_argument("--dry-run", action="store_true", help="print the gh commands instead of running the mutating ones")
    args = ap.parse_args()
    hq = queue_settings(args.config)
    if hq.ticketing != "github_issues" or not hq.enabled:
        print(f"human_queue.ticketing is {hq.ticketing!r} (enabled: {hq.enabled}) in {args.config}: no tickets filed or synced")
        return 0
    args.label = args.label or hq.label
    # the pipeline reads the backlog at <workspace>/<human_queue.backlog_file>; written anywhere else, G-11's
    # tightening never triggered
    args.backlog_file = args.backlog_file or resolve(hq.backlog_file)
    status = 0
    try:
        if args.queue:
            created, skipped = create_tickets(args.queue, args.repo, args.label, args.dry_run, args.decisions_dir)
            print(f"tickets: {created} created, {skipped} already filed or decided")
        if args.sync_decisions:
            written, open_count, unrecorded = sync_decisions(args.repo, args.label, args.decisions_dir, args.backlog_file,
                                                             args.dry_run, args.register)
            print(f"decisions: {written} written to {args.decisions_dir}; open backlog {open_count}")
            if unrecorded:
                print(f"ERROR: {len(unrecorded)} closed ticket(s) carry a decision that was not recorded (listed above); "
                      "fix the labels and close again, or reopen them (docs/human-queue.md)", file=sys.stderr)
                status = 2
        if not args.queue and not args.sync_decisions:
            ap.error("give --queue and/or --sync-decisions")
    except (GhError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    return status


if __name__ == "__main__":
    sys.exit(main())
