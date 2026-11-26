"""The Pilot poller (GLOSSARY.md): the shadow phase's reviews of the Pilot repository's pull requests.

  python scripts/pilot_poller.py --pilot owner/repo --tickets owner/repo --config config/local/mara.yaml --clones DIR
                                 [--dry-run]

Terms (GLOSSARY.md): Pilot poller, Pilot repository, Ticket repository, Withdrawn ticket, Sync record, Human queue,
Queue key, MARA workspace (MARA_HOME, read once in main), Review scope (incremental). It follows no ADR of its own;
docs/pilot-runbook.md is how a host runs it. Not pure: it calls gh and git, runs children, and writes and commits the
workspace.

One run, under a lock in DIR (a second run while one is going does nothing and exits 0), looks at each open pull
request of the Pilot repository whose base is its default branch, drafts left out, forks included, and at each pull
request of its state that is no longer listed and not settled, read alone to see whether it closed. For each:

1. an open pull request, or one merged since it was last listed, has its head reviewed once: fetched into a clone of
   its own, DIR/<pull request>, whose origin is the Pilot repository (so every review names the same target), and
   reviewed incrementally with the config given (`mara review <clone> --base <merge base> --config <config>`), the
   output in the workspace under pilot/reviews/<pull request>/<head>/. The merge base is the head's with the default
   branch; for a head the default branch already holds (merged with a merge commit), with the merge commit's first
   parent, the default branch before the merge;
2. the head's human queue is filed in the Ticket repository (`scripts/human_queue_issues.py --queue`) whenever the head
   is not the one last filed for that pull request, so a head pushed back to an earlier one is filed again;
3. once the head is filed, the pull request withdraws its open tickets without a decision label whose queue key one of
   its other heads queued and this head did not (withdrawals); a pull request closed without being merged withdraws
   all of them. A merged or unmerged pull request is then settled: it is not read alone again, and one listed open
   again (reopened) is no longer settled and has its head filed again.

Then the run syncs the decisions once (`scripts/human_queue_issues.py --sync-decisions`), which writes the backlog and
the decision records below the workspace, writes the Sync record, and commits what changed below pilot/, the decision
directory and the backlog file, nothing else of the workspace, pushing it to the workspace's own remote.

The workspace's files it writes (pilot/): state.json, `{"pulls": {"<n>": {"heads": {"<head>": {"keys": [<queue
key>...]}}, "filed": "<head>", "closed": "merged" | "unmerged"}}}`, each head reviewed with the keys its queue held, the
head last filed and, once settled, how the pull request closed; sync.json, the Sync record `{"at": <ISO 8601, UTC>,
"repo": "<owner/repo>", "exit": <int>}`.

These print an ERROR line on stderr, which cron mails, and make the run exit 1: a review that wrote no report.json (its
head is left unreviewed, so the next run tries it again); one that wrote it and exited other than 0 (a PSIRT hand-off
that failed exits 3 after the report), or wrote a human_queue.json that cannot be read (the head is kept either way, a
review not paid for twice, and an unreadable queue fails its filing); a filing that fails (tried again by the next run,
without a second review); a pull request that fails (a git or gh call, a response or a listed entry not of the shape
read), which fails alone, the others and the sync going on; a sync that exits 2 (a decision not recorded), recorded
and committed like any other. A review that wrote no human_queue.json (the human queue is off) leaves nothing to file,
and is no error.

--dry-run goes through the same steps and prints, for each, what a run would review, file and withdraw, and reviews,
files, withdraws, syncs, writes and commits nothing; a head not reviewed yet would withdraw its pull request's other
heads' keys unless it queues them too, which only its review tells, so those are printed with that proviso. Exit 2:
the clones and the workspace hold one another (a review refuses a workspace inside its target).

Not seen: a pull request opened and closed between two runs never enters the state, so it is never reviewed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from human_queue_issues import DECISION_LABELS, MARKER_RE, queue_settings  # noqa: E402

from mara.workspace import PILOT_REVIEWS, SYNC_RECORD, Workspace, resolve  # noqa: E402

TICKET_SCRIPT = ROOT / "scripts" / "human_queue_issues.py"
LOCK = ".pilot-poller.lock"  # in the clones directory: never committed
COMMIT_ID = re.compile(r"[0-9a-f]{40}")


class PollError(RuntimeError):
    """A call of gh or git that failed, or a response not of the shape read."""


def run(argv: list[str], env: dict[str, str]) -> int:
    """Run one child (a review, or the ticket script) with `env`; its exit code."""
    return subprocess.run(argv, env=env, check=False).returncode


def gh_text(gh: str, *args: str) -> str:
    """What gh prints for `args`; PollError when it fails."""
    cp = subprocess.run([gh, *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if cp.returncode != 0:
        raise PollError(f"gh {' '.join(args[:4])} failed: {cp.stderr.strip()[-500:]}")
    return cp.stdout


def gh_json(gh: str, *args: str) -> object:
    """What gh prints for `args`, parsed as JSON; PollError when gh fails or prints something else."""
    out = gh_text(gh, *args)
    try:
        return json.loads(out)
    except ValueError as e:
        raise PollError(f"gh {' '.join(args[:4])}: unreadable response ({e})") from None


def gh_list(gh: str, what: str, path: str, *fields: str) -> list:
    """Every item of the API list at `path` with the query `fields`, all pages; PollError naming `what` when the
    response is not a list of pages."""
    query = [arg for f in (*fields, "per_page=100") for arg in ("-f", f)]
    pages = gh_json(gh, "api", "--method", "GET", path, *query, "--paginate", "--slurp")
    if not isinstance(pages, list) or not all(isinstance(page, list) for page in pages):
        raise PollError(f"{what}: unexpected response shape")
    return [item for page in pages for item in page]


def git(cwd: Path, *args: str) -> str:
    cp = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, encoding="utf-8",
                        errors="replace", check=False)
    if cp.returncode != 0:
        raise PollError(f"git {' '.join(args[:2])} in {cwd} failed: {cp.stderr.strip()[-500:]}")
    return cp.stdout.strip()


def pull_shape_problem(p: object, *, alone: bool = False) -> str | None:
    """What is wrong with one pull request of the API, for the parts a run reads: its number (an integer, a clone's and
    a directory's name), `draft`, its base's branch, its head's commit id (40 hex digits: it is a directory's name and
    an argument of git, so it must not be read as an option) and, for one read alone (`alone`), `state`, `merged` and,
    once merged, the merge commit's id; None when nothing is."""
    if not isinstance(p, dict):
        return "an entry that is not an object"
    number, base, head = p.get("number"), p.get("base"), p.get("head")
    if not isinstance(number, int) or isinstance(number, bool):
        return f"number {number!r} is not an integer"
    if not isinstance(p.get("draft"), bool):
        return f"#{number}: draft is not true or false"
    if not isinstance(base, dict) or not isinstance(base.get("ref"), str):
        return f"#{number}: no base branch"
    sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(sha, str) or not COMMIT_ID.fullmatch(sha):
        return f"#{number}: head {sha!r} is not a commit id"
    if alone and (p.get("state") not in ("open", "closed") or not isinstance(p.get("merged"), bool)):
        return f"#{number}: no state open or closed, or merged not true or false"
    merge = p.get("merge_commit_sha")
    if alone and p.get("merged") and not (isinstance(merge, str) and COMMIT_ID.fullmatch(merge)):
        return f"#{number}: merged, but its merge commit {merge!r} is not a commit id"
    return None


def ticket_shape_problem(issue: object) -> str | None:
    """What is wrong with one issue of the API's list, for the parts a run reads: its number (an argument of gh issue
    close), its body (text or null) and its labels (objects with a name); None when nothing is."""
    if not isinstance(issue, dict):
        return "an entry that is not an object"
    number, labels = issue.get("number"), issue.get("labels")
    if not isinstance(number, int) or isinstance(number, bool):
        return f"number {number!r} is not an integer"
    if not isinstance(issue.get("body"), (str, type(None))):
        return f"#{number}: body is not text"
    if not isinstance(labels, list) or not all(isinstance(lab, dict) and isinstance(lab.get("name"), str) for lab in labels):
        return f"#{number}: labels are not named"
    return None


def default_branch(gh: str, pilot: str) -> str:
    repo = gh_json(gh, "api", f"repos/{pilot}")
    default = repo.get("default_branch") if isinstance(repo, dict) else None
    if not isinstance(default, str):
        raise PollError(f"repository {pilot}: no default branch in the response")
    return default


def listing(gh: str, pilot: str, state: dict) -> tuple[str, list[dict], list[int], list[str]]:
    """The default branch; the open pull requests to it that are not drafts; the pull requests of `state` no longer
    listed and not settled, by number, to read alone; and what is wrong with each listed entry not of the shape read,
    which is left out. A listed pull request that was settled is listed with the others (reopened)."""
    default = default_branch(gh, pilot)
    entries = gh_list(gh, f"pull requests of {pilot}", f"repos/{pilot}/pulls", "state=open")
    pulls, problems = [], []
    for p in entries:
        problem = pull_shape_problem(p)
        if problem:
            problems.append(f"pull requests of {pilot}: {problem}")
        else:
            pulls.append(p)
    listed = {p["number"] for p in pulls}
    unlisted = [int(n) for n in sorted(state["pulls"], key=int) if int(n) not in listed and not state["pulls"][n].get("closed")]
    return default, [p for p in pulls if not p["draft"] and p["base"]["ref"] == default], unlisted, problems


def read_alone(gh: str, pilot: str, number: int) -> dict:
    """Pull request `number` read alone; PollError when it is not of the shape read."""
    p = gh_json(gh, "api", f"repos/{pilot}/pulls/{number}")
    problem = pull_shape_problem(p, alone=True)
    if problem:
        raise PollError(f"pull request {number} of {pilot}: {problem}")
    assert isinstance(p, dict)
    return p


def open_undecided_tickets(gh: str, repo: str, label: str) -> dict[str, int]:
    """Queue key -> number of each open ticket in `repo` carrying `label` and no decision label; an issue that is a
    pull request, or that carries no ticket marker, is left out."""
    issues = gh_list(gh, f"tickets of {repo}", f"repos/{repo}/issues", f"labels={label}", "state=open")
    keys: dict[str, int] = {}
    for issue in issues:
        problem = ticket_shape_problem(issue)
        if problem:
            raise PollError(f"tickets of {repo}: {problem}")
        if "pull_request" in issue:
            continue
        m = MARKER_RE.search(issue["body"] or "")
        if m and not {lab["name"] for lab in issue["labels"]} & DECISION_LABELS.keys():
            keys[m.group(1)] = issue["number"]
    return keys


def queue_keys(queue: Path) -> list[str]:
    """The queue keys of a review's human_queue.json; none when the review wrote none (the human queue is off);
    PollError when it cannot be read as a human queue."""
    if not queue.is_file():
        return []
    try:
        items = json.loads(queue.read_text(encoding="utf-8")).get("items", [])
        return [item["key"] for item in items]
    except (ValueError, AttributeError, TypeError, KeyError) as e:
        raise PollError(f"{queue}: not a human queue ({e!r})") from None


def withdrawals(pull: dict, head: str | None) -> set[str]:
    """The queue keys whose open, undecided tickets the pull request `pull` (its state) withdraws once `head` is filed:
    those its other heads queued that `head` did not. With no head (closed without being merged), or a head not in the
    state yet (not reviewed), nothing is kept: all its heads' keys."""
    keep = set(pull["heads"][head]["keys"]) if head in pull["heads"] else set()
    return {k for h, rec in pull["heads"].items() if h != head for k in rec["keys"]} - keep


class Poller:
    """One run's work on the pull requests, done (a run) or printed (a dry run): its options, the workspace root, the
    clones, the children's environment, the default branch, and the Ticket repository's open undecided tickets, read
    once when first needed."""

    def __init__(self, a: argparse.Namespace, root: Path, clones: Path, default: str):
        self.a, self.root, self.clones, self.default, self.dry_run = a, root, clones, default, a.dry_run
        self.url = a.pilot_url or f"https://github.com/{a.pilot}.git"
        self.env = {**os.environ, "MARA_HOME": str(root)}
        self.label = queue_settings(a.config).label
        self._undecided: dict[str, int] | None = None

    def undecided(self) -> dict[str, int]:
        if self._undecided is None:
            self._undecided = open_undecided_tickets(self.a.gh, self.a.tickets, self.label)
        return self._undecided

    def withdraw(self, number: int, keys: set[str], proviso: str = "") -> None:
        undecided = self.undecided() if keys else {}
        for key in sorted(keys & undecided.keys(), key=undecided.__getitem__):
            if self.dry_run:
                print(f"would withdraw ticket #{undecided[key]} (key {key}) of pull request #{number}{proviso}")
                continue
            gh_text(self.a.gh, "issue", "close", str(undecided.pop(key)), "--repo", self.a.tickets, "--reason", "not planned")

    def review(self, number: int, head: str, merge_commit: str | None) -> tuple[Path, int] | None:
        """Review `head` of pull request `number`: its output directory and exit code, or None when it wrote no
        report.json."""
        out = self.root / PILOT_REVIEWS / str(number) / head
        shutil.rmtree(out, ignore_errors=True)  # a report found there is this review's
        clone = self.clones / str(number)
        if not (clone / ".git").is_dir():
            git(self.clones, "clone", "-q", "--no-checkout", self.url, str(clone))
        git(clone, "fetch", "-q", "origin", f"+refs/pull/{number}/head:refs/pilot/head",
            f"+refs/heads/{self.default}:refs/pilot/base")
        git(clone, "checkout", "-q", "--detach", head)
        base = git(clone, "merge-base", head, "refs/pilot/base")
        if base == head and merge_commit:  # merged with a merge commit: the default branch already holds the head
            base = git(clone, "merge-base", head, f"{merge_commit}^1")
        code = run([sys.executable, "-m", "mara.cli", "review", str(clone), "--base", base, "--config", str(self.a.config),
                    "--out", str(out)], self.env)
        return (out, code) if (out / "report.json").is_file() else None

    def look_at(self, pull: dict, number: int, head: str, kind: str, merge_commit: str | None = None) -> bool:
        """Review, file and withdraw for one pull request (its state `pull`, updated unless a dry run) of `kind` open,
        merged or unmerged; False when a step failed."""
        if kind == "unmerged":
            self.withdraw(number, withdrawals(pull, None))
            if not self.dry_run:
                pull["closed"] = kind
            return True
        if pull.get("closed"):  # settled, and listed open again: reopened
            pull.pop("closed")
            pull.pop("filed", None)
        ok, known = True, head in pull["heads"]
        if not known and self.dry_run:
            print(f"would review pull request #{number} at {head}")
        elif not known:
            reviewed = self.review(number, head, merge_commit)
            if reviewed is None:
                print(f"ERROR: the review of pull request #{number} at {head} wrote no report; the next run tries it again",
                      file=sys.stderr)
                return False
            out, code = reviewed
            if code != 0:
                print(f"ERROR: the review of pull request #{number} at {head} completed with exit {code}", file=sys.stderr)
                ok = False
            try:
                keys = queue_keys(out / "human_queue.json")
            except PollError as e:
                print(f"ERROR: {e}; the review is kept", file=sys.stderr)
                keys, ok = [], False
            pull["heads"][head] = {"keys": keys}
        if pull.get("filed") != head and self.dry_run:
            print(f"would file the queue of pull request #{number} at {head}")
        elif pull.get("filed") != head:
            queue = self.root / PILOT_REVIEWS / str(number) / head / "human_queue.json"
            if queue.is_file() and run([sys.executable, str(TICKET_SCRIPT), "--queue", str(queue), "--repo", self.a.tickets,
                                        "--config", str(self.a.config)], self.env) != 0:
                print(f"ERROR: filing the queue of pull request #{number} at {head} failed; the next run files it",
                      file=sys.stderr)
                return False
            pull["filed"] = head
        self.withdraw(number, withdrawals(pull, head), "" if known else ", unless the new head queues its key too")
        if kind == "merged" and not self.dry_run:
            pull["closed"] = kind
        return ok


def load_state(root: Path) -> dict:
    state_file = root / "pilot" / "state.json"
    return json.loads(state_file.read_text(encoding="utf-8")) if state_file.is_file() else {"pulls": {}}


def commit(root: Path, paths: list[Path]) -> None:
    """Commit what changed below `paths` of the workspace (and nothing else in it, staged or not) and push it to the
    workspace's own remote; nothing when nothing changed."""
    present = sorted({str(p) for p in paths if (root / p).exists()})
    if not present:
        return
    git(root, "add", "-A", "--", *present)
    if subprocess.run(["git", "-C", str(root), "diff", "--cached", "--quiet", "--", *present], check=False).returncode == 0:
        return
    git(root, "commit", "-q", "-m", f"Pilot poller: run of {dt.datetime.now(dt.UTC).isoformat(timespec='seconds')}",
        "--", *present)
    git(root, "push", "-q", "origin", "HEAD")


def look_at_each(a: argparse.Namespace, root: Path, clones: Path, state: dict) -> tuple[Poller, int]:
    """Every pull request of one run, each failing alone: the Poller (for its environment) and 0, or 1 when one failed."""
    status = 0
    try:
        default, pulls, unlisted, problems = listing(a.gh, a.pilot, state)
    except PollError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        default, pulls, unlisted, problems, status = "", [], [], [], 1
    for problem in problems:
        print(f"ERROR: {problem}", file=sys.stderr)
        status = 1
    poller = Poller(a, root, clones, default)
    for number, p in [(p["number"], p) for p in pulls] + [(n, None) for n in unlisted]:
        pull = state["pulls"].setdefault(str(number), {"heads": {}})
        try:
            if p is None:  # no longer listed: closed, or open but now a draft or based elsewhere
                p = read_alone(a.gh, a.pilot, number)
                if p["state"] != "closed":
                    continue
                kind = "merged" if p["merged"] else "unmerged"
            else:
                kind = "open"
            ok = poller.look_at(pull, number, p["head"]["sha"], kind, p.get("merge_commit_sha"))
        except PollError as e:
            print(f"ERROR: pull request #{number}: {e}", file=sys.stderr)
            ok = False
        status = status or int(not ok)
    return poller, status


def poll(a: argparse.Namespace, root: Path, clones: Path) -> int:
    """One run, holding the lock: 0 when every pull request and the sync succeeded, 1 otherwise. The state is written
    whatever happens, so a review that completed is never paid for twice."""
    state = load_state(root)
    try:
        poller, status = look_at_each(a, root, clones, state)
        synced = run([sys.executable, str(TICKET_SCRIPT), "--repo", a.tickets, "--config", str(a.config),
                      "--sync-decisions"], poller.env)
        record = {"at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "repo": a.tickets, "exit": synced}
        (root / "pilot").mkdir(parents=True, exist_ok=True)
        (root / SYNC_RECORD).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        if synced != 0:
            print(f"ERROR: the decision sync exited {synced}", file=sys.stderr)
            status = 1
    finally:
        (root / "pilot").mkdir(parents=True, exist_ok=True)
        (root / "pilot" / "state.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return status


def main(argv: list[str] | None = None) -> int:
    ws = Workspace.from_env()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pilot", required=True, help="the Pilot repository, owner/repo")
    ap.add_argument("--tickets", required=True, help="the Ticket repository, owner/repo")
    ap.add_argument("--config", type=Path, required=True, help="the config each review and the ticket script read")
    ap.add_argument("--clones", type=Path, required=True, help="the directory of the clones, outside the workspace")
    ap.add_argument("--dry-run", action="store_true", help="print what a run would review, file and withdraw; do none of it")
    ap.add_argument("--gh", default="gh", help=argparse.SUPPRESS)  # a stand-in gh (tests)
    ap.add_argument("--pilot-url", default=None, help=argparse.SUPPRESS)  # the Pilot repository's git URL (tests)
    a = ap.parse_args(argv)
    clones, root = a.clones.resolve(), ws.root.resolve()
    if clones.is_relative_to(root) or root.is_relative_to(clones):
        # a review refuses a workspace inside its target, and the workspace's commits must not take in a clone
        print(f"ERROR: the clones ({clones}) and the MARA workspace ({root}) must not hold one another", file=sys.stderr)
        return 2
    if a.dry_run:  # reads GitHub and the state; reviews, files, withdraws, syncs, writes and commits nothing
        return look_at_each(a, root, clones, load_state(root))[1]
    clones.mkdir(parents=True, exist_ok=True)
    with (clones / LOCK).open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"another run holds {clones / LOCK}; this one does nothing")
            return 0
        status = poll(a, root, clones)
        # the decision directory and the backlog where the ticket script writes them (its own defaults)
        written = [resolve("calib/decisions", root), resolve(queue_settings(a.config).backlog_file, root)]
        try:
            commit(root, [Path("pilot"), *(p.relative_to(root) for p in written if p.is_relative_to(root))])
        except PollError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            status = 1
        return status


if __name__ == "__main__":
    sys.exit(main())
