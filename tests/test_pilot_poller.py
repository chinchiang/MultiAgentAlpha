"""scripts/pilot_poller.py, the Pilot poller (GLOSSARY.md), driven through main: GitHub is a stand-in gh the test
writes (--gh), the Pilot repository a bare repository below tmp_path with its pull requests' heads under
refs/pull/<n>/head (--pilot-url), the MARA workspace a git repository below tmp_path (MARA_HOME), and the children it
runs (`mara review`, `scripts/human_queue_issues.py`) a fake `pilot_poller.run` that records them and writes what a
review writes (tests/SEAMS.md, "The Pilot poller")."""

from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_poller  # noqa: E402

PILOT, TICKETS = "org/pilot", "org/security"

FAKE_GH = '''
"""A stand-in gh: answers the calls pilot_poller makes from the files beside it; any other call fails loudly."""
import json, sys
from pathlib import Path
here = Path(__file__).parent
args = sys.argv[1:]
with (here / "calls.jsonl").open("a") as f:
    f.write(json.dumps(args) + "\\n")
pilot = (here / "pilot").read_text()
single = json.loads((here / "single.json").read_text())
if args == ["api", f"repos/{pilot}"]:
    print((here / "repo.json").read_text())
elif len(args) == 2 and args[0] == "api" and args[1].startswith(f"repos/{pilot}/pulls/") and args[1].rsplit("/", 1)[1] in single:
    print(json.dumps(single[args[1].rsplit("/", 1)[1]]))
elif args[:4] == ["api", "--method", "GET", f"repos/{pilot}/pulls"]:
    print(json.dumps([json.loads((here / "pulls.json").read_text())]))
elif args[:4] == ["api", "--method", "GET", "repos/org/security/issues"] and "state=open" in args:
    print(json.dumps([json.loads((here / "tickets.json").read_text())]))
elif args[:2] == ["issue", "close"]:
    pass
else:
    sys.exit(f"stand-in gh: no answer for {args}")
'''


def _git(cwd: Path, *args: str) -> str:
    cp = subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                        check=True)
    return cp.stdout.strip()


class Pilot:
    """The Pilot repository: a bare repository with a default branch `main`, and a working copy that makes its pull
    requests' heads, each pushed to refs/pull/<n>/head as GitHub keeps them."""

    def __init__(self, tmp_path: Path):
        self.url = tmp_path / "pilot.git"
        self.work = tmp_path / "pilot-work"
        _git(tmp_path, "init", "-q", "--bare", str(self.url))
        _git(tmp_path, "init", "-q", "-b", "main", str(self.work))
        _git(self.work, "config", "user.email", "t@example.invalid")
        _git(self.work, "config", "user.name", "t")
        self.commit("app.py", "print('main')\n")
        _git(self.work, "push", "-q", str(self.url), "main")
        self.main = _git(self.work, "rev-parse", "HEAD")

    def commit(self, name: str, text: str) -> str:
        (self.work / name).write_text(text, encoding="utf-8")
        _git(self.work, "add", name)
        _git(self.work, "commit", "-q", "-m", name)
        return _git(self.work, "rev-parse", "HEAD")

    def merge(self, head: str) -> str:
        """Merge `head` into main with a merge commit, as GitHub's "Create a merge commit" does; the merge commit."""
        _git(self.work, "checkout", "-q", "main")
        _git(self.work, "merge", "-q", "--no-ff", "-m", "merge", head)
        _git(self.work, "push", "-q", str(self.url), "main")
        return _git(self.work, "rev-parse", "HEAD")

    def pull(self, n: int, text: str) -> str:
        """A new head of pull request `n`: a commit on main's tip, pushed to refs/pull/<n>/head."""
        _git(self.work, "checkout", "-q", "--detach", self.main)
        head = self.commit(f"pr{n}.py", text)
        _git(self.work, "push", "-q", "--force", str(self.url), f"{head}:refs/pull/{n}/head")
        return head


def _gh(tmp_path: Path, pulls: list[dict], tickets: list[dict] = (), single: dict[int, dict] | None = None,
        repo: dict | None = None) -> Path:
    """The stand-in gh, answering `pulls` for the Pilot repository's open pull requests, `single` for a pull request
    read alone (by number), `repo` for the repository (default branch `main`) and `tickets` for the Ticket repository's
    open tickets; it records every call in calls.jsonl beside it."""
    d = tmp_path / "gh"
    d.mkdir(exist_ok=True)
    (d / "pilot").write_text(PILOT)
    (d / "pulls.json").write_text(json.dumps(pulls))
    (d / "tickets.json").write_text(json.dumps(list(tickets)))
    (d / "single.json").write_text(json.dumps({str(n): p for n, p in (single or {}).items()}))
    (d / "repo.json").write_text(json.dumps({"default_branch": "main"} if repo is None else repo))
    gh = d / "gh"
    gh.write_text(f"#!{sys.executable}" + FAKE_GH)
    gh.chmod(0o755)
    return gh


def _pull(n: int, head: str, *, draft: bool = False, base: str = "main") -> dict:
    return {"number": n, "draft": draft, "base": {"ref": base}, "head": {"sha": head}}


def _closed(n: int, head: str, *, merged: bool, merge_commit: str = "e" * 40) -> dict:
    """Pull request `n` read alone once closed, merged (by `merge_commit`) or not."""
    return {**_pull(n, head), "state": "closed", "merged": merged, "merge_commit_sha": merge_commit if merged else None}


def _key(n: int) -> str:
    return f"v2-{n:024x}"


def _ticket(number: int, key: str, *labels: str) -> dict:
    """An open ticket as the issues API lists it: its key in the marker scripts/human_queue_issues.py writes."""
    return {"number": number, "body": f"<!-- mara-hq:{key} -->\nfinding", "labels": [{"name": n} for n in labels]}


def _pushed(remote: Path, path: str | None = None) -> set[str] | str | None:
    """The files of the Ticket repository's main as pushed (an empty set before anything is), or with `path` that
    file's text (None when it was not pushed)."""
    spec = ["show", f"main:{path}"] if path else ["ls-tree", "-r", "--name-only", "main"]
    cp = subprocess.run(["git", "-C", str(remote), *spec], capture_output=True, text=True, encoding="utf-8",
                        errors="replace", check=False)
    if path:
        return cp.stdout if cp.returncode == 0 else None
    return set(cp.stdout.splitlines()) if cp.returncode == 0 else set()


def _withdrawn(tmp_path: Path) -> list[str]:
    """The tickets the stand-in gh was asked to close, in order."""
    return [c[2] for c in _gh_calls(tmp_path) if c[:2] == ["issue", "close"]]


def _gh_calls(tmp_path: Path) -> list[list[str]]:
    log = tmp_path / "gh" / "calls.jsonl"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


class Children:
    """The fake `pilot_poller.run`: records each child's argv and, for a review, the head checked out in its target at
    the time; unless `review_writes` is off, writes the outputs a review writes into its --out directory, the queue
    holding the keys `keys` gives the head (none when `queue` is off, one not a human queue when it is "unreadable"),
    and exits `review_exit`. The ticket script exits
    `sync_exit` for the sync, `tickets_exit` for a filing."""

    def __init__(self):
        self.calls: list[list[str]] = []
        self.reviewed: list[tuple[str, str]] = []
        self.keys: dict[str, list[str]] = {}
        self.tickets_exit = self.sync_exit = self.review_exit = 0
        self.review_writes = self.queue = True

    def __call__(self, argv: list[str], env: dict[str, str]) -> int:
        self.calls.append(list(argv))
        if argv[1:4] == ["-m", "mara.cli", "review"]:
            target = Path(argv[4])
            head = _git(target, "rev-parse", "HEAD")
            self.reviewed.append((target.name, head))
            if not self.review_writes:
                return self.review_exit or 1
            out = Path(argv[argv.index("--out") + 1])
            out.mkdir(parents=True, exist_ok=True)
            (out / "report.json").write_text("{}", encoding="utf-8")
            if self.queue == "unreadable":
                (out / "human_queue.json").write_text("[]", encoding="utf-8")
            elif self.queue:
                items = [{"key": k, "finding_id": f"F-{i}"} for i, k in enumerate(self.keys.get(head, []))]
                (out / "human_queue.json").write_text(json.dumps({"items": items, "target": str(target)}), encoding="utf-8")
            return self.review_exit
        if Path(argv[1]).name == "human_queue_issues.py":
            return self.sync_exit if "--sync-decisions" in argv else self.tickets_exit
        return 0

    def ticket_runs(self) -> list[list[str]]:
        return [c for c in self.calls if Path(c[1]).name == "human_queue_issues.py"]


@pytest.fixture
def poller(tmp_path, monkeypatch):
    """A run of the Pilot poller: `poller(pulls)` runs main once with the stand-in gh answering `pulls`."""
    pilot = Pilot(tmp_path)
    ws, remote = tmp_path / "ws", tmp_path / "ws.git"  # the workspace, a clone of the Ticket repository
    _git(tmp_path, "init", "-q", "--bare", "-b", "main", str(remote))
    _git(tmp_path, "clone", "-q", str(remote), str(ws))
    _git(ws, "config", "user.email", "poller@example.invalid")
    _git(ws, "config", "user.name", "poller")
    monkeypatch.setenv("MARA_HOME", str(ws))
    children = Children()
    monkeypatch.setattr(pilot_poller, "run", children)

    def run(pulls: list[dict], *, clones: Path | None = None, tickets: list[dict] = (), dry_run: bool = False,
            single: dict[int, dict] | None = None, repo: dict | None = None) -> int:
        gh = _gh(tmp_path, pulls, tickets, single, repo)
        return pilot_poller.main(["--pilot", PILOT, "--tickets", TICKETS, "--config", str(tmp_path / "mara.yaml"),
                                  "--clones", str(clones or tmp_path / "clones"), "--gh", str(gh),
                                  "--pilot-url", str(pilot.url), *(["--dry-run"] if dry_run else [])])

    run.pilot, run.children, run.ws, run.tmp, run.remote = pilot, children, ws, tmp_path, remote  # type: ignore[attr-defined]
    return run


def test_each_open_non_draft_pull_request_to_the_default_branch_is_reviewed_once_per_head(poller):
    pilot, children = poller.pilot, poller.children
    one, two, three = pilot.pull(1, "a = 1\n"), pilot.pull(2, "b = 2\n"), pilot.pull(3, "c = 3\n")
    pulls = [_pull(1, one), _pull(2, two, draft=True), _pull(3, three, base="release")]

    assert poller(pulls) == 0
    assert children.reviewed == [("1", one)]  # the draft and the pull request to another base are left out

    assert poller(pulls) == 0
    assert children.reviewed == [("1", one)]  # a head is reviewed once

    newer = pilot.pull(1, "a = 2\n")
    assert poller([_pull(1, newer), *pulls[1:]]) == 0
    assert children.reviewed == [("1", one), ("1", newer)]  # a new head is a new review


def test_a_review_is_incremental_against_the_merge_base_with_the_config_given_and_its_output_in_the_workspace(poller):
    pilot = poller.pilot
    pilot.commit("later.py", "on main after the pull request was cut\n")  # main moves on: its tip is not the merge base
    _git(pilot.work, "push", "-q", str(pilot.url), "HEAD:main")
    head = pilot.pull(4, "d = 4\n")  # cut from the old tip, pilot.main

    assert poller([_pull(4, head)]) == 0
    (review,) = [c for c in poller.children.calls if c[3:4] == ["review"]]
    target, options = Path(review[4]), dict(zip(review[5::2], review[6::2], strict=True))
    assert options.get("--base") == pilot.main
    assert options.get("--config") == str(poller.tmp / "mara.yaml")
    assert Path(options.get("--out", "")) == poller.ws / "pilot" / "reviews" / "4" / head
    assert target.parent == poller.tmp / "clones" and not target.is_relative_to(poller.ws)


@pytest.mark.parametrize("inside", ["clones in the workspace", "workspace in the clones"])
def test_clones_and_workspace_that_hold_one_another_are_refused_with_exit_2_before_any_review(poller, inside):
    head = poller.pilot.pull(1, "a = 1\n")
    clones = poller.ws / "clones" if inside == "clones in the workspace" else poller.tmp
    assert poller([_pull(1, head)], clones=clones) == 2
    assert poller.children.calls == []


def test_each_review_files_its_human_queue_in_the_ticket_repository_with_the_config_given(poller):
    head = poller.pilot.pull(1, "a = 1\n")
    assert poller([_pull(1, head)]) == 0
    filings = [c for c in poller.children.ticket_runs() if "--queue" in c]
    assert len(filings) == 1
    options = dict(zip(filings[0][2::2], filings[0][3::2], strict=True))
    assert options.get("--queue") == str(poller.ws / "pilot" / "reviews" / "1" / head / "human_queue.json")
    assert options.get("--repo") == TICKETS
    assert options.get("--config") == str(poller.tmp / "mara.yaml")


def test_a_new_head_withdraws_the_open_undecided_tickets_of_the_same_pull_requests_earlier_heads(poller):
    pilot, children = poller.pilot, poller.children
    old, other = pilot.pull(1, "a = 1\n"), pilot.pull(2, "b = 1\n")
    children.keys = {old: [_key(1), _key(2)], other: [_key(9)]}
    assert poller([_pull(1, old), _pull(2, other)]) == 0
    assert _withdrawn(poller.tmp) == []  # nothing earlier yet

    new = pilot.pull(1, "a = 2\n")
    children.keys[new] = [_key(3)]
    open_tickets = [_ticket(11, _key(1)), _ticket(12, _key(2), "decision:true-positive"), _ticket(13, _key(9)),
                    _ticket(14, _key(3))]
    assert poller([_pull(1, new), _pull(2, other)], tickets=open_tickets) == 0
    filed = [Path(c[c.index("--queue") + 1]).parent.name for c in children.ticket_runs() if "--queue" in c]
    assert filed == [old, other, new]  # the new head is filed before its pull request withdraws
    # #11: earlier head, undecided -> withdrawn; #12 decided, #13 another pull request, #14 the current head: left alone
    assert [c for c in _gh_calls(poller.tmp) if c[:2] == ["issue", "close"]] == [
        ["issue", "close", "11", "--repo", TICKETS, "--reason", "not planned"]]


def test_a_run_syncs_the_decisions_once_and_records_the_sync_in_the_workspace(poller):
    one, two = poller.pilot.pull(1, "a = 1\n"), poller.pilot.pull(2, "b = 1\n")
    assert poller([_pull(1, one), _pull(2, two)]) == 0
    syncs = [c for c in poller.children.ticket_runs() if "--sync-decisions" in c]
    assert len(syncs) == 1
    options = dict(zip(syncs[0][2:-1:2], syncs[0][3:-1:2], strict=True))  # the options before --sync-decisions
    assert "--queue" not in syncs[0] and options.get("--repo") == TICKETS
    assert options.get("--config") == str(poller.tmp / "mara.yaml")
    record = json.loads((poller.ws / "pilot" / "sync.json").read_text(encoding="utf-8"))
    assert record["repo"] == TICKETS and record["exit"] == 0
    assert dt.datetime.fromisoformat(record["at"]).tzinfo is not None


def test_a_sync_that_exits_2_is_recorded_and_the_run_exits_non_zero(poller):
    poller.children.sync_exit = 2  # a closed ticket whose decision could not be recorded (UNRECORDED)
    assert poller([]) != 0
    assert json.loads((poller.ws / "pilot" / "sync.json").read_text(encoding="utf-8"))["exit"] == 2


def test_a_review_that_writes_no_report_leaves_its_head_unreviewed_for_the_next_run_and_the_run_exits_non_zero(poller):
    head, children = poller.pilot.pull(1, "a = 1\n"), poller.children
    children.review_writes = False
    assert poller([_pull(1, head)]) != 0
    assert children.ticket_runs()[-1][-1] == "--sync-decisions" and len(children.ticket_runs()) == 1  # nothing filed
    children.review_writes = True
    assert poller([_pull(1, head)]) == 0
    assert poller([_pull(1, head)]) == 0
    assert children.reviewed == [("1", head), ("1", head)]  # tried again once, then done


def test_a_filing_that_fails_is_tried_again_by_the_next_run_without_reviewing_the_head_again(poller):
    head, children = poller.pilot.pull(1, "a = 1\n"), poller.children
    children.tickets_exit = 1
    assert poller([_pull(1, head)]) != 0
    children.tickets_exit = 0
    assert poller([_pull(1, head)]) == 0
    assert poller([_pull(1, head)]) == 0
    assert children.reviewed == [("1", head)]
    assert len([c for c in children.ticket_runs() if "--queue" in c]) == 2  # failed, then filed; not a third time


def test_a_run_that_finds_another_run_going_exits_without_acting(poller):
    import fcntl

    head = poller.pilot.pull(1, "a = 1\n")
    clones = poller.tmp / "clones"
    clones.mkdir()
    with (clones / ".pilot-poller.lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert poller([_pull(1, head)]) == 0
    assert poller.children.calls == [] and _gh_calls(poller.tmp) == []


def test_a_run_commits_and_pushes_what_it_wrote_in_the_workspace_and_nothing_else(poller):
    head = poller.pilot.pull(1, "a = 1\n")
    (poller.ws / "calib" / "decisions").mkdir(parents=True)
    (poller.ws / "calib" / "decisions" / "backlog.json").write_text('{"open": 0}', encoding="utf-8")  # as the sync writes it
    (poller.ws / "notes.txt").write_text("someone's file\n", encoding="utf-8")
    assert poller([_pull(1, head)]) == 0
    pushed = _pushed(poller.remote)
    assert {"pilot/state.json", "pilot/sync.json", f"pilot/reviews/1/{head}/report.json",
            f"pilot/reviews/1/{head}/human_queue.json", "calib/decisions/backlog.json"} <= pushed
    assert "notes.txt" not in pushed


def test_a_run_whose_sync_exits_2_still_commits_and_pushes_its_records(poller):
    poller.children.sync_exit = 2
    assert poller([]) != 0
    record = _pushed(poller.remote, "pilot/sync.json")
    assert record is not None and json.loads(record)["exit"] == 2


def test_a_dry_run_lists_what_it_would_review_and_withdraw_and_does_none_of_it(poller, capsys):
    pilot, children = poller.pilot, poller.children
    old = pilot.pull(1, "a = 1\n")
    children.keys = {old: [_key(1)]}
    assert poller([_pull(1, old)]) == 0
    calls, pushed = len(children.calls), _git(poller.remote, "rev-parse", "main")  # the first run pushed main
    state = (poller.ws / "pilot" / "state.json").read_text(encoding="utf-8")
    sync = (poller.ws / "pilot" / "sync.json").read_text(encoding="utf-8")
    capsys.readouterr()

    new = pilot.pull(1, "a = 2\n")
    assert poller([_pull(1, new)], tickets=[_ticket(11, _key(1))], dry_run=True) == 0
    assert len(children.calls) == calls and _withdrawn(poller.tmp) == []
    assert (poller.ws / "pilot" / "state.json").read_text(encoding="utf-8") == state
    assert (poller.ws / "pilot" / "sync.json").read_text(encoding="utf-8") == sync
    assert _git(poller.remote, "rev-parse", "main") == pushed
    out = capsys.readouterr().out
    assert f"would review pull request #1 at {new}" in out
    assert "would withdraw ticket #11" in out


def test_a_pull_request_from_a_fork_is_reviewed_like_any_other(poller):
    head = poller.pilot.pull(5, "e = 5\n")  # GitHub keeps a fork's head under refs/pull/<n>/head of the base repository
    fork = {**_pull(5, head), "head": {"sha": head, "repo": {"full_name": "someone/pilot-fork"}}}
    assert poller([fork]) == 0
    assert poller.children.reviewed == [("5", head)]


@pytest.mark.parametrize("pull", [
    {"number": 1, "draft": False, "base": {"ref": "main"}, "head": {"sha": "--upload-pack=touch /tmp/x"}},
    {"number": "1", "draft": False, "base": {"ref": "main"}, "head": {"sha": "a" * 40}},
    {"number": 1, "draft": False, "head": {"sha": "a" * 40}},
], ids=["head not a commit id", "number not an integer", "no base"])
def test_a_pull_request_not_of_the_shape_read_fails_the_run_before_any_review_and_the_sync_still_runs(poller, pull, capsys):
    assert poller([pull]) == 1
    assert not [c for c in poller.children.calls if c[3:4] == ["review"]]
    assert "pull requests of org/pilot" in capsys.readouterr().err
    assert [c[-1] for c in poller.children.ticket_runs()] == ["--sync-decisions"]


def test_the_earlier_heads_tickets_are_not_withdrawn_while_the_current_head_is_not_filed(poller):
    pilot, children = poller.pilot, poller.children
    old = pilot.pull(1, "a = 1\n")
    children.keys = {old: [_key(1)]}
    assert poller([_pull(1, old)]) == 0
    new = pilot.pull(1, "a = 2\n")
    children.keys[new], children.tickets_exit = [_key(3)], 1
    assert poller([_pull(1, new)], tickets=[_ticket(11, _key(1))]) != 0
    assert _withdrawn(poller.tmp) == []  # #11 still asks its question


def test_a_new_head_that_queues_the_same_key_keeps_its_ticket(poller):
    pilot, children = poller.pilot, poller.children
    old = pilot.pull(1, "a = 1\n")
    children.keys = {old: [_key(1)]}
    assert poller([_pull(1, old)]) == 0
    new = pilot.pull(1, "a = 1\n# only the message and a comment changed\n")
    children.keys[new] = [_key(1)]  # the same tree gives the same queue key, so the open ticket is the new head's too
    assert poller([_pull(1, new)], tickets=[_ticket(11, _key(1))]) == 0
    assert _withdrawn(poller.tmp) == []


def test_a_head_pushed_back_to_an_earlier_one_is_filed_again_and_withdraws_the_other_heads_tickets(poller):
    pilot, children = poller.pilot, poller.children
    first, second = pilot.pull(1, "a = 1\n"), pilot.pull(1, "a = 2\n")
    children.keys = {first: [_key(1)], second: [_key(2)]}
    assert poller([_pull(1, first)]) == 0
    assert poller([_pull(1, second)], tickets=[_ticket(11, _key(1)), _ticket(12, _key(2))]) == 0
    assert _withdrawn(poller.tmp) == ["11"]
    _git(pilot.work, "push", "-q", "--force", str(pilot.url), f"{first}:refs/pull/1/head")  # force-pushed back

    assert poller([_pull(1, first)], tickets=[_ticket(12, _key(2)), _ticket(13, _key(1))]) == 0
    filings = [Path(c[c.index("--queue") + 1]).parent.name for c in children.ticket_runs() if "--queue" in c]
    assert filings == [first, second, first]  # filed again
    assert children.reviewed == [("1", first), ("1", second)]  # not reviewed again
    assert _withdrawn(poller.tmp) == ["11", "12"]  # the second head's ticket is the earlier one now


def test_a_merged_pull_request_has_its_last_head_reviewed_and_filed_and_is_then_left_alone(poller):
    pilot, children = poller.pilot, poller.children
    first = pilot.pull(1, "a = 1\n")
    assert poller([_pull(1, first)]) == 0
    last = pilot.pull(1, "a = 2\n")  # pushed and merged between two runs
    assert poller([], single={1: _closed(1, last, merged=True)}) == 0
    assert children.reviewed == [("1", first), ("1", last)]
    assert [c for c in children.ticket_runs() if "--queue" in c][-1][3].endswith(f"/1/{last}/human_queue.json")
    assert poller([], single={1: _closed(1, last, merged=True)}) == 0
    assert [c for c in _gh_calls(poller.tmp) if c == ["api", f"repos/{PILOT}/pulls/1"]] == [["api", f"repos/{PILOT}/pulls/1"]]


def test_a_pull_request_closed_unmerged_withdraws_every_undecided_ticket_of_its_heads_and_is_then_left_alone(poller):
    pilot, children = poller.pilot, poller.children
    head = pilot.pull(1, "a = 1\n")
    children.keys = {head: [_key(1), _key(2)]}
    assert poller([_pull(1, head)]) == 0
    tickets = [_ticket(11, _key(1)), _ticket(12, _key(2), "decision:false-positive"), _ticket(13, _key(9))]
    assert poller([], tickets=tickets, single={1: _closed(1, head, merged=False)}) == 0
    assert _withdrawn(poller.tmp) == ["11"]  # #12 is decided, #13 not this pull request's
    assert children.reviewed == [("1", head)]
    assert poller([], tickets=tickets, single={1: _closed(1, head, merged=False)}) == 0
    assert _withdrawn(poller.tmp) == ["11"]


def test_a_review_that_wrote_its_report_and_exited_non_zero_is_kept_and_the_run_exits_non_zero(poller, capsys):
    head, children = poller.pilot.pull(1, "a = 1\n"), poller.children
    children.review_exit = 3  # a PSIRT hand-off that failed, after the report was written
    assert poller([_pull(1, head)]) == 1
    children.review_exit = 0
    assert poller([_pull(1, head)]) == 0
    assert children.reviewed == [("1", head)]  # not paid for twice
    assert "completed with exit 3" in capsys.readouterr().err


def test_a_review_that_wrote_no_human_queue_files_nothing_and_the_run_goes_on(poller):
    one, two = poller.pilot.pull(1, "a = 1\n"), poller.pilot.pull(2, "b = 1\n")
    poller.children.queue = False  # human_queue.enabled: false
    assert poller([_pull(1, one), _pull(2, two)]) == 0
    assert poller.children.reviewed == [("1", one), ("2", two)]
    assert [c[-1] for c in poller.children.ticket_runs()] == ["--sync-decisions"]


def test_a_pull_request_that_fails_fails_alone_and_the_others_and_the_sync_go_on(poller, capsys):
    two = poller.pilot.pull(2, "b = 1\n")
    lost = {**_pull(1, "f" * 40)}  # listed, but the Pilot repository holds no refs/pull/1/head: its fetch fails
    assert poller([lost, _pull(2, two)]) == 1
    assert "pull request #1:" in capsys.readouterr().err
    assert poller.children.reviewed == [("2", two)]
    assert [c[-1] for c in poller.children.ticket_runs()][-1] == "--sync-decisions"


@pytest.mark.parametrize("ticket", [
    {"number": "11", "body": "<!-- mara-hq:v2-000000000000000000000001 -->", "labels": []},
    {"number": 11, "body": "<!-- mara-hq:v2-000000000000000000000001 -->", "labels": ["decision:true-positive"]},
], ids=["number not an integer", "labels not objects"])
def test_a_ticket_not_of_the_shape_read_fails_its_pull_request_and_the_sync_still_runs(poller, ticket, capsys):
    pilot, children = poller.pilot, poller.children
    old = pilot.pull(1, "a = 1\n")
    children.keys = {old: [_key(1)]}
    assert poller([_pull(1, old)]) == 0
    new = pilot.pull(1, "a = 2\n")
    assert poller([_pull(1, new)], tickets=[ticket]) == 1
    assert "tickets of org/security" in capsys.readouterr().err
    assert _withdrawn(poller.tmp) == []
    assert [c[-1] for c in children.ticket_runs()][-1] == "--sync-decisions"


def test_a_repository_without_a_default_branch_fails_the_run_and_the_sync_still_runs(poller, capsys):
    assert poller([], repo={"name": "pilot"}) == 1
    assert "no default branch" in capsys.readouterr().err
    assert [c[-1] for c in poller.children.ticket_runs()] == ["--sync-decisions"]


def test_the_commit_leaves_out_what_else_was_staged_in_the_workspace(poller):
    (poller.ws / "notes.txt").write_text("staged by someone\n", encoding="utf-8")
    _git(poller.ws, "add", "notes.txt")
    assert poller([]) == 0
    assert "notes.txt" not in _pushed(poller.remote) and "pilot/sync.json" in _pushed(poller.remote)


def test_a_dry_run_lists_the_filing_and_withdrawals_of_a_head_reviewed_but_not_filed_and_of_a_closed_pull_request(
        poller, capsys):
    pilot, children = poller.pilot, poller.children
    old, other = pilot.pull(1, "a = 1\n"), pilot.pull(2, "b = 1\n")
    children.keys = {old: [_key(1)], other: [_key(5)]}
    assert poller([_pull(1, old), _pull(2, other)]) == 0
    new = pilot.pull(1, "a = 2\n")
    children.keys[new], children.tickets_exit = [_key(3)], 1
    assert poller([_pull(1, new), _pull(2, other)]) == 1  # reviewed, its filing failed
    children.tickets_exit, calls = 0, len(children.calls)
    capsys.readouterr()

    tickets = [_ticket(11, _key(1)), _ticket(15, _key(5))]
    assert poller([_pull(1, new)], tickets=tickets, single={2: _closed(2, other, merged=False)}, dry_run=True) == 0
    assert len(children.calls) == calls  # nothing filed
    out = capsys.readouterr().out
    assert "would review pull request #1" not in out
    assert f"would file the queue of pull request #1 at {new}" in out
    assert "would withdraw ticket #11 (key " + _key(1) + ") of pull request #1\n" in out
    assert "would withdraw ticket #15 (key " + _key(5) + ") of pull request #2\n" in out


def test_a_pull_request_merged_with_a_merge_commit_is_reviewed_against_where_it_was_cut_from(poller):
    pilot = poller.pilot
    pilot.commit("later.py", "main moved on before the merge\n")
    _git(pilot.work, "push", "-q", str(pilot.url), "HEAD:main")
    first = pilot.pull(1, "a = 1\n")  # cut from pilot.main
    assert poller([_pull(1, first)]) == 0
    last = pilot.pull(1, "a = 2\n")
    merge = pilot.merge(last)  # main now holds the head: its merge base with main is the head itself
    assert poller([], single={1: _closed(1, last, merged=True, merge_commit=merge)}) == 0
    review = [c for c in poller.children.calls if c[3:4] == ["review"]][-1]
    assert dict(zip(review[5::2], review[6::2], strict=True)).get("--base") == pilot.main


def test_a_pull_request_reopened_after_it_closed_unmerged_is_filed_again_and_withdraws_when_it_closes_again(poller):
    pilot, children = poller.pilot, poller.children
    head = pilot.pull(1, "a = 1\n")
    children.keys = {head: [_key(1)]}
    assert poller([_pull(1, head)]) == 0
    assert poller([], tickets=[_ticket(11, _key(1))], single={1: _closed(1, head, merged=False)}) == 0
    assert _withdrawn(poller.tmp) == ["11"]

    assert poller([_pull(1, head)]) == 0  # reopened: its ticket was withdrawn, so its queue is filed again
    filed = [Path(c[c.index("--queue") + 1]).parent.name for c in children.ticket_runs() if "--queue" in c]
    assert filed == [head, head]
    newer = pilot.pull(1, "a = 2\n")
    children.keys[newer] = [_key(2)]
    assert poller([_pull(1, newer)], tickets=[_ticket(12, _key(1))]) == 0
    assert poller([], tickets=[_ticket(20, _key(2))], single={1: _closed(1, newer, merged=False)}) == 0
    assert _withdrawn(poller.tmp) == ["11", "12", "20"]  # closed again: the newer head's ticket is withdrawn too


def test_a_pull_request_that_cannot_be_read_alone_fails_alone(poller, capsys):
    pilot = poller.pilot
    one, two = pilot.pull(1, "a = 1\n"), pilot.pull(2, "b = 1\n")
    assert poller([_pull(1, one)]) == 0
    assert poller([_pull(2, two)]) == 1  # #1 is no longer listed, and the stand-in gh has no answer for it alone
    assert "pull request #1:" in capsys.readouterr().err
    assert poller.children.reviewed == [("1", one), ("2", two)]


def test_a_listed_pull_request_not_of_the_shape_read_fails_alone(poller, capsys):
    two = poller.pilot.pull(2, "b = 1\n")
    bad = {"number": 1, "draft": False, "head": {"sha": "a" * 40}}  # no base
    assert poller([bad, _pull(2, two)]) == 1
    assert "pull requests of org/pilot: #1: no base branch" in capsys.readouterr().err
    assert poller.children.reviewed == [("2", two)]


def test_a_review_whose_human_queue_cannot_be_read_is_kept_and_its_filing_fails(poller, capsys):
    head, children = poller.pilot.pull(1, "a = 1\n"), poller.children
    children.queue = "unreadable"
    children.tickets_exit = 1  # the ticket script cannot read it either
    assert poller([_pull(1, head)]) == 1
    assert "not a human queue" in capsys.readouterr().err
    assert poller([_pull(1, head)]) == 1
    assert children.reviewed == [("1", head)]  # not paid for twice


def test_a_dry_run_goes_on_past_a_pull_request_that_fails(poller, capsys):
    pilot, children = poller.pilot, poller.children
    old = pilot.pull(1, "a = 1\n")
    children.keys = {old: [_key(1)]}
    assert poller([_pull(1, old)]) == 0
    new, two = pilot.pull(1, "a = 2\n"), pilot.pull(2, "b = 1\n")
    capsys.readouterr()
    bad_ticket = {"number": "11", "body": f"<!-- mara-hq:{_key(1)} -->", "labels": []}
    assert poller([_pull(1, new), _pull(2, two)], tickets=[bad_ticket], dry_run=True) == 1
    captured = capsys.readouterr()
    assert "pull request #1: tickets of org/security" in captured.err
    assert f"would review pull request #2 at {two}" in captured.out
