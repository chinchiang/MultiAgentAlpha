"""Wait for a pull request's checks, then print in one place what step 6 of docs/agents/pr-flow.md reads.

  .venv/bin/python scripts/pr_checks.py 327    # the checks of pull request 327, once none is pending

It reads everything through gh: the pull request's head (gh pr view), its checks (gh pr checks) and the log of each
check that is a job (gh run view --job <id> --log). While a check is pending, or none is reported yet (right after a
push), it waits, saying so on stderr and printing nothing on stdout, and reads the checks again every 30 seconds. After
each read of the checks it reads the head again, and if the head moved it stops (exit 1): the checks it read are no
longer the pull request's. Interrupted (Ctrl-C) it stops with exit 130, as gh pr checks --watch does.

Once none is pending it prints the head it read, then one line per check: its bucket (pass, fail, skipping, cancel),
its name and how long it ran. A job whose log cannot be read is named on a LOG line, and the rest is still printed.

Then the result line of each tool step 6 reads (RESULTS): the last line printed by the step that runs that tool's
script, the step found by its command; a step on the seeded fixture is not one on the change, and is left out. A
script with no hit prints its clean line last (RESULTS copies each); one with hits prints them, then a summary that is
not clean. Each result line is printed once with its job: ok when it is the clean line, NOT when it is another or the
step printed nothing (with the step to read), and MISS when the logs hold fewer of the tool's steps than CI runs (one
each; four for osv-scanner).

Then the skipped tests of each job that runs pytest: how many (pytest -rs folds one reason's skips into one line,
SKIPPED [n]), and in full every skip no missing tool explains. A reason holding "not installed" (TOOL_NOT_INSTALLED) is
a tool missing on the runner, except in a job that installs the tools (TOOLS_INSTALLED), where no skip is.

Last, each workflow of .github/workflows that a pull request triggers but that has no check on this one (docs-check,
for one, runs only when its paths change), with its jobs and the active rulesets of the repository that require one of
them (gh api .../rulesets); a required check that did not run holds the merge.

Exit 0 when every check passed or was skipped, every result line is ok, every skip is a tool not installed, every
job's log was read and no workflow that did not run is required; 1 otherwise, or when the head moved; 2 when gh fails
or cannot be started; 130 when interrupted.

GLOSSARY.md terms: Change, Required check, Result line. Not pure: it runs gh and reads the workflow files.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import NamedTuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
PASSING = ("pass", "skipping")
NO_CHECK_YET = "no checks reported"  # what gh pr checks says before GitHub has reported any check of the pull request


class Result(NamedTuple):
    """A tool whose last line step 6 reads: its step's command, how many steps CI runs, and its clean line, which
    `script` prints (`printed` is the part of that print that is the same every run)."""

    tool: str
    command: re.Pattern
    steps: int
    clean: re.Pattern
    script: str
    printed: str


RESULTS = (
    Result("line width", re.compile(r"python3 scripts/line_width\.py\b"), 1,
           re.compile(r"^no added line is wider than \d+ columns$"), "scripts/line_width.py", "no added line is wider than"),
    Result("control characters", re.compile(r"python3 scripts/control_chars\.py\b"), 1,
           re.compile(r"^no control character in what the change adds$"), "scripts/control_chars.py",
           "no control character in what the change adds"),
    Result("gitleaks", re.compile(r"python3 scripts/gitleaks_ci\.py\b"), 1, re.compile(r"^no leaks found$"),
           "scripts/gitleaks_ci.py", "no leaks found"),
    Result("semgrep", re.compile(r"python3 scripts/semgrep_ci\.py --target \. "), 1,
           re.compile(r"^clean: \d+ accepted finding\(s\), 0 untriaged$"), "scripts/semgrep_ci.py",
           "accepted finding(s), 0 untriaged"),
    Result("osv-scanner", re.compile(r"python3 scripts/osv_ci\.py --lockfile "), 4,
           re.compile(r"^no un-ignored known vulnerabilities\b"), "scripts/osv_ci.py", "no un-ignored known vulnerabilities"),
)
TOOL_NOT_INSTALLED = (re.compile(r"\bnot installed\b"),)  # the skip reasons a tool not installed on the runner explains
TOOLS_INSTALLED = ("tests + mock review",)  # the jobs that install the tools their tests need: no skip there is one
SKIPPED = re.compile(r"^SKIPPED \[(\d+)\] (.+)$")
PYTEST = re.compile(r"\bpytest\b")  # the command of a step that runs the tests
ANSI = re.compile(r"\x1b\[[0-9;]*m")

Step = tuple[str, str, list[str]]  # (job, step, its lines)


def gh_text(gh: str, *args: str) -> str:
    """What gh prints for `args`; CalledProcessError when gh fails, or cannot be started (its error as stderr)."""
    try:
        return subprocess.run([gh, *args], capture_output=True, encoding="utf-8", errors="replace", check=True).stdout
    except OSError as e:
        raise subprocess.CalledProcessError(127, [gh, *args], stderr=str(e)) from e


def gh_json(gh: str, *args: str) -> object:
    """What gh prints for `args`, parsed as JSON; CalledProcessError as gh_text raises it."""
    return json.loads(gh_text(gh, *args))


def steps(log: str) -> list[Step]:
    """(job, step, its lines) of a job's log as gh run view --log writes it, one line per `job<TAB>step<TAB>time text`,
    the time and terminal colours taken off."""
    out: list[Step] = []
    for row in log.splitlines():
        job, _, rest = row.partition("\t")
        step, _, text = rest.partition("\t")
        text = ANSI.sub("", text.partition(" ")[2])
        if not out or out[-1][:2] != (job, step):
            out.append((job, step, []))
        out[-1][2].append(text)
    return out


def duration(check: dict) -> str:
    """How long a check ran, as 9s or 2m25s; empty when it has not finished."""
    try:
        start, end = (dt.datetime.fromisoformat(check[k].replace("Z", "+00:00")) for k in ("startedAt", "completedAt"))
    except (KeyError, ValueError, AttributeError):
        return ""
    minutes, seconds = divmod(max(0, int((end - start).total_seconds())), 60)
    return f"{minutes}m{seconds}s" if minutes else f"{seconds}s"


def head_of(gh: str, pr: str) -> str:
    """The SHA of the pull request's head commit."""
    return gh_json(gh, "pr", "view", pr, "--json", "headRefOid")["headRefOid"]


def wait_for_checks(gh: str, pr: str, interval: float) -> tuple[str, list[dict]] | str:
    """(the head, its checks) once none is pending and the head is the one read first; the reason it stopped instead,
    when the head moved. CalledProcessError when gh fails, KeyboardInterrupt when interrupted."""
    head = head_of(gh, pr)
    while True:
        try:
            checks = gh_json(gh, "pr", "checks", pr, "--json", "name,bucket,state,link,workflow,startedAt,completedAt")
            pending = sum(check["bucket"] == "pending" for check in checks)
            waiting = f"{pending} of {len(checks)} checks pending"
        except subprocess.CalledProcessError as e:
            if NO_CHECK_YET not in (e.stderr or ""):
                raise
            pending, waiting = 1, "no check reported yet"
        now = head_of(gh, pr)
        if now != head:
            return f"the head moved from {head} to {now}; run it again for the new head"
        if not pending:
            return head, checks
        print(f"waiting: {waiting}", file=sys.stderr, flush=True)
        time.sleep(interval)


def runs(lines: list[str], command: re.Pattern) -> bool:
    """Whether a step, by its lines, runs a command `command` matches."""
    return bool(lines) and lines[0].startswith("##[group]Run ") and bool(command.search(lines[0]))


def result_lines(logs: list[list[Step]]) -> tuple[list[str], int]:
    """(the lines to print, how many are not ok) of each tool's result lines in the jobs' logs (RESULTS)."""
    out, bad = [], 0
    for result in RESULTS:
        found = [(job, step, next((t for t in reversed(lines) if t.strip() and not t.startswith("##[")), ""))
                 for log in logs for job, step, lines in log if runs(lines, result.command)]
        for job, step, line in found:
            ok = bool(line) and bool(result.clean.search(line))
            out.append(f"{'ok' if ok else 'NOT':4} {result.tool}  [{job}]  {line or '(the step printed nothing)'}")
            if not ok:
                out.append(f"     read the step: {step}")
                bad += 1
        if len(found) < result.steps:
            out.append(f"MISS {result.tool}  " + (f"{len(found)} of {result.steps} result lines found" if found else
                                                  "no result line in any job log"))
            bad += 1
    return out, bad


def skip_lines(log: list[Step]) -> tuple[list[str], int]:
    """(the lines to print, how many skips no missing tool explains) of one job's skipped tests; no line for a job that
    runs no pytest and skips nothing."""
    job = log[0][0]
    skips = [m for _, _, lines in log for line in lines if (m := SKIPPED.match(line))]
    if not skips:
        return ([f"skips  [{job}]  0"] if any(runs(lines, PYTEST) for _, _, lines in log) else []), 0
    tools_missing = job not in TOOLS_INSTALLED
    other = [m[0] for m in skips if not (tools_missing and any(p.search(m[2]) for p in TOOL_NOT_INSTALLED))]
    prefix = f"skips  [{job}]  {sum(int(m[1]) for m in skips)}, "
    if not other:
        return [prefix + "each a tool not installed"], 0
    return [prefix + f"{len(other)} no missing tool explains:", *(f"  {line}" for line in other)], len(other)


def pull_request_workflows(directory: Path) -> list[tuple[str, list[str]]]:
    """(name, the names of its jobs) of each workflow in `directory` a pull request triggers."""
    out = []
    for path in sorted(directory.glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        on = data.get("on", data.get(True))  # YAML 1.1 reads a bare `on:` key as True
        triggers = [on] if isinstance(on, str) else list(on or [])
        if {"pull_request", "pull_request_target"} & set(triggers):
            job_names = [job.get("name") or key for key, job in (data.get("jobs") or {}).items()]
            out.append((data.get("name") or path.stem, job_names))
    return out


def required_checks(gh: str) -> list[tuple[str, set[str]]]:
    """(name, the checks it requires) of each active ruleset of the repository (one disabled, or only evaluated,
    holds no merge)."""
    out = []
    for ruleset in gh_json(gh, "api", "repos/{owner}/{repo}/rulesets"):
        if ruleset.get("enforcement") != "active":
            continue
        rules = gh_json(gh, "api", f"repos/{{owner}}/{{repo}}/rulesets/{ruleset['id']}").get("rules", [])
        out.append((ruleset["name"], {c["context"] for r in rules if r.get("type") == "required_status_checks"
                                      for c in r.get("parameters", {}).get("required_status_checks", [])}))
    return out


def not_run_lines(not_run: list[tuple[str, list[str]]], rulesets: list[tuple[str, set[str]]]) -> tuple[list[str], int]:
    """(the lines to print, how many are required) of the workflows that did not run."""
    out, bad = [], 0
    for name, job_names in not_run:
        requiring = [ruleset for ruleset, required in rulesets if required & set(job_names)]
        out.append(f"not run  {name} ({', '.join(job_names)})  required by {', '.join(requiring) or 'no ruleset'}")
        bad += bool(requiring)
    return out, bad


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pr", help="the pull request's number")
    ap.add_argument("--gh", default="gh", help=argparse.SUPPRESS)  # a stand-in gh (tests)
    ap.add_argument("--interval", type=float, default=30, help=argparse.SUPPRESS)  # seconds between polls
    ap.add_argument("--workflows", type=Path, default=ROOT / ".github" / "workflows", help=argparse.SUPPRESS)  # (tests)
    args = ap.parse_args(argv)
    try:
        waited = wait_for_checks(args.gh, args.pr, args.interval)
        if isinstance(waited, str):
            print(f"ERROR: {waited}", file=sys.stderr)
            return 1
        head, checks = waited
        logs, unread = [], []
        for check in checks:
            if m := re.search(r"/job/(\d+)$", check.get("link", "")):
                try:
                    logs.append(steps(gh_text(args.gh, "run", "view", "--job", m[1], "--log")))
                except subprocess.CalledProcessError as e:
                    unread.append(f"LOG  {check['name']}  log unavailable: {(e.stderr or '').strip()}")
        ran = {check.get("workflow") for check in checks}
        not_run = [(name, job_names) for name, job_names in pull_request_workflows(args.workflows) if name not in ran]
        rulesets = required_checks(args.gh) if not_run else []
    except subprocess.CalledProcessError as e:
        print(f"ERROR: gh {' '.join(e.cmd[1:3])} failed: {(e.stderr or '').strip()}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted while waiting", file=sys.stderr)
        return 130
    print(f"head {head}")
    for check in checks:
        print(f"{check['bucket']:8} {check['name']}  {duration(check)}")
    bad = sum(check["bucket"] not in PASSING for check in checks) + len(unread)
    sections = [(unread, 0), result_lines(logs), *(skip_lines(log) for log in logs if log), not_run_lines(not_run, rulesets)]
    for lines, n in sections:
        for line in lines:
            print(line)
        bad += n
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
