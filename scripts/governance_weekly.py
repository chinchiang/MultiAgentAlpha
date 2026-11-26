"""The Weekly governance check: G-1 to G-13 judged with the host's config and the MARA workspace, plus the week's
tokens, posted to the tracking issues of the Ticket repository.

  MARA_HOME=<workspace> python scripts/governance_weekly.py --repo owner/repo --config config/local/mara.yaml
                                                             [--root DIR] [--date YYYY-MM-DD] [--dry-run]

Terms (GLOSSARY.md): Weekly governance check, MARA workspace (MARA_HOME, read once in main), Pilot poller, Sync record,
Ticket repository. It follows no ADR of its own; docs/pilot-runbook.md is how a host runs it. Not pure: it reads the
workspace and calls gh.

The check is `run_all` of scripts/governance_check.py over --root (default: this checkout) with --config and the
workspace, rendered as that script renders it but naming this script and no exit code, followed by one line of the
week's tokens: the input and the output tokens (mara.govdocs.report_tokens, as baseline_metrics sums them; a report
with no token counts counts 0) of each report.json the Pilot poller wrote below the workspace
(mara.workspace.PILOT_REVIEWS, <pull request>/<head>/) whose `generated_at` falls on one of the seven UTC days before
--date (default: today in UTC), so that weekly runs cover the days one after the other. A report that cannot be read,
is not a JSON object, holds a `bias_audit` that is not an object, or whose `generated_at` is not an ISO 8601 time with
a time zone, is left out, and the line says how many were.

The comment is posted to every open issue of --repo labelled governance-check or, when none is open, to a new one so
labelled, the label created first, as .github/workflows/governance.yml does for this repository's own check. --dry-run
prints the comment and calls no gh.

Exit 0 when the comment was posted or printed, whatever the checks say (the comment holds them); 1 when a gh call
fails or answers in a shape not read (an ERROR line on stderr, which cron mails).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
import governance_check  # noqa: E402

from mara.govdocs import report_tokens  # noqa: E402
from mara.workspace import PILOT_REVIEWS, Workspace  # noqa: E402

LABEL = "governance-check"
TITLE = "Governance compliance check (G-1..G-13)"
DAYS = 7


class GhError(RuntimeError):
    """A gh call that failed, or answered in a shape not read."""


@dataclass(frozen=True)
class Week:
    """The tokens of the reports of the seven days from `start` to `end`: how many reports, their input and output
    tokens, and how many reports were left out unread."""

    start: dt.date
    end: dt.date
    reports: int
    tokens_in: int
    tokens_out: int
    unread: int

    def line(self) -> str:
        line = f"本週 token（{self.start} 至 {self.end}，{self.reports} 份報告）：輸入 {self.tokens_in}、輸出 {self.tokens_out}"
        return line + (f"；{self.unread} 份報告讀不到、形狀不對或沒有帶時區的 `generated_at`，未計入" if self.unread else "")


def generated_on(report: dict) -> dt.date | None:
    """The UTC day of a report's `generated_at`; None when it is not an ISO 8601 time with a time zone."""
    when = governance_check.aware_time(report.get("generated_at"))
    return when.astimezone(dt.UTC).date() if when is not None else None


def week(workspace: Path, end: dt.date) -> Week:
    """The seven days ending on `end` of the report.json files the Pilot poller wrote below `workspace`."""
    start = end - dt.timedelta(days=DAYS - 1)  # `end` the last of the seven days
    reports = tokens_in = tokens_out = unread = 0
    for path in sorted((workspace / PILOT_REVIEWS).glob("*/*/report.json")):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError):
            unread += 1
            continue
        day = generated_on(report) if isinstance(report, dict) and isinstance(report.get("bias_audit", {}), dict) else None
        if day is None:
            unread += 1
        elif start <= day <= end:
            r_in, r_out = report_tokens(report)
            reports, tokens_in, tokens_out = reports + 1, tokens_in + r_in, tokens_out + r_out
    return Week(start, end, reports, tokens_in, tokens_out, unread)


def gh(exe: str, *args: str, body: str | None = None) -> str:
    """What gh prints for `args`, `body` on its stdin; GhError when it fails."""
    cp = subprocess.run([exe, *args], input=body, capture_output=True, text=True, encoding="utf-8", errors="replace",
                        check=False)
    if cp.returncode != 0:
        raise GhError(f"gh {' '.join(args[:3])} failed: {cp.stderr.strip()[-500:]}")
    return cp.stdout


def post(exe: str, repo: str, body: str) -> list[str]:
    """Post `body` to every open issue of `repo` labelled governance-check, or to a new one; what was done, a line each."""
    gh(exe, "label", "create", LABEL, "--force", "--color", "5319e7", "--description", "Weekly G-1..G-13 compliance check",
       "--repo", repo)
    listed = gh(exe, "issue", "list", "--repo", repo, "--label", LABEL, "--state", "open", "--json", "number")
    try:
        issues = json.loads(listed)
    except ValueError:
        issues = None
    if not isinstance(issues, list) or not all(isinstance(i, dict) and type(i.get("number")) is int for i in issues):
        raise GhError(f"gh issue list: unexpected response shape: {listed.strip()[:200]}")
    for n in (i["number"] for i in issues):
        gh(exe, "issue", "comment", str(n), "--repo", repo, "--body-file", "-", body=body)
    if issues:
        return [f"commented on {repo}#{i['number']}" for i in issues]
    created = gh(exe, "issue", "create", "--repo", repo, "--label", LABEL, "--title", TITLE, "--body-file", "-", body=body)
    return [f"created {created.strip()}"]


def main(argv: list[str] | None = None) -> int:
    ws = Workspace.from_env()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, help="the repository of the tracking issue, owner/repo")
    ap.add_argument("--config", type=Path, required=True)
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--date", type=dt.date.fromisoformat, default=dt.datetime.now(dt.UTC).date(),
                    help="the day of the run (default: today, UTC); the week is the seven UTC days before it")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--gh", default="gh", help=argparse.SUPPRESS)  # a stand-in gh (tests)
    a = ap.parse_args(argv)
    root, config = a.root.resolve(), a.config.resolve()
    results = governance_check.run_all(root, config, a.date, ws)
    table = governance_check.render(results, root=root, config_path=config, date=a.date.isoformat(),
                                    producer="scripts/governance_weekly.py", fails_the_run=False)
    body = table + "\n" + week(ws.root, a.date - dt.timedelta(days=1)).line() + "\n"
    if a.dry_run:
        print(body, end="")
        print(f"would post to every open {LABEL} issue of {a.repo}, or create one")
        return 0
    try:
        done = post(a.gh, a.repo, body)
    except GhError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    print("\n".join(done))
    return 0


if __name__ == "__main__":
    sys.exit(main())
