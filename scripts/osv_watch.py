"""Daily watch on L0's locked tool closures (.github/workflows/osv-watch.yml): run the three osv-scanner scans and keep one
tracking issue, labelled l0-advisory, in step with what they find.

  python3 scripts/osv_watch.py --repo <owner>/<repo> --run-url https://github.com/<owner>/<repo>/actions/runs/<id>

The scans are scripts/check_local.py's OSV_SCANS, which tests keep equal to L0's in .github/workflows/mara-review.yml.
Exit 0 when every scan is clean, 2 when one reports un-ignored advisories, 1 when one does not complete.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from check_local import OSV_SCANS  # noqa: E402
from osv_ci import facts_commands, summarize  # noqa: E402

LABEL = "l0-advisory"
MARKER = re.compile(r"<!-- osv-watch:state=([0-9a-f]{16}) -->")
Scan = Callable[[str, list[str]], tuple[int, list[dict]]]


class Issues(Protocol):
    """The l0-advisory issues, through gh."""

    def open_issues(self) -> list[dict]: ...
    def create(self, title: str, body: str) -> None: ...
    def comment(self, number: int, body: str) -> None: ...
    def close(self, number: int, body: str) -> None: ...


def run_scan(name: str, args: list[str]) -> tuple[int, list[dict]]:
    """One scan through scripts/osv_ci.py, its output shown in the log: its exit code and its un-ignored findings."""
    with tempfile.TemporaryDirectory() as d:
        report = Path(d) / f"{name}.sarif"
        code = subprocess.run([sys.executable, str(HERE / "osv_ci.py"), *args, "--report", str(report)], cwd=HERE.parent).returncode
        rows = summarize(json.loads(report.read_text(encoding="utf-8"))) if report.is_file() else []
    return code, [x for x in rows if not x["suppressed"]]


class GhIssues:
    """The l0-advisory issues of one repository, through the gh CLI (GH_TOKEN from the workflow)."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def _gh(self, *args: str, stdin: str | None = None) -> str:
        return subprocess.run(["gh", *args, "--repo", self.repo], input=stdin, capture_output=True, text=True, check=True).stdout

    def open_issues(self) -> list[dict]:
        found = json.loads(self._gh("issue", "list", "--label", LABEL, "--state", "open", "--json", "number,body,comments"))
        return [{"number": i["number"], "body": i["body"], "comments": [c["body"] for c in i["comments"]]} for i in found]

    def create(self, title: str, body: str) -> None:
        self._gh("label", "create", LABEL, "--force", "--color", "B60205",
                 "--description", "osv-scanner finds un-ignored advisories on L0's locked closures (scripts/osv_watch.py)")
        self._gh("issue", "create", "--title", title, "--label", LABEL, "--body-file", "-", stdin=body)

    def comment(self, number: int, body: str) -> None:
        self._gh("issue", "comment", str(number), "--body-file", "-", stdin=body)

    def close(self, number: int, body: str) -> None:
        self._gh("issue", "close", str(number), "--comment", body)


def _lockfiles(args: list[str]) -> list[str]:
    return [args[i + 1] for i, a in enumerate(args) if a == "--lockfile"]


def state_of(results: dict[str, tuple[int, list[dict]]]) -> str:
    """A digest of what the scans found: each scan's exit code and its un-ignored advisories, in a fixed order."""
    norm = {name: [code, sorted([x["id"], sorted(map(list, x["packages"]))] for x in live)] for name, (code, live) in results.items()}
    return hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()[:16]


def last_state(issue: dict) -> str | None:
    """The state the issue last recorded, in its body or a later comment."""
    found = MARKER.findall("\n".join([issue.get("body") or "", *(issue.get("comments") or [])]))
    return found[-1] if found else None


def body_for(results: dict[str, tuple[int, list[dict]]], run_url: str) -> str:
    lines = [f"osv-scanner on L0's locked closures, run {run_url}", ""]
    for name, (code, live) in results.items():
        if code == 0:
            continue
        lockfiles = _lockfiles(list(OSV_SCANS[name]))
        kind = "un-ignored advisories (exit 2)" if code == 2 else f"the scan did not complete (exit {code})"
        lines += [f"### {name}: {kind}", f"Lockfiles: {', '.join(f'`{lf}`' for lf in lockfiles)}", ""]
        lines += [f"- {x['id']}  {', '.join(f'{n}@{v}' for n, v in x['packages'])}" for x in live]
        lines += ["", *(f"Facts for a relock or a dated exception: `{c}`" for c in facts_commands(lockfiles, live)), ""]
    return "\n".join([*lines, f"<!-- osv-watch:state={state_of(results)} -->"])


def watch(run_url: str, scan: Scan, gh: Issues) -> int:
    results = {name: scan(name, list(args)) for name, args in OSV_SCANS.items()}
    issues = gh.open_issues()
    if all(code == 0 for code, _ in results.values()):
        for issue in issues:
            gh.close(issue["number"], f"All three scans are clean as of {run_url}; closing.")
        return 0
    advisories = sum(len(live) for code, live in results.values() if code == 2)
    broken = [name for name, (code, _) in results.items() if code not in (0, 2)]
    body = body_for(results, run_url)
    if not issues:
        title = f"L0 osv-scanner: {advisories} un-ignored advisory(ies) on the locked tool closures"
        if broken:
            title += f"; {', '.join(broken)} did not complete"
        gh.create(title, body)
    elif last_state(issues[0]) != state_of(results):
        gh.comment(issues[0]["number"], "The scans now find:\n\n" + body)
    return 1 if broken else 2


def main(argv: list[str] | None = None, scan: Scan | None = None, gh: Issues | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--repo", help="owner/name, for gh (the workflow passes github.repository)")
    ap.add_argument("--run-url", required=True, help="this workflow run, linked from the issue")
    args = ap.parse_args(argv)
    if gh is None:
        if not args.repo:
            ap.error("--repo is required unless an issues adapter is given")
        gh = GhIssues(args.repo)
    return watch(args.run_url, scan or run_scan, gh)


if __name__ == "__main__":
    sys.exit(main())
