"""scripts/osv_watch.py, run daily by .github/workflows/osv-watch.yml: the three osv-scanner scans of L0's locked closures,
and one tracking issue labelled l0-advisory that a new advisory opens, a changed list comments on and a clean scan
closes. The scans and gh are stand-ins here; nothing touches the network or GitHub."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import osv_watch  # noqa: E402

RUN_URL = "https://github.com/o/r/actions/runs/7"


def finding(vid: str, package: str, version: str, lockfile: str) -> dict:
    """One row as scripts/osv_ci.py's summarize() gives it."""
    return {"id": vid, "uri": f"file:///w/{lockfile}", "packages": [(package, version)], "suppressed": False}


class Scans:
    """Each scan's (exit code, findings), as scripts/osv_ci.py would end; clean unless told otherwise."""

    def __init__(self, **results: tuple[int, list[dict]]) -> None:
        self.results = results
        self.ran: list[tuple[str, tuple[str, ...]]] = []

    def __call__(self, name: str, args: list[str]) -> tuple[int, list[dict]]:
        self.ran.append((name, tuple(args)))
        return self.results.get(name.replace("-", "_"), (0, []))


class Gh:
    """The open l0-advisory issues, and what osv_watch did to them."""

    def __init__(self, *issues: dict) -> None:
        self.issues = [dict(i) for i in issues]
        self.done: list[tuple] = []

    def open_issues(self) -> list[dict]:
        return self.issues

    def create(self, title: str, body: str) -> None:
        self.done.append(("create", title, body))

    def comment(self, number: int, body: str) -> None:
        self.done.append(("comment", number, body))

    def close(self, number: int, body: str) -> None:
        self.done.append(("close", number, body))


def watch(scans: Scans, gh: Gh) -> int:
    return osv_watch.main(["--run-url", RUN_URL], scan=scans, gh=gh)


MCP = finding("CVE-2026-116684", "mcp", "1.29.0", "tools/semgrep-requirements.txt")


def test_a_new_advisory_opens_the_tracking_issue_and_the_run_goes_red():
    gh = Gh()
    assert watch(Scans(osv_semgrep=(2, [MCP])), gh) != 0
    assert [d[0] for d in gh.done] == ["create"]
    _, title, body = gh.done[0]
    assert "1 un-ignored advisory" in title
    assert "osv-semgrep" in body and "tools/semgrep-requirements.txt" in body
    assert "CVE-2026-116684" in body and "mcp@1.29.0" in body
    assert RUN_URL in body and "un-ignored advisories (exit 2)" in body
    assert "python3 scripts/advisory_facts.py --lockfile tools/semgrep-requirements.txt mcp" in body


def _opened(scans: Scans) -> dict:
    """The issue the first watch of `scans` opens, as GitHub then lists it."""
    gh = Gh()
    watch(scans, gh)
    return {"number": 12, "body": gh.done[0][2], "comments": []}


def test_the_same_list_again_leaves_the_issue_as_it_is_and_the_run_red():
    issue = _opened(Scans(osv_semgrep=(2, [MCP])))
    gh = Gh(issue)
    assert watch(Scans(osv_semgrep=(2, [MCP])), gh) != 0
    assert gh.done == []


def test_a_changed_list_comments_on_the_open_issue_with_the_new_one():
    issue = _opened(Scans(osv_semgrep=(2, [MCP])))
    langgraph = finding("CVE-2026-118667", "langgraph", "1.2.11", "tools/model-eval-requirements.txt")
    gh = Gh(issue)
    assert watch(Scans(osv_semgrep=(2, [MCP]), osv_model_eval=(2, [langgraph])), gh) != 0
    assert [d[:2] for d in gh.done] == [("comment", 12)]
    assert "CVE-2026-118667" in gh.done[0][2] and "langgraph@1.2.11" in gh.done[0][2]
    # and that comment is what the next run compares with
    issue["comments"] = [gh.done[0][2]]
    gh = Gh(issue)
    watch(Scans(osv_semgrep=(2, [MCP]), osv_model_eval=(2, [langgraph])), gh)
    assert gh.done == []


def test_a_clean_scan_closes_the_open_issue_and_otherwise_does_nothing():
    issue = _opened(Scans(osv_semgrep=(2, [MCP])))
    gh = Gh(issue)
    assert watch(Scans(), gh) == 0
    assert [d[:2] for d in gh.done] == [("close", 12)]
    assert "clean" in gh.done[0][2] and RUN_URL in gh.done[0][2]
    gh = Gh()
    assert watch(Scans(), gh) == 0
    assert gh.done == []


def test_a_scan_that_does_not_complete_is_reported_as_such_and_exits_1():
    gh = Gh()
    assert watch(Scans(osv_model_eval=(1, [])), gh) == 1
    assert [d[0] for d in gh.done] == ["create"]
    title, body = gh.done[0][1], gh.done[0][2]
    assert "did not complete" in title
    assert "osv-model-eval: the scan did not complete (exit 1)" in body and "tools/model-eval-requirements.txt" in body


def test_it_runs_the_three_scans_l0_runs():
    """The lockfiles and configs of L0's osv-scanner steps in mara-review.yml, every one, and no other scan."""
    workflow = (ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8")
    ci = set()
    for line in re.findall(r"run: python3 scripts/osv_ci\.py (--lockfile .*)\n", workflow):
        args = line.split()
        i = args.index("--report")
        ci.add(tuple(args[:i] + args[i + 2:]))
    scans = Scans()
    watch(scans, Gh())
    assert len(ci) == 3 and {args for _, args in scans.ran} == ci
    assert [name for name, _ in scans.ran] == ["osv-runtime", "osv-model-eval", "osv-semgrep"]


def test_the_workflow_runs_daily_and_by_hand_with_issues_write_alone():
    """.github/workflows/osv-watch.yml: 04:00 UTC every day and workflow_dispatch, never on a pull request; top-level
    permissions {}; one job, contents: read and issues: write; it installs only what the osv-scanner scans need and runs
    osv_watch.py with this run's URL."""
    import yaml

    doc = yaml.safe_load((ROOT / ".github" / "workflows" / "osv-watch.yml").read_text(encoding="utf-8"))
    on = doc[True] if True in doc else doc["on"]  # YAML 1.1 reads the key `on` as True
    assert set(on) == {"schedule", "workflow_dispatch"} and on["schedule"] == [{"cron": "0 4 * * *"}]
    assert doc["permissions"] == {}
    [(name, job)] = doc["jobs"].items()
    assert job["permissions"] == {"contents": "read", "issues": "write"}
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "scripts/install_tools.py --only" in runs
    assert re.search(r"python3 scripts/osv_watch\.py --repo \S+ --run-url \S+", runs), runs
