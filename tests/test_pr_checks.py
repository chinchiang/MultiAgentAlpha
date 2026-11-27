"""scripts/pr_checks.py: wait for a pull request's checks and print what step 6 of docs/agents/pr-flow.md reads, driven
through main with a stand-in gh that answers from files the test writes (--gh), and no waiting (--interval 0)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pr_checks  # noqa: E402

FAKE_GH = '''
"""A stand-in gh: answers the calls pr_checks makes from the files beside it; any other call fails loudly."""
import json, shutil, sys
from pathlib import Path
here = Path(__file__).parent
args = sys.argv[1:]


def nth(name, answers):
    """The answer to the n-th call of its kind, the last one ever after (`name`.count holds how many were made)."""
    count = here / f"{name}.count"
    n = int(count.read_text()) if count.exists() else 0
    count.write_text(str(n + 1))
    return answers[min(n, len(answers) - 1)]


if args[:2] == ["pr", "view"]:
    print(json.dumps({"headRefOid": nth("head", (here / "head").read_text().split())}))
elif args[:2] == ["pr", "checks"]:
    poll = nth("checks", json.loads((here / "polls.json").read_text()))
    if poll == "none":
        sys.exit("no checks reported on the 'feat/x' branch")
    print(json.dumps(poll))
elif args[:3] == ["run", "view", "--job"] and args[4:] == ["--log"]:
    log = here / "logs" / f"{args[3]}.log"
    if not log.exists():
        sys.exit("HTTP 410: the log has expired")
    print(log.read_text(), end="")
elif args[:2] == ["run", "list"]:
    if args[2:] != ["--workflow", "mara-review", "--branch", "main", "--event", "push", "--status", "completed",
                    "--limit", "10", "--json", "databaseId,headSha"]:
        sys.exit(f"stand-in gh: no answer for {args}")
    nth("run-list", [None])
    print(json.dumps([{"databaseId": run, "headSha": "b" * 40} for run in json.loads((here / "main_runs.json").read_text())]))
elif args[:2] == ["run", "view"] and args[3:] == ["--json", "jobs"]:
    run = int(args[2])
    print(json.dumps({"jobs": [{"databaseId": run * 100 + 2, "name": "tests + mock review"},
                               {"databaseId": run * 100 + 1, "name": "L0 deterministic tools"}]}))
elif args[:2] == ["run", "download"] and args[3:6] == ["-n", "l0-sarif", "-D"] and len(args) == 7:
    nth("download", [None])
    artifact = here / "artifacts" / args[2]
    if not artifact.exists():
        sys.exit("no valid artifacts found to download")
    shutil.copytree(artifact, args[6])
elif args == ["api", "repos/{owner}/{repo}/rulesets"]:
    disabled = json.loads((here / "disabled.json").read_text())
    print(json.dumps([{"id": i, "name": name, "enforcement": "disabled" if name in disabled else "active"}
                      for i, name in enumerate(json.loads((here / "rulesets.json").read_text()))]))
elif len(args) == 2 and args[0] == "api" and args[1].startswith("repos/{owner}/{repo}/rulesets/"):
    name, contexts = list(json.loads((here / "rulesets.json").read_text()).items())[int(args[1].rsplit("/", 1)[1])]
    rule = {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": c} for c in contexts]}}
    print(json.dumps({"name": name, "rules": [{"type": "update"}, rule] if contexts else [{"type": "update"}]}))
else:
    sys.exit(f"stand-in gh: no answer for {args}")
'''


def _check(name: str, bucket: str = "pass", seconds: int = 9, job: int | None = None, workflow: str = "") -> dict:
    link = f"https://github.com/o/r/actions/runs/1/job/{job}" if job else "https://github.com/o/r/runs/7"
    return {"name": name, "bucket": bucket, "state": bucket.upper(), "link": link, "workflow": workflow,
            "startedAt": "2026-11-15T09:00:00Z", "completedAt": f"2026-11-15T09:{seconds // 60:02d}:{seconds % 60:02d}Z"}


def _gh(tmp_path: Path, *polls: list[dict] | str, heads: list[str] | None = None, logs: dict[int, str] | None = None,
        rulesets: dict[str, list[str]] | None = None, disabled: tuple[str, ...] = (),
        workflows: dict[str, str] | None = None, main_runs: dict[int, str | None] | None = None,
        artifacts: dict[int, list[dict] | None] | None = None) -> Path:
    """A directory holding the stand-in gh and its answers; the path of the gh.

    `polls` are the answers to successive gh pr checks calls, the last one repeated ("none": gh says no check is
    reported yet), and `heads` those to gh pr view. `logs` maps a job's id to its log (a job without one has an expired
    log); `rulesets` maps each ruleset's name to the checks it requires, `disabled` names those not enforced;
    `workflows` are the workflow files of the repository (none unless given). `main_runs` maps each of main's push runs,
    newest first, to the log of its L0 job, whose id is the run's times 100 plus 1 (None: an expired log; one run, 21,
    whose semgrep line is CLEAN's, unless given); `artifacts` maps a run (the pull request's is 1, as _check's links
    give) to the results of the semgrep.sarif of its l0-sarif (None: a SARIF with no run; a run without one has no
    artifact)."""
    d = tmp_path / "gh"
    (d / "logs").mkdir(parents=True)
    (d / "workflows").mkdir()
    (d / "head").write_text("\n".join(heads or ["a" * 40]))
    (d / "polls.json").write_text(json.dumps(list(polls)))
    (d / "rulesets.json").write_text(json.dumps(rulesets or {"R1": []}))
    (d / "disabled.json").write_text(json.dumps(list(disabled)))
    main_runs = {21: _main_l0(CLEAN["semgrep"])} if main_runs is None else main_runs
    (d / "main_runs.json").write_text(json.dumps(list(main_runs)))
    for job, log in {**(logs or {}), **{run * 100 + 1: log for run, log in main_runs.items() if log is not None}}.items():
        (d / "logs" / f"{job}.log").write_text(log)
    for run, results in (artifacts or {}).items():
        (d / "artifacts" / str(run)).mkdir(parents=True)
        runs = [] if results is None else [{"results": results}]
        (d / "artifacts" / str(run) / "semgrep.sarif").write_text(json.dumps({"version": "2.1.0", "runs": runs}))
    for name, text in (workflows or {}).items():
        (d / "workflows" / name).write_text(text)
    gh = d / "gh"
    gh.write_text(f"#!{sys.executable}" + FAKE_GH)
    gh.chmod(0o755)
    return gh


def _run(gh: Path, *args: str) -> int:
    return pr_checks.main(["327", "--gh", str(gh), "--interval", "0", "--workflows", str(gh.parent / "workflows"), *args])


def _step(job: str, step: str, command: str, *lines: str) -> str:
    """One step of a job's log as gh run view --log writes it: job, step and a timestamp before each line."""
    out = [f"##[group]Run {command}", "##[endgroup]", *lines]
    return "".join(f"{job}\t{step}\t2026-11-15T09:10:51.2015491Z {line}\n" for line in out)


L0, MOCK, PY312 = "L0 deterministic tools", "tests + mock review", "tests (CPython 3.12)"
OSV_CLEAN = {  # each L0 osv-scanner step's clean line, with the config that step passes, as scripts/osv_ci.py printed it on 2026-11-23
    "bootstrap-requirements.txt": "no un-ignored known vulnerabilities (0 IgnoredVulns entries in tools/osv-scanner.toml)",
    "model-eval-requirements.txt": "no un-ignored known vulnerabilities (0 IgnoredVulns entries in tools/osv-model-eval.toml)",
    "cyberseceval-requirements.txt": "no un-ignored known vulnerabilities (10 IgnoredVulns entries in tools/osv-cyberseceval.toml)",
    "semgrep-requirements.txt": "no un-ignored known vulnerabilities (8 IgnoredVulns entries in tools/osv-semgrep.toml)",
}
OSV_LOCKS = tuple(OSV_CLEAN)
CLEAN = {  # each tool's clean result line, as CI printed it on #327; osv-scanner's, one of OSV_CLEAN
    "line width": "no added line is wider than 150 columns",
    "control characters": "no control character in what the change adds",
    "gitleaks": "no leaks found",
    "semgrep": "clean: 165 accepted finding(s), 0 untriaged",
    "osv-scanner": OSV_CLEAN["semgrep-requirements.txt"],
}
WIDTH_STEP = "Line width of the lines the pull request adds"


def _ci(*, semgrep: str | None = CLEAN["semgrep"], width: tuple[str, ...] = (CLEAN["line width"],),
        skips: tuple[str, ...] = (), mock_skips: tuple[str, ...] = (), osv_locks: tuple[str, ...] = OSV_LOCKS) -> dict[int, str]:
    """The logs of the three jobs whose result lines step 6 reads, as CI writes them: gitleaks, semgrep and four
    osv-scanner scans in L0 (with the seeded fixture's semgrep and osv steps beside them), line width, control
    characters and the tests in the mock review (which skips none), and the skips of a CPython job."""
    l0 = (_step(L0, "gitleaks (locked CLI) on this change's commits", 'python3 scripts/gitleaks_ci.py --base "$BASE_SHA"',
                "  INF no leaks found", CLEAN["gitleaks"])
          + _step(L0, "semgrep must trip on the seeded fixture", "python3 scripts/semgrep_ci.py --target fixtures/vuln-sample",
                  "fixture matches the recording")
          + (_step(L0, "semgrep on this repository", "python3 scripts/semgrep_ci.py --target . --report semgrep.sarif",
                   "  accepted   rule-x  tests/test_x.py:1", semgrep) if semgrep else "")
          + _step(L0, "osv-scanner must report the seeded fixture", "python3 scripts/osv_ci.py --target fixtures/vuln-sample",
                  "requests 2.19.0 reported")
          + "".join(_step(L0, f"osv-scanner on {lock}", f"python3 scripts/osv_ci.py --lockfile tools/{lock}",
                          OSV_CLEAN[lock]) for lock in osv_locks))
    mock = (_step(MOCK, WIDTH_STEP, 'python3 scripts/line_width.py --base "$BASE_SHA"', *width)
            + _step(MOCK, "Control characters in what the pull request adds", 'python3 scripts/control_chars.py --base "$BASE_SHA"',
                    CLEAN["control characters"])
            + _step(MOCK, "Unit and end-to-end tests", "pytest -q -rs", *mock_skips, "2025 passed in 109.94s (0:01:49)"))
    tests = _step(PY312, "Unit and end-to-end tests", "python -m pytest -q -rs",
                  "SKIPPED [1] tests/test_gitleaks_ci.py:46: locked gitleaks not installed under .mara-tools",
                  "SKIPPED [1] tests/test_tools_csp.py:215: real csp-evaluator not installed", *skips,
                  "1989 passed, 2 skipped in 107.67s (0:01:47)")
    return {11: l0, 12: mock, 13: tests}


def _main_l0(semgrep: str) -> str:
    """The log of the L0 job of a run of main, its semgrep step ending on `semgrep`."""
    return _step(L0, "semgrep on this repository", "python3 scripts/semgrep_ci.py --target . --report semgrep.sarif", semgrep)


CHANGE = "     Change run 1"  # the first line under the semgrep line: the Change run, the stand-in's 1
REFERENCE = f"     Reference run 21 ({'b' * 12}): {CLEAN['semgrep']}"  # the line under it when the Reference run is CLEAN's
JOBS = [_check(L0, job=11, workflow="mara-review"), _check(MOCK, job=12, workflow="mara-review"),
        _check(PY312, job=13, workflow="mara-review"), _check("Semgrep OSS")]
CLEAN_RESULTS = [
    f"ok   line width  [{MOCK}]  {CLEAN['line width']}",
    f"ok   control characters  [{MOCK}]  {CLEAN['control characters']}",
    f"ok   gitleaks  [{L0}]  {CLEAN['gitleaks']}",
    f"ok   semgrep  [{L0}]  {CLEAN['semgrep']}",
    CHANGE,
    REFERENCE,
    *[f"ok   osv-scanner  [{L0}]  {line}" for line in OSV_CLEAN.values()],
]
CLEAN_SKIPS = [f"skips  [{MOCK}]  0", f"skips  [{PY312}]  2, each a tool not installed"]


# each check's state, and the exit


def test_every_check_is_one_line_and_all_passing_exits_0(tmp_path, capsys):
    """A skipped check (the human queue's, on every pull request) passes as well."""
    checks = [_check("Semgrep OSS", seconds=9), _check("report build", seconds=145),
              _check("human queue → tickets (G-11)", bucket="skipping", seconds=0), *JOBS[:3]]
    assert _run(_gh(tmp_path, checks, logs=_ci())) == 0
    assert capsys.readouterr().out.splitlines()[:4] == [f"head {'a' * 40}", "pass     Semgrep OSS  9s",
                                                        "pass     report build  2m25s", "skipping human queue → tickets (G-11)  0s"]


def test_a_failed_check_exits_1(tmp_path, capsys):
    """The jobs' logs are clean, so the failed check is what the exit says."""
    assert _run(_gh(tmp_path, [*JOBS[:3], _check("Trivy", bucket="fail", seconds=60)], logs=_ci())) == 1
    assert "fail     Trivy  1m0s" in capsys.readouterr().out.splitlines()


# the Reference run, under the semgrep line


AUDIT = "python.lang.security.audit.dangerous-subprocess-use-audit"
TIMED_OUT = "clean: 164 accepted finding(s), 0 untriaged; 1 timeout(s) (tests/test_m.py)"
MORE = "clean: 166 accepted finding(s), 0 untriaged"


def _hit(uri: str, line: int, rule: str = AUDIT) -> dict:
    return {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}


def _under_semgrep(out: str) -> list[str]:
    """The indented lines under the semgrep result line."""
    lines = out.splitlines()
    i = lines.index(next(line for line in lines if line.startswith("ok   semgrep  ")))
    below = lines[i + 1:]
    return below[:next((n for n, line in enumerate(below) if not line.startswith("     ")), len(below))]


def test_a_reference_run_with_the_same_semgrep_count_is_named_under_the_line_and_nothing_is_downloaded(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci())
    assert _run(gh) == 0
    assert not (gh.parent / "download.count").exists()
    assert _under_semgrep(capsys.readouterr().out) == [CHANGE, REFERENCE]


def test_a_run_of_main_whose_semgrep_line_has_a_timeout_is_passed_over_for_an_older_one_without(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(), main_runs={22: _main_l0(TIMED_OUT), 21: _main_l0(CLEAN["semgrep"])})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [CHANGE, REFERENCE]


def test_differing_counts_print_the_hits_the_change_adds_and_drops_against_the_reference_run(tmp_path, capsys):
    """The Change run is 1, the Reference run 21; the two runs' semgrep.sarif are compared by rule, file and line."""
    kept, added, dropped = _hit("tests/test_x.py", 3), _hit("tests/test_new.py", 39), _hit("scripts/old.py", 7)
    gh = _gh(tmp_path, JOBS, logs=_ci(semgrep=MORE), artifacts={1: [kept, added, added], 21: [kept, dropped, added]})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [
        CHANGE, REFERENCE, f"     + {AUDIT}  tests/test_new.py:39", f"     - {AUDIT}  scripts/old.py:7"]
    assert (gh.parent / "download.count").read_text() == "2"


def test_differing_counts_with_no_hit_that_differs_say_so(tmp_path, capsys):
    same = [_hit("tests/test_x.py", 3)]
    gh = _gh(tmp_path, JOBS, logs=_ci(semgrep=MORE), artifacts={1: same, 21: same})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [CHANGE, REFERENCE, "     no hit differs by rule, file and line"]


def test_no_run_of_main_without_a_timeout_among_its_last_ten_is_said_and_leaves_the_exit(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(), main_runs={22: _main_l0(TIMED_OUT), 23: _main_l0("not a semgrep line")})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [
        CHANGE, "     Reference run: none of main's last 10 completed push runs of mara-review has a semgrep line that is clean with"
        " no timeout"]


def test_a_gh_call_for_the_reference_run_that_fails_is_said_and_leaves_the_exit(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(), main_runs={21: None})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [CHANGE, "     Reference run: gh run view failed: HTTP 410: the log has expired"]


def test_a_download_that_fails_is_said_and_leaves_the_exit(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(semgrep=MORE))
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [
        CHANGE, REFERENCE, "     Reference run 21: gh run download 1 failed: no valid artifacts found to download"]


def test_a_semgrep_sarif_that_cannot_be_read_is_said_and_leaves_the_exit(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(semgrep=MORE), artifacts={1: None, 21: [_hit("tests/test_x.py", 3)]})
    assert _run(gh) == 0
    assert _under_semgrep(capsys.readouterr().out) == [CHANGE, REFERENCE, "     Reference run 21: <download>/change/semgrep.sarif: holds no run"]


def test_a_semgrep_line_that_is_not_clean_prints_nothing_under_it_and_looks_for_no_run_of_main(tmp_path, capsys):
    """Whether such a line fails the run is the result lines' to say (below)."""
    gh = _gh(tmp_path, JOBS, logs=_ci(semgrep="1 untriaged finding(s)"))
    _run(gh)
    assert not (gh.parent / "run-list.count").exists()
    assert "Change run" not in capsys.readouterr().out


# the result lines and the skips


def test_each_result_line_is_printed_once_with_its_job_and_the_skips_a_tool_not_installed_explains(tmp_path, capsys):
    """The seeded fixture's steps are not results on the change; each pytest job's skipped tests are counted, none
    being 0, and every skip a tool not being installed explains is left unprinted."""
    assert _run(_gh(tmp_path, JOBS, logs=_ci())) == 0
    assert capsys.readouterr().out.splitlines()[5:] == [*CLEAN_RESULTS, *CLEAN_SKIPS]


def test_a_result_line_no_job_log_holds_is_named_and_exits_1(tmp_path, capsys):
    assert _run(_gh(tmp_path, JOBS, logs=_ci(semgrep=None))) == 1
    assert "MISS semgrep  no result line in any job log" in capsys.readouterr().out.splitlines()


def test_fewer_osv_scans_than_ci_runs_are_named_and_exit_1(tmp_path, capsys):
    """L0 scans four hash-locked closures; three clean ones are not a clean run."""
    assert _run(_gh(tmp_path, JOBS, logs=_ci(osv_locks=OSV_LOCKS[:3]))) == 1
    out = capsys.readouterr().out.splitlines()
    assert [line for line in out if line.startswith("ok   osv-scanner")] == [f"ok   osv-scanner  [{L0}]  {OSV_CLEAN[lock]}" for lock in OSV_LOCKS[:3]]
    assert "MISS osv-scanner  3 of 4 result lines found" in out


def test_a_result_line_that_is_not_clean_names_its_step_and_exits_1(tmp_path, capsys):
    """A script with hits prints them, then its summary: the summary is the result line, and the step is named, so its
    log is read."""
    summary = "1 added line(s) wider than 150 columns"
    assert _run(_gh(tmp_path, JOBS, logs=_ci(width=("new.py:3: 166 columns", summary)))) == 1
    out = capsys.readouterr().out.splitlines()
    i = out.index(f"NOT  line width  [{MOCK}]  {summary}")
    assert out[i + 1] == f"     read the step: {WIDTH_STEP}"


def test_a_step_that_printed_nothing_is_not_ok_and_exits_1(tmp_path, capsys):
    assert _run(_gh(tmp_path, JOBS, logs=_ci(width=()))) == 1
    out = capsys.readouterr().out.splitlines()
    i = out.index(f"NOT  line width  [{MOCK}]  (the step printed nothing)")
    assert out[i + 1] == f"     read the step: {WIDTH_STEP}"


def test_a_skip_no_missing_tool_explains_is_printed_whole_and_exits_1(tmp_path, capsys):
    skip = "SKIPPED [1] tests/test_web_server.py:88: needs a port the runner refused"
    assert _run(_gh(tmp_path, JOBS, logs=_ci(skips=(skip,)))) == 1
    assert capsys.readouterr().out.splitlines()[-2:] == [f"skips  [{PY312}]  3, 1 no missing tool explains:", f"  {skip}"]


def test_a_tool_not_installed_in_a_job_that_installs_the_tools_is_printed_whole_and_exits_1(tmp_path, capsys):
    """The mock review installs the tools so that their tests run: a skip for one not being installed is to be read."""
    skip = "SKIPPED [1] tests/test_gitleaks_ci.py:46: locked gitleaks not installed under .mara-tools"
    assert _run(_gh(tmp_path, JOBS, logs=_ci(mock_skips=(skip,)))) == 1
    out = capsys.readouterr().out.splitlines()
    i = out.index(f"skips  [{MOCK}]  1, 1 no missing tool explains:")
    assert out[i + 1] == f"  {skip}"


def test_the_jobs_that_install_the_tools_are_jobs_of_the_workflow_that_install_them():
    jobs = yaml.safe_load((ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8"))["jobs"]
    installing = {job.get("name") for job in jobs.values()
                  if any(step.get("name", "").startswith("Install the locked") for step in job.get("steps", []))}
    assert set(pr_checks.TOOLS_INSTALLED) <= installing and pr_checks.TOOLS_INSTALLED


def test_the_skips_counted_are_tests_not_lines(tmp_path, capsys):
    """pytest -rs folds skips of one reason into one line: SKIPPED [3] is three tests."""
    skip = "SKIPPED [3] tests/test_semgrep_ci.py:204: locked semgrep + semgrep-rules not installed under .mara-tools"
    assert _run(_gh(tmp_path, JOBS, logs=_ci(skips=(skip,)))) == 0
    assert capsys.readouterr().out.splitlines()[-1] == f"skips  [{PY312}]  5, each a tool not installed"


def test_a_job_whose_log_cannot_be_read_is_named_and_the_rest_is_still_printed(tmp_path, capsys):
    logs = _ci()
    del logs[13]
    assert _run(_gh(tmp_path, JOBS, logs=logs)) == 1
    out = capsys.readouterr().out.splitlines()
    i = out.index(f"LOG  {PY312}  log unavailable: HTTP 410: the log has expired")
    assert out[i + 1:i + 1 + len(CLEAN_RESULTS)] == CLEAN_RESULTS  # named before the result lines it leaves out


@pytest.mark.parametrize("tool", list(CLEAN))
def test_a_clean_result_line_is_what_its_script_prints(tool):
    """RESULTS copies each script's clean line; the copy must still be in the script, and match what CI printed."""
    entry = next(r for r in pr_checks.RESULTS if r.tool == tool)
    assert entry.printed in (ROOT / entry.script).read_text(encoding="utf-8")
    assert entry.printed in CLEAN[tool] and entry.clean.search(CLEAN[tool])


@pytest.mark.parametrize("line, clean", [
    ("clean: 168 accepted finding(s), 0 untriaged", True),
    ("clean: 167 accepted finding(s), 0 untriaged; 1 timeout(s) (tests/test_model_eval.py)", True),
    ("clean: 166 accepted finding(s), 0 untriaged; 3 timeout(s) (a.py, b.py)", True),
    ("clean: 166 accepted finding(s), 0 untriaged; 1 rule(s) timed out (a.py)", False),
    ("clean: 167 accepted finding(s), 0 untriaged; nothing else", False),
    ("UNTRIAGED: 1 finding(s) not covered by tools/semgrep-triage.yaml (fix the code, or add an entry with a reason)", False),
], ids=["no-timeout", "one-timeout", "timeouts-on-two-files", "rules-not-timeouts", "other-tail", "untriaged"])
def test_semgrep_s_clean_line_is_clean_with_or_without_the_rules_that_timed_out(line, clean):
    """A scan that timed out still completes and passes: CI can time out, and its clean line is still `ok`."""
    entry = next(r for r in pr_checks.RESULTS if r.tool == "semgrep")
    assert bool(entry.clean.search(line)) is clean


# a workflow a pull request triggers that did not run


WORKFLOWS = {
    "docs-check.yml": "name: docs-check\non:\n  pull_request:\n    paths: [\"docs/**\"]\njobs:\n  report:\n"
                      "    name: report build, word count, citations\n    runs-on: ubuntu-latest\n",
    "governance.yml": "name: governance-check\non:\n  schedule: [{cron: '0 3 * * 1'}]\njobs:\n  check:\n    runs-on: ubuntu-latest\n",
    "mara-review.yml": "name: mara-review\non: [pull_request, push]\njobs:\n  l0:\n    name: L0 deterministic tools\n",
}
NOT_RUN = "not run  docs-check (report build, word count, citations)  required by "


def test_a_workflow_a_pull_request_triggers_that_did_not_run_is_listed_with_no_ruleset_requiring_it(tmp_path, capsys):
    """docs-check runs only when its paths change, so a change outside them has no such check; no ruleset requires it,
    so the merge is not held. A workflow no pull request triggers (governance-check) is not expected, and not listed."""
    assert _run(_gh(tmp_path, JOBS, logs=_ci(), workflows=WORKFLOWS)) == 0
    assert capsys.readouterr().out.splitlines()[-1] == NOT_RUN + "no ruleset"


def test_a_workflow_that_did_not_run_and_a_ruleset_requires_exits_1(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(), workflows=WORKFLOWS, rulesets={"R1": ["report build, word count, citations"]})
    assert _run(gh) == 1
    assert capsys.readouterr().out.splitlines()[-1] == NOT_RUN + "R1"


def test_a_ruleset_not_enforced_requires_nothing(tmp_path, capsys):
    gh = _gh(tmp_path, JOBS, logs=_ci(), workflows=WORKFLOWS, disabled=("R2",),
             rulesets={"R1": [], "R2": ["report build, word count, citations"]})
    assert _run(gh) == 0
    assert capsys.readouterr().out.splitlines()[-1] == NOT_RUN + "no ruleset"


# waiting, the head moving, gh failing


PENDING = [{**c, "bucket": "pending", "state": "IN_PROGRESS", "completedAt": None} for c in JOBS[:1]] + JOBS[1:]


def test_while_a_check_is_pending_it_waits_and_prints_only_the_final_result(tmp_path, capsys):
    """Nothing is printed on stdout until no check is pending, so what is there is final; the waiting is said on
    stderr."""
    assert _run(_gh(tmp_path, PENDING, PENDING, JOBS, logs=_ci())) == 0
    captured = capsys.readouterr()
    out = captured.out.splitlines()
    assert out[0] == f"head {'a' * 40}" and out.count(out[0]) == 1
    assert [line for line in out if line.startswith("pending")] == []
    assert captured.err.splitlines() == ["waiting: 1 of 4 checks pending"] * 2


def test_a_pull_request_with_no_check_reported_yet_is_waited_on(tmp_path, capsys):
    """Step 6 runs it right after the push, before GitHub has reported any check: gh says so, and it waits."""
    assert _run(_gh(tmp_path, "none", JOBS, logs=_ci())) == 0
    captured = capsys.readouterr()
    assert captured.err.splitlines() == ["waiting: no check reported yet"]
    assert captured.out.splitlines()[5:] == [*CLEAN_RESULTS, *CLEAN_SKIPS]


def test_a_head_that_moves_while_it_waits_stops_it_with_exit_1(tmp_path, capsys):
    assert _run(_gh(tmp_path, PENDING, heads=["a" * 40, "b" * 40], logs=_ci())) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines()[-1] == f"ERROR: the head moved from {'a' * 40} to {'b' * 40}; run it again for the new head"


def test_a_head_that_moved_before_the_checks_it_read_stops_it_with_exit_1(tmp_path, capsys):
    """No check was pending, but the checks read are those of a later push."""
    assert _run(_gh(tmp_path, JOBS, heads=["a" * 40, "b" * 40], logs=_ci())) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.splitlines() == [f"ERROR: the head moved from {'a' * 40} to {'b' * 40}; run it again for the new head"]


def test_an_interrupted_wait_exits_130_as_gh_pr_checks_does_and_prints_no_traceback(tmp_path, capsys, monkeypatch):
    def interrupt(seconds):
        raise KeyboardInterrupt
    monkeypatch.setattr(pr_checks.time, "sleep", interrupt)  # Ctrl-C while it waits between two polls
    assert _run(_gh(tmp_path, PENDING, logs=_ci())) == 130
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.splitlines()[-1] == "interrupted while waiting"


def test_gh_failing_exits_2_and_names_the_call(tmp_path, capsys):
    gh = tmp_path / "gh-that-fails"
    gh.write_text(f"#!{sys.executable}\nimport sys\nsys.exit('HTTP 404: Not Found')\n")
    gh.chmod(0o755)
    assert pr_checks.main(["327", "--gh", str(gh), "--interval", "0", "--workflows", str(tmp_path)]) == 2
    assert capsys.readouterr().err.splitlines() == ["ERROR: gh pr view failed: HTTP 404: Not Found"]


def test_a_gh_that_cannot_be_started_exits_2_and_names_the_call(tmp_path, capsys):
    gh = tmp_path / "no-such-gh"
    assert pr_checks.main(["327", "--gh", str(gh), "--interval", "0", "--workflows", str(tmp_path)]) == 2
    assert capsys.readouterr().err.splitlines() == [f"ERROR: gh pr view failed: [Errno 2] No such file or directory: '{gh}'"]
