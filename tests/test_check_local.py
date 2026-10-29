"""scripts/check_local.py: six of the checks a pull request's CI runs, and on request its three osv-scanner scans, run
before the push with every output kept."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_local  # noqa: E402

WORKFLOW = (ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8")


def test_the_lint_is_the_one_ci_runs():
    assert f"run: ruff check {' '.join(check_local.RUFF_PATHS)}\n" in WORKFLOW


def test_the_osv_scans_are_the_three_closure_scans_ci_runs_and_report_into_the_logs(tmp_path):
    """L0 scans each hash-locked closure with its own config; a lock or config changed there and not here fails."""
    def without_report(args):
        i = args.index("--report")
        return tuple(args[:i] + args[i + 2:]), args[i + 1]

    ci = {without_report(line.split())[0] for line in re.findall(r"run: python3 scripts/osv_ci\.py (--lockfile .*)\n", WORKFLOW)}
    here = set()
    for name in check_local.GROUPS["osv"]:
        argv, env, first = check_local.CHECKS[name](argparse.Namespace(logs=tmp_path))
        args, report = without_report(argv[argv.index(str(ROOT / "scripts" / "osv_ci.py")) + 1:])
        assert report == str(tmp_path / f"{name}.sarif") and env == {} and first is None
        here.add(args)
    assert len(ci) == 3 and here == ci


def test_the_semgrep_check_is_l0s_repository_scan_reporting_into_the_logs(tmp_path):
    """The step that failed #196's first CI run: semgrep on the repository against tools/semgrep-triage.yaml."""
    [ci] = re.findall(r"run: python3 scripts/semgrep_ci\.py (--target \. .*)\n", WORKFLOW)
    ci_args = ci.split()
    i = ci_args.index("--report")
    argv, env, first = check_local.CHECKS["semgrep"](argparse.Namespace(logs=tmp_path))
    here = argv[argv.index(str(ROOT / "scripts" / "semgrep_ci.py")) + 1:]
    j = here.index("--report")
    assert here[:j] + here[j + 2:] == ci_args[:i] + ci_args[i + 2:]
    assert here[j + 1] == str(tmp_path / "semgrep.sarif") and env == {} and first is None


def test_the_suite_runs_with_the_options_ci_runs_it_with():
    """CI lists the skipped tests (-rs): a tool test skipping for a missing binary is seen, not passed over."""
    ci = set(re.findall(r"run: pytest(.*)\n", WORKFLOW))
    argv, env, _ = check_local.CHECKS["pytest"](None)
    assert len(ci) == 1 and argv[argv.index("pytest") + 1:] == ci.pop().split()
    assert env == {"GITHUB_ACTIONS": "true"}


def test_the_type_check_environment_is_the_closure_the_ci_type_check_job_installs_in_its_order():
    """The type-check job (CPython 3.12) installs three hash-pinned requirement files, the package itself between the
    second and the third; a local environment built from anything else would type-check against other versions."""
    job = WORKFLOW[:WORKFLOW.index("Type check (mypy")]
    steps = job[job.rindex("- name: Install"):]
    installed = re.findall(r"-r (tools/\S+\.txt)|(-e \.)", steps)
    assert [r or e for r, e in installed] == [*check_local.TYPECHECK_REQUIREMENTS[:2], "-e .", check_local.TYPECHECK_REQUIREMENTS[2]]
    assert "run: python3 -m mypy\n" in WORKFLOW


def test_a_failed_check_keeps_its_whole_output_and_the_summary_names_its_log(tmp_path, monkeypatch, capsys):
    """A failure read off a truncated run's last line could not be named afterwards; the log holds all of it."""
    lines = "; ".join(f"print('line {i}')" for i in range(50))
    monkeypatch.setattr(check_local, "CHECKS", {
        "passes": lambda a: ([sys.executable, "-c", "print('all good')"], {}, None),
        "fails": lambda a: ([sys.executable, "-c", f"{lines}; raise SystemExit(3)"], {}, None),
    })
    assert check_local.main(["--only", "passes", "fails", "--logs", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "ok   passes   all good" in out and "FAIL fails    line 49" in out
    assert f"failed: {tmp_path / 'fails.log'}" in out and "passes.log" not in out.split("logs:")[0].split("failed:", 1)[-1]
    logged = (tmp_path / "fails.log").read_text(encoding="utf-8").splitlines()
    assert logged[0].startswith("$ ") and logged[1:] == [f"line {i}" for i in range(50)], "the command, then all it printed"
    assert check_local.main(["--only", "passes", "--logs", str(tmp_path / "again")]) == 0


def test_a_check_that_cannot_be_set_up_fails_with_why(tmp_path, monkeypatch, capsys):
    def broken(a):
        raise OSError("python3.12 not found")

    monkeypatch.setattr(check_local, "CHECKS", {"broken": broken})
    assert check_local.main(["--only", "broken", "--logs", str(tmp_path)]) == 1
    assert "could not set up broken: python3.12 not found" in (tmp_path / "broken.log").read_text(encoding="utf-8")
    assert "FAIL broken" in capsys.readouterr().out


def _recording(monkeypatch, names):
    """CHECKS replaced by checks that pass, each recording its name when it runs; the names in the order they ran."""
    ran = []

    def check(name):
        def set_up(a):
            ran.append(name)
            return [sys.executable, "-c", "pass"], {}, None
        return set_up

    monkeypatch.setattr(check_local, "CHECKS", {name: check(name) for name in names})
    return ran


def test_a_repeated_only_runs_every_check_it_names_once(tmp_path, monkeypatch):
    """`--only a --only b` once ran b alone; a check named twice runs once."""
    ran = _recording(monkeypatch, ["a", "b", "c"])
    assert check_local.main(["--only", "b", "--only", "a", "--logs", str(tmp_path / "1")]) == 0
    assert check_local.main(["--only", "a", "--only", "a", "--logs", str(tmp_path / "2")]) == 0
    assert ran == ["b", "a", "a"]


NINE = ["ruff", "lines", "mypy", "semgrep", "pytest", "gitleaks", "osv-runtime", "osv-model-eval", "osv-semgrep"]


def test_only_osv_runs_the_three_osv_scans(tmp_path, monkeypatch):
    """`osv` names L0's three osv-scanner closure scans; a scan named again runs once."""
    ran = _recording(monkeypatch, NINE)
    assert check_local.main(["--only", "osv", "--logs", str(tmp_path / "1")]) == 0
    assert ran == ["osv-runtime", "osv-model-eval", "osv-semgrep"]
    ran.clear()
    assert check_local.main(["--only", "osv", "--only", "osv-semgrep", "--only", "ruff", "--logs", str(tmp_path / "2")]) == 0
    assert ran == ["osv-runtime", "osv-model-eval", "osv-semgrep", "ruff"]


def test_without_only_the_six_checks_run_in_their_order_and_no_osv_scan(tmp_path, monkeypatch):
    """The osv scans need the network: they run when named, never by default. semgrep needs none, so it runs by default,
    after the static checks and before the suite."""
    ran = _recording(monkeypatch, NINE)
    assert check_local.main(["--logs", str(tmp_path)]) == 0
    assert ran == ["ruff", "lines", "mypy", "semgrep", "pytest", "gitleaks"]


def test_only_semgrep_runs_the_semgrep_check_alone(tmp_path, monkeypatch):
    ran = _recording(monkeypatch, NINE)
    assert check_local.main(["--only", "semgrep", "--logs", str(tmp_path)]) == 0
    assert ran == ["semgrep"]


def _git(repo, *args):
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, text=True, check=True).stdout


def test_the_uncommitted_changes_are_what_git_status_lists(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "base")
    assert check_local.uncommitted(repo) == []
    (repo / "a.py").write_text("a = 2\n", encoding="utf-8")
    (repo / "b.py").write_text("b = 1\n", encoding="utf-8")
    assert check_local.uncommitted(repo) == [" M a.py", "?? b.py"]


def test_uncommitted_changes_are_warned_of_when_a_check_that_reads_commits_ran(tmp_path, monkeypatch, capsys):
    """gitleaks scans the branch's commits: a run before the commit passes it without having seen the change."""
    monkeypatch.setattr(check_local, "CHECKS", {name: (lambda a: ([sys.executable, "-c", "print('ok')"], {}, None))
                                                for name in ("ruff", "gitleaks")})
    monkeypatch.setattr(check_local, "uncommitted", lambda root: [" M a.py", "?? b.py"])
    assert check_local.main(["--only", "ruff", "gitleaks", "--logs", str(tmp_path / "1")]) == 0, "a warning, not a failure"
    out = capsys.readouterr().out
    assert "WARNING: 2 uncommitted change(s), which gitleaks did not see: it reads the branch's commits" in out
    assert "--only gitleaks" in out
    assert check_local.main(["--only", "ruff", "--logs", str(tmp_path / "2")]) == 0
    assert "WARNING" not in capsys.readouterr().out, "ruff read the working tree"
    monkeypatch.setattr(check_local, "uncommitted", lambda root: [])
    assert check_local.main(["--only", "gitleaks", "--logs", str(tmp_path / "3")]) == 0
    assert "WARNING" not in capsys.readouterr().out


def test_the_line_width_check_reads_commits_too_and_is_warned_of_with_gitleaks(tmp_path, monkeypatch, capsys):
    """scripts/line_width.py reads the lines the branch's commits add, so an uncommitted line is not measured either."""
    monkeypatch.setattr(check_local, "CHECKS", {name: (lambda a: ([sys.executable, "-c", "print('ok')"], {}, None))
                                                for name in ("ruff", "lines", "gitleaks")})
    monkeypatch.setattr(check_local, "uncommitted", lambda root: [" M a.py"])
    assert check_local.main(["--only", "ruff", "lines", "gitleaks", "--logs", str(tmp_path / "1")]) == 0
    out = capsys.readouterr().out
    assert "1 uncommitted change(s), which lines, gitleaks did not see: they read the branch's commits" in out
    assert "--only lines gitleaks" in out
    assert check_local.main(["--only", "lines", "--logs", str(tmp_path / "2")]) == 0
    assert "which lines did not see: it reads" in capsys.readouterr().out


def test_a_failed_suite_names_its_failed_tests_in_the_summary(tmp_path, monkeypatch, capsys):
    """With -rs pytest's short summary lists skips only, so the summary reads the names off the log's FAILURES and ERRORS
    sections: a failed run is named without opening its log."""
    suite = tmp_path / "suite" / "test_some.py"
    suite.parent.mkdir()
    suite.write_text("import pytest\n\n\n@pytest.fixture\ndef broken():\n    raise RuntimeError('no')\n\n\n"
                     "def test_passes():\n    assert True\n\n\ndef test_fails():\n    assert 1 == 2\n\n\n"
                     "def test_errors(broken):\n    pass\n\n\nclass TestGroup:\n    def test_fails_too(self):\n        assert False\n",
                     encoding="utf-8")
    monkeypatch.setattr(check_local, "CHECKS", {"pytest": lambda a: ([sys.executable, "-m", "pytest", "-q", "-rs", "-p", "no:cacheprovider",
                                                                     str(suite)], {}, None)})
    monkeypatch.setattr(check_local, "uncommitted", lambda root: [])
    assert check_local.main(["--only", "pytest", "--logs", str(tmp_path / "logs")]) == 1
    out = capsys.readouterr().out
    assert "FAIL pytest   2 failed, 1 passed, 1 error" in out
    assert "  failed tests: test_fails, TestGroup.test_fails_too; errors: ERROR at setup of test_errors" in out


def test_only_the_headers_of_the_failures_and_errors_sections_name_tests():
    """A traceback through several frames separates them with `_ _ _` lines, and -rP adds a PASSES section with headers of
    its own: neither names a failed test."""
    log = ("=== PASSES ===\n____ test_passes ____\n=== FAILURES ===\n____ test_deep ____\n    def test_deep():\n"
           "_ _ _ _ _ _ _ _\n    def helper():\n=== ERRORS ===\n____ ERROR collecting tests/test_x.py ____\n"
           "=== short test summary info ===\n")
    assert check_local.failed_tests(log) == (["test_deep"], ["ERROR collecting tests/test_x.py"])
    assert check_local.failed_tests("....\n4 passed in 0.1s\n") == ([], [])
