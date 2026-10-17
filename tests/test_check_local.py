"""scripts/check_local.py: four of the checks a pull request's CI runs, run before the push with every output kept."""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_local  # noqa: E402

WORKFLOW = (ROOT / ".github" / "workflows" / "mara-review.yml").read_text(encoding="utf-8")


def test_the_lint_is_the_one_ci_runs():
    assert f"run: ruff check {' '.join(check_local.RUFF_PATHS)}\n" in WORKFLOW


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
