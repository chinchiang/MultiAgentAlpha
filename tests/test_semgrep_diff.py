"""scripts/semgrep_diff.py: two semgrep SARIF files, CI's or scripts/check_local.py's, compared hit by hit (rule, file,
line), with each file's timeouts, through main and through compare."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import semgrep_diff  # noqa: E402

AUDIT = "python.lang.security.audit.dangerous-subprocess-use-audit"
TAINT = "python.lang.security.audit.dangerous-subprocess-use-tainted-env-args"


def _result(rule: str, uri: str, line: int) -> dict:
    return {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}]}


def _timeout(rule: str, file: str) -> dict:
    """A timeout as semgrep records it: the rule, with the prefix of where the rules are installed, and the file in the
    text alone."""
    return {"descriptor": {"id": "Timeout"}, "level": "warning",
            "message": {"text": f"Timeout when running mara-tools.semgrep-rules.{rule} on {file}:\n "}}


def _sarif(path: Path, *results: dict, notes: tuple[dict, ...] = ()) -> Path:
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}, "results": list(results),
                                         "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": list(notes)}]}]}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _main(capsys, *paths: Path) -> tuple[int, list[str]]:
    code = semgrep_diff.main([str(p) for p in paths])
    return code, capsys.readouterr().out.splitlines()


def test_a_file_compared_with_itself_differs_in_nothing(tmp_path, capsys):
    a = _sarif(tmp_path / "a.sarif", _result(AUDIT, "tests/test_x.py", 3), _result(TAINT, "scripts/y.py", 9))
    assert _main(capsys, a, a) == (0, [f"{a}: 2 hit(s)", f"{a}: 2 hit(s)", "no hit differs by rule, file and line"])


def test_a_rule_named_with_the_prefix_of_where_the_rules_are_installed_is_the_same_rule(tmp_path, capsys):
    """A scan that left the rule ids as semgrep wrote them, and one whose ids semgrep_ci.py made canonical."""
    local = _sarif(tmp_path / "local.sarif", _result(f"mara-tools.semgrep-rules.{AUDIT}", "tests/test_x.py", 3))
    ci = _sarif(tmp_path / "ci.sarif", _result(AUDIT, "tests/test_x.py", 3))
    assert _main(capsys, local, ci)[1][2:] == ["no hit differs by rule, file and line"]


def test_a_hit_one_file_holds_and_the_other_does_not_is_named_once_on_its_side(tmp_path, capsys):
    """The same rule twice on one line counts twice: a hit is dropped when the other holds it fewer times."""
    main = _sarif(tmp_path / "main.sarif", _result(AUDIT, "tests/test_x.py", 3), _result(AUDIT, "tests/test_x.py", 3),
                  _result(TAINT, "scripts/y.py", 9))
    change = _sarif(tmp_path / "change.sarif", _result(AUDIT, "tests/test_x.py", 3), _result(AUDIT, "tests/test_z.py", 39),
                    _result(TAINT, "scripts/y.py", 9))
    assert _main(capsys, main, change) == (0, [
        f"{main}: 3 hit(s)", f"{change}: 3 hit(s)",
        f"only in {change}: {AUDIT}  tests/test_z.py:39", f"only in {main}: {AUDIT}  tests/test_x.py:3"])


def test_each_timeout_of_either_file_is_named_with_its_rule_and_file(tmp_path, capsys):
    a = _sarif(tmp_path / "a.sarif", _result(TAINT, "tests/test_m.py", 171))
    b = _sarif(tmp_path / "b.sarif", notes=(_timeout(TAINT, "tests/test_m.py"),))
    assert _main(capsys, a, b)[1] == [f"{a}: 1 hit(s)", f"{b}: 0 hit(s), 1 timeout(s)",
                                      f"only in {a}: {TAINT}  tests/test_m.py:171", f"timeout in {b}: {TAINT} on tests/test_m.py"]


def test_compare_gives_the_counts_the_hits_only_in_each_and_the_timeouts_of_each(tmp_path):
    a = _sarif(tmp_path / "a.sarif", _result(AUDIT, "tests/test_x.py", 3), notes=(_timeout(TAINT, "tests/test_m.py"),))
    b = _sarif(tmp_path / "b.sarif", _result(TAINT, "scripts/y.py", 9))
    assert semgrep_diff.compare(a, b) == semgrep_diff.Comparison(
        counts=(1, 1), only_a=[(AUDIT, "tests/test_x.py", 3)], only_b=[(TAINT, "scripts/y.py", 9)],
        timeouts_a=[(TAINT, "tests/test_m.py")], timeouts_b=[])


def test_a_file_that_is_not_json_not_shaped_as_sarif_with_no_run_or_missing_exits_2_naming_it(tmp_path, capsys):
    good = _sarif(tmp_path / "good.sarif")
    (tmp_path / "text.sarif").write_text("not json", encoding="utf-8")
    (tmp_path / "shape.sarif").write_text(json.dumps({"runs": [{"results": [{"locations": "x"}]}]}), encoding="utf-8")
    (tmp_path / "no-run.sarif").write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
    for bad in ("text.sarif", "shape.sarif", "no-run.sarif", "missing.sarif"):
        code = semgrep_diff.main([str(good), str(tmp_path / bad)])
        out, err = capsys.readouterr()
        assert code == 2 and out == "" and err.startswith(f"ERROR: {tmp_path / bad}: "), (bad, err)
