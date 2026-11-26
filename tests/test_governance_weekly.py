"""scripts/governance_weekly.py, the Weekly governance check (GLOSSARY.md), driven through main: the MARA workspace is a
directory below tmp_path (MARA_HOME) holding the report.json files the Pilot poller writes below pilot/reviews/, and
GitHub a stand-in gh the test writes (--gh) that records each call (tests/SEAMS.md, "The weekly governance check")."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import governance_weekly  # noqa: E402

REPO = "org/private"
CONFIG = ROOT / "config" / "mara.mock.yaml"


def _report(ws: Path, pull: str, head: str, generated_at: object, tokens_in: int | None, tokens_out: int | None) -> Path:
    """A report.json where the Pilot poller puts it, with `generated_at` and the token counts (left out when None)."""
    audit = {k: v for k, v in (("input_tokens", tokens_in), ("output_tokens", tokens_out)) if v is not None}
    path = ws / "pilot" / "reviews" / pull / head / "report.json"
    path.parent.mkdir(parents=True)
    report = {"bias_audit": audit} | ({} if generated_at is None else {"generated_at": generated_at})
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _weekly(tmp_path: Path, monkeypatch, *args: str) -> int:
    """main with --gh a stand-in that refuses every call, unless the test gives its own: no run reaches the real gh."""
    monkeypatch.setenv("MARA_HOME", str(tmp_path / "ws"))
    if "--gh" not in args:
        refusing = tmp_path / "no-gh"
        refusing.write_text('#!/bin/sh\necho "stand-in gh: no call expected: $*" >&2\nexit 1\n', encoding="utf-8")
        refusing.chmod(0o755)
        args = ("--gh", str(refusing), *args)
    return governance_weekly.main(["--repo", REPO, "--config", str(CONFIG), "--date", "2026-11-26", *args])


FAKE_GH = '''
"""A stand-in gh: records each call and its stdin, answers `issue list` from open.json beside it."""
import json, sys
from pathlib import Path

here = Path(__file__).parent
args = sys.argv[1:]
with (here / "calls.jsonl").open("a") as f:
    f.write(json.dumps({"args": args, "stdin": sys.stdin.read() if "-" in args else None}) + "\\n")
if args[:2] == ["issue", "list"]:
    print((here / "open.json").read_text())
elif args[:2] == ["issue", "create"]:
    print("https://github.com/org/private/issues/12")
elif args[:2] == ["issue", "comment"] and (here / "fail-comment").exists():
    sys.exit("stand-in gh: comment refused")
elif args[:2] not in (["label", "create"], ["issue", "comment"]):
    sys.exit(f"stand-in gh: no answer for {args}")
'''


def _gh(tmp_path: Path, open_issues: str) -> Path:
    gh = tmp_path / "gh-stand-in" / "gh.py"
    gh.parent.mkdir()
    gh.write_text(FAKE_GH, encoding="utf-8")
    (gh.parent / "open.json").write_text(open_issues, encoding="utf-8")
    return gh


def _calls(gh: Path) -> list[dict]:
    calls = gh.parent / "calls.jsonl"
    return [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()] if calls.exists() else []


def _run(tmp_path, monkeypatch, gh: Path, *args: str) -> int:
    exe = tmp_path / "gh"
    exe.write_text(f"#!/bin/sh\nexec {sys.executable} {gh} \"$@\"\n", encoding="utf-8")
    exe.chmod(0o755)
    return _weekly(tmp_path, monkeypatch, "--gh", str(exe), *args)


# first: every test below that runs --dry-run fails as well on a dry run that posts
def test_a_dry_run_prints_the_comment_and_calls_no_gh(tmp_path, monkeypatch, capsys):
    gh = _gh(tmp_path, '[{"number": 7}]')
    assert _run(tmp_path, monkeypatch, gh, "--dry-run") == 0
    assert _calls(gh) == []
    assert "治理合規檢查（2026-11-26）" in capsys.readouterr().out


def test_the_token_line_sums_the_reports_of_the_seven_days_before_the_date_and_counts_one_with_no_counts_as_0(
        tmp_path, monkeypatch, capsys):
    ws = tmp_path / "ws"
    _report(ws, "1", "a" * 40, "2026-11-26T01:00:00+00:00", 77777, 7777)  # the day of --date: the next week's
    _report(ws, "1", "b" * 40, "2026-11-25T23:00:00+00:00", 1000, 100)  # the day before
    _report(ws, "2", "c" * 40, "2026-11-19T00:00:00+00:00", 100, 10)  # the first of the seven days
    _report(ws, "2", "d" * 40, "2026-11-18T23:59:59+00:00", 99999, 9999)  # the week before
    _report(ws, "4", "a" * 40, "2026-11-19T05:00:00+09:00", 88888, 8888)  # 2026-11-18 in UTC
    _report(ws, "3", "e" * 40, "2026-11-22T00:00:00+00:00", None, None)  # no token counts: 0
    assert _weekly(tmp_path, monkeypatch, "--dry-run") == 0
    assert "本週 token（2026-11-19 至 2026-11-25，3 份報告）：輸入 1100、輸出 110" in capsys.readouterr().out


def test_a_report_that_cannot_be_read_or_is_not_of_the_shape_read_is_left_out_and_counted_on_the_line(tmp_path, monkeypatch,
                                                                                                         capsys):
    ws = tmp_path / "ws"
    _report(ws, "1", "a" * 40, "2026-11-25T01:00:00+00:00", 100, 10)
    _report(ws, "1", "b" * 40, None, 1000, 100)  # no generated_at
    _report(ws, "2", "c" * 40, "2026-11-25T01:00:00", 1000, 100)  # no time zone
    _report(ws, "2", "d" * 40, 20261125, 1000, 100)  # not a time
    _report(ws, "3", "e" * 40, "2026-11-25T01:00:00+00:00", 1, 1).write_text("not json", encoding="utf-8")
    _report(ws, "3", "f" * 40, "2026-11-25T01:00:00+00:00", 1, 1).write_text("[]", encoding="utf-8")
    _report(ws, "5", "a" * 40, "2026-11-25T01:00:00+00:00", 1, 1).write_text(
        '{"generated_at": "2026-11-25T01:00:00+00:00", "bias_audit": "none"}', encoding="utf-8")
    assert _weekly(tmp_path, monkeypatch, "--dry-run") == 0
    out = capsys.readouterr().out
    assert ("（2026-11-19 至 2026-11-25，1 份報告）：輸入 100、輸出 10；"
            "6 份報告讀不到、形狀不對或沒有帶時區的 `generated_at`，未計入") in out, out


def test_the_comment_names_the_weekly_script_and_no_exit_code(tmp_path, monkeypatch, capsys):
    assert _weekly(tmp_path, monkeypatch, "--dry-run") == 0
    out = capsys.readouterr().out
    assert "本檔由 `scripts/governance_weekly.py` 產生" in out, out
    assert "governance_check.py` 產生" not in out and "結束碼" not in out and "非零結束" not in out, out


def test_the_check_reads_the_workspace_of_mara_home(tmp_path, monkeypatch, capsys):
    ws = tmp_path / "ws"
    (ws / "pilot").mkdir(parents=True)
    (ws / "pilot" / "sync.json").write_text('{"at": "2026-11-26T03:00:00+00:00", "repo": "org/tickets", "exit": 0}',
                                            encoding="utf-8")
    assert _weekly(tmp_path, monkeypatch, "--dry-run") == 0
    assert "Sync record `pilot/sync.json`：2026-11-26T03:00:00+00:00 對 org/tickets 同步" in capsys.readouterr().out


def test_the_comment_is_posted_to_every_open_tracking_issue_of_the_repository(tmp_path, monkeypatch, capsys):
    _report(tmp_path / "ws", "1", "a" * 40, "2026-11-25T01:00:00+00:00", 100, 10)
    gh = _gh(tmp_path, '[{"number": 7}, {"number": 9}]')
    assert _run(tmp_path, monkeypatch, gh) == 0
    calls = _calls(gh)
    assert calls[0]["args"][:3] == ["label", "create", "governance-check"] and "--repo" in calls[0]["args"]
    listed = calls[1]["args"]
    assert listed[:2] == ["issue", "list"] and listed[listed.index("--repo") + 1] == REPO
    assert listed[listed.index("--label") + 1] == "governance-check" and listed[listed.index("--state") + 1] == "open"
    comments = [c for c in calls if c["args"][:2] == ["issue", "comment"]]
    assert [(c["args"][2], c["args"][c["args"].index("--repo") + 1]) for c in comments] == [("7", REPO), ("9", REPO)]
    assert all("治理合規檢查（2026-11-26）" in c["stdin"] and "輸入 100、輸出 10" in c["stdin"] for c in comments)
    assert not [c for c in calls if c["args"][:2] == ["issue", "create"]]
    assert "commented on org/private#7" in capsys.readouterr().out


def test_with_no_open_tracking_issue_one_is_created_labelled_with_the_comment(tmp_path, monkeypatch):
    gh = _gh(tmp_path, "[]")
    assert _run(tmp_path, monkeypatch, gh) == 0
    created = [c for c in _calls(gh) if c["args"][:2] == ["issue", "create"]]
    assert len(created) == 1, _calls(gh)
    args = created[0]["args"]
    assert args[args.index("--repo") + 1] == REPO and args[args.index("--label") + 1] == "governance-check"
    assert "治理合規檢查（2026-11-26）" in created[0]["stdin"]


def test_a_gh_call_that_fails_or_answers_another_shape_exits_1_with_an_error_line(tmp_path, monkeypatch, capsys):
    gh = _gh(tmp_path, '[{"number": 7}]')
    (gh.parent / "fail-comment").touch()
    assert _run(tmp_path, monkeypatch, gh) == 1
    assert "ERROR: gh issue comment" in capsys.readouterr().err
    (gh.parent / "fail-comment").unlink()
    (gh.parent / "open.json").write_text('[{"number": "7"}]', encoding="utf-8")
    assert _run(tmp_path, monkeypatch, gh) == 1
    assert "ERROR: gh issue list: unexpected response shape" in capsys.readouterr().err
