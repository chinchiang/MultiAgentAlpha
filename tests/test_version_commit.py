"""scripts/version_commit.py makes a branch's version commit (GLOSSARY.md): the next version, its CHANGELOG row with the
查證狀態 counted now, and the demo page, tested and committed as one command. Each test builds a repository of its own,
with stand-ins for the demo builder, the two counting scripts and the version and demo tests."""

from __future__ import annotations

import datetime as dt
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "version_commit.py"
HEADER = "# 變更紀錄\n\n| 日期 | 版本 | 變更摘要 | 變更者 | 查證狀態 |\n|---|---|---|---|---|\n"
BASE_ROW = "| 2026-11-18 | v0.13.111 | 基準。展示頁未重新擷取。報告正文未變 | t | 舊的 |\n"
DEMO_BUILDER = '''import re, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
v = re.search(r'__version__ = "(.+)"', (root / "src/mara/__init__.py").read_text()).group(1)
page = root / "docs/workbench/index.html"
page.write_text(re.sub(r'(<span class="version-chip">)[^<]*(</span>)', rf"\\g<1>{v}\\g<2>", page.read_text()))
'''
CITATIONS = 'print("附錄A 條目: 247；正文引用的不同編號: 235；未被引用的條目: 12")\nprint("citations PASS")\n'
WORDS = ('print("正文（第一到十部）                     37,265")\nprint("合計（不含附錄A）                     43,807")\n'
         'print("證據標記:", {"已證實": 178, "廠商主張": 38, "第三方評論": 32, "尚未證實": 22}, "合計", 270)\n')
# the rule of tests/test_version.py: the newest row says whether the demo was recaptured, and ends on the report body
VERSION_TEST = '''from pathlib import Path


def test_the_newest_row_says_the_demo_and_the_report_body():
    row = next(l for l in Path("docs/CHANGELOG.md").read_text(encoding="utf-8").splitlines() if l.startswith("| 20"))
    summary = row.split(" | ")[2]
    assert "展示頁" in summary and "擷取" in summary and summary.endswith("報告正文未變")
'''
DEMO_TEST = '''from pathlib import Path


def test_the_demo_shows_the_version():
    version = Path("src/mara/__init__.py").read_text(encoding="utf-8").split('"')[-2]
    assert f">{version}<" in Path("docs/workbench/index.html").read_text(encoding="utf-8")
'''
SUMMARY = "腳本變更（新增，`scripts/x.py`）：(1) 一件事。展示頁只依新版本重新組合，未重新擷取。報告正文未變"
STATUS = "附錄A 247 條，引用 235 個編號；證據標記 已證實 178／廠商主張 38／第三方評論 32／尚未證實 22；43,807 字"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, encoding="utf-8", check=check)


def _write(repo: Path, rel: str, text: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def _repo(tmp_path: Path) -> Path:
    """A repository at v0.13.111, its main as origin/main, and a branch of one commit after it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    for rel, text in {"docs/CHANGELOG.md": HEADER + BASE_ROW, "src/mara/__init__.py": '"""mara."""\n\n__version__ = "0.13.111"\n',
                      "docs/workbench/index.html": '<span class="version-chip">0.13.111</span>\n',
                      "scripts/build_workbench_demo.py": DEMO_BUILDER, "scripts/check_citations.py": CITATIONS,
                      "scripts/count_words.py": WORDS, "tests/test_version.py": VERSION_TEST,
                      "tests/test_workbench_demo.py": DEMO_TEST, ".gitignore": "__pycache__/\n"}.items():
        _write(repo, rel, text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    _git(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    _write(repo, "src/mara/feature.py", "LIMIT = 3\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "a feature")
    return repo


def _version_commit(repo: Path, summary: str = SUMMARY, *args: str, row: str | None = None) -> subprocess.CompletedProcess:
    """Run it with a row file of `summary` and a 變更者, or of `row` as given."""
    (repo.parent / "row.txt").write_text(row if row is not None else f"{summary} | chinchiang（Claude Code 協作）\n",
                                         encoding="utf-8")
    return subprocess.run([sys.executable, str(SCRIPT), "--row", str(repo.parent / "row.txt"), "--for", "a feature", *args],
                          cwd=repo, capture_output=True, text=True, encoding="utf-8")


def test_it_commits_the_next_version_its_row_counted_now_and_the_demo_with_the_message_and_trailers_given(tmp_path):
    repo = _repo(tmp_path)
    done = _version_commit(repo, SUMMARY, "--trailer", "Reviewed-by: B <b@example.invalid>", "--trailer", "Co-Authored-By: A <a@example.invalid>")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _git(repo, "log", "-1", "--format=%B").stdout.rstrip("\n") == (
        "v0.13.112: CHANGELOG row and demo page for a feature\n\nReviewed-by: B <b@example.invalid>\nCo-Authored-By: A <a@example.invalid>")
    assert _git(repo, "log", "-1", "--format=%(trailers:only)").stdout.strip().splitlines() == [
        "Reviewed-by: B <b@example.invalid>", "Co-Authored-By: A <a@example.invalid>"], "git reads them as trailers"
    assert _git(repo, "show", "--name-only", "--format=", "HEAD").stdout.split() == [
        "docs/CHANGELOG.md", "docs/workbench/index.html", "src/mara/__init__.py"]
    rows = [line for line in (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8").splitlines() if line.startswith("| 20")]
    assert rows == [f"| {dt.date.today().isoformat()} | v0.13.112 | {SUMMARY} | chinchiang（Claude Code 協作） | {STATUS} |",
                    BASE_ROW.rstrip("\n")]
    assert '__version__ = "0.13.112"' in (repo / "src/mara/__init__.py").read_text(encoding="utf-8")
    assert (repo / "docs/workbench/index.html").read_text(encoding="utf-8") == '<span class="version-chip">0.13.112</span>\n'
    assert _git(repo, "status", "--porcelain").stdout == ""


def _unchanged_head(repo: Path) -> str:
    return _git(repo, "log", "-1", "--format=%s").stdout.strip()


def test_a_row_that_does_not_say_whether_the_demo_was_recaptured_fails_at_the_tests_and_is_not_committed(tmp_path):
    """tests/test_version.py states the rule; the files changed before the tests are left as they are."""
    repo = _repo(tmp_path)
    done = _version_commit(repo, "腳本變更：(1) 一件事。報告正文未變")
    assert done.returncode == 1, done.stdout + done.stderr
    assert done.stderr.startswith(
        "version_commit: the version and demo tests failed, and the files changed so far are left as they are: "), done.stderr
    assert "test_the_newest_row_says_the_demo_and_the_report_body" in done.stderr
    assert _unchanged_head(repo) == "a feature"
    assert sorted(_git(repo, "status", "--porcelain").stdout.split()[1::2]) == [
        "docs/CHANGELOG.md", "docs/workbench/index.html", "src/mara/__init__.py"]


def test_a_demo_builder_that_fails_stops_it_at_the_demo_page_before_the_tests(tmp_path):
    repo = _repo(tmp_path)
    _write(repo, "scripts/build_workbench_demo.py", "raise SystemExit(3)\n")
    _git(repo, "commit", "-qam", "a builder that fails")
    done = _version_commit(repo)
    assert done.returncode == 1, done.stdout + done.stderr
    assert done.stderr == ("version_commit: the demo page failed, and the files changed so far are left as they are: "
                           "scripts/build_workbench_demo.py exit 3\n")
    assert _unchanged_head(repo) == "a builder that fails"
    assert '<span class="version-chip">0.13.111</span>' in (repo / "docs/workbench/index.html").read_text(encoding="utf-8")
    assert '__version__ = "0.13.112"' in (repo / "src/mara/__init__.py").read_text(encoding="utf-8"), "left as it is"
    assert "| v0.13.112 | " in (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8"), "left as it is"


def _files(repo: Path) -> dict[str, str]:
    return {rel: (repo / rel).read_text(encoding="utf-8") for rel in ("docs/CHANGELOG.md", "docs/workbench/index.html",
                                                                      "src/mara/__init__.py")}


def test_a_working_tree_that_changes_another_file_or_holds_an_untracked_one_is_refused_with_nothing_changed(tmp_path):
    repo = _repo(tmp_path)
    before = _files(repo)
    for dirty, said in (("src/mara/feature.py", "src/mara/feature.py"), ("notes.txt", "notes.txt")):
        _write(repo, dirty, "LIMIT = 4\n")
        done = _version_commit(repo)
        assert done.returncode == 2, done.stdout + done.stderr
        assert done.stderr == f"version_commit: the working tree changes more than the version commit's files: {said}\n"
        assert _files(repo) == before and _unchanged_head(repo) == "a feature"
        _git(repo, "checkout", "--", "src/mara/feature.py")
        (repo / "notes.txt").unlink(missing_ok=True)


def test_a_version_the_newest_row_already_holds_is_refused_with_nothing_changed(tmp_path):
    repo = _repo(tmp_path)
    before = _files(repo)
    done = _version_commit(repo, SUMMARY, "--to", "0.13.111")
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr == "version_commit: docs/CHANGELOG.md's newest row already holds v0.13.111\n"
    assert _files(repo) == before and _unchanged_head(repo) == "a feature"


def test_a_row_file_that_is_not_one_line_of_two_cells_is_refused_with_nothing_changed(tmp_path):
    repo = _repo(tmp_path)
    before = _files(repo)
    for row in ("一件事，沒有變更者\n", "第一行 | t\n第二行 | t\n", ""):
        done = _version_commit(repo, row=row)
        assert done.returncode == 2, done.stdout + done.stderr
        assert done.stderr == f"version_commit: {repo.parent / 'row.txt'}: not one line of `<變更摘要> | <變更者>`\n"
        assert _files(repo) == before and _unchanged_head(repo) == "a feature"


def test_to_takes_the_version_given(tmp_path):
    repo = _repo(tmp_path)
    done = _version_commit(repo, SUMMARY, "--to", "0.14.0")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _git(repo, "log", "-1", "--format=%s").stdout.strip() == "v0.14.0: CHANGELOG row and demo page for a feature"
    assert '__version__ = "0.14.0"' in (repo / "src/mara/__init__.py").read_text(encoding="utf-8")


def test_a_counting_script_that_fails_or_prints_no_count_to_read_stops_it_at_the_row(tmp_path):
    """__version__, set before the row, is left as it is; the CHANGELOG and the demo are not reached."""
    for script, text, said in (
            ("scripts/check_citations.py", "print('citations FAIL')\nraise SystemExit(1)\n",
             "scripts/check_citations.py exit 1: citations FAIL"),
            ("scripts/count_words.py", "print('證據標記: {已證實: 1} 合計 1')\nprint('合計（不含附錄A）  9')\n",
             "check_citations.py or count_words.py printed no count to read")):
        (tmp_path / script.split("/")[1]).mkdir()
        repo = _repo(tmp_path / script.split("/")[1])
        _write(repo, script, text)
        _git(repo, "commit", "-qam", "a counting script that fails")
        before = _files(repo)
        done = _version_commit(repo)
        assert done.returncode == 1, done.stdout + done.stderr
        assert done.stderr == ("version_commit: the CHANGELOG row failed, and the files changed so far are left as they are: "
                               f"{said}\n"), done.stderr
        assert _unchanged_head(repo) == "a counting script that fails"
        after = _files(repo)
        assert after["src/mara/__init__.py"] == before["src/mara/__init__.py"].replace("0.13.111", "0.13.112")
        assert after["docs/CHANGELOG.md"] == before["docs/CHANGELOG.md"]
        assert after["docs/workbench/index.html"] == before["docs/workbench/index.html"]


def test_a_row_file_that_cannot_be_read_is_refused_with_nothing_changed(tmp_path):
    repo = _repo(tmp_path)
    before = _files(repo)
    missing = tmp_path / "no-row.txt"
    done = subprocess.run([sys.executable, str(SCRIPT), "--row", str(missing), "--for", "a feature"], cwd=repo,
                          capture_output=True, text=True, encoding="utf-8")
    assert done.returncode == 2, done.stdout + done.stderr
    assert done.stderr == f"version_commit: {missing}: cannot be read: No such file or directory\n"
    assert _files(repo) == before and _unchanged_head(repo) == "a feature"
