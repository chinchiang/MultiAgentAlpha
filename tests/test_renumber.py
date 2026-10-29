"""scripts/renumber.py, run where a rebase stopped on a version collision ("## 版本規則" in docs/CHANGELOG.md): it takes
the next version, keeps both CHANGELOG rows with the branch's on top, re-assembles the demo, checks that every other
file changes as the branch's commit did, and finishes the rebase. Each test builds a repository of its own."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "renumber.py"


def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, text=True, check=check)


def _renumber(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=repo, capture_output=True, text=True)


def _rebasing(repo: Path) -> bool:
    """git leaves REBASE_HEAD behind when a rebase ends; its state directory is what says one is in progress."""
    return any((repo / ".git" / d).is_dir() for d in ("rebase-merge", "rebase-apply"))


def test_outside_a_rebase_it_refuses(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    res = _renumber(repo)
    assert res.returncode == 2, res.stdout + res.stderr
    assert "no rebase in progress" in res.stderr


HEADER = "# 變更紀錄\n\n| 日期 | 版本 | 變更摘要 | 變更者 | 查證狀態 |\n|---|---|---|---|---|\n"
BASE_ROW = "| 2026-10-24 | v0.13.25 | 基準。報告正文未變 | t | 0 |\n"
# The stand-in for scripts/build_workbench_demo.py, which re-assembles the page it reads: the version chips in the
# current page follow mara.__version__, and anything else (conflict markers included) stays.
DEMO_BUILDER = '''import re, pathlib
root = pathlib.Path(__file__).resolve().parents[1]
v = re.search(r'__version__ = "(.+)"', (root / "src/mara/__init__.py").read_text()).group(1)
page = root / "docs/workbench/index.html"
page.write_text(re.sub(r'(<span class="version-chip">)[^<]*(</span>)', rf"\\g<1>{v}\\g<2>", page.read_text()))
'''


def _write(repo: Path, rel: str, text: str) -> None:
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(text, encoding="utf-8")


def _release(repo: Path, version: str, row: str, message: str, files: dict[str, str] | None = None) -> None:
    """One commit as this repository makes them: a CHANGELOG row on top, the version, the demo, and its own files."""
    changelog = (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8")
    _write(repo, "docs/CHANGELOG.md", changelog.replace(HEADER, HEADER + row, 1))
    _write(repo, "src/mara/__init__.py", f'"""mara."""\n\n__version__ = "{version}"\n')
    _write(repo, "docs/workbench/index.html", f'<span class="version-chip">{version}</span>\n')
    for rel, text in (files or {}).items():
        _write(repo, rel, text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


def _repo(tmp_path: Path) -> Path:
    """A repository at v0.13.25 with the files renumber.py touches, a demo builder and one module."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _write(repo, "docs/CHANGELOG.md", HEADER + BASE_ROW)
    _write(repo, "src/mara/__init__.py", '"""mara."""\n\n__version__ = "0.13.25"\n')
    _write(repo, "docs/workbench/index.html", '<span class="version-chip">0.13.25</span>\n')
    _write(repo, "scripts/build_workbench_demo.py", DEMO_BUILDER)
    _write(repo, "src/mara/feature.py", "LIMIT = 3\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base, v0.13.25")
    return repo


def _rows(repo: Path) -> list[str]:
    lines = (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8").splitlines()
    return [line.split(" | ")[1] + " " + line.split(" | ")[2] for line in lines if line.startswith("| 2026-")]


def test_a_collision_on_the_changelog_alone_takes_the_next_version_and_finishes_the_rebase(tmp_path):
    """Both sides moved v0.13.25 to v0.13.26, so the version and the demo merge cleanly and only the CHANGELOG conflicts."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "-c", "branch")
    _release(repo, "0.13.26", "| 2026-10-28 | v0.13.26 | 分支的修正。報告正文未變 | t | 0 |\n",
             "The feature waits for four, v0.13.26. Its first sentence names the version", {"src/mara/feature.py": "LIMIT = 4\n"})
    _git(repo, "switch", "-q", "main")
    _release(repo, "0.13.26", "| 2026-10-27 | v0.13.26 | main 的修正。報告正文未變 | t | 0 |\n", "main's fix, v0.13.26")
    main_tip = _git(repo, "rev-parse", "HEAD").stdout.strip()
    _git(repo, "switch", "-q", "branch")
    assert _git(repo, "rebase", "main", check=False).returncode != 0
    assert _git(repo, "diff", "--name-only", "--diff-filter=U").stdout.split() == ["docs/CHANGELOG.md"]

    res = _renumber(repo)
    assert res.returncode == 0, res.stdout + res.stderr
    assert not _rebasing(repo)
    assert _git(repo, "rev-parse", "HEAD~1").stdout.strip() == main_tip
    assert _rows(repo) == ["v0.13.27 分支的修正。報告正文未變", "v0.13.26 main 的修正。報告正文未變", "v0.13.25 基準。報告正文未變"]
    assert '__version__ = "0.13.27"' in (repo / "src/mara/__init__.py").read_text(encoding="utf-8")
    assert (repo / "docs/workbench/index.html").read_text(encoding="utf-8") == '<span class="version-chip">0.13.27</span>\n'
    assert (repo / "src/mara/feature.py").read_text(encoding="utf-8") == "LIMIT = 4\n"
    assert _git(repo, "log", "-1", "--format=%s").stdout.strip() == ("The feature waits for four, v0.13.27. "
                                                                      "Its first sentence names the version")
    assert _git(repo, "status", "--porcelain").stdout == ""
    again = _renumber(repo)  # REBASE_HEAD is still there, the rebase is not
    assert again.returncode == 2 and "no rebase in progress" in again.stderr, again.stdout + again.stderr


def test_a_collision_on_the_version_and_the_demo_too_takes_the_version_asked_for(tmp_path):
    """main has moved past the branch's version, so the version and the demo conflict as well; --to picks the number."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "-c", "branch")
    _release(repo, "0.13.26", "| 2026-10-28 | v0.13.26 | 分支的修正。報告正文未變 | t | 0 |\n", "The feature, v0.13.26",
             {"src/mara/feature.py": "LIMIT = 4\n"})
    _git(repo, "switch", "-q", "main")
    _release(repo, "0.13.26", "| 2026-10-27 | v0.13.26 | 第一個。報告正文未變 | t | 0 |\n", "first, v0.13.26")
    _release(repo, "0.13.27", "| 2026-10-27 | v0.13.27 | 第二個。報告正文未變 | t | 0 |\n", "second, v0.13.27")
    _git(repo, "switch", "-q", "branch")
    assert _git(repo, "rebase", "main", check=False).returncode != 0
    assert sorted(_git(repo, "diff", "--name-only", "--diff-filter=U").stdout.split()) == [
        "docs/CHANGELOG.md", "docs/workbench/index.html", "src/mara/__init__.py"]

    res = _renumber(repo, "--to", "0.13.30")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not _rebasing(repo)
    assert _rows(repo) == ["v0.13.30 分支的修正。報告正文未變", "v0.13.27 第二個。報告正文未變", "v0.13.26 第一個。報告正文未變",
                           "v0.13.25 基準。報告正文未變"]
    assert (repo / "src/mara/__init__.py").read_text(encoding="utf-8") == '"""mara."""\n\n__version__ = "0.13.30"\n'
    assert (repo / "docs/workbench/index.html").read_text(encoding="utf-8") == '<span class="version-chip">0.13.30</span>\n'
    assert (repo / "src/mara/feature.py").read_text(encoding="utf-8") == "LIMIT = 4\n"
    assert _git(repo, "log", "-1", "--format=%s").stdout.strip() == "The feature, v0.13.30"


def test_a_conflict_in_any_other_file_is_left_to_a_human(tmp_path):
    """Only the version's three files are renumber.py's to resolve; with another conflict it changes nothing."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "-c", "branch")
    _release(repo, "0.13.26", "| 2026-10-28 | v0.13.26 | 分支。報告正文未變 | t | 0 |\n", "branch, v0.13.26",
             {"src/mara/feature.py": "LIMIT = 4\n"})
    _git(repo, "switch", "-q", "main")
    _release(repo, "0.13.26", "| 2026-10-27 | v0.13.26 | main。報告正文未變 | t | 0 |\n", "main, v0.13.26",
             {"src/mara/feature.py": "LIMIT = 5\n"})
    _git(repo, "switch", "-q", "branch")
    assert _git(repo, "rebase", "main", check=False).returncode != 0
    before = {rel: (repo / rel).read_text(encoding="utf-8") for rel in ("docs/CHANGELOG.md", "src/mara/feature.py")}

    res = _renumber(repo)
    assert res.returncode == 2, res.stdout + res.stderr
    assert "conflicts outside the version's files" in res.stderr and "src/mara/feature.py" in res.stderr
    assert _rebasing(repo)
    assert {rel: (repo / rel).read_text(encoding="utf-8") for rel in before} == before


def test_a_file_whose_changes_differ_after_the_rebase_is_reported_before_anything_changes(tmp_path):
    """main already holds part of the branch's change (the same new file), so git merges it silently and the rebased
    commit would no longer add it; renumber.py names the file and leaves the rebase as it stopped."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "-c", "branch")
    _release(repo, "0.13.26", "| 2026-10-28 | v0.13.26 | 分支。報告正文未變 | t | 0 |\n", "branch, v0.13.26",
             {"src/mara/feature.py": "LIMIT = 4\n", "src/mara/extra.py": "X = 1\n"})
    _git(repo, "switch", "-q", "main")
    _release(repo, "0.13.26", "| 2026-10-27 | v0.13.26 | main。報告正文未變 | t | 0 |\n", "main, v0.13.26",
             {"src/mara/extra.py": "X = 1\n"})
    _git(repo, "switch", "-q", "branch")
    assert _git(repo, "rebase", "main", check=False).returncode != 0
    assert _git(repo, "diff", "--name-only", "--diff-filter=U").stdout.split() == ["docs/CHANGELOG.md"]
    changelog = (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8")

    res = _renumber(repo)
    assert res.returncode == 2, res.stdout + res.stderr
    assert "src/mara/extra.py" in res.stderr and "src/mara/feature.py" not in res.stderr
    assert _rebasing(repo)
    assert (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8") == changelog


def test_a_rebase_with_more_commits_to_apply_is_refused(tmp_path):
    """Each PR here is one commit; with more to apply, --continue could stop again and the amend would reword the wrong one."""
    repo = _repo(tmp_path)
    _git(repo, "switch", "-q", "-c", "branch")
    _release(repo, "0.13.26", "| 2026-10-28 | v0.13.26 | 分支。報告正文未變 | t | 0 |\n", "branch, v0.13.26")
    _write(repo, "src/mara/feature.py", "LIMIT = 4\n")
    _git(repo, "commit", "-q", "-am", "a second commit")
    _git(repo, "switch", "-q", "main")
    _release(repo, "0.13.26", "| 2026-10-27 | v0.13.26 | main。報告正文未變 | t | 0 |\n", "main, v0.13.26")
    _git(repo, "switch", "-q", "branch")
    assert _git(repo, "rebase", "main", check=False).returncode != 0
    changelog = (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8")

    res = _renumber(repo)
    assert res.returncode == 2, res.stdout + res.stderr
    assert "one commit" in res.stderr
    assert _rebasing(repo) and (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8") == changelog
