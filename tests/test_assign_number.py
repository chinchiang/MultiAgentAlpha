"""scripts/assign_number.py, which replaces the GSMD placeholder number with the registry-allocated one in every
tracked text file and then checks with git grep that none is left. The script finds its repository from its own path,
so each test copies it into a repository of its own and runs it there."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.locale_env import not_utf8_env

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = "GSMD-RPT-2026-0908-TBD"
NUMBER = "GSMD-RPT-2026-0908-01"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=repo, capture_output=True, encoding="utf-8", check=True)


def _repo(tmp_path: Path, files: dict[str, str]) -> Path:
    """A repository holding the script and the given files, all tracked."""
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "assign_number.py", repo / "scripts" / "assign_number.py")
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text, encoding="utf-8")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    return repo


def _assign(repo: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """The script run in repo; its output is written in UTF-8 whatever the locale, so that a path beyond ascii reads back."""
    env = env or {**os.environ, "PYTHONIOENCODING": "utf-8"}
    return subprocess.run([sys.executable, str(repo / "scripts" / "assign_number.py"), NUMBER, *args], cwd=repo, env=env,
                          capture_output=True, encoding="utf-8")


def test_a_text_file_whose_name_is_beyond_ascii_is_edited_too(tmp_path):
    repo = _repo(tmp_path, {"docs/報告.md": f"編號 {PLACEHOLDER}\n"})
    res = _assign(repo, "--dry-run")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "would edit: " + str(Path("docs/報告.md")) in res.stdout.splitlines()


BUILDERS = ("build_report.py", "build_html.py", "count_words.py", "check_citations.py")


def test_a_placeholder_left_in_a_file_beyond_ascii_is_named_and_the_script_itself_is_not(tmp_path):
    # A .csv is not a text file the script edits, so its placeholder stays; the script holds the placeholder as a
    # constant and leaves it there on purpose. The builders it runs afterwards do nothing here.
    repo = _repo(tmp_path, {"docs/筆記.csv": f"編號,{PLACEHOLDER}\n", **{f"scripts/{b}": "" for b in BUILDERS}})
    res = _assign(repo, env=not_utf8_env())
    assert res.returncode == 1, res.stdout + res.stderr
    assert res.stderr == "placeholder still present in: docs/筆記.csv\n"


def test_the_file_list_is_read_as_utf8_whatever_the_locale(tmp_path):
    # The name beyond ascii is on a .csv, which the script lists but never opens: in Linux's C locale the filesystem
    # encoding is ascii too, and no str path beyond ascii opens there.
    repo = _repo(tmp_path, {"docs/筆記.csv": "編號\n", "docs/report.md": f"{PLACEHOLDER}\n"})
    res = _assign(repo, "--dry-run", env=not_utf8_env())
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.splitlines() == ["would edit: " + str(Path("docs/report.md"))]
