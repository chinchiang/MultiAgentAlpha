"""scripts/version_files.py: what scripts/renumber.py and scripts/version_commit.py both compute about a version commit
(the next version, a row's version, __version__, the demo rebuild)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import version_files  # noqa: E402


def test_the_next_version_is_the_next_patch():
    assert version_files.next_version("0.13.9") == "0.13.10"
    assert version_files.next_version("1.0.0") == "1.0.1"


def test_a_row_takes_another_version_and_keeps_every_other_cell():
    assert (version_files.with_row_version("| 2026-11-19 | v0.13.1 | 摘要 v0.13.1 | t | 0 |\n", "0.13.2")
            == "| 2026-11-19 | v0.13.2 | 摘要 v0.13.1 | t | 0 |\n")


def test_the_version_is_read_from_and_written_into_the_version_file():
    text = '"""mara."""\n\n__version__ = "1.2.3"\n'
    assert version_files.version_of(text) == "1.2.3"
    assert version_files.version_of("no version here\n") is None
    assert version_files.with_version(text, "1.2.4") == '"""mara."""\n\n__version__ = "1.2.4"\n'


def test_the_demo_is_rebuilt_by_the_builder_of_the_root_given_and_a_builder_that_fails_raises(tmp_path):
    (tmp_path / "scripts").mkdir()
    builder = tmp_path / "scripts" / "build_workbench_demo.py"
    builder.write_text("import pathlib\npathlib.Path('built').write_text('yes')\n", encoding="utf-8")
    version_files.rebuild_demo(tmp_path)
    assert (tmp_path / "built").read_text(encoding="utf-8") == "yes", "it ran in the root, with the root's builder"
    builder.write_text("raise SystemExit(3)\n", encoding="utf-8")
    with pytest.raises(subprocess.CalledProcessError):
        version_files.rebuild_demo(tmp_path)
