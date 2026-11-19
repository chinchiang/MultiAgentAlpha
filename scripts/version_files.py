"""What a version commit (GLOSSARY.md) is made of, and what scripts/renumber.py and scripts/version_commit.py both
compute about it: the next version, a CHANGELOG row's version, __version__ in src/mara/__init__.py, and the demo page
rebuilt by scripts/build_workbench_demo.py.

GLOSSARY.md terms: Version commit. Pure, except that rebuild_demo runs the demo builder, which writes the demo page.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

CHANGELOG = "docs/CHANGELOG.md"
VERSION_FILE = "src/mara/__init__.py"
DEMO = "docs/workbench/index.html"
VERSION_RE = re.compile(r'^__version__ = "(\d+\.\d+\.\d+)"$', re.M)
ROW_RE = re.compile(r"^(\| \d{4}-\d{2}-\d{2} \| v)(\d+\.\d+\.\d+)( \|)", re.M)  # the opening of a CHANGELOG row


def version_of(text: str) -> str | None:
    """The `__version__` the text of src/mara/__init__.py gives; None when it gives none."""
    m = VERSION_RE.search(text)
    return m.group(1) if m else None


def with_version(text: str, version: str) -> str:
    """The text of src/mara/__init__.py with its `__version__` made `version`."""
    return VERSION_RE.sub(f'__version__ = "{version}"', text)


def next_version(version: str) -> str:
    """The next patch version: 0.13.9 is followed by 0.13.10."""
    major, minor, patch = (int(n) for n in version.split("."))
    return f"{major}.{minor}.{patch + 1}"


def with_row_version(row: str, version: str) -> str:
    """The CHANGELOG row (or the first row of the text) with its version made `version`; every other cell as it was."""
    return ROW_RE.sub(lambda m: m.group(1) + version + m.group(3), row, count=1)


def rebuild_demo(root: Path) -> None:
    """Re-assemble the demo page with `root`'s scripts/build_workbench_demo.py, which reads mara from `root`;
    CalledProcessError when the builder fails."""
    subprocess.run([sys.executable, str(root / "scripts" / "build_workbench_demo.py")], cwd=root, check=True)
