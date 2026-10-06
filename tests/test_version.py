"""One version string. pyproject.toml said 0.1.0 (and the SARIF driver and ML-BOM hard-coded it) while
docs/CHANGELOG.md had reached v0.3.21: reports could not be traced to the code that produced them."""

import re
import tomllib
from pathlib import Path

import mara
from mara.report.sarif_out import to_sarif

ROOT = Path(__file__).resolve().parents[1]


def _newest_changelog_version() -> str:
    for line in (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| \d{4}-\d{2}-\d{2} \| v(\d+\.\d+\.\d+) \|", line)
        if m:
            return m.group(1)  # rows are newest first
    raise AssertionError("no version row in docs/CHANGELOG.md")


def test_the_package_version_is_the_newest_changelog_row():
    assert mara.__version__ == _newest_changelog_version(), (
        "bump src/mara/__init__.py __version__ together with the new docs/CHANGELOG.md row")


def test_pyproject_takes_the_version_from_the_package():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in meta["project"] and meta["project"]["dynamic"] == ["version"]
    assert meta["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "mara.__version__"}


def test_outputs_carry_the_package_version(mock_report):
    from mara import mlbom

    _, report = mock_report
    assert to_sarif(report)["runs"][0]["tool"]["driver"]["version"] == mara.__version__
    bom = mlbom.build_bom([], timestamp="2026-10-06T00:00:00Z", serial="urn:uuid:00000000-0000-0000-0000-000000000000")
    assert bom["metadata"]["component"]["version"] == bom["metadata"]["tools"]["components"][0]["version"] == mara.__version__
