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


def test_the_changelog_versions_decrease_down_the_rows():
    """Two PRs that took one version both pass the test above once merged; the one merged second takes the next
    (docs/CHANGELOG.md, 版本規則). The three v0.1.0 rows of 2026-09 predate the rule."""
    rows = [m.group(1) for line in (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
            if (m := re.match(r"^\| \d{4}-\d{2}-\d{2} \| v(\d+\.\d+\.\d+) \|", line))]
    versions = [tuple(int(n) for n in v.split(".")) for v in rows]
    wrong = [f"v{rows[i]} above v{rows[i + 1]}" for i in range(len(rows) - 1)
             if versions[i] <= versions[i + 1] and not rows[i] == rows[i + 1] == "0.1.0"]
    assert not wrong, f"each row takes a version above the next: {', '.join(wrong)}"


def test_the_newest_changelog_row_says_whether_the_report_body_and_the_demo_changed():
    """CODING_STANDARDS.md, "A CHANGELOG row records one version": the summary says whether the workbench demo was
    recaptured and ends with whether the report body changed, "報告正文未變" or "報告正文變更：" and what changed."""
    row = next(line for line in (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8").splitlines()
               if re.match(r"^\| \d{4}-\d{2}-\d{2} \| v\d+\.\d+\.\d+ \|", line))
    summary = row.split(" | ", 2)[2].rsplit(" | ", 2)[0]
    sentences = [s.strip() for s in summary.split("。") if s.strip()]
    last = sentences[-1]
    assert last == "報告正文未變" or (last.startswith("報告正文變更：") and len(last) > len("報告正文變更：")), last
    assert any("展示頁" in s and "擷取" in s for s in sentences), "no sentence says whether the demo was recaptured"


def test_every_changelog_row_is_one_line_of_printable_text():
    """v0.5.3 and v0.5.9 meant the escapes `\\n`, `\\r\\n`, `\\x1c`, `.\\app.py` and got the characters
    themselves (a shell heredoc expanded them): each row broke over several lines, so the table lost
    them, and BEL, FS, RS, NEL, LS and PS sat in the text."""
    text = (ROOT / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    hidden = sorted({hex(ord(c)) for c in text if (ord(c) < 0x20 and c != "\n") or c in "\x7f\x85\u2028\u2029"})
    assert not hidden, f"control or line-separator characters in docs/CHANGELOG.md: {hidden}"
    lines = text.split("\n")
    header = lines.index("|---|---|---|---|---|")
    table = lines[header + 1:lines.index("", header)]
    broken = [n for n, line in enumerate(table, header + 2)
              if not re.fullmatch(r"\| \d{4}-\d{2}-\d{2} \| v\d+\.\d+\.\d+ \| .* \|", line)]
    assert not broken, f"docs/CHANGELOG.md lines that are not a whole row: {broken}"
    glued = _lines_holding_more_than_one_row(table)
    assert not glued, f"docs/CHANGELOG.md has rows glued into one line (table lines {glued})"


ROW = re.compile(r"\| \d{4}-\d{2}-\d{2} \| v\d+\.\d+\.\d+ \|")


def _lines_holding_more_than_one_row(lines: list[str]) -> list[int]:
    """Numbers (1-based, within `lines`) of the lines with two or more `| date | vX.Y.Z |` openings: two rows glued
    by the characters `\\n` instead of a line break. A whole-row match with `.*` takes them for one row."""
    return [n for n, line in enumerate(lines, 1) if len(ROW.findall(line)) > 1]


def test_two_changelog_rows_glued_into_one_line_are_found():
    glued = r"| 2026-11-10 | v0.13.78 | 摘要一 | 變更者 | 查證 |\n| 2026-11-10 | v0.13.77 | 摘要二 | 變更者 | 查證 |"
    assert _lines_holding_more_than_one_row(["| 2026-11-10 | v0.13.76 | 摘要 | 變更者 | 查證 |", glued]) == [2]


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
