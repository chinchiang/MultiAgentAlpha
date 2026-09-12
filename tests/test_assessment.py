"""The shipped gap assessment (Appendix E prompt 3) must satisfy prompt 3's acceptance criteria."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from score_assessment import check  # noqa: E402


def test_shipped_assessments_pass_acceptance_checks():
    paths = sorted((ROOT / "docs").glob("assessment-*.md"))
    assert paths, "no docs/assessment-<date>.md found"
    for p in paths:
        assert check(p) == [], p.name


def test_check_reports_missing_and_mismatched(tmp_path):
    doc = ROOT / "docs" / "assessment-2026-09-12.md"
    text = doc.read_text(encoding="utf-8")
    broken = text.replace("| 1 | 每個 repo 的 CI 都執行 SAST", "| 61 | 每個 repo 的 CI 都執行 SAST", 1)
    p = tmp_path / "assessment-x.md"
    p.write_text(broken, encoding="utf-8")
    errors = check(p)
    assert any("missing questions: [1]" in e for e in errors)
    assert any("unexpected question numbers: [61]" in e for e in errors)
    assert any(e.startswith("L0:") for e in errors)
