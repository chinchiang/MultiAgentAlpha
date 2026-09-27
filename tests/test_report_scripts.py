"""The docs-check scripts: build_report, count_words, check_citations (Appendix E prompt 1, item 3)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_report  # noqa: E402
import check_citations  # noqa: E402
import count_words  # noqa: E402

SOURCES = "| 編號 | 來源 |\n|---|---|\n| A1 | x |\n| B79 | x |\n| B80 | x |\n| B81 | x |\n| B82 | x |\n| C7.14 | x |\n"


def _parts(tmp_path: Path, **texts: str) -> Path:
    parts = tmp_path / "parts"
    parts.mkdir()
    files = {"01_executive.md": "# 第一部\n本報告摘要。\n", "A_sources.md": SOURCES, **texts}
    for name, text in files.items():
        (parts / name).write_text(text, encoding="utf-8")
    (parts / "ORDER.txt").write_text("\n".join(sorted(files)) + "\n", encoding="utf-8")
    return parts


def _ledger(tmp_path: Path, ids=("A1", "B79", "B80", "B81", "B82", "C7.14"), **extra) -> Path:
    entries = [{"id": i, "verification_status": "待核實", **extra.get(i, {})} for i in ids]
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps({"sources": entries}), encoding="utf-8")
    return p


def test_the_committed_report_is_what_the_parts_build(tmp_path):
    # the same check the docs-check job runs, so a stale report fails here too
    built = build_report.build(out=tmp_path / "report.md")
    assert built.read_bytes() == build_report.OUT.read_bytes(), "run python3 scripts/build_report.py and commit the result"


def test_build_concatenates_in_order_and_refuses_an_unlisted_part(tmp_path):
    parts = _parts(tmp_path, **{"02_b.md": "二\n\n\n", "00_a.md": "一"})
    (parts / "ORDER.txt").write_text("02_b.md\n\n00_a.md\n", encoding="utf-8")
    (parts / "01_executive.md").unlink()
    (parts / "A_sources.md").unlink()
    out = build_report.build(parts, tmp_path / "r.md")
    assert out.read_text(encoding="utf-8") == "二\n\n一\n"
    (parts / "03_new.md").write_text("三", encoding="utf-8")
    with pytest.raises(SystemExit, match="03_new.md"):
        build_report.build(parts, tmp_path / "r.md")
    (parts / "ORDER.txt").write_text("02_b.md\n00_a.md\n03_new.md\n02_b.md\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="twice"):
        build_report.build(parts, tmp_path / "r.md")


def test_word_count_counts_cjk_only_and_leaves_appendix_a_out(tmp_path, capsys):
    parts = _parts(tmp_path, **{"02_body.md": "資安 review 審查【已證實｜A1】", "B_gaps.md": "缺口 gap"})
    assert count_words.count("資安 review 審查 㐀") == 5
    # 第一部本報告摘要 (8) + 資安審查已證實 (7) + 缺口 (2); A_sources.md and its CJK are left out
    assert count_words.main(parts, threshold=17) == 0
    out = capsys.readouterr().out
    assert "合計（不含附錄A）" in out and out.split("合計（不含附錄A）")[1].split()[0] == "17" and "'已證實': 1" in out
    assert count_words.main(parts, threshold=18) == 1
    assert "FAIL" in capsys.readouterr().out


def test_citations_pass_on_known_keys_ranges_and_a_bare_level(tmp_path):
    parts = _parts(tmp_path, **{"02_body.md": "甲【已證實｜A1】乙【尚未證實｜B79–B82】丙【C7.14】丁【尚未證實】"})
    assert check_citations.main(parts, _ledger(tmp_path)) == 0


@pytest.mark.parametrize("body, message", [
    ("甲【已證實｜A2】", "MISSING in 02_body.md: ['A2']"),
    ("甲【尚未證實｜B78–B80】", "MISSING in 02_body.md: ['B78']"),
    ("甲【尚未證實｜B79–B84】", "MISSING in 02_body.md: ['B83', 'B84']"),
    ("甲【已證實｜A】", "marker names no source key: 02_body.md: 【已證實｜A】"),
    ("甲【第三方評論（摘要）｜】", "marker names no source key"),
])
def test_citations_fail_on_unknown_or_missing_keys(tmp_path, capsys, body, message):
    parts = _parts(tmp_path, **{"02_body.md": body})
    assert check_citations.main(parts, _ledger(tmp_path)) == 1
    assert message in capsys.readouterr().out


def test_ranges_expand_to_every_key_in_between():
    assert sorted(check_citations.keys_in("B79–B82、A1")) == ["A1", "B79", "B80", "B81", "B82"]
    assert sorted(check_citations.keys_in("B79–82")) == ["B79", "B80", "B81", "B82"]


def test_citations_check_the_ledger_and_the_executive_summary(tmp_path, capsys):
    parts = _parts(tmp_path)
    assert check_citations.main(parts, _ledger(tmp_path, ids=("A1",))) == 1
    assert "ledger does not match" in capsys.readouterr().out
    verified = {"A1": {"verification_status": "原文核對", "checked_at": "2026-09-01", "reviewer": "", "claim_excerpt": "x"}}
    assert check_citations.main(parts, _ledger(tmp_path, **verified)) == 1
    assert "verified source lacks evidence: A1" in capsys.readouterr().out
    (parts / "01_executive.md").write_text("# 第一部\n修補 CVE-2026-1234 需升級到 2.7 並啟用 TLS。\n", encoding="utf-8")
    assert check_citations.main(parts, _ledger(tmp_path)) == 1
    assert "'CVE-2026-1234', '2.7', 'TLS'" in capsys.readouterr().out
    (parts / "01_executive.md").write_text("# 第一部 v1.0\n本報告摘要。\n", encoding="utf-8")  # headings are exempt
    (parts / "A_sources.md").write_text(SOURCES + "| B99 | 摘要 | 已證實 |\n", encoding="utf-8")
    assert check_citations.main(parts, _ledger(tmp_path, ids=("A1", "B79", "B80", "B81", "B82", "C7.14", "B99"))) == 1
    assert "snippet-only source must not be marked confirmed" in capsys.readouterr().out


def test_the_committed_report_passes_both_checks():
    assert count_words.main() == 0 and check_citations.main() == 0
