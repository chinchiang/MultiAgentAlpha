"""Appendix E prompt 8: the governance checker's verdicts on this repository, plus unit checks that
each decidable rule flips with the evidence it looks at. No network."""

import datetime as dt
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from governance_check import FAIL, MANUAL, PASS, check_g6, check_g8, check_g9, check_g12, render, run_all  # noqa: E402

TODAY = dt.date(2026, 9, 12)


@pytest.fixture(scope="module")
def results():
    return {r.id: r for r in run_all(ROOT, ROOT / "config" / "mara.yaml", TODAY)}


def test_every_item_has_a_verdict_and_evidence(results):
    assert sorted(results) == [f"G-{i}" for i in range(1, 14)] or len(results) == 13
    for r in results.values():
        assert r.status in (PASS, FAIL, MANUAL) and r.evidence.strip() and r.standards


def test_verdicts_on_this_repository(results):
    passing = ("G-2", "G-3", "G-5", "G-6", "G-11")
    assert {k: results[k].status for k in passing} == dict.fromkeys(passing, PASS)
    failing = ("G-1", "G-4", "G-7", "G-8", "G-10", "G-12", "G-13")
    assert {k: results[k].status for k in failing} == dict.fromkeys(failing, FAIL)
    assert results["G-9"].status == FAIL and "mock" in results["G-9"].evidence
    assert not [k for k, r in results.items() if r.status == MANUAL], "every item is machine-decidable now (templates for G-1, G-4, G-10)"


def test_render_has_thirteen_rows_and_nonzero_exit_signal(results):
    md = render(list(results.values()), root=ROOT, config_path=ROOT / "config" / "mara.yaml", date="2026-09-12")
    rows = [ln for ln in md.splitlines() if ln.startswith("| G-")]
    assert len(rows) == 13 and all(ln.count("|") == 6 for ln in rows)
    assert "結束碼 1" in md


def test_g8_and_g9_freshness(tmp_path):
    """G-8/G-9 need dated reports within 90 days whose front matter says mode: live (a bare dated
    file, or a legacy body line, is never enough; the detailed rules are in tests/test_model_eval.py)."""
    docs = tmp_path / "docs"
    docs.mkdir()
    live = "---\nmode: live\nfamilies: []\n---\n# x\n"
    assert check_g8(tmp_path, TODAY).status == FAIL
    (docs / "garak-2026-05-01.md").write_text(live)
    (docs / "cyberseceval-2026-05-01.md").write_text(live)
    assert check_g8(tmp_path, TODAY).status == FAIL, "older than 90 days"
    (docs / "garak-2026-08-20.md").write_text("fresh but no front matter")
    (docs / "cyberseceval-2026-08-20.md").write_text(live)
    assert check_g8(tmp_path, TODAY).status == FAIL, "garak report not marked live"
    (docs / "garak-2026-08-20.md").write_text(live)
    assert check_g8(tmp_path, TODAY).status == PASS
    (docs / "calibration-2026-09-01.md").write_text("# 校準\n\n執行模式：**mock**。\n")
    r = check_g9(tmp_path, TODAY)
    assert r.status == FAIL and "mock" in r.evidence
    (docs / "calibration-2026-09-05.md").write_text("---\nmode: live\nfamilies: []\nprovider_modes: [live]\nlabels: 3\n---\n# 校準\n")
    assert check_g9(tmp_path, TODAY).status == PASS


def test_g6_fails_on_the_seeded_fixture_workflow(tmp_path):
    src = ROOT / "fixtures" / "vuln-sample" / ".github" / "workflows"
    dst = tmp_path / ".github" / "workflows"
    shutil.copytree(src, dst)
    r = check_g6(tmp_path)
    assert r.status == FAIL
    for needle in ("非 SHA", "pull_request_target", "permissions"):
        assert needle in r.evidence


def test_g12_needs_an_enabled_narrow_psirt_block(tmp_path):
    cfg = tmp_path / "mara.yaml"
    cfg.write_text("models: []\npsirt:\n  enabled: true\n  webhook_url: https://psirt.example.internal/hook\n  product: IPC-7000\n")
    assert check_g12(tmp_path, cfg).status == PASS
    cfg.write_text("models: []\npsirt:\n  enabled: false\n  webhook_url: https://psirt.example.internal/hook\n")
    assert check_g12(tmp_path, cfg).status == FAIL
    cfg.write_text("models: []\npsirt:\n  enabled: true\n  webhook_url: http://psirt.example.internal/hook\n  product: IPC-7000\n  trigger_tiers: [A, C]\n")
    r = check_g12(tmp_path, cfg)
    assert r.status == FAIL and "https" in r.evidence and "過寬" in r.evidence
    cfg.write_text("models: []\n")
    assert check_g12(tmp_path, cfg).status == FAIL
