"""Appendix E prompt 8: the governance checker's verdicts on this repository, plus unit checks that
each decidable rule flips with the evidence it looks at. No network."""

import datetime as dt
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from governance_check import FAIL, MANUAL, PASS, check_g3, check_g6, check_g8, check_g9, check_g12, render, run_all  # noqa: E402

TODAY = dt.date(2026, 9, 12)


@pytest.fixture(scope="module")
def results():
    return {r.id: r for r in run_all(ROOT, ROOT / "config" / "mara.yaml", TODAY)}


def test_every_item_has_a_verdict_and_evidence(results):
    assert sorted(results) == [f"G-{i}" for i in range(1, 14)] or len(results) == 13
    for r in results.values():
        assert r.status in (PASS, FAIL, MANUAL) and r.evidence.strip() and r.standards


def test_verdicts_on_this_repository(results):
    passing = ("G-2", "G-3", "G-5", "G-6")
    assert {k: results[k].status for k in passing} == dict.fromkeys(passing, PASS)
    # G-11 fails until the ticket sync has run for real (the human-queue job is in dry-run): it used to pass on a
    # workflow merely naming the human queue
    failing = ("G-1", "G-4", "G-7", "G-8", "G-10", "G-11", "G-12", "G-13")
    assert {k: results[k].status for k in failing} == dict.fromkeys(failing, FAIL)
    # the one calibration report dated before TODAY has no front matter: a body line that says mock says nothing
    assert results["G-9"].status == FAIL and "`docs/calibration-2026-09-11.md`（2026-09-11，mode 未標示）" in results["G-9"].evidence
    assert not [k for k, r in results.items() if r.status == MANUAL], "every item is machine-decidable now (templates for G-1, G-4, G-10)"


def test_g3_names_the_retention_approval_and_fails_a_retained_model_without_one(tmp_path):
    import yaml

    assert "gemini-reviewer=20261006-GISMD-Approve-01" in check_g3(ROOT, ROOT / "config" / "mara.yaml").evidence
    raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8"))
    gemini = next(m for m in raw["models"] if m["data_residency"] == "vendor_api_retained")
    gemini["retention_approval_ref"] = ""
    raw["allow_source_code_to_non_on_prem"] = True  # P5 would refuse the file outright; G-3 must still flag it
    cfg = tmp_path / "config" / "mara.yaml"
    cfg.parent.mkdir()
    cfg.write_text(yaml.safe_dump(raw), encoding="utf-8")
    r = check_g3(tmp_path, cfg)
    assert r.status == FAIL and f"{gemini['name']} 的 data_residency=vendor_api_retained" in r.evidence


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
    (docs / "calibration-2026-09-01.md").write_text("# 校準\n\n執行模式：**mock**。\n", encoding="utf-8")
    r = check_g9(tmp_path, TODAY)
    assert r.status == FAIL and "（2026-09-01，mode 未標示）" in r.evidence, "a body line says nothing: only the front matter does"
    (docs / "calibration-2026-09-05.md").write_text("---\nmode: live\nfamilies: []\nprovider_modes: [live]\nlabels: 3\n---\n# 校準\n", encoding="utf-8")
    assert check_g9(tmp_path, TODAY).status == PASS


def test_g8_and_g9_refuse_reports_dated_in_the_future(tmp_path):
    """A negative age used to pass the `age > 90` freshness test: a report dated 2027-01-01 kept G-8/G-9
    green until April 2027."""
    docs = tmp_path / "docs"
    docs.mkdir()
    live = "---\nmode: live\nfamilies: []\nprovider_modes: [live]\nlabels: 3\n---\n# x\n"
    for name in ("garak-2027-01-01.md", "cyberseceval-2027-01-01.md", "calibration-2027-01-01.md"):
        (docs / name).write_text(live, encoding="utf-8")
    g8, g9 = check_g8(tmp_path, TODAY), check_g9(tmp_path, TODAY)
    assert g8.status == FAIL and "晚於今天" in g8.evidence
    assert g9.status == FAIL and "晚於今天" in g9.evidence


def _doc(docs: Path, name: str, date: str, **meta) -> None:
    docs.mkdir(exist_ok=True)
    (docs / f"{name}-{date}.md").write_text("---\n" + yaml.safe_dump(meta) + "---\n# x\n", encoding="utf-8")


# TODAY is 2026-09-12: 2026-09-05 is 7 days old, 2026-05-01 is 134 days old (more than the 90 a record stands)
@pytest.mark.parametrize(
    ("date", "meta", "g8", "g9"),
    [
        pytest.param("2026-05-01", {"mode": "live", "families": []}, "已 134 天（> 90）", "最新校準報告 134 天前", id="stale"),
        pytest.param("2026-09-13", {"mode": "live", "families": []}, "的日期 2026-09-13 晚於今天", "（2026-09-13，日期晚於今天）", id="future"),
        pytest.param("2026-09-05", {"mode": "mock", "families": []}, "（2026-09-05）mode 為 mock，不是 live", "（2026-09-05，mock）", id="mock"),
        pytest.param("2026-09-05", {"families": []}, "（2026-09-05）mode 為 未標示，不是 live", "（2026-09-05，mode 未標示）", id="no-mode"),
        # several faults: the report is said to be stale, or in the future, and nothing else
        pytest.param("2026-05-01", {"mode": "mock", "families": []}, "已 134 天（> 90）", "最新校準報告 134 天前", id="stale-and-mock"),
        pytest.param("2026-09-13", {"mode": "mock", "families": []}, "的日期 2026-09-13 晚於今天", "（2026-09-13，日期晚於今天）",
                     id="future-and-mock"),
    ],
)
def test_g8_and_g9_say_one_thing_about_a_report_and_in_the_order_they_always_have(tmp_path, date, meta, g8, g9):
    docs = tmp_path / "docs"
    for name in ("garak", "cyberseceval", "calibration"):
        _doc(docs, name, date, provider_modes=["live"], labels=3, **meta)
    r8, r9 = check_g8(tmp_path, TODAY), check_g9(tmp_path, TODAY)
    assert r8.status == FAIL and g8 in r8.evidence
    assert r9.status == FAIL and g9 in r9.evidence


def test_g8_and_g9_say_what_stands_in_the_words_they_always_have(tmp_path):
    docs = tmp_path / "docs"
    for name in ("garak", "cyberseceval", "calibration"):
        _doc(docs, name, "2026-09-05", mode="live", families=[], provider_modes=["live"], labels=3)
    r8, r9 = check_g8(tmp_path, TODAY), check_g9(tmp_path, TODAY)
    assert r8.status == PASS and "`docs/garak-2026-09-05.md`（2026-09-05，7 天前，live，家族 []）" in r8.evidence
    assert r9.status == PASS and "`docs/calibration-2026-09-05.md`（2026-09-05，7 天前，live，家族 []，3 個標籤）" in r9.evidence


def test_g9_asks_a_calibration_report_to_have_run_on_live_providers(tmp_path):
    docs = tmp_path / "docs"
    _doc(docs, "calibration", "2026-09-05", mode="live", families=[], provider_modes=["mock"], labels=3)
    r = check_g9(tmp_path, TODAY)
    assert r.status == FAIL and "（2026-09-05，未涵蓋 ['mock']）" in r.evidence
    _doc(docs, "calibration", "2026-09-05", mode="live", families=[], labels=3)  # a report that names no provider modes is not refused for them
    assert check_g9(tmp_path, TODAY).status == PASS


@pytest.mark.parametrize("mode", ["Live", "LIVE", " live", "True"])
def test_g8_and_g9_take_the_mode_as_written_only_lower_case_live_is_live(tmp_path, mode):
    """The writers write `live`; a mode written otherwise is a record somebody edited, and an edit is no run."""
    docs = tmp_path / "docs"
    for name in ("garak", "cyberseceval", "calibration"):
        _doc(docs, name, "2026-09-05", mode=mode, families=[], provider_modes=["live"], labels=3)
    r8, r9 = check_g8(tmp_path, TODAY), check_g9(tmp_path, TODAY)
    assert r8.status == FAIL and f"mode 為 {mode}，不是 live" in r8.evidence
    assert r9.status == FAIL and f"（2026-09-05，{mode}）" in r9.evidence


def test_g8_and_g9_never_open_a_report_that_is_too_old_or_too_new_to_count(tmp_path):
    """A report is judged by its date first. The front matter of a stale or future one may be broken without the check
    failing for it, as it always could not."""
    docs = tmp_path / "docs"
    docs.mkdir()
    for name in ("garak", "cyberseceval", "calibration"):
        (docs / f"{name}-2026-05-01.md").write_text("---\nmode: [unclosed\n---\n# x\n", encoding="utf-8")  # stale, and not YAML
        (docs / f"{name}-2026-09-13.md").write_text("---\nmode: [unclosed\n---\n# x\n", encoding="utf-8")  # in the future
    assert check_g8(tmp_path, TODAY).status == FAIL
    assert check_g9(tmp_path, TODAY).status == FAIL
    (docs / "garak-2026-09-05.md").write_text("---\nmode: [unclosed\n---\n# x\n", encoding="utf-8")  # fresh: it is opened
    with pytest.raises(yaml.YAMLError):
        check_g8(tmp_path, TODAY)


def test_calibrate_refuses_a_future_or_malformed_date(tmp_path, monkeypatch):
    import calibrate

    run = ("s1", {"provider_mode": "mock", "findings": [], "bias_audit": {}}, [])
    monkeypatch.setattr(calibrate, "load_runs", lambda *_, **__: [run])
    tomorrow = (dt.date.today() + dt.timedelta(days=1)).isoformat()
    for bad, match in ((tomorrow, "in the future"), ("2026-13-01", "YYYY-MM-DD")):
        monkeypatch.setattr(sys, "argv", ["calibrate", "--out-dir", str(tmp_path), "--date", bad, "--report", str(tmp_path / "r.md")])
        with pytest.raises(SystemExit, match=match):
            calibrate.main()
    assert not (tmp_path / "r.md").exists()


def test_g6_fails_on_the_seeded_fixture_workflow(tmp_path):
    src = ROOT / "fixtures" / "vuln-sample" / ".github" / "workflows"
    dst = tmp_path / ".github" / "workflows"
    shutil.copytree(src, dst)
    r = check_g6(tmp_path)
    assert r.status == FAIL
    for needle in ("非 SHA", "pull_request_target", "permissions"):
        assert needle in r.evidence


def test_g12_needs_an_enabled_narrow_psirt_block_and_a_fresh_handshake(tmp_path):
    import json

    cfg = tmp_path / "mara.yaml"
    cfg.write_text("models: []\npsirt:\n  enabled: true\n  webhook_url: https://psirt.example.internal/hook\n  product: IPC-7000\n")
    r = check_g12(tmp_path, cfg)
    assert r.status == FAIL and "握手" in r.evidence, "enabled: true alone proves nothing about the endpoint"
    hs = tmp_path / "ops" / "psirt" / "handshake.json"
    hs.parent.mkdir(parents=True)
    hs.write_text(json.dumps({"sent_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"), "webhook_url": "https://psirt.example.internal/hook",
                              "status_code": 202, "ok": True}))
    assert check_g12(tmp_path, cfg).status == PASS
    cfg.write_text("models: []\npsirt:\n  enabled: false\n  webhook_url: https://psirt.example.internal/hook\n")
    assert check_g12(tmp_path, cfg).status == FAIL
    cfg.write_text("models: []\npsirt:\n  enabled: true\n  webhook_url: http://psirt.example.internal/hook\n  product: IPC-7000\n  trigger_tiers: [A, C]\n")
    r = check_g12(tmp_path, cfg)
    assert r.status == FAIL and "https" in r.evidence and "過寬" in r.evidence
    cfg.write_text("models: []\n")
    assert check_g12(tmp_path, cfg).status == FAIL
