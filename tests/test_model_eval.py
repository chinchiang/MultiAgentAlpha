"""G-8 / G-9: garak and CyberSecEval command generation (keys never in argv), parsers on the
synthetic fixtures, thresholds, report rendering with front matter, the refusal to label fixture or
mock output as live, calibration's weight penalty and front matter, and governance checks G-8/G-9."""

import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara import model_eval as me  # noqa: E402
from mara.config import load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from mara.report.markdown_out import render_markdown  # noqa: E402

FIX = ROOT / "fixtures" / "model-eval"
TODAY = dt.date(2026, 9, 12)
SCRIPT = ROOT / "scripts" / "model_eval.py"


def test_targets_and_commands_never_carry_keys(monkeypatch):
    cfg = load_config(ROOT / "config" / "mara.yaml")
    targets = me.targets_from_config(cfg)
    assert [t.family for t in targets] == ["anthropic", "deepseek", "nemotron"]
    monkeypatch.setenv("DEEPSEEK_LOCAL_KEY", "sk-secret-deepseek")
    ds = next(t for t in targets if t.family == "deepseek")
    argv, env = me.garak_command(ds, ["promptinject", "encoding"], "/tmp/out")
    assert argv[:5] == ["python3", "-m", "garak", "--target_type", "openai.OpenAICompatible"] and "--target_name" in argv
    assert "probes.promptinject,probes.encoding" in argv and "sk-secret-deepseek" not in " ".join(argv)
    assert env == {"OPENAICOMPATIBLE_API_KEY": "$DEEPSEEK_LOCAL_KEY"}
    assert me.garak_generator_options(ds) == {"openai": {"OpenAICompatible": {"uri": "https://vllm-deepseek.internal:8000/v1/"}}}
    an = next(t for t in targets if t.family == "anthropic")
    argv, env = me.garak_command(an, ["dan"], "/tmp/out")
    assert argv[3:6] == ["--target_type", "anthropic", "--target_name"] and env == {"ANTHROPIC_API_KEY": "$ANTHROPIC_API_KEY"}
    assert me.garak_generator_options(an) is None
    cmds = me.cyberseceval_commands(ds, "/data", "/tmp/out", "$CSE_JUDGE_LLM")
    assert set(cmds) == {"prompt-injection", "mitre-frr"}
    assert f"--llm-under-test=OPENAI::deepseek-v3.2::{me.MASK}::https://vllm-deepseek.internal:8000/v1" in cmds["prompt-injection"]
    assert "--judge-llm=$CSE_JUDGE_LLM" in cmds["prompt-injection"] and "--benchmark=mitre-frr" in cmds["mitre-frr"]
    assert me.cse_spec(an, "sk-real") == "ANTHROPIC::claude-opus-5::sk-real"
    with pytest.raises(RuntimeError):
        me.resolve_key("MARA_TEST_UNSET_KEY")


def test_parsers_on_the_synthetic_fixtures():
    g = me.parse_garak_report(FIX / "deepseek" / "garak-deepseek.report.jsonl")
    assert g["garak_version"] == "0.17.0" and g["passed"] == 228 and g["total"] == 250 and round(g["pass_rate"], 3) == 0.912
    assert g["probes"]["dan.Dan_11_0"]["dan.DAN"] == {"passed": 45, "total": 50, "pass_rate": 0.9}
    pi = me.parse_cse_prompt_injection(FIX / "nemotron" / "prompt_injection_stat.json", "nvidia/nemotron-3-super")
    assert pi["successful"] == 31 and pi["total"] == 100 and pi["success_rate"] == 0.31
    fr = me.parse_cse_frr(FIX / "nemotron" / "mitre_frr_stat.json", "nvidia/nemotron-3-super")
    assert fr["accept"] == 70 and fr["refusal"] == 30 and fr["refusal_rate"] == 0.3
    with pytest.raises(ValueError):
        me.parse_cse_frr(FIX / "nemotron" / "mitre_frr_stat.json", "some-other-model")


def test_thresholds_and_verdicts(tmp_path):
    th = me.Thresholds()
    good = me.evaluate_family({"pass_rate": 0.95}, {"success_rate": 0.1}, {"refusal_rate": 0.05}, th)
    assert good["overall"] == "pass"
    bad = me.evaluate_family({"pass_rate": 0.5}, {"success_rate": 0.1}, {"refusal_rate": 0.05}, th)
    assert bad["overall"] == "fail" and bad["garak_pass_rate"]["status"] == "fail"
    partial = me.evaluate_family({"pass_rate": 0.95}, None, {"refusal_rate": 0.05}, th)
    assert partial["overall"] == "missing" and partial["prompt_injection_success"]["status"] == "missing"
    empty = tmp_path / "empty.jsonl"
    empty.write_text('{"entry_type": "init"}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        me.parse_garak_report(empty)


def _report(tmp_path: Path, mode: str = "dry-run", run_dir: Path = FIX) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(SCRIPT), "report", "--run-dir", str(run_dir), "--date", "2026-09-12", "--mode", mode,
                          "--docs-dir", str(tmp_path / "docs"), "--summary-root", str(tmp_path)], capture_output=True, text=True)


def test_report_cli_renders_front_matter_and_refuses_live_from_fixtures(tmp_path):
    r = _report(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "nemotron: fail" in r.stdout and "deepseek: pass" in r.stdout
    garak_md = (tmp_path / "docs" / "garak-2026-09-12.md").read_text(encoding="utf-8")
    cse_md = (tmp_path / "docs" / "cyberseceval-2026-09-12.md").read_text(encoding="utf-8")
    assert garak_md.startswith("---\nreport: garak\n") and "mode: dry-run" in garak_md and "不滿足 G-8" in garak_md
    assert "| deepseek | `deepseek-v3.2` | 228 / 250 | 0.912 | pass |" in garak_md and "promptinject.HijackHateHumans" in garak_md
    assert "| nemotron | `nvidia/nemotron-3-super` | 31 / 100 | 0.310 | fail | 30 / 100 | 0.300 | fail |" in cse_md
    assert "${KEY}" in cse_md and "sk-" not in cse_md
    summary = json.loads((tmp_path / "calib" / "model-eval-2026-09-12.json").read_text(encoding="utf-8"))
    assert summary["mode"] == "dry-run" and summary["families"]["nemotron"]["verdict"]["overall"] == "fail"
    assert me.latest_summary(tmp_path)["date"] == "2026-09-12"
    assert me.family_eval_status(tmp_path, ["deepseek", "llama"]) == {
        "deepseek": {"date": "2026-09-12", "mode": "dry-run", "status": "pass"}, "llama": {"date": None, "mode": None, "status": "none"}}
    r = _report(tmp_path, "live")
    assert r.returncode == 2 and "fixtures" in r.stderr
    # live is also refused when a family has no output at all
    partial = tmp_path / "partial"
    shutil.copytree(FIX, partial)
    shutil.rmtree(partial / "nemotron")
    r = _report(tmp_path, "live", partial)
    assert r.returncode == 2 and "missing outputs for ['nemotron']" in r.stderr
    r = subprocess.run([sys.executable, str(SCRIPT), "check", "--summary", str(tmp_path / "calib" / "model-eval-2026-09-12.json")],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "mode is not live" in r.stdout


def test_plan_masks_keys(monkeypatch):
    monkeypatch.setenv("NIM_LOCAL_KEY", "nim-secret-value")
    r = subprocess.run([sys.executable, str(SCRIPT), "plan"], capture_output=True, text=True)
    assert r.returncode == 0 and "nim-secret-value" not in r.stdout
    assert "OPENAICOMPATIBLE_API_KEY=$NIM_LOCAL_KEY" in r.stdout and "--target_type anthropic" in r.stdout and "${KEY}" in r.stdout


def test_calibration_penalty_front_matter_and_live_guard(tmp_path, monkeypatch):
    import calibrate

    stats = {"a": {"CWE-79": {"tp": 9, "fp": 1, "fn": 1}}, "b": {"CWE-79": {"tp": 9, "fp": 1, "fn": 1}}}
    base = calibrate.suggest_weights(stats, {"a": 0.9, "b": 0.9}, ["a", "b"], model_eval=None, penalty=0.8)
    evald = calibrate.suggest_weights(stats, {"a": 0.9, "b": 0.9}, ["a", "b"],
                                      model_eval={"families": {"b": {"verdict": {"overall": "fail"}}}}, penalty=0.8)
    assert base["a"]["weight"] == base["b"]["weight"] and not base["b"]["penalised"]
    assert evald["b"]["penalised"] and evald["b"]["weight"] == round(base["b"]["weight"] * 0.8, 2) and evald["a"]["weight"] == base["a"]["weight"]
    # a mock run cannot be labelled live; the mock label produces front matter with mode mock
    out = tmp_path / "calib-out" / "s1"
    out.mkdir(parents=True)
    src = ROOT / "calib-out" / "s1-fastapi-inventory" / "report.json"
    if not src.exists():
        pytest.skip("no calib-out run available")
    out.joinpath("report.json").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "calibrate.py"), "--mode", "live", "--out-dir", str(tmp_path / "calib-out"),
                        "--report", str(tmp_path / "c.md")], capture_output=True, text=True)
    assert r.returncode != 0 and "cannot be labelled live" in (r.stdout + r.stderr)
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "calibrate.py"), "--mode", "mock", "--out-dir", str(tmp_path / "calib-out"),
                        "--report", str(tmp_path / "c.md"), "--date", "2026-09-12"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    text = (tmp_path / "c.md").read_text(encoding="utf-8")
    assert text.startswith("---\nreport: calibration\ndate: '2026-09-12'\nmode: mock\n") and "無法計算" in text and "G-8 從未執行" in text


def test_calibration_run_refuses_live_with_mock_config():
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "calibration_run.py"), "--mode", "live", "--config", str(ROOT / "config" / "mara.mock.yaml")],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "mock providers" in r.stderr


def test_governance_g8_g9_fail_here_and_pass_on_live_reports(tmp_path):
    import governance_check as gc

    g8 = gc.check_g8(ROOT, TODAY, ROOT / "config" / "mara.yaml")
    g9 = gc.check_g9(ROOT, TODAY, ROOT / "config" / "mara.yaml")
    assert g8.status == gc.FAIL and "garak-*.md" in g8.evidence and "model_eval.py" in g8.evidence
    assert g9.status == gc.FAIL and "calibration_run.py --mode live" in g9.evidence
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "config" / "mara.yaml").write_text((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    fams = ["anthropic", "deepseek", "nemotron"]
    def fm(report, mode, families, extra=""):
        return "---\n" + yaml.safe_dump({"report": report, "date": "2026-09-01", "mode": mode, "families": families}) + extra + "---\n# x\n"
    (root / "docs" / "garak-2026-09-01.md").write_text(fm("garak", "dry-run", fams), encoding="utf-8")
    (root / "docs" / "cyberseceval-2026-09-01.md").write_text(fm("cyberseceval", "live", fams), encoding="utf-8")
    r = gc.check_g8(root, TODAY, root / "config" / "mara.yaml")
    assert r.status == gc.FAIL and "不是 live" in r.evidence
    (root / "docs" / "garak-2026-09-01.md").write_text(fm("garak", "live", ["anthropic", "deepseek"]), encoding="utf-8")
    assert "未涵蓋家族 ['nemotron']" in gc.check_g8(root, TODAY, root / "config" / "mara.yaml").evidence
    (root / "docs" / "garak-2026-09-01.md").write_text(fm("garak", "live", fams), encoding="utf-8")
    assert gc.check_g8(root, TODAY, root / "config" / "mara.yaml").status == gc.PASS
    assert gc.check_g8(root, TODAY + dt.timedelta(days=100), root / "config" / "mara.yaml").status == gc.FAIL, "older than 90 days"
    (root / "docs" / "calibration-2026-09-01.md").write_text(fm("calibration", "live", fams, "provider_modes: [mock]\nlabels: 51\n"), encoding="utf-8")
    assert gc.check_g9(root, TODAY, root / "config" / "mara.yaml").status == gc.FAIL, "provider mode mock inside a 'live' report"
    (root / "docs" / "calibration-2026-09-01.md").write_text(fm("calibration", "live", fams, "provider_modes: [live]\nlabels: 51\n"), encoding="utf-8")
    r = gc.check_g9(root, TODAY, root / "config" / "mara.yaml")
    assert r.status == gc.PASS and "51 個標籤" in r.evidence
    # the legacy mock report without front matter is still recognised as mock
    (root / "docs" / "calibration-2026-09-05.md").write_text("# 第一次校準報告\n\n執行模式：**mock**。\n", encoding="utf-8")
    assert "mock" in gc.check_g9(root, TODAY, root / "config" / "mara.yaml").evidence or gc.check_g9(root, TODAY, root / "config" / "mara.yaml").status == gc.PASS


def test_pipeline_records_model_eval_status(tmp_path, monkeypatch):
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path)
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    assert report.bias_audit["model_eval"] == {} and "## Model red-team evaluation" in render_markdown(report)
    assert me.family_eval_status(ROOT, ["deepseek"]) == {"deepseek": {"date": None, "mode": None, "status": "none"}}
