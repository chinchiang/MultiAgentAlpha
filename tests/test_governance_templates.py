"""G-1 / G-4 / G-10 templates: the policy front matter, the cold-standby configs and drill register,
and the rollout phase are machine-decidable; the repository state fails each with a precise reason."""

import datetime as dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara import govdocs  # noqa: E402
from mara.cli import app  # noqa: E402
from mara.config import MaraConfig, load_config  # noqa: E402
from mara.policy import evaluate_policies  # noqa: E402
from mara.schemas import ModelFamily  # noqa: E402

TODAY = dt.date(2026, 9, 12)
POLICY = ROOT / "docs" / "policy" / "mara-review-policy.md"


# ---------------------------------------------------------------- G-1

def test_policy_template_is_a_complete_draft_and_approval_flips_it():
    st = govdocs.policy_status(POLICY, TODAY)
    assert not st.ok and st.state == "draft" and all(st.statements[s] for s in govdocs.POLICY_REQUIRED)
    assert any("approved" in p for p in st.problems) and st.meta["policy_id"] == "MARA-POL-001"


def test_policy_status_states(tmp_path):
    text = POLICY.read_text(encoding="utf-8")
    approved = text.replace("status: draft ", "status: approved ").replace('approved_by: ""', 'approved_by: "pso-login"') \
        .replace('approved_on: ""', 'approved_on: "2026-09-01"').replace('review_by: ""', 'review_by: "2027-09-01"')
    p = tmp_path / "policy.md"
    p.write_text(approved, encoding="utf-8")
    st = govdocs.policy_status(p, TODAY)
    assert st.ok and st.state == "approved", st.problems
    assert govdocs.policy_status(p, dt.date(2027, 9, 2)).state == "stale"           # review_by passed
    stale = approved.replace('review_by: "2027-09-01"', 'review_by: ""')
    p.write_text(stale, encoding="utf-8")
    assert govdocs.policy_status(p, dt.date(2027, 9, 2)).state == "stale"           # > 365 days, no review date
    broken = approved.replace("<!-- policy:S2 -->", "")
    p.write_text(broken, encoding="utf-8")
    st = govdocs.policy_status(p, TODAY)
    assert st.state == "incomplete" and not st.statements["S2"]
    assert govdocs.policy_status(tmp_path / "none.md", TODAY).state == "missing"


# ---------------------------------------------------------------- G-4

def test_standby_configs_swap_exactly_one_family_and_pass_policies():
    prod = load_config(ROOT / "config" / "mara.yaml")
    fams = govdocs.production_families(prod)
    assert fams == ["anthropic", "deepseek", "nemotron"]
    standbys = govdocs.standby_configs(ROOT)
    assert set(standbys) == set(fams)
    for fam, path in standbys.items():
        sb_fam, problem = govdocs._standby_family_of(fams, path, fam)
        assert not problem and sb_fam in ("llama", "mistral", "qwen"), (fam, problem)
        cfg = load_config(path)
        assert all(r.passed for r in evaluate_policies(cfg))
        assert yaml.safe_load(path.read_text(encoding="utf-8"))["standby_for"] == fam
    assert {"llama", "mistral", "qwen"} <= {f.value for f in ModelFamily}


def test_p2_holds_qwen_to_private_endpoints():
    raw = yaml.safe_load((ROOT / "config" / "examples" / "standby-for-deepseek.yaml").read_text(encoding="utf-8"))
    raw["models"][1].update({"family": "qwen", "name": "qwen-reviewer", "base_url": "https://dashscope.example.com/v1"})
    raw["roles"] = {k: ([n if n != "llama-reviewer" else "qwen-reviewer" for n in v] if isinstance(v, list) else (v if v != "llama-reviewer" else "qwen-reviewer"))
                    for k, v in raw["roles"].items()}
    with pytest.raises(ValueError, match="P2"):
        MaraConfig.model_validate(raw)
    raw["models"][1]["base_url"] = "http://vllm-qwen.internal:8000/v1"
    assert MaraConfig.model_validate(raw).models[1].family == ModelFamily.QWEN


def test_drills_register_and_status(tmp_path):
    drills = tmp_path / "drills.yaml"
    shutil.copy(ROOT / "ops" / "model-swap-drills.yaml", drills)
    prod = load_config(ROOT / "config" / "mara.yaml")
    st = {s.family: s for s in govdocs.drill_status(prod, ROOT, TODAY, drills)}
    assert all(s.config_ok and not s.drill_ok and s.drill_problem == "no live drill recorded" for s in st.values())
    govdocs.append_drill(drills, govdocs.Drill(TODAY, "rehearsal", "deepseek", "llama", "config/examples/standby-for-deepseek.yaml", 0.01, "pass", "x", "mock"))
    assert not govdocs.drill_status(prod, ROOT, TODAY, drills)[1].drill_ok, "a rehearsal never satisfies G-4"
    govdocs.append_drill(drills, govdocs.Drill(TODAY - dt.timedelta(days=10), "live", "deepseek", "llama",
                                               "config/examples/standby-for-deepseek.yaml", 200.0, "pass", "x", "CHG-1"))
    s = {x.family: x for x in govdocs.drill_status(prod, ROOT, TODAY, drills)}["deepseek"]
    assert not s.drill_ok and "need pass within 168 h" in s.drill_problem
    govdocs.append_drill(drills, govdocs.Drill(TODAY - dt.timedelta(days=5), "live", "deepseek", "llama",
                                               "config/examples/standby-for-deepseek.yaml", 54.0, "pass", "x", "CHG-2"))
    s = {x.family: x for x in govdocs.drill_status(prod, ROOT, TODAY, drills)}["deepseek"]
    assert s.drill_ok and s.drill.evidence == "CHG-2"
    assert not {x.family: x for x in govdocs.drill_status(prod, ROOT, TODAY + dt.timedelta(days=400), drills)}["deepseek"].drill_ok, "older than a year"
    text = drills.read_text(encoding="utf-8")
    assert text.startswith("# Model-swap drill register") and text.count("kind: live") == 2


def test_drill_cli_rehearse_record_check(tmp_path):
    drills = tmp_path / "drills.yaml"
    shutil.copy(ROOT / "ops" / "model-swap-drills.yaml", drills)
    script = ROOT / "scripts" / "model_swap_drill.py"
    run = lambda *a: subprocess.run([sys.executable, str(script), "--drills", str(drills), "--today", "2026-09-12", *a],  # noqa: E731
                                    capture_output=True, text=True)
    assert run("check").returncode == 1
    r = run("rehearse", "--standby", str(ROOT / "config" / "examples" / "standby-for-nemotron.yaml"))
    assert r.returncode == 0 and "replaces nemotron with mistral" in r.stdout and "dimensions unchanged: True" in r.stdout
    r = run("record", "--replaced", "nemotron", "--standby-config", str(ROOT / "config" / "examples" / "standby-for-nemotron.yaml"),
            "--started", "2026-09-01T09:00", "--completed", "2026-09-02T09:00", "--outcome", "pass", "--performed-by", "ops", "--evidence", "CHG-9")
    assert r.returncode == 0 and "24.0 h pass; counts for G-4" in r.stdout
    r = run("check")
    assert r.returncode == 1 and "nemotron: OK" in r.stdout and "anthropic: MISSING" in r.stdout
    r = run("record", "--replaced", "anthropic", "--standby-config", str(ROOT / "config" / "examples" / "standby-for-nemotron.yaml"),
            "--started", "2026-09-01T09:00", "--completed", "2026-09-02T09:00", "--outcome", "pass", "--performed-by", "ops", "--evidence", "x")
    assert r.returncode == 2 and "still contains the anthropic family" in r.stderr


# ---------------------------------------------------------------- G-10

def _cfg(**rollout) -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = {**raw.get("rollout", {}), **rollout}
    return MaraConfig.model_validate(raw)


def test_rollout_status_by_phase(tmp_path):
    assert not govdocs.rollout_status(_cfg(), ROOT, TODAY).ok
    st = govdocs.rollout_status(_cfg(phase="shadow", started_on="2026-08-01"), ROOT, TODAY)
    assert st.ok and st.days_in_phase == 42 and st.due == dt.date(2026, 9, 30)
    st = govdocs.rollout_status(_cfg(phase="shadow", started_on="2026-05-01"), ROOT, TODAY)
    assert not st.ok and "produce the baseline report" in st.problems[0]
    assert not govdocs.rollout_status(_cfg(phase="shadow", started_on="2026-12-01"), ROOT, TODAY).ok, "future start"
    st = govdocs.rollout_status(_cfg(phase="advisory", started_on="2026-09-01"), ROOT, TODAY)
    assert not st.ok and "baseline_report is empty" in st.problems[0]
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "rollout-baseline-2026-08-31.md").write_text("# baseline\n", encoding="utf-8")
    cfg = _cfg(phase="advisory", started_on="2026-09-01", baseline_report="docs/rollout-baseline-2026-08-31.md")
    assert govdocs.rollout_status(cfg, tmp_path, TODAY).ok
    assert not govdocs.rollout_status(cfg, ROOT, TODAY).ok, "baseline file missing under this root"
    cfg = _cfg(phase="blocking", started_on="2026-09-01", baseline_report="docs/rollout-baseline-2026-08-31.md")
    st = govdocs.rollout_status(cfg, tmp_path, TODAY)
    assert st.ok and "blocks" in st.notes[0]


def test_review_exit_code_follows_the_rollout_phase(tmp_path):
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    runner = CliRunner()
    for phase, expected in (("not_started", 0), ("shadow", 0), ("advisory", 0), ("blocking", 2)):
        raw["rollout"] = {"phase": phase, "started_on": "2026-09-01"}
        cfg = tmp_path / f"{phase}.yaml"
        cfg.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        r = runner.invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(cfg),
                                "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(tmp_path / phase)])
        assert r.exit_code == expected, (phase, r.output[-600:])
        report = json.loads((tmp_path / phase / "report.json").read_text(encoding="utf-8"))
        assert report["bias_audit"]["rollout_phase"] == phase and not report["gate_passed"]
        md = (tmp_path / phase / "report.md").read_text(encoding="utf-8")
        assert f"rollout phase `{phase}`" in md and (("recorded, not enforced" in md) == (phase != "blocking"))
    r = runner.invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(tmp_path / "shadow.yaml"),
                            "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(tmp_path / "forced"), "--fail-on-gate"])
    assert r.exit_code == 2, "--fail-on-gate still forces the exit code in shadow"


def test_baseline_report_and_advance_cli(tmp_path):
    runner = CliRunner()
    for i in range(2):
        r = runner.invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock",
                                "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"), "--out", str(tmp_path / f"run{i}")])
        assert r.exit_code == 0
    metrics = govdocs.baseline_metrics(sorted(tmp_path.rglob("report.json")), ROOT / "calib" / "decisions")
    assert metrics["reviews"] == 2 and metrics["gate_would_block_rate"] == 1.0 and metrics["modes"] == ["mock"]
    assert metrics["tiers"]["A"] > 0 and metrics["false_positive_rate_from_decisions"] is None
    script = ROOT / "scripts" / "rollout_phase.py"
    r = subprocess.run([sys.executable, str(script), "--today", "2026-09-12", "baseline", "--runs", str(tmp_path), "--out", str(tmp_path / "b.md")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "2 review(s)" in r.stdout and "mock-mode reports included" in r.stdout
    text = (tmp_path / "b.md").read_text(encoding="utf-8")
    assert "| gate would-block rate | 1.0 |" in text and "Mock mode reports are included" in text
    r = subprocess.run([sys.executable, str(script), "--today", "2026-09-12", "status"], capture_output=True, text=True)
    assert r.returncode == 1 and "not_started" in r.stdout
    r = subprocess.run([sys.executable, str(script), "--today", "2026-09-12", "advance", "--to", "shadow"], capture_output=True, text=True)
    assert r.returncode == 0 and "phase: shadow" in r.stdout
    r = subprocess.run([sys.executable, str(script), "--today", "2026-09-12", "advance", "--to", "blocking"], capture_output=True, text=True)
    assert r.returncode == 2 and "cannot advance" in r.stderr
    # advancing out of shadow needs time, a baseline, and no mock baseline
    raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8"))
    raw["rollout"] = {"phase": "shadow", "started_on": "2026-06-01", "baseline_report": "docs/nonexistent.md"}
    cfg = tmp_path / "shadow.yaml"
    cfg.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    r = subprocess.run([sys.executable, str(script), "--config", str(cfg), "--today", "2026-09-12", "advance", "--to", "advisory"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "baseline report missing" in r.stdout and "only" not in r.stdout


# ---------------------------------------------------------------- governance rows

def test_governance_rows_are_decidable_now():
    import governance_check as gc

    g1 = gc.check_g1(ROOT, TODAY)
    g4 = gc.check_g4(ROOT, ROOT / "config" / "mara.yaml", TODAY)
    g10 = gc.check_g10(ROOT, ROOT / "config" / "mara.yaml", TODAY)
    assert (g1.status, g4.status, g10.status) == (gc.FAIL, gc.FAIL, gc.FAIL)
    assert "草案" in g1.evidence and "approved_by" in g1.evidence
    assert "no live drill recorded" in g4.evidence and "standby-for-deepseek.yaml" in g4.evidence
    assert "not_started" in g10.evidence
    assert all(r.status != gc.MANUAL for r in gc.run_all(ROOT, ROOT / "config" / "mara.yaml", TODAY))
