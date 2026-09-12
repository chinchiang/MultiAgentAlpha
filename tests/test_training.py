"""G-13: AI-literacy training register (EU AI Act Article 4): quiz grading, record validity and
expiry, coverage per role, CLI exit codes, governance check G-13, and the config block."""

import datetime as dt
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara import training  # noqa: E402
from mara.config import load_config  # noqa: E402

SCRIPT = ROOT / "scripts" / "training_register.py"
QUIZ = ROOT / "training" / "quiz.yaml"
TODAY = dt.date(2026, 9, 12)


def _answers(role: str) -> dict[str, str]:
    return {q["id"]: q["answer"] for q in training.questions_for(training.load_quiz(QUIZ), role)}


def _register(tmp_path: Path) -> Path:
    p = tmp_path / "records.yaml"
    p.write_text((ROOT / "training" / "records.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    return p


def test_quiz_is_well_formed_and_every_rationale_points_at_something_real():
    quiz = training.load_quiz(QUIZ)
    assert len(quiz) >= 12 and all(set(q["options"]) >= {"a", "b"} for q in quiz)
    for q in quiz:
        for role in q.get("roles") or training.ROLES:
            assert role in training.ROLES, q["id"]
        # every rationale names a file in this repository or a report section
        refs = [tok.strip("(),;.") for tok in q["rationale"].split() if "/" in tok]
        assert any((ROOT / r.split("::")[0]).exists() for r in refs) or "report" in q["rationale"], q["id"]
    for role in training.ROLES:
        assert len(training.questions_for(quiz, role)) >= 8, role
    assert training.grade(quiz, "adjudicator", _answers("adjudicator")) == (1.0, [])
    score, wrong = training.grade(quiz, "developer", {**_answers("developer"), "T1": "a", "T3": "c"})
    assert wrong == ["T1", "T3"] and 0 < score < 1
    assert training.grade(quiz, "security", {})[0] == 0.0


def test_records_validity_expiry_and_coverage(tmp_path):
    reg = training.load_register(_register(tmp_path))
    assert reg.curriculum_version == "2026-09" and reg.records == [] and reg.valid(TODAY) == []
    rec = training.add_record(reg, "alice", "adjudicator", TODAY, score=0.9, assessor="quiz", evidence="quiz")
    assert rec.expires == TODAY + dt.timedelta(days=365)
    training.add_record(reg, "bob", "developer", TODAY - dt.timedelta(days=400), score=None, assessor="carol", evidence="TRN-1")
    training.save_register(reg)
    text = reg.path.read_text(encoding="utf-8")
    assert text.startswith("# AI-literacy training register") and "person: alice" in text  # header comments survive a save
    reg2 = training.load_register(reg.path)
    assert training.is_trained(reg2, "alice", "adjudicator", TODAY) and training.is_trained(reg2, "ALICE", "adjudicator", TODAY)
    assert not training.is_trained(reg2, "alice", "security", TODAY)
    assert not training.is_trained(reg2, "bob", "developer", TODAY), "expired 35 days ago"
    assert not training.is_trained(reg2, "alice", "adjudicator", TODAY + dt.timedelta(days=366)), "expires after validity_days"
    assert not training.is_trained(None, "alice", "adjudicator", TODAY)
    cov = training.coverage(reg2, training.ROLES, TODAY)
    assert [len(cov[r]) for r in training.ROLES] == [0, 0, 1]
    assert [r.person for r in reg2.expiring(TODAY + dt.timedelta(days=340))] == ["alice"]
    # a new curriculum version invalidates old records
    reg2.curriculum_version = "2027-01"
    assert reg2.valid(TODAY) == []
    with pytest.raises(ValueError):
        training.add_record(reg2, "x", "manager", TODAY, score=None, assessor="y", evidence="z")


def test_cli_assess_add_check_status(tmp_path):
    reg = _register(tmp_path)
    run = lambda *a: subprocess.run([sys.executable, str(SCRIPT), "--register", str(reg), "--today", "2026-09-12", *a],  # noqa: E731
                                    capture_output=True, text=True)
    assert run("check").returncode == 1 and "no valid record for: developer, security, adjudicator" in run("check").stdout
    good = ",".join(f"{k}={v}" for k, v in _answers("adjudicator").items())
    r = run("assess", "--person", "alice", "--role", "adjudicator", "--answers", good)
    assert r.returncode == 0 and "record written: alice adjudicator 2026-09 2026-09-12" in r.stdout
    bad = ",".join(f"{k}=a" for k in _answers("developer"))
    r = run("assess", "--person", "dave", "--role", "developer", "--answers", bad)
    assert r.returncode == 1 and "not passed" in r.stdout
    assert run("status", "--person", "dave", "--role", "developer").returncode == 1
    r = run("add", "--person", "erin", "--role", "security", "--assessor", "frank", "--evidence", "TRN-7")
    assert r.returncode == 0 and "assessor frank" in r.stdout
    r = run("check")
    assert r.returncode == 1 and "no valid record for: developer" in r.stdout and "security: 1 valid (erin)" in r.stdout
    assert run("status", "--person", "alice", "--role", "adjudicator").returncode == 0
    r = subprocess.run([sys.executable, str(SCRIPT), "--register", str(reg), "--today", "2027-09-13", "status", "--person", "alice", "--role", "adjudicator"],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "NOT trained" in r.stdout
    r = subprocess.run([sys.executable, str(SCRIPT), "show-quiz", "--role", "developer"], capture_output=True, text=True)
    assert r.returncode == 0 and "T10." in r.stdout and "T12." not in r.stdout


def test_governance_g13_fails_here_and_passes_with_a_trained_person_per_role(tmp_path):
    import governance_check as gc

    r = gc.check_g13(ROOT, TODAY, ROOT / "config" / "mara.yaml")
    assert r.status == gc.FAIL and "developer, security, adjudicator" in r.evidence and "training_register.py" in r.evidence
    root = tmp_path / "repo"
    (root / "training").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "training" / "curriculum.md").write_text("# curriculum\n", encoding="utf-8")
    (root / "config" / "mara.yaml").write_text(yaml.safe_dump({"training": {"required_roles": ["developer", "security", "adjudicator"]}}), encoding="utf-8")
    reg = _register(root / "training")
    r = gc.check_g13(root, TODAY, root / "config" / "mara.yaml")
    assert r.status == gc.FAIL
    loaded = training.load_register(reg)
    for person, role in (("a", "developer"), ("b", "security"), ("c", "adjudicator")):
        training.add_record(loaded, person, role, TODAY - dt.timedelta(days=350), score=1.0, assessor="quiz", evidence="quiz")
    training.save_register(loaded)
    r = gc.check_g13(root, TODAY, root / "config" / "mara.yaml")
    assert r.status == gc.PASS and "adjudicator：1 筆有效（c）" in r.evidence and "30 天內到期" in r.evidence
    assert gc.check_g13(root, TODAY + dt.timedelta(days=20), root / "config" / "mara.yaml").status == gc.FAIL, "all expired"
    (root / "training" / "curriculum.md").unlink()
    assert "curriculum.md" in gc.check_g13(root, TODAY, root / "config" / "mara.yaml").evidence


def test_config_training_block():
    cfg = load_config(ROOT / "config" / "mara.yaml")
    assert cfg.training.register_file == "training/records.yaml" and cfg.training.require_trained_adjudicator
    assert cfg.training.required_roles == ["developer", "security", "adjudicator"]
