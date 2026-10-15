"""Regression tests for the remaining #74 review points (even judge chunks, '../' control citations, L3 canary
report counts, the one-judge-per-family rule in `mara check-config`) and tools review items 5 and 6
(install_tools.py's default directory, stale mock fixtures and gen_mock_fixtures.py --check)."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from mara import exchange
from mara.agents import skeptic
from mara.cli import app
from mara.config import MaraConfig, load_config
from mara.context.repo_map import RepoContext
from mara.pipeline import MAX_L4_FINDINGS, Pipeline, l4_chunks
from mara.schemas import Finding, ModelFamily, Provenance, RedTeamNote, SkepticVerdict
from mara.tools import runner
from tests.reply_records import ballot

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import gen_mock_fixtures  # noqa: E402
import install_tools  # noqa: E402

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _finding(i: int) -> Finding:
    return Finding(id=f"F-{i:04d}", dimension="vulnerabilities", title=f"finding {i}", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=1, quote="unsafe()", verified=True)],
                   reachability="reachable", reachability_argument="public", exploit_sketch="input",
                   cvss4_vector=VECTOR, model_confidence=0.9, source_family=ModelFamily.ANTHROPIC, source_model="test")


# ------------------------------------------------------------------ even judge chunks

@pytest.mark.parametrize("n, sizes", [(0, []), (1, [1]), (25, [25]), (26, [13, 13]), (27, [14, 13]), (51, [17, 17, 17]), (60, [20, 20, 20])])
def test_judge_chunks_are_as_few_and_as_even_as_possible(n, sizes):
    order = list(range(n))
    chunks = l4_chunks(order)
    assert [len(c) for c in chunks] == sizes and [x for c in chunks for x in c] == order
    assert all(len(c) <= MAX_L4_FINDINGS for c in chunks)


def test_no_finding_is_left_alone_in_a_judge_chunk(tmp_path, monkeypatch):
    """26 findings used to give chunks of 25 and 1: the last one's reverse pass was its forward pass."""
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")
    findings = [_finding(i) for i in range(1, 27)]
    calls = []
    monkeypatch.setattr("mara.pipeline.judge.run_judge",
                        lambda p, batch, pass_id, self_ids=None: (calls.append([b["finding_id"] for b in batch]),
                                                                  ([], ballot("judge", p.family.value, len(batch), exchange.REFUSAL,
                                                                              pass_id=pass_id)))[1])
    pipe.run_jury(RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h"), findings, {},
                  {f.id: {ModelFamily.ANTHROPIC} for f in findings})
    assert calls and {len(c) for c in calls} == {13}


# ------------------------------------------------------------------ control citations outside the target

def test_control_citations_outside_the_target_are_not_rewritten_into_shown_files():
    ctx = RepoContext(root=Path("."), content={"app.py": "import db\n\nq = db.param(x)\n", "config/app.py": "a\nb\nc = 1\n",
                                               ".env": "KEY=1\n"})
    shown = {"app.py", "config/app.py", ".env"}
    assert not skeptic._control_location_ok(ctx, "see ../app.py:3", shown), "a file above the target"
    assert not skeptic._control_location_ok(ctx, "see ../config/app.py:3", shown)
    assert not skeptic._control_location_ok(ctx, "see ../../app.py:3", shown)
    assert skeptic._control_location_ok(ctx, "see ...app.py:3", shown), "an ellipsis in prose is still dropped"
    assert skeptic._control_location_ok(ctx, ".env:1", shown) and skeptic._control_location_ok(ctx, "./app.py:3", shown)


# ------------------------------------------------------------------ L3 canary reports in the bias audit

def test_l3_canary_reports_reach_the_bias_audit(tmp_path, monkeypatch):
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")
    f = _finding(1)
    verdict = SkepticVerdict(finding_id=f.id, verdict="stands", reason="r", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON,
                             source_model="m")
    note = RedTeamNote(finding_id=f.id, exploitable="unknown", preconditions="none", source_family=ModelFamily.DEEPSEEK, source_model="m")
    # each answered its one finding with a verdict that names the planted file: kept, and counted as a report
    monkeypatch.setattr("mara.pipeline.skeptic.run_skeptic", lambda p, ctx, fs: ([verdict], ballot("skeptic", p.family.value, 1, canary_reports=1)))
    monkeypatch.setattr("mara.pipeline.redteam.run_redteam", lambda p, ctx, fs: ([note], ballot("redteam", p.family.value, 1, canary_reports=1)))
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"})
    pipe.run_skeptics(ctx, [f], {f.id: {ModelFamily.ANTHROPIC}})
    pipe.run_redteam(ctx, [f], {f.id: {ModelFamily.ANTHROPIC}})
    assert pipe.audit["skeptic_canary_reports"] == 1 and pipe.audit["skeptic_canary_reports[nemotron]"] == 1
    assert pipe.audit["redteam_canary_reports"] == 1 and pipe.audit["redteam_canary_reports[deepseek]"] == 1


# ------------------------------------------------------------------ one judge per family, as a policy

def _two_anthropic_judges() -> dict:
    return {
        "models": [{"name": n, "family": fam, "provider": "mock", "model": n, "data_residency": "on_prem"}
                   for n, fam in (("a", "anthropic"), ("a2", "anthropic"), ("d", "deepseek"), ("n", "nemotron"))],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "a2", "d"]},
    }


def test_check_config_reports_two_judges_of_one_family_in_its_policy_table(tmp_path):
    cfg = tmp_path / "two-judges.yaml"
    cfg.write_text(yaml.safe_dump(_two_anthropic_judges()), encoding="utf-8")
    r = CliRunner().invoke(app, ["check-config", str(cfg), "--json"])
    assert r.exit_code == 1 and not isinstance(r.exception, ValueError), "a policy failure, not an aborted validation"
    results = {x["id"]: x for x in json.loads(r.stdout)}  # stdout is one JSON document; the summary goes to stderr
    assert set(results) >= {"P1", "P2", "P3", "P4", "P5"}, "every other policy is still evaluated and shown"
    reason = " ".join(results["P3"]["reason"].split())
    assert not results["P3"]["passed"] and "each judge must come from a different model family" in reason
    with pytest.raises(ValueError, match="P3 panel-size: each judge must come from a different model family"):
        MaraConfig.model_validate(_two_anthropic_judges())


# ------------------------------------------------------------------ install_tools.py installs where mara looks

@pytest.mark.parametrize("env", [{}, {"MARA_HOME": "ws"}, {"MARA_TOOLS_DIR": "abs"}, {"MARA_TOOLS_DIR": "rel-tools"},
                                 {"MARA_HOME": "ws", "MARA_TOOLS_DIR": "rel-tools"}])
def test_install_tools_default_directory_is_the_runners(tmp_path, monkeypatch, env):
    monkeypatch.delenv("MARA_HOME", raising=False)
    monkeypatch.delenv("MARA_TOOLS_DIR", raising=False)
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    for key, value in env.items():
        monkeypatch.setenv(key, str(tmp_path / value) if value in ("ws", "abs") else value)
    lock = install_tools.load_lock(ROOT / "tools" / "versions.lock")
    assert install_tools.default_install_dir(lock).resolve() == runner.tools_dir()


# ------------------------------------------------------------------ mock fixtures stay generated

def test_committed_mock_fixtures_are_what_the_generator_writes(capsys):
    assert gen_mock_fixtures.main(["--check"]) == 0, capsys.readouterr().err


def test_check_mode_reports_stale_missing_and_extra_files_and_writes_nothing(tmp_path, monkeypatch):
    copy = tmp_path / "mock-responses"
    shutil.copytree(gen_mock_fixtures.OUT, copy)
    monkeypatch.setattr(gen_mock_fixtures, "OUT", copy)
    stale = copy / "reviewer_xss_anthropic.json"
    doc = json.loads(stale.read_text(encoding="utf-8"))
    doc["findings"][0]["provenance"][0]["line"] -= 1
    stale.write_text(json.dumps(doc, indent=1, ensure_ascii=False), encoding="utf-8")
    (copy / "judge_anthropic.json").unlink()
    (copy / "leftover.json").write_text("{}", encoding="utf-8")
    before = {p.name: p.read_bytes() for p in copy.glob("*.json")}
    assert gen_mock_fixtures.main(["--check"]) == 1
    assert gen_mock_fixtures.stale(copy) == ["judge_anthropic.json", "leftover.json", "reviewer_xss_anthropic.json"]
    assert {p.name: p.read_bytes() for p in copy.glob("*.json")} == before, "--check writes nothing"


def test_every_genuine_mock_quote_is_exactly_its_claimed_line():
    """A quote one line off still passed the +-3-line provenance window, so stale fixtures went unnoticed and
    line-level tool corroboration was not really exercised. Only the one deliberately fabricated quote may miss."""
    sample = ROOT / "fixtures" / "vuln-sample"
    misses = []
    for path in sorted(gen_mock_fixtures.OUT.glob("reviewer_*.json")):
        for f in json.loads(path.read_text(encoding="utf-8")).get("findings", []):
            for p in f["provenance"]:
                lines = (sample / p["file"]).read_text(encoding="utf-8").splitlines()
                if lines[p["line"] - 1].strip()[:200] != p["quote"]:
                    misses.append((path.name, f["title"]))
    assert misses == [("reviewer_vulnerabilities_anthropic.json", "SQL injection in profile query")]
