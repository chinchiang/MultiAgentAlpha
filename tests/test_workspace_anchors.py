"""MARA's own state - calibration evidence, decisions, the backlog, the training register, the PSIRT ledger and
handshake, the ML-BOM signature, the review output - is written and read in one place: the workspace (MARA_HOME,
else the working directory). The scripts used to write it below their own checkout (ROOT) while src/ read it from
the workspace, so with MARA_HOME set every reader missed what the writers wrote (architecture review candidate 3)."""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

from mara.config import MaraConfig

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


@pytest.fixture
def home(tmp_path, monkeypatch):
    """MARA_HOME somewhere, the working directory somewhere else."""
    h = tmp_path / "mara-home"
    h.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(h))
    monkeypatch.chdir(elsewhere)
    return h


def _mock_cfg(**over) -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    for k, v in over.items():
        raw[k] = {**raw.get(k, {}), **v}
    return MaraConfig.model_validate(raw, context={"skip_policies": True})


def test_no_script_builds_a_trust_anchor_path_from_its_checkout():
    anchors = re.compile(r'ROOT / "calib" / "(decisions|latest\.json|history\.json)"|ROOT / "training" / "records\.yaml"'
                         r'|ROOT / ps\.handshake_file|else ROOT / p\b')
    offenders = [f"{p.name}:{n}" for p in sorted((ROOT / "scripts").glob("*.py"))
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if anchors.search(line)]
    assert offenders == [], offenders


def test_calibration_writes_where_policy_p8_reads(home):
    import calibrate

    from mara.policy import AAT_EVIDENCE
    from mara.workspace import Workspace, resolve

    paths = calibrate.anchor_paths(Workspace.from_env())
    assert paths["latest"] == home / "calib" / "latest.json" == resolve(AAT_EVIDENCE)
    assert paths["history"].parent == paths["decisions"].parent == home / "calib"


def test_the_psirt_ledger_and_handshake_are_where_the_review_writes_them(home):
    import psirt_ops

    from mara.workspace import Workspace

    cfg = _mock_cfg()
    assert psirt_ops._ledger_path(cfg, Workspace.from_env()) == home / cfg.psirt.ledger_file


def test_the_default_review_output_is_in_the_workspace(home):
    from mara.pipeline import Pipeline

    assert Pipeline(_mock_cfg()).out_dir == home / "out"


@pytest.mark.parametrize("content", ["[1, 2]", '"open"', "7"])
def test_a_damaged_backlog_is_unknown_not_a_crash(home, content):
    """A list-shaped backlog.json raised AttributeError in Pipeline.__init__ (read_backlog caught TypeError only)."""
    from mara.decisions import read_backlog
    from mara.pipeline import Pipeline

    cfg = _mock_cfg()
    path = home / cfg.human_queue.backlog_file
    path.parent.mkdir(parents=True)
    path.write_text(content, encoding="utf-8")
    assert read_backlog(cfg) is None
    assert Pipeline(cfg).backlog is None


@pytest.mark.parametrize("content", ["[]", '"live"', "{not json"])
def test_damaged_calibration_evidence_fails_policy_p8_instead_of_crashing(home, content):
    from mara.policy import p8_unsupervised_reject

    (home / "calib").mkdir()
    (home / "calib" / "latest.json").write_text(content, encoding="utf-8")
    result = p8_unsupervised_reject(_mock_cfg(gate={"unsupervised_reject_allowed": True}))
    assert not result.passed and "missing or unreadable" in result.reason


def test_the_ml_bom_signature_bundle_is_found_in_the_workspace(home):
    """P7 looked for the bundle relative to the working directory while the BOM itself was read from the workspace."""
    from mara.policy import p7_ml_bom

    raw = yaml.safe_load((ROOT / "config" / "examples" / "ml-bom-required.yaml").read_text(encoding="utf-8"))
    raw["ml_bom"] = {**raw.get("ml_bom", {}), "require_signature": True, "bundle": "sbom/bom.sigstore.json",
                     "certificate_identity": "ci@example", "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"}
    cfg = MaraConfig.model_validate(raw, context={"skip_policies": True})
    assert "signature bundle sbom/bom.sigstore.json not found" in p7_ml_bom(cfg).reason
    (home / "sbom").mkdir()
    (home / "sbom" / "bom.sigstore.json").write_text(json.dumps({}), encoding="utf-8")
    assert "sbom/bom.sigstore.json not found" not in p7_ml_bom(cfg).reason


# ---------------------------------------------------------------- G-8 model-eval summaries


def _eval_summary(root, date="2026-09-12"):
    (root / "calib").mkdir(parents=True, exist_ok=True)
    (root / "calib" / f"model-eval-{date}.json").write_text(json.dumps(
        {"date": date, "mode": "live", "garak_version": "0.17.0", "cyberseceval_ref": "ref",
         "families": {"glm": {"verdict": {"overall": "pass"}}}}), encoding="utf-8")


def test_calibration_reads_the_model_eval_summary_the_pipeline_reads(home):
    """calibrate.load_model_eval read calib/model-eval-*.json from the script's checkout while the pipeline's
    bias audit (family_eval_status) reads the workspace: with MARA_HOME set the suggested weights ignored G-8."""
    import calibrate

    from mara.workspace import Workspace

    _eval_summary(home)
    assert (calibrate.load_model_eval(Workspace.from_env()) or {}).get("date") == "2026-09-12"


def test_model_eval_report_and_check_use_the_workspace(home, monkeypatch, capsys):
    import model_eval

    monkeypatch.setattr(sys, "argv", ["model_eval.py", "--config", str(ROOT / "config" / "examples" / "psirt-enabled.yaml"), "report",
                                      "--run-dir", str(ROOT / "fixtures" / "model-eval"), "--date", "2026-09-12",
                                      "--docs-dir", str(home / "docs")])
    assert model_eval.main() == 0
    assert (home / "calib" / "model-eval-2026-09-12.json").is_file(), "written where family_eval_status reads"
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["model_eval.py", "check"])
    model_eval.main()
    assert "2026-09-12 mode dry-run" in capsys.readouterr().out


def test_no_script_reads_or_writes_model_eval_summaries_in_its_checkout():
    pattern = re.compile(r"latest_summary\(ROOT\)|\"--summary-root\".*default=ROOT\)")
    offenders = [f"{p.name}:{n}" for p in sorted((ROOT / "scripts").glob("*.py"))
                 for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if pattern.search(line)]
    assert offenders == [], offenders


# ---------------------------------------------------------------- check_outside judges the workspace it is given

def _outside_environment(monkeypatch, tmp_path):
    """MARA_HOME, MARA_TOOLS_DIR and MARA_TRIVY_CACHE_DIR all well outside any target."""
    env = tmp_path / "environment"
    env.mkdir()
    monkeypatch.setenv("MARA_HOME", str(env))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(env / "tools"))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(env / "cache"))
    return env


@pytest.mark.parametrize("anchor, match", [("root", "MARA workspace"), ("tools_dir", "tool directory"), ("trivy_cache", "trivy")])
def test_check_outside_refuses_a_target_that_holds_an_anchor_of_the_workspace_it_is_given(tmp_path, monkeypatch, anchor, match):
    """Each anchor is the given workspace's own, never the environment's, which here lies outside the target."""
    from mara import workspace
    from mara.workspace import Workspace

    _outside_environment(monkeypatch, tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    safe = tmp_path / "safe"
    anchors = {"root": safe / "root", "tools_dir": safe / "tools", "trivy_cache": safe / "cache"}
    anchors[anchor] = target / anchor
    ws = Workspace(anchors["root"], anchors["tools_dir"], anchors["trivy_cache"])
    with pytest.raises(workspace.WorkspaceInsideTarget, match=match):
        workspace.check_outside(target, workspace=ws)


def test_check_outside_accepts_a_target_when_the_anchors_of_the_workspace_it_is_given_lie_outside_it(tmp_path, monkeypatch):
    """The environment's anchors are not consulted: they lie inside the target here, the given workspace's do not."""
    from mara import workspace
    from mara.workspace import Workspace

    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("MARA_HOME", str(target))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(target / "tools"))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(target / "cache"))
    safe = tmp_path / "safe"
    workspace.check_outside(target, workspace=Workspace(safe, safe / "tools", safe / "cache"))


# ---------------------------------------------------------------- a script hands its workspace to the readers that take one

# The functions of src/ that read the environment again when they are given no workspace, and how each takes one: the
# `workspace=` keyword, or for those of _NEEDS_SECOND_ARGUMENT the second argument named there.
_NEEDS_WORKSPACE_KEYWORD = frozenset({"tools_dir", "cache_dir", "tool_path", "installed_version", "installed_manifest_entry",
                                      "rules_dir", "installed_rule_paths", "driver_path", "run_csp_eval"})
_NEEDS_SECOND_ARGUMENT = {"load_config": "workspace", "evaluate_policies": "workspace", "status_for_config": "root",
                          "resolve": "base", "from_config_file": "workspace"}


def _mara_names(tree) -> set[str]:
    """The names a script imports from the `mara` package (a script's own `load_config`, as trivy_db.py's, is not one)."""
    import ast

    return {a.asname or a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "mara"
            for a in n.names}


def _anchor_violations(source: str) -> list[str]:
    """The calls in `source` that leave the workspace to the environment, and the imports of `mara.workspace.root`."""
    import ast

    tree = ast.parse(source)
    mara = _mara_names(tree)
    aliases = {a.asname or a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
               and (n.module or "").split(".")[0] == "mara" for a in n.names} | {"tdb", "mlbom"}
    found = []
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "mara.workspace" and any(a.name == "root" for a in n.names):
            found.append(f"{n.lineno}: imports mara.workspace.root, which goes when every caller passes its workspace")
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in mara:
            name = f.id
        elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in aliases:
            name = f.attr
        else:
            continue
        kws = {k.arg for k in n.keywords}
        if name in _NEEDS_WORKSPACE_KEYWORD and "workspace" not in kws:
            found.append(f"{n.lineno}: {name}() without workspace=")
        elif name in _NEEDS_SECOND_ARGUMENT and len(n.args) < 2 and _NEEDS_SECOND_ARGUMENT[name] not in kws:
            found.append(f"{n.lineno}: {name}() without its {_NEEDS_SECOND_ARGUMENT[name]}")
    return sorted(found)


@pytest.mark.parametrize("source, count", [
    ("from mara.config import load_config\nload_config(p)", 1),
    ("from mara.config import load_config\nload_config(p, ws)", 0),
    ("from mara.config import load_config\nload_config(p, workspace=ws, enforce_policies=False)", 0),
    ("from mara.policy import evaluate_policies\nevaluate_policies(cfg)", 1),
    ("from mara.policy import evaluate_policies\nevaluate_policies(cfg, ws)", 0),
    ("from mara.tools.runner import tools_dir\ntools_dir()", 1),
    ("from mara.tools.runner import tools_dir\ntools_dir(root)", 1),
    ("from mara.tools.runner import tools_dir\ntools_dir(workspace=ws)", 0),
    ("from mara.tools.runner import tool_path, installed_version\ntool_path('a'); installed_version('a')", 2),
    ("from mara.tools.runner import tool_path\ntool_path('a', workspace=ws)", 0),
    ("from mara.tools import trivy_db as tdb\ntdb.cache_dir()", 1),
    ("from mara.tools import trivy_db as tdb\ntdb.cache_dir(workspace=ws)", 0),
    ("from mara import mlbom\nmlbom.status_for_config(cfg)", 1),
    ("from mara import mlbom\nmlbom.status_for_config(cfg, ws.root)", 0),
    ("from mara.decisions import TrainingRequirement\nTrainingRequirement.from_config_file(p)", 1),
    ("from mara.decisions import TrainingRequirement\nTrainingRequirement.from_config_file(p, ws)", 0),
    ("from mara.decisions import TrainingRequirement\nTrainingRequirement.from_config_file(p, workspace=ws)", 0),
    ("class Thing:\n    def from_config_file(self, p):\n        pass\nThing().from_config_file(p)", 0),  # not a mara reader
    ("from mara.workspace import resolve\nresolve('config/mara.yaml')", 1),
    ("from mara.workspace import resolve\nresolve('config/mara.yaml', ws.root)", 0),
    ("from mara.workspace import resolve\nresolve('config/mara.yaml', base=ws.root)", 0),
    ("from mara.workspace import root\nroot()", 1),
    ("from mara.workspace import root as workspace_root\nworkspace_root()", 1),
    ("from mara.workspace import Workspace\nWorkspace.from_env()", 0),
    ("def load_config(path):\n    pass\nload_config(p)", 0),  # a script's own function of the name
    ("from trivy_db import load_config\nload_config()", 0),  # another script's, not mara's
    ("resolver.resolve(repo, ref)", 0),  # not mara.workspace.resolve
])
def test_the_scan_for_calls_that_leave_the_workspace_to_the_environment_sees_what_it_should(source, count):
    assert len(_anchor_violations(source)) == count, _anchor_violations(source)


@pytest.mark.parametrize("script", sorted((ROOT / "scripts").glob("*.py")), ids=lambda p: p.name)
def test_no_script_calls_a_reader_without_the_workspace(script):
    """Each call in a script of a reader named above gives it a workspace; a reader given none reads the environment
    again. The scan reads calls only: it does not count how often a script builds a workspace, and it does not see a
    reader it does not name."""
    assert _anchor_violations(script.read_text(encoding="utf-8")) == []
