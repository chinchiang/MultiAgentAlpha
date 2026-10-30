"""The review invocation (GLOSSARY.md: Review invocation, Provider mode) through `mara.invocation`'s public functions:
a config's models classify as mock, live or mixed, and a review runs only in the provider mode its models have."""

import re
import shutil
from pathlib import Path

import pytest
import yaml
from typer.main import get_command
from typer.testing import CliRunner

from mara import progress
from mara.cli import app
from mara.invocation import REVIEW_ARTIFACTS, InvocationError, ReviewInvocation, argv, check_provider_mode, config_provider_mode, exit_code, outcome
from tests import cli_output

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(("kinds", "provider_mode"), [({"mock"}, "mock"), ({"bedrock"}, "live"), ({"mock", "bedrock"}, "mixed")])
def test_a_configs_models_classify_as_mock_live_or_mixed(kinds, provider_mode):
    assert config_provider_mode(kinds) == provider_mode


@pytest.mark.parametrize(("kinds", "provider_mode"), [({"mock"}, "mock"), ({"bedrock"}, "live")])
def test_a_review_runs_in_the_provider_mode_its_models_have(kinds, provider_mode):
    check_provider_mode(kinds, provider_mode)


@pytest.mark.parametrize(("kinds", "provider_mode", "message"), [
    ({"mock"}, "live", "the models' providers are ['mock']; --provider live needs no mock model"),
    ({"bedrock"}, "mock", "the models' providers are ['bedrock']; --provider mock needs only mock models"),
    ({"mock", "bedrock"}, "live", "the models' providers are ['bedrock', 'mock']; --provider live needs no mock model"),
    ({"mock", "bedrock"}, "mock", "the models' providers are ['bedrock', 'mock']; --provider mock needs only mock models"),
])
def test_any_other_provider_mode_is_refused_on_provider(kinds, provider_mode, message):
    with pytest.raises(InvocationError) as e:
        check_provider_mode(kinds, provider_mode)
    assert (e.value.kind, e.value.param, str(e.value)) == ("provider_mismatch", "--provider", message)


@pytest.mark.parametrize(("psirt_failed", "gate_enforced", "code"), [(False, False, 0), (False, True, 2), (True, False, 3), (True, True, 3)])
def test_the_exit_code_is_3_for_a_failed_psirt_hand_off_which_outranks_an_enforced_gates_2(psirt_failed, gate_enforced, code):
    assert exit_code(psirt_failed, gate_enforced) == code


@pytest.mark.parametrize(("code", "report", "gate_enforced", "psirt_failed"), [
    (3, {"gate_enforced": True}, True, True),
    (2, {"gate_enforced": False}, False, False),
    (2, {}, True, False),  # a report written before the field: the exit code is all there is to go by
    (0, {}, False, False),
])
def test_a_finished_review_reads_back_as_whether_its_gate_was_enforced_and_its_psirt_hand_off_failed(code, report, gate_enforced,
                                                                                                    psirt_failed):
    assert outcome(code, report) == (gate_enforced, psirt_failed)


def parsed(inv: ReviewInvocation) -> dict:
    """The parameters the real `mara review` command reads from `argv(inv)`, as it parses them (strings, before Typer
    converts them)."""
    args = argv(inv)
    assert args[0] == "review"
    command = get_command(app).commands["review"]
    return command.make_context("review", args[1:]).params


def test_the_argv_of_an_invocation_with_every_option_is_read_back_by_mara_review_as_given():
    inv = ReviewInvocation(target=Path("/w/target"), config=Path("/w/config/mara.mock.yaml"), provider="mock", out=Path("/w/out/runs/r1"),
                           sarif_dir=Path("/w/sarif"), mock_fixtures=Path("/w/fixtures"), fail_on_gate=True, notify_psirt=True,
                           psirt_event=Path("/w/event.json"), psirt_resend=True, base="origin/main", calibration_sample=True,
                           progress_file=Path("/w/out/runs/r1/progress.json"))
    assert parsed(inv) == {
        "target": "/w/target", "config": "/w/config/mara.mock.yaml", "provider": "mock", "out": "/w/out/runs/r1",
        "sarif_dir": "/w/sarif", "mock_fixtures": "/w/fixtures", "fail_on_gate": True, "notify_psirt": True,
        "psirt_event": "/w/event.json", "psirt_resend": True, "base": "origin/main", "calibration_sample": True,
        "progress_file": "/w/out/runs/r1/progress.json",
    }


def test_the_argv_of_an_invocation_with_no_option_set_is_read_back_with_every_default():
    inv = ReviewInvocation(target=Path("/w/target"), config=Path("/w/config/mara.yaml"), provider="live", out=Path("/w/out"))
    assert parsed(inv) == {
        "target": "/w/target", "config": "/w/config/mara.yaml", "provider": "live", "out": "/w/out", "sarif_dir": None,
        "mock_fixtures": None, "fail_on_gate": False, "notify_psirt": False, "psirt_event": None, "psirt_resend": False,
        "base": None, "calibration_sample": False, "progress_file": None,
    }


def test_a_base_ref_that_starts_with_a_dash_stays_the_value_of_base():
    inv = ReviewInvocation(target=Path("/w/target"), config=Path("/w/config/mara.yaml"), provider="live", out=Path("/w/out"), base="-x")
    assert parsed(inv)["base"] == "-x"


def test_a_review_with_the_human_queue_and_psirt_writes_exactly_the_review_artifacts(tmp_path):
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {"enabled": True, "webhook_url": "https://psirt.example.internal/intake", "product": "IPC-7000 web console",
                    "shipped": True}
    cfg = tmp_path / "mock-psirt.yaml"
    cfg.write_text(yaml.safe_dump(raw), encoding="utf-8")
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--config", str(cfg),
                                   "--sarif-dir", str(ROOT / "fixtures" / "vuln-sample-sarif"),
                                   "--mock-fixtures", str(ROOT / "fixtures" / "mock-responses"),
                                   "--out", str(out), "--progress-file", str(out / "progress.json")],
                             env={"MARA_HOME": str(ROOT)})
    assert res.exit_code == 0, res.output
    assert {p.name for p in out.iterdir() if p.is_file()} == set(REVIEW_ARTIFACTS)


def squashed(output: str) -> str:
    """CLI output without ANSI codes, rich's box characters or any whitespace: a path rich folded reads whole again."""
    return "".join(re.sub(r"[│╭╮╰╯─]", "", cli_output.plain(output)).split())


def test_provider_mock_without_the_workspaces_mock_config_is_config_not_found_with_no_fallback_to_mara_yaml(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "config").mkdir(parents=True)
    shutil.copy(ROOT / "config" / "mara.yaml", workspace / "config" / "mara.yaml")
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", "mock", "--out", str(tmp_path / "out")],
                             env={"MARA_HOME": str(workspace)})
    said = squashed(res.output)
    assert res.exit_code == 2, res.output
    assert "Invalidvaluefor--config:configfilenotfound:" in said, res.output
    assert "".join(str(workspace / "config" / "mara.mock.yaml").split()) in said, res.output
    assert "Invalidvaluefor--provider" not in said, res.output


def duplicate_model_names(tmp_path: Path) -> Path:
    """The mock config with its first model listed twice: a structure error (model names must be unique)."""
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["models"].append(dict(raw["models"][0]))
    cfg = tmp_path / "duplicate-names.yaml"
    cfg.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return cfg


@pytest.mark.parametrize(("config", "provider_mode", "reason"), [
    (lambda tmp_path: ROOT / "config" / "examples" / "violating.yaml", "live", "configurationviolatespolicy:"),
    (duplicate_model_names, "mock", "modelnamesmustbeunique"),
], ids=["policy", "structure"])
def test_a_config_that_fails_validation_is_a_usage_error_on_config_with_a_failed_progress_record(tmp_path, config, provider_mode, reason):
    out = tmp_path / "out"
    res = CliRunner().invoke(app, ["review", str(ROOT / "fixtures" / "vuln-sample"), "--provider", provider_mode, "--config", str(config(tmp_path)),
                                   "--out", str(out), "--progress-file", str(out / "progress.json")],
                             env={"MARA_HOME": str(ROOT)})
    said = squashed(res.output)
    assert res.exit_code == 2, (res.exit_code, repr(res.exception), res.output)
    assert "Invalidvaluefor--config:" in said and reason in said, res.output
    record = progress.read(out / "progress.json")
    assert record["status"] == "failed" and record["error"] == "BadParameter", record
    assert not (out / "report.json").exists()
