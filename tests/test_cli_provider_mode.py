"""`mara review --provider` against the config's models: a provider mode the config's models do not have is a usage error
on `--provider`, whatever other options are given, and never a traceback. Each refusal comes before a model is asked."""

import re
from pathlib import Path

import yaml
from typer.testing import CliRunner

from mara.cli import app
from tests import cli_output

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fixtures" / "vuln-sample"
MOCK_CONFIG = ROOT / "config" / "mara.mock.yaml"


def plain(text: str) -> str:
    """CLI output as `cli_output.plain` gives it, also without rich's box characters."""
    return cli_output.plain(re.sub(r"[│╭╮╰╯─]", " ", text))


def review(tmp_path: Path, *args: str):
    return CliRunner().invoke(app, ["review", str(TARGET), "--out", str(tmp_path / "out"), *args],
                              env={"MARA_HOME": str(ROOT)})


def test_provider_live_with_mock_models_is_a_usage_error_on_provider(tmp_path):
    res = review(tmp_path, "--provider", "live", "--config", str(MOCK_CONFIG))
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert "Invalid value for --provider: the models' providers are ['mock']; --provider live needs no mock model" in out, out
    assert not (tmp_path / "out" / "report.json").exists()


def test_provider_mismatch_is_not_reported_as_a_broken_base(tmp_path):
    """`--base` turns the review's own ValueErrors into usage errors on `--base`; a provider mismatch is not one of them."""
    res = review(tmp_path, "--provider", "live", "--config", str(MOCK_CONFIG), "--base", "HEAD")
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert "Invalid value for --provider: the models' providers are ['mock']; --provider live needs no mock model" in out, out
    assert "--base" not in out, out


def test_provider_live_with_a_mock_model_among_live_ones_is_a_usage_error_on_provider(tmp_path):
    """The mock config with one model served by a local OpenAI-compatible server: one mock model is enough to refuse."""
    cfg = yaml.safe_load(MOCK_CONFIG.read_text(encoding="utf-8"))
    cfg["models"][-1].update(provider="openai_compatible", base_url="http://127.0.0.1:1234/v1", api_key_env="MARA_TEST_KEY")
    mixed = tmp_path / "mixed.yaml"
    mixed.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    res = review(tmp_path, "--provider", "live", "--config", str(mixed))
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert ("Invalid value for --provider: the models' providers are ['mock', 'openai_compatible']; --provider live needs no mock model"
            in out), out


def test_provider_mock_with_live_models_is_a_usage_error_on_provider(tmp_path):
    res = review(tmp_path, "--provider", "mock", "--config", str(ROOT / "config" / "mara.test.yaml"))
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert ("Invalid value for --provider: the models' providers are ['bedrock', 'gemini', 'openai_compatible']; --provider mock needs "
            "only mock models" in out), out


def test_provider_neither_live_nor_mock_is_a_usage_error_on_provider(tmp_path):
    res = review(tmp_path, "--provider", "foo", "--config", str(MOCK_CONFIG))
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert "Invalid value for '--provider': 'foo' is not one of 'live', 'mock'." in out, out


def test_provider_neither_live_nor_mock_is_not_reported_as_a_broken_base(tmp_path):
    res = review(tmp_path, "--provider", "foo", "--config", str(MOCK_CONFIG), "--base", "HEAD")
    assert res.exit_code == 2, res.output
    assert isinstance(res.exception, SystemExit), res.exception
    out = plain(res.output)
    assert "Invalid value for '--provider': 'foo' is not one of 'live', 'mock'." in out, out
    assert "--base" not in out, out
