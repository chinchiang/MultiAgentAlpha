"""invocation.admit (GLOSSARY.md: Admitted invocation, Review invocation, Usage error): a review invocation is refused in
one order, the paths first, then the config, then the target's own options, the same for the command line and the
workbench (docs/adr/0006-local-web-workbench.md). The progress record starts only once the paths are admitted, and a
usage error after that leaves it failed, naming the usage error's kind."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import shutil
from pathlib import Path

import pytest
import yaml

from mara import invocation, progress
from mara.invocation import InvocationError, ProviderMode, ReviewInvocation

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "fixtures" / "vuln-sample"


def _inv(out: Path, **kw) -> ReviewInvocation:
    return ReviewInvocation(**{"target": TARGET, "config": None, "provider": ProviderMode.mock, "out": out, **kw})


def test_an_invocation_every_check_passes_is_admitted_with_its_config_loaded(tmp_path):
    admitted = invocation.admit(_inv(tmp_path / "out"), ROOT)
    assert admitted.config_path == ROOT / "config" / "mara.mock.yaml"
    assert {m.provider for m in admitted.config.models} == {"mock"}
    assert admitted.invocation == _inv(tmp_path / "out")


def test_an_admitted_invocation_has_started_its_progress_record(tmp_path):
    record = tmp_path / "out" / "progress.json"
    admitted = invocation.admit(_inv(tmp_path / "out", progress_file=record), ROOT)
    assert progress.read(record)["status"] == "running"
    admitted.progress.finish(ok=True)
    assert progress.read(record)["status"] == "finished"


def test_a_config_inside_the_target_is_refused_before_it_is_read_and_no_record_is_started(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "mara.yaml").write_text("{ not yaml", encoding="utf-8")  # read, it would be config_invalid
    record = tmp_path / "out" / "progress.json"
    with pytest.raises(InvocationError) as e:
        invocation.admit(_inv(tmp_path / "out", target=target, config=target / "mara.yaml", progress_file=record), ROOT)
    assert (e.value.kind, e.value.param) == ("inside_target", "TARGET")
    assert not record.exists()


def test_a_usage_error_after_the_paths_leaves_the_record_failed_with_its_kind(tmp_path):
    record = tmp_path / "out" / "progress.json"
    with pytest.raises(InvocationError) as e:  # a live config for a mock review
        invocation.admit(_inv(tmp_path / "out", config=ROOT / "config" / "mara.yaml", progress_file=record), ROOT)
    assert (e.value.kind, e.value.param) == ("provider_mismatch", "--provider")
    d = progress.read(record)
    assert (d["status"], d["error"]) == ("failed", "provider_mismatch")


def _mixed(tmp_path: Path) -> Path:
    """The mock config with one model served by a local OpenAI-compatible server."""
    cfg = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    cfg["models"][-1].update(provider="openai_compatible", base_url="http://127.0.0.1:1234/v1", api_key_env="MARA_TEST_KEY")
    (tmp_path / "mixed.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return tmp_path / "mixed.yaml"


@pytest.mark.parametrize("config", [lambda tmp_path: ROOT / "config" / "mara.mock.yaml", _mixed], ids=["mock", "mixed"])
def test_a_live_review_of_a_config_with_a_mock_model_is_refused_before_the_review_starts(tmp_path, config):
    # Pipeline.run would refuse it too, in the same words: only admit tells a usage error before the review from one after
    with pytest.raises(InvocationError) as e:
        invocation.admit(_inv(tmp_path / "out", provider=ProviderMode.live, config=config(tmp_path)), ROOT)
    assert (e.value.kind, e.value.param) == ("provider_mismatch", "--provider")


def test_any_other_exception_after_the_paths_leaves_the_record_failed_with_its_name(tmp_path, monkeypatch):
    def load_config(path, workspace=None):
        raise RuntimeError("a bug, not a usage error")

    monkeypatch.setattr(invocation, "load_config", load_config)
    record = tmp_path / "out" / "progress.json"
    with pytest.raises(RuntimeError):
        invocation.admit(_inv(tmp_path / "out", progress_file=record), ROOT)
    d = progress.read(record)
    assert (d["status"], d["error"]) == ("failed", "RuntimeError")


LABELS = {"sample": "s1", "labels": [{"dimension": "secrets", "cwe": "CWE-798", "file": "app.py", "line": 3, "quote": "q", "title": "t"}]}


def test_a_calibration_sample_is_one_of_the_workspace_admit_is_given_not_of_the_environment(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    (workspace / "config").mkdir(parents=True)
    shutil.copy(ROOT / "config" / "mara.mock.yaml", workspace / "config" / "mara.mock.yaml")
    sample = workspace / "calib" / "samples" / "s1"
    sample.mkdir(parents=True)
    (sample / "labels.json").write_text(json.dumps(LABELS), encoding="utf-8")
    monkeypatch.setenv("MARA_HOME", str(ROOT))  # the environment names another workspace
    inv = _inv(tmp_path / "out", target=sample, calibration_sample=True, progress_file=tmp_path / "out" / "progress.json")
    assert invocation.admit(inv, workspace).invocation == inv
    with pytest.raises(InvocationError) as e:  # not a sample of ROOT's calib/samples
        invocation.admit(dataclasses.replace(inv, config=workspace / "config" / "mara.mock.yaml"), ROOT)
    assert (e.value.kind, e.value.param) == ("bad_calibration_sample", "--calibration-sample")
    assert progress.read(inv.progress_file)["error"] == "bad_calibration_sample"


def test_the_config_is_loaded_under_the_policies_of_the_workspace_admit_is_given_not_of_the_environment(tmp_path, monkeypatch):
    from mara.policy import AAT_METHOD

    # a config that allows unsupervised rejection, which policy P8 lets load only beside a passing Evidence record
    cfg = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    cfg["gate"] = {**cfg.get("gate", {}), "unsupervised_reject_allowed": True}
    config = tmp_path / "mara.yaml"
    config.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    workspace = tmp_path / "workspace"
    (workspace / "calib").mkdir(parents=True)
    record = {"date": dt.date.today().isoformat(), "mode": "live", "aat": {
        "method": AAT_METHOD, "passed": True, "n": 12, "agreement": 1.0, "chance_agreement": 0.5, "p_value": 0.0002,
        "rejection": {"n": 59, "misses": 0, "miss_rate_upper": 0.0495, "passed": True}}}
    (workspace / "calib" / "latest.json").write_text(json.dumps(record), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"  # the environment names another workspace, with no Evidence record
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(elsewhere))
    monkeypatch.chdir(elsewhere)
    inv = _inv(tmp_path / "out", config=config, progress_file=tmp_path / "out" / "progress.json")

    assert invocation.admit(inv, workspace).config.gate.unsupervised_reject_allowed
    with pytest.raises(InvocationError) as e:  # and no Evidence record below the workspace given: P8 refuses the config
        invocation.admit(inv, tmp_path / "out")
    assert (e.value.kind, e.value.param) == ("config_invalid", "--config")
    assert "P8 unsupervised-reject" in str(e.value)


def test_a_base_git_cannot_diff_against_is_refused_last(tmp_path):
    record = tmp_path / "out" / "progress.json"
    inv = _inv(tmp_path / "out", base="no-such-ref-anywhere", progress_file=record)
    with pytest.raises(InvocationError) as e:  # the config is checked before the base
        invocation.admit(dataclasses.replace(inv, config=ROOT / "config" / "mara.yaml"), ROOT)
    assert e.value.kind == "provider_mismatch"
    with pytest.raises(InvocationError) as e:
        invocation.admit(inv, ROOT)
    assert (e.value.kind, e.value.param) == ("bad_base_ref", "--base")
    assert progress.read(record)["error"] == "bad_base_ref"


def test_an_admitted_invocation_remembers_the_workspace_it_was_admitted_against(tmp_path, monkeypatch):
    """Not the environment's: MARA_HOME names another directory, and the working directory a third."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setenv("MARA_HOME", str(elsewhere))
    assert invocation.admit(_inv(tmp_path / "out"), ROOT).workspace == ROOT
