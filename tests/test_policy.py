"""Policy-as-code (Appendix E prompt 6): each policy has a passing and a failing case, and
`mara check-config` lists every violation of the deliberately broken example config."""

import pytest
from typer.testing import CliRunner

from mara.cli import app
from mara.config import MaraConfig, load_config
from mara.policy import evaluate_policies


def _base(**over):
    cfg = {
        "models": [
            {"name": "a", "family": "anthropic", "provider": "anthropic", "model": "claude-opus-5", "data_residency": "vendor_api_zdr"},
            {"name": "d", "family": "deepseek", "provider": "openai_compatible", "model": "deepseek-v3.2",
             "base_url": "https://vllm-deepseek.internal:8000/v1", "data_residency": "on_prem"},
            {"name": "n", "family": "nemotron", "provider": "openai_compatible", "model": "nvidia/nemotron-3-super",
             "base_url": "https://192.168.10.5:8000/v1", "data_residency": "on_prem"},
        ],
        "roles": {"reviewers": ["a", "d", "n"], "skeptic": "n", "redteam": "d", "judges": ["a", "d", "n"]},
    }
    cfg.update(over)
    return cfg


def test_baseline_passes_all_policies():
    cfg = MaraConfig.model_validate(_base())
    assert all(r.passed for r in evaluate_policies(cfg))


def test_p1_covered_model_requires_authorization():
    bad = _base()
    bad["models"][0]["model"] = "claude-fable-5-1"
    with pytest.raises(ValueError, match="P1 covered-models"):
        MaraConfig.model_validate(bad)
    ok = dict(bad, anthropic_covered_models_authorized=True, anthropic_covered_models_authorization_ref="LEGAL-2026-017")
    assert MaraConfig.model_validate(ok).anthropic_covered_models_authorized
    half = dict(bad, anthropic_covered_models_authorized=True)  # no reference
    with pytest.raises(ValueError, match="P1"):
        MaraConfig.model_validate(half)


@pytest.mark.parametrize("url", ["https://api.deepseek.com/v1", "https://deepseek.com/v1", "https://8.8.8.8:8000/v1", "https://models.example.com/v1"])
def test_p2_rejects_vendor_api_and_public_hosts(url):
    bad = _base()
    bad["models"][1]["base_url"] = url
    with pytest.raises(ValueError, match="P2 deepseek-on-prem"):
        MaraConfig.model_validate(bad)


@pytest.mark.parametrize("url", ["https://10.0.0.7:8000/v1", "https://172.16.4.4/v1", "https://192.168.1.1:8000/v1", "https://vllm.internal/v1", "http://localhost:8000/v1"])
def test_p2_accepts_private_hosts(url):
    ok = _base()
    ok["models"][1]["base_url"] = url
    assert MaraConfig.model_validate(ok)


def test_p2_rejects_non_openai_compatible_provider_for_deepseek():
    bad = _base()
    bad["models"][1]["provider"] = "anthropic"
    with pytest.raises(ValueError, match="P2"):
        MaraConfig.model_validate(bad)


def test_p3_two_families_need_reason():
    two = _base()
    two["roles"] = {"reviewers": ["d", "n"], "skeptic": "n", "redteam": "d", "judges": ["d", "n"]}
    with pytest.raises(ValueError, match="P3 panel-size"):
        MaraConfig.model_validate(two)
    ok = dict(two, reduced_panel_reason="中國廠區境內管線")
    assert MaraConfig.model_validate(ok)
    one = _base()
    one["roles"] = {"reviewers": ["d"], "skeptic": "n", "redteam": "d", "judges": ["d", "n", "a"]}
    with pytest.raises(ValueError, match="P3"):
        MaraConfig.model_validate(dict(one, reduced_panel_reason="x"))


def test_p4_gate_bounds():
    with pytest.raises(ValueError, match="self_judge_discount"):
        MaraConfig.model_validate(_base(gate={"self_judge_discount": 0.8}))
    with pytest.raises(ValueError, match="human_threshold_alpha"):
        MaraConfig.model_validate(_base(gate={"human_threshold_alpha": 0.1}))
    assert MaraConfig.model_validate(_base(gate={"self_judge_discount": 0.5, "human_threshold_alpha": 0.3}))


def test_p5_data_residency():
    bad = _base()
    bad["models"][0]["data_residency"] = "vendor_api_30d"
    with pytest.raises(ValueError, match="data-residency"):
        MaraConfig.model_validate(bad)
    assert MaraConfig.model_validate(dict(bad, allow_source_code_to_non_on_prem=True))


def test_shipped_configs_load(root):
    assert load_config(root / "config" / "mara.yaml")
    assert load_config(root / "config" / "mara.mock.yaml")
    assert load_config(root / "config" / "examples" / "prc-site.yaml").reduced_panel_reason


def test_check_config_lists_every_violation(root):
    runner = CliRunner()
    res = runner.invoke(app, ["check-config", str(root / "config" / "examples" / "violating.yaml")])
    assert res.exit_code == 1, res.output
    for pid in ("P1", "P2", "P3", "P4", "P5", "P6"):
        assert pid in res.output, f"{pid} missing from output:\n{res.output}"
    assert res.output.count("FAIL") == 5
    ok = runner.invoke(app, ["check-config", str(root / "config" / "mara.yaml")])
    assert ok.exit_code == 0, ok.output
    assert "7/7 policies pass" in ok.output
    js = runner.invoke(app, ["check-config", str(root / "config" / "examples" / "violating.yaml"), "--json"])
    assert js.exit_code == 1 and '"passed": false' in js.output
