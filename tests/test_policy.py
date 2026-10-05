"""Policy-as-code (Appendix E prompt 6): each policy has a passing and a failing case, and
`mara check-config` lists every violation of the deliberately broken example config."""

import datetime as dt
import json

import pytest
import yaml
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


@pytest.mark.parametrize("url", ["https://169.254.10.1:8000/v1", "https://192.0.2.10/v1", "https://[fe80::1]:8000/v1",
                                 "https://[2001:db8::1]/v1", "https://dashscope.aliyuncs.com/compatible-mode/v1"])
def test_p2_refuses_link_local_documentation_and_vendor_hosts(url):
    # ipaddress' is_private admits link-local and the documentation ranges; neither is an on-prem host
    bad = _base()
    bad["models"][1]["base_url"] = url
    with pytest.raises(ValueError, match="P2 deepseek-on-prem"):
        MaraConfig.model_validate(bad)


@pytest.mark.parametrize("url", ["https://[::ffff:10.0.0.7]:8000/v1", "https://[fd12:3456::1]/v1"])
def test_p2_accepts_mapped_rfc1918_and_unique_local(url):
    ok = _base()
    ok["models"][1]["base_url"] = url
    assert MaraConfig.model_validate(ok)


def test_p2_does_not_trust_the_declared_family():
    """`family: other` used to switch P2 (and with a self-declared on_prem, P5) off entirely."""
    vendor = _base()
    vendor["models"][1].update(family="other", base_url="https://api.deepseek.com/v1")
    with pytest.raises(ValueError, match="P2 deepseek-on-prem.*declares family 'other'"):
        MaraConfig.model_validate(vendor)
    misdeclared = _base()
    misdeclared["models"][1].update(family="other")  # deepseek-v3.2 on a private host, but not called deepseek
    with pytest.raises(ValueError, match="is DeepSeek/Qwen but declares family 'other'"):
        MaraConfig.model_validate(misdeclared)


def test_p5_on_prem_must_match_the_endpoint():
    public = _base()
    public["models"][2]["base_url"] = "https://models.example.com/v1"  # nemotron, declared on_prem
    with pytest.raises(ValueError, match="P5 data-residency.*on_prem but host models.example.com"):
        MaraConfig.model_validate(public)
    vendor = _base()
    vendor["models"][0]["data_residency"] = "on_prem"  # the Anthropic API is not on-prem
    with pytest.raises(ValueError, match="on_prem but provider anthropic is a vendor API"):
        MaraConfig.model_validate(vendor)


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


def test_gate_rejects_out_of_bounds_unknown_and_empty_values():
    """A typo in the blocking lists or thresholds must fail loudly: lowercase tiers or a negative
    accept_threshold would otherwise silently turn the blocking gate into a no-op."""
    for gate in (
        {"block_on_tiers": ["a", "B"]},  # lowercase typo
        {"block_on_tiers": []},
        {"block_on_severity": ["high"]},
        {"block_on_severity": []},
        {"accept_threshold": -0.1},
        {"accept_threshold": 1.1},
        {"min_dimension_score": -1},
        {"min_dimension_score": 101},
        {"unknown_gate_key": True},
    ):
        with pytest.raises(ValueError):
            MaraConfig.model_validate(_base(gate=gate))
    assert MaraConfig.model_validate(_base(gate={"block_on_tiers": ["A", "B", "C", "D"], "block_on_severity": ["Medium"]}))


def test_top_level_unknown_keys_are_refused():
    # `gates:` instead of `gate:` would otherwise fall back to the default gate and disable the bounds
    with pytest.raises(ValueError, match="gates"):
        MaraConfig.model_validate(dict(_base(), gates={"self_judge_discount": 0.9}))
    assert MaraConfig.model_validate(dict(_base(), standby_for="anthropic")).standby_for == "anthropic"


@pytest.mark.parametrize("section,typo", [
    ("rollout", {"phse": "blocking"}),         # would load as not_started: the gate never blocks
    ("ml_bom", {"requried": True}),            # would load as required: false: P7 never enforces
    ("psirt", {"enable": True}),               # would load as enabled: false: no PSIRT hand-off
    ("human_queue", {"backlog_limt": 5}),
    ("training", {"require_trained_adjudicater": False}),
    ("model_eval", {"thresholds": {"garak_pass_rate": 0.9}}),
    ("roles", {"skeptik": "n"}),
])
def test_unknown_keys_inside_sections_are_refused(section, typo):
    """Every nested section refuses unknown keys like the top level and the gate: a misspelt key
    would otherwise load silently as the default, which for rollout/ml_bom/psirt is the weaker one."""
    raw = _base()
    if section == "roles":
        raw["roles"] = dict(raw["roles"], **typo)
    else:
        raw[section] = typo
    with pytest.raises(ValueError, match=next(iter(typo if section != "model_eval" else typo["thresholds"]))):
        MaraConfig.model_validate(raw, context={"skip_policies": True})


def test_unknown_model_keys_are_refused():
    raw = _base()
    raw["models"][1]["baseurl"] = "https://vllm-deepseek.internal:8000/v1"
    with pytest.raises(ValueError, match="baseurl"):
        MaraConfig.model_validate(raw, context={"skip_policies": True})


def test_check_config_refuses_structurally_invalid_configs(tmp_path):
    """check-config validates the whole structure first: it can never report "policies pass" for a
    file load_config would refuse (duplicate names, unknown keys, out-of-bounds gate values)."""
    runner = CliRunner()
    dup = _base()
    dup["models"].append(dict(dup["models"][0]))
    p = tmp_path / "dup-models.yaml"
    p.write_text(yaml.safe_dump(dup), encoding="utf-8")
    res = runner.invoke(app, ["check-config", str(p)])
    assert res.exit_code == 1 and "invalid config structure" in res.output and "model names must be unique" in res.output
    p = tmp_path / "unknown-key.yaml"
    p.write_text(yaml.safe_dump(dict(_base(), gates={})), encoding="utf-8")
    res = runner.invoke(app, ["check-config", str(p)])
    assert res.exit_code == 1 and "gates" in res.output
    p = tmp_path / "bad-gate.yaml"
    p.write_text(yaml.safe_dump(_base(gate={"block_on_tiers": ["a"]})), encoding="utf-8")
    res = runner.invoke(app, ["check-config", str(p)])
    assert res.exit_code == 1 and "block_on_tiers" in res.output


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
    assert "8/8 policies pass" in ok.output
    js = runner.invoke(app, ["check-config", str(root / "config" / "examples" / "violating.yaml"), "--json"])
    assert js.exit_code == 1 and '"passed": false' in js.output


def _p8(cfg):
    return [r for r in evaluate_policies(cfg) if r.id == "P8"][0]


def _allow(**gate_over):
    return MaraConfig.model_validate(dict(_base(), gate=dict(unsupervised_reject_allowed=True, **gate_over)))


def test_p8_unsupervised_reject_needs_a_recent_passing_live_aat(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # P8 reads calib/latest.json relative to the working directory
    assert _p8(MaraConfig.model_validate(_base())).passed  # the default (false) is always allowed
    calib = tmp_path / "calib"
    calib.mkdir()
    from mara.policy import AAT_METHOD

    evidence = {"date": dt.date.today().isoformat(), "mode": "live", "aat": {
        "method": AAT_METHOD, "passed": True, "n": 12, "agreement": 1.0, "chance_agreement": 0.5, "p_value": 0.0002,
        "rejection": {"n": 59, "misses": 0, "miss_rate_upper": 0.0495, "passed": True}}}
    (calib / "latest.json").write_text(json.dumps(evidence), encoding="utf-8")
    assert _p8(_allow()).passed and "Alternative Annotator Test passed" in _p8(_allow()).reason

    def bad(mutate, match):
        ev = json.loads(json.dumps(evidence))
        mutate(ev)
        (calib / "latest.json").write_text(json.dumps(ev), encoding="utf-8")
        with pytest.raises(ValueError, match=match):  # P8 also blocks the config from loading at all
            _allow()

    (calib / "latest.json").unlink()
    with pytest.raises(ValueError, match="P8 unsupervised-reject"):
        _allow()  # no evidence at all
    (calib / "latest.json").write_text(json.dumps(evidence), encoding="utf-8")
    bad(lambda ev: ev["aat"].update(passed=False), "did not pass")
    bad(lambda ev: ev["aat"]["rejection"].update(passed=False), "did not pass")
    # a result from the first, untagged AAT (fixed 0.5 baseline, rejections never examined) is no evidence
    bad(lambda ev: ev["aat"].pop("method"), "uses method None")
    bad(lambda ev: ev["aat"].pop("rejection"), "did not pass")
    bad(lambda ev: ev.update(mode="mock"), "not live")
    bad(lambda ev: ev.update(date=(dt.date.today() - dt.timedelta(days=91)).isoformat()), "rerun the calibration")
    bad(lambda ev: ev.update(date=(dt.date.today() + dt.timedelta(days=1)).isoformat()), "in the future")
    ev = json.loads(json.dumps(evidence))
    ev["date"] = (dt.date.today() - dt.timedelta(days=90)).isoformat()
    (calib / "latest.json").write_text(json.dumps(ev), encoding="utf-8")
    assert _p8(_allow()).passed  # exactly 90 days is still within the window
