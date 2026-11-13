"""mara.credentials.key_env: the one place that says which environment variable a model's key is read from.

The table is written out by hand (not derived from the module's own defaults), so it can disagree with the code.
"""

from __future__ import annotations

import typing

import pytest

from mara.config import ModelSpec
from mara.credentials import key_env

PROVIDERS = typing.get_args(ModelSpec.model_fields["provider"].annotation)


@pytest.mark.parametrize("provider, api_key_env, expected", [
    # the vendor APIs have a default variable of their own
    ("anthropic", None, "ANTHROPIC_API_KEY"),
    ("anthropic", "", "ANTHROPIC_API_KEY"),
    ("gemini", None, "GEMINI_API_KEY"),
    ("gemini", "", "GEMINI_API_KEY"),
    # an explicit api_key_env wins, for every provider
    ("anthropic", "TEAM_ANTHROPIC_KEY", "TEAM_ANTHROPIC_KEY"),
    ("gemini", "GEMINI_TEST_KEY", "GEMINI_TEST_KEY"),
    ("openai_compatible", "GLM_LOCAL_KEY", "GLM_LOCAL_KEY"),
    ("bedrock", "ANY_KEY", "ANY_KEY"),
    # an openai_compatible endpoint has no default: it gets no key, never another vendor's
    ("openai_compatible", None, None),
    ("openai_compatible", "", None),
    # bedrock reads the AWS credential chain and mock needs none: no variable
    ("bedrock", None, None),
    ("mock", None, None),
])
def test_which_variable_a_models_key_is_read_from(provider, api_key_env, expected):
    assert key_env(provider, api_key_env) == expected


def test_every_provider_the_config_accepts_has_an_answer():
    """A provider added to ModelSpec makes this fail until the table above says what its key is."""
    for provider in PROVIDERS:
        key_env(provider, None)  # does not raise
    assert set(PROVIDERS) == {"anthropic", "bedrock", "gemini", "openai_compatible", "mock"}


def test_the_answer_does_not_depend_on_which_keys_are_set(monkeypatch):
    """The Anthropic key in the environment never becomes a self-hosted endpoint's key (it was sent to its base_url once)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("GEMINI_API_KEY", "gem-secret")
    assert key_env("openai_compatible", None) is None
    assert key_env("openai_compatible", "") is None


# ------------------------------------------------------------------ the provider adapters ask it

def _spec(**kw) -> ModelSpec:
    d = {"name": "m", "family": "glm", "provider": "openai_compatible", "model": "m1",
         "base_url": "https://vllm.internal:8000/v1", "data_residency": "on_prem"}
    d.update(kw)
    return ModelSpec(**d)


def test_a_self_hosted_endpoint_is_not_sent_the_anthropic_key(monkeypatch):
    from mara.providers.openai_compatible import OpenAICompatibleProvider

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    monkeypatch.setenv("GEMINI_API_KEY", "gem-secret")
    assert "authorization" not in OpenAICompatibleProvider(_spec()).client.headers


def test_the_anthropic_adapter_reads_its_default_or_the_named_variable(monkeypatch):
    import anthropic

    from mara.providers.anthropic_provider import AnthropicProvider

    seen: list[dict] = []
    monkeypatch.setattr(anthropic, "Anthropic", lambda **kw: seen.append(kw))
    spec = _spec(family="anthropic", provider="anthropic", model="claude-opus-5-5", base_url=None, data_residency="vendor_api_zdr")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "default-key")
    monkeypatch.setenv("TEAM_ANTHROPIC_KEY", "team-key")
    AnthropicProvider(spec)
    AnthropicProvider(spec.model_copy(update={"api_key_env": "TEAM_ANTHROPIC_KEY"}))
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    AnthropicProvider(spec)  # nothing set: the zero-argument client, which finds an `ant auth login` profile itself
    assert seen == [{"api_key": "default-key"}, {"api_key": "team-key"}, {}]


def test_the_gemini_adapter_reads_its_default_or_the_named_variable(monkeypatch):
    from mara.providers.gemini_provider import GeminiProvider

    # built without validation: the spec's data_residency rules are not what is under test
    monkeypatch.setenv("GEMINI_API_KEY", "default-key")
    monkeypatch.setenv("GEMINI_TEST_KEY", "named-key")
    default = GeminiProvider(ModelSpec.model_construct(name="g", provider="gemini", model="m", api_key_env=None))
    named = GeminiProvider(ModelSpec.model_construct(name="g", provider="gemini", model="m", api_key_env="GEMINI_TEST_KEY"))
    assert default.client.headers["x-goog-api-key"] == "default-key"
    assert named.client.headers["x-goog-api-key"] == "named-key"


# ------------------------------------------------------------------ the evaluation asks it

def _target(provider: str, api_key_env: str = "", base_url: str = ""):
    from mara import model_eval as me

    return me.EvalTarget(family="x", name="x", model="m", provider=provider, base_url=base_url, api_key_env=api_key_env)


@pytest.mark.parametrize("target, expected_env", [
    (_target("anthropic"), {"ANTHROPIC_API_KEY": "$ANTHROPIC_API_KEY"}),
    (_target("anthropic", "TEAM_ANTHROPIC_KEY"), {"ANTHROPIC_API_KEY": "$TEAM_ANTHROPIC_KEY"}),
    (_target("gemini"), {"OPENAICOMPATIBLE_API_KEY": "$GEMINI_API_KEY"}),
    (_target("openai_compatible", "GLM_LOCAL_KEY", "https://x/v1"), {"OPENAICOMPATIBLE_API_KEY": "$GLM_LOCAL_KEY"}),
    (_target("openai_compatible", "", "https://x/v1"), {}),
    (_target("bedrock"), {}),
])
def test_garak_maps_the_key_variable_the_target_names_into_the_one_garak_reads(target, expected_env, monkeypatch):
    from mara import model_eval as me
    from mara.config import ModelEvalConfig

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    plan = me.invocations([target], ModelEvalConfig(garak_probes=["dan"]), "/tmp/out", "/data")
    # the variable garak reads, and the one its key is in as plan prints it
    env = {var: kv.shown for var, kv in plan.of(target.family, "garak")[0].key_variables.items()}
    assert env == expected_env


# ------------------------------------------------------------------ the workbench's environment page asks it

@pytest.mark.parametrize("provider, api_key_env, env_set, expected", [
    ("anthropic", None, {"ANTHROPIC_API_KEY": "v"}, {"kind": "env", "env": "ANTHROPIC_API_KEY", "present": True}),
    ("anthropic", "TEAM_ANTHROPIC_KEY", {}, {"kind": "env", "env": "TEAM_ANTHROPIC_KEY", "present": False}),
    ("gemini", None, {}, {"kind": "env", "env": "GEMINI_API_KEY", "present": False}),
    ("openai_compatible", "GLM_LOCAL_KEY", {"GLM_LOCAL_KEY": "v"}, {"kind": "env", "env": "GLM_LOCAL_KEY", "present": True}),
    # no variable named and no default: the page says so, even with another vendor's key set
    ("openai_compatible", None, {"ANTHROPIC_API_KEY": "v"}, {"kind": "env", "env": None, "present": False}),
    ("mock", None, {}, {"kind": "none", "env": None, "present": True}),
    ("bedrock", None, {"AWS_PROFILE": "p"}, {"kind": "aws_chain", "env": "AWS_PROFILE", "present": True}),
])
def test_the_environment_page_names_the_variable_never_its_value(provider, api_key_env, env_set, expected, monkeypatch):
    from mara.web.env import credential

    for name in ("ANTHROPIC_API_KEY", "GEMINI_API_KEY", "TEAM_ANTHROPIC_KEY", "GLM_LOCAL_KEY", "AWS_PROFILE", "AWS_ACCESS_KEY_ID"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env_set.items():
        monkeypatch.setenv(name, value)
    spec = ModelSpec.model_construct(name="m", provider=provider, model="m1", api_key_env=api_key_env)
    assert credential(spec) == expected


@pytest.mark.parametrize("target, expected", [
    (_target("anthropic"), "ANTHROPIC_API_KEY"),
    (_target("gemini"), "GEMINI_API_KEY"),
    (_target("gemini", "GEMINI_TEST_KEY"), "GEMINI_TEST_KEY"),
    (_target("openai_compatible", "GLM_LOCAL_KEY", "https://x/v1"), "GLM_LOCAL_KEY"),
    (_target("openai_compatible", "", "https://x/v1"), ""),
    (_target("bedrock"), ""),
])
def test_cyberseceval_takes_the_key_from_the_variable_the_target_names(target, expected, monkeypatch):
    """scripts/model_eval.py reads this variable for the CyberSecEval spec; "" means the target gets no key at all."""
    from mara import model_eval as me

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    assert me.target_key_env(target) == expected
