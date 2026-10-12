"""Claude on Bedrock and Gemini through the Gemini API, without network: Bedrock gets a fake
Anthropic client, Gemini an httpx.MockTransport. Same contract as the other providers: structured
JSON in, refusals and truncations told apart, provider failures raised as sanitised codes."""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest

from mara import exchange
from mara.config import ModelSpec
from mara.providers import make_provider
from mara.providers.bedrock_provider import BedrockProvider
from mara.providers.gemini_provider import GeminiProvider

SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}, "required": ["findings"]}
GOOD = {"findings": [{"title": "x"}]}


def _call(p):
    """The adapter's reply as mara.exchange classifies it: what every agent sees."""
    return exchange.classify(p.complete(system="s", user="u", schema=SCHEMA, role="reviewer:xss"), SCHEMA)


# ------------------------------------------------------------------ Bedrock

def _bedrock_spec(**kw):
    d = {"name": "claude-reviewer", "family": "anthropic", "provider": "bedrock", "model": "global.anthropic.claude-opus-5-5",
         "region": "ap-southeast-1", "data_residency": "vendor_api_zdr"}
    d.update(kw)
    return ModelSpec(**d)


def _fake_client(stop_reason="end_turn", text=json.dumps(GOOD), raises=None, served="claude-opus-5-5", content=None):
    blocks = content if content is not None else [SimpleNamespace(type="text", text=text)]
    msg = SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="thinking", thinking="…"), *blocks], model=served,
                          usage=SimpleNamespace(input_tokens=5, output_tokens=3))

    @contextmanager
    def stream(**kwargs):
        stream.kwargs = kwargs
        if raises is not None:
            raise raises
        yield SimpleNamespace(get_final_message=lambda: msg)

    return SimpleNamespace(messages=SimpleNamespace(stream=stream)), stream


def test_bedrock_needs_a_region_and_no_base_url():
    with pytest.raises(ValueError, match="needs region"):
        _bedrock_spec(region=None)
    with pytest.raises(ValueError, match="takes no base_url"):
        _bedrock_spec(base_url="https://bedrock.example")
    with pytest.raises(ValueError, match="strict_schema is only valid with provider openai_compatible"):
        _bedrock_spec(strict_schema=False)


def _tool(data, name="submit_result"):
    return SimpleNamespace(type="tool_use", name=name, input=data)


def _text(t):
    return SimpleNamespace(type="text", text=t)


def test_bedrock_sends_the_schema_as_its_one_tool_not_as_output_format():
    """Bedrock refuses output_config.format and tool_choice tool/any for Opus 5 and 5.5 (HTTP 400 on every
    call, 2026-10-07): the schema is the input_schema of the one tool, with tool_choice auto."""
    import anthropic

    client, stream = _fake_client(stop_reason="tool_use", content=[_tool(GOOD)])
    c = _call(BedrockProvider(_bedrock_spec(), client=client))
    assert c.data == GOOD and not c.refused and not c.truncated
    kw = stream.kwargs
    assert kw["model"] == "global.anthropic.claude-opus-5-5" and kw["max_tokens"] == 64000 and kw["thinking"] == {"type": "adaptive"}
    assert kw["output_config"] == {"effort": "high"} and kw["tool_choice"] == {"type": "auto"}
    assert [t["name"] for t in kw["tools"]] == ["submit_result"] and kw["tools"][0]["input_schema"] == anthropic.transform_schema(SCHEMA)
    assert kw["system"][0]["cache_control"] == {"type": "ephemeral"} and "submit_result tool exactly once" in kw["system"][1]["text"]
    assert "temperature" not in kw and "top_p" not in kw  # Opus 5.5 on Bedrock: "deprecated for this model"


def test_bedrock_tool_answers_keep_the_prose_for_the_canary_and_are_clipped():
    from mara.agents.skeptic import SKEPTIC_SCHEMA

    client, _ = _fake_client(stop_reason="tool_use", content=[_text("Looking at the code…"), _tool({"findings": [{"title": "CANARY-1"}]})])
    c = _call(BedrockProvider(_bedrock_spec(), client=client))
    assert c.aside == "Looking at the code…" and "Looking at the code…" in c.text and "CANARY-1" in c.text
    # Claude as skeptic wrote a 671-character reason (bound 600) and pydantic discarded the whole batch
    item = {"finding_id": "F-1", "verdict": "stands", "reason": "r" * 671, "sanitizer_or_control": "app.py:3 " + "c" * 400}
    client, _ = _fake_client(stop_reason="tool_use", content=[_tool({"items": [item]})])
    raw = BedrockProvider(_bedrock_spec(), client=client).complete(system="s", user="u", schema=SKEPTIC_SCHEMA, role="skeptic")
    got = exchange.classify(raw, SKEPTIC_SCHEMA).data["items"][0]
    assert (len(got["reason"]), len(got["sanitizer_or_control"])) == (600, 300) and got["sanitizer_or_control"].startswith("app.py:3 ")


def test_bedrock_without_the_tool_call_is_unusable_not_a_refusal():
    def call(**kw):
        client, _ = _fake_client(**kw)
        return _call(BedrockProvider(_bedrock_spec(), client=client))

    assert call(stop_reason="end_turn", content=[_text(json.dumps(GOOD))]).data == GOOD  # a bare JSON answer still counts
    c = call(stop_reason="end_turn", content=[_text("I reviewed the files and found nothing.")])
    assert c.unparseable and not c.truncated and not c.refused and c.data is None
    assert call(stop_reason="tool_use", content=[_tool(GOOD, name="other")]).data is None
    assert call(stop_reason="tool_use", content=[_tool(["x"])]).unparseable, "a tool input that is not an object"
    assert call(stop_reason="max_tokens", content=[_tool({})]).truncated
    # a bare JSON answer followed by another text block: that block is aside, so the canary check sees it
    c = call(stop_reason="end_turn", content=[_text(json.dumps(GOOD)), _text("Also: CANARY-2")])
    assert c.data == GOOD and c.aside == "Also: CANARY-2"


def test_bedrock_refusal_and_truncation_keep_their_meaning():
    client, _ = _fake_client(stop_reason="refusal", text="")
    assert _call(BedrockProvider(_bedrock_spec(), client=client)).refused
    client, _ = _fake_client(stop_reason="max_tokens", text='{"findings": [')
    c = _call(BedrockProvider(_bedrock_spec(), client=client))
    assert c.truncated and not c.refused


def test_bedrock_credential_errors_become_a_sanitised_code():
    class NoCredentialsError(Exception):  # stands in for botocore.exceptions.NoCredentialsError
        pass

    NoCredentialsError.__module__ = "botocore.exceptions"
    client, _ = _fake_client(raises=NoCredentialsError("Unable to locate credentials in profile Inventec-IT-..."))
    with pytest.raises(RuntimeError, match=r"^provider_auth_failed$"):
        _call(BedrockProvider(_bedrock_spec(), client=client))
    client, _ = _fake_client(raises=KeyError("bug"))
    with pytest.raises(KeyError):  # not a botocore failure: left to the agent layer, which logs and codes it
        _call(BedrockProvider(_bedrock_spec(), client=client))


def test_bedrock_records_the_model_the_response_names():
    client, _ = _fake_client(served="claude-opus-4-8")
    assert _call(BedrockProvider(_bedrock_spec(), client=client)).served_model == "claude-opus-4-8"


def test_make_provider_builds_a_bedrock_client_for_the_region():
    p = make_provider(_bedrock_spec())
    assert isinstance(p, BedrockProvider) and p.client.aws_region == "ap-southeast-1"


# ------------------------------------------------------------------ Gemini

def _gemini_spec(**kw):
    d = {"name": "gemini-reviewer", "family": "gemini", "provider": "gemini", "model": "gemini-test-pro",
         "api_key_env": "GEMINI_TEST_KEY", "data_residency": "vendor_api_retained", "retention_approval_ref": "TEST-1"}
    d.update(kw)
    return ModelSpec(**d)


def _gemini(handler, sleeps=None):
    sleeps = [] if sleeps is None else sleeps
    client = httpx.Client(base_url="https://generativelanguage.googleapis.com/v1beta", transport=httpx.MockTransport(handler))
    return GeminiProvider(_gemini_spec(), client=client, sleep=sleeps.append)


def _answer(text, finish="STOP", thought=None, **extra):
    parts = ([{"text": thought, "thought": True}] if thought else []) + ([{"text": text}] if text is not None else [])
    body = {"candidates": [{"content": {"role": "model", "parts": parts}, "finishReason": finish}],
            "usageMetadata": {"promptTokenCount": 9, "candidatesTokenCount": 4, "thoughtsTokenCount": 2}, **extra}
    return httpx.Response(200, json=body)


def test_gemini_sends_the_schema_and_the_key_in_a_header_not_the_url(monkeypatch):
    monkeypatch.setenv("GEMINI_TEST_KEY", "AIza-test-key")
    seen = {}

    def handler(req):
        seen["url"], seen["body"], seen["key"] = str(req.url), json.loads(req.content), req.headers.get("x-goog-api-key")
        return _answer(json.dumps(GOOD), thought="reasoning that must not be parsed")

    p = GeminiProvider(_gemini_spec(), client=None)
    p.client = httpx.Client(base_url="https://generativelanguage.googleapis.com/v1beta", headers=dict(p.client.headers),
                            transport=httpx.MockTransport(handler))
    c = _call(p)
    assert c.data == GOOD and (c.input_tokens, c.output_tokens) == (9, 6)
    assert seen["url"].endswith("/v1beta/models/gemini-test-pro:generateContent") and "key=" not in seen["url"]
    assert seen["key"] == "AIza-test-key"
    gc = seen["body"]["generationConfig"]
    assert gc["responseMimeType"] == "application/json" and gc["responseJsonSchema"] == SCHEMA and gc["temperature"] == 0.0
    assert seen["body"]["systemInstruction"]["parts"][0]["text"] == "s"


def test_gemini_max_tokens_is_truncation_even_with_no_text():
    for text in (None, '{"findings": ['):
        c = _call(_gemini(lambda req, text=text: _answer(text, finish="MAX_TOKENS")))
        assert c.truncated and not c.refused


@pytest.mark.parametrize("response", [
    _answer("", finish="SAFETY"), _answer(None, finish="PROHIBITED_CONTENT"),
    httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}),
])
def test_gemini_blocks_are_refusals(response):
    c = _call(_gemini(lambda req: response))
    assert c.refused and not c.truncated and c.data is None


def test_gemini_empty_answer_is_an_empty_reply_not_a_refusal():
    """It used to be a refusal here and nothing on the Anthropic adapter (docs/adr/0001-reply-outcome-accounting.md)."""
    c = _call(_gemini(lambda req: _answer("   ")))
    assert c.empty and not c.refused and c.data is None


def test_gemini_failures_are_sanitised_codes_and_transient_ones_are_retried():
    with pytest.raises(RuntimeError, match=r"^provider_http_error:400$"):
        _call(_gemini(lambda req: httpx.Response(400, json={"error": {"message": "API key not valid"}})))
    calls, sleeps = [], []

    def flaky(req):
        calls.append(req)
        return httpx.Response(503) if len(calls) == 1 else _answer(json.dumps(GOOD))

    assert _call(_gemini(flaky, sleeps)).data == GOOD and len(calls) == 2 and len(sleeps) == 1

    def down(req):
        raise httpx.ConnectError("no route")

    with pytest.raises(RuntimeError, match=r"^provider_connection_failed$"):
        _call(_gemini(down))


def test_gemini_records_the_model_version_that_answered():
    c = _call(_gemini(lambda req: _answer(json.dumps(GOOD), modelVersion="gemini-test-pro-001")))
    assert c.data == GOOD and c.served_model == "gemini-test-pro-001"
    assert _call(_gemini(lambda req: _answer(json.dumps(GOOD)))).served_model == "", "absent modelVersion stays empty"


def test_the_gateway_models_use_its_current_names_and_one_endpoint():
    """Since 2026-10-07 the IEC gateway serves GLM and DeepSeek from one endpoint with one key, told apart by
    `model` (glm / deepseek); the key may access only those two names, and the old DeepSeek endpoint answers 401."""
    from pathlib import Path

    from mara.config import load_config

    root = Path(__file__).resolve().parents[1]
    prod = {m.name: m for m in load_config(root / "config" / "mara.yaml").models}
    assert (prod["glm-reviewer"].model, prod["glm-reviewer"].strict_schema) == ("glm", False)
    for sb in sorted((root / "config" / "examples").glob("standby-for-*.yaml")):
        models = {m.name: m for m in load_config(sb).models}
        ds = models["deepseek-reviewer"]
        assert (ds.model, ds.base_url, ds.api_key_header, ds.strict_schema) == ("deepseek", prod["glm-reviewer"].base_url, None, True), sb.name
        if "glm-reviewer" in models:
            assert models["glm-reviewer"] == prod["glm-reviewer"], sb.name


# ------------------------------------------------------------------ Haiku 4.5 for tests (config/mara.test.yaml, AWS_MODEL)

HAIKU = "global.anthropic.claude-haiku-4-5-20251001-v1:0"


def test_models_without_adaptive_thinking_get_a_budget_and_no_effort():
    """Haiku 4.5 and Sonnet 4.5 on Bedrock: "adaptive thinking is not supported on this model" and "does not support
    the effort parameter" (2026-10-08). Opus 5.x keeps adaptive thinking at effort high."""
    from mara.providers.anthropic_provider import THINKING_BUDGET, AnthropicProvider, thinking_for

    assert thinking_for(HAIKU) == ({"type": "enabled", "budget_tokens": THINKING_BUDGET}, {})
    assert thinking_for("global.anthropic.claude-sonnet-4-5-20250929-v1:0")[1] == {}
    assert thinking_for("global.anthropic.claude-opus-5-5") == ({"type": "adaptive"}, {"effort": "high"})
    client, stream = _fake_client(stop_reason="tool_use", content=[_tool(GOOD)])
    assert _call(BedrockProvider(_bedrock_spec(model=HAIKU), client=client)).data == GOOD
    assert stream.kwargs["thinking"] == {"type": "enabled", "budget_tokens": THINKING_BUDGET} and "output_config" not in stream.kwargs
    assert stream.kwargs["tools"][0]["name"] == "submit_result" and stream.kwargs["tool_choice"] == {"type": "auto"}
    spec = ModelSpec(name="claude-reviewer", family="anthropic", provider="anthropic", model="claude-haiku-4-5", data_residency="vendor_api_zdr")
    client, stream = _fake_client()
    _call(AnthropicProvider(spec, client=client))
    assert set(stream.kwargs["output_config"]) == {"format"}, "the direct API path keeps structured output, without effort"


def test_model_env_replaces_the_model_before_the_policies_judge_it(monkeypatch):
    from pathlib import Path

    import yaml

    from mara.config import MaraConfig, load_config

    root = Path(__file__).resolve().parents[1]
    monkeypatch.delenv("AWS_MODEL", raising=False)
    test_cfg = load_config(root / "config" / "mara.test.yaml")
    assert (test_cfg.models[0].model, test_cfg.models[0].model_env) == (HAIKU, "AWS_MODEL"), "the test default is Haiku 4.5"
    monkeypatch.setenv("AWS_MODEL", "global.anthropic.claude-opus-5-5")
    overridden = load_config(root / "config" / "mara.test.yaml").models[0]
    # replaced before validation: the policies and the provider see the model that is actually called
    assert overridden.model == "global.anthropic.claude-opus-5-5" and make_provider(overridden).model == "global.anthropic.claude-opus-5-5"
    monkeypatch.setenv("AWS_MODEL", "  ")
    assert load_config(root / "config" / "mara.test.yaml").models[0].model == HAIKU, "a blank variable is no override"
    monkeypatch.delenv("AWS_MODEL")
    with pytest.raises(ValueError, match="not an environment variable name"):
        _bedrock_spec(model_env="aws-model")
    # production never reads AWS_MODEL: only the test config names it
    assert load_config(root / "config" / "mara.yaml").models[0].model == "global.anthropic.claude-opus-5-5"
    # apart from Claude's seat the test config is the production one
    prod = yaml.safe_load((root / "config" / "mara.yaml").read_text(encoding="utf-8"))
    test = yaml.safe_load((root / "config" / "mara.test.yaml").read_text(encoding="utf-8"))
    claude_p, claude_t = prod["models"][0], test["models"][0]
    assert {k: v for k, v in claude_t.items() if k not in ("model", "model_env")} == {k: v for k, v in claude_p.items() if k != "model"}
    assert test["models"][1:] == prod["models"][1:] and {k: v for k, v in test.items() if k != "models"} == {k: v for k, v in prod.items() if k != "models"}
    assert MaraConfig.model_validate(test).roles == MaraConfig.model_validate(prod).roles


def test_live_smoke_reports_each_model_and_fails_on_any(monkeypatch, capsys):
    import sys
    from pathlib import Path

    from mara.providers.base import STOP_END, STOP_REFUSAL, RawReply

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "scripts"))
    import live_smoke

    answers = {"claude-reviewer": RawReply(STOP_END, structured={"answer": 5, "note": "ok"}, served_model="anthropic.claude-haiku-4-5"),
               "gemini-reviewer": RawReply(STOP_END, answer_text='{"answer": 5, "note": "ok"}'),
               "glm-reviewer": RawReply(STOP_REFUSAL)}

    class Fake:
        def __init__(self, spec):
            self.spec = spec

        def complete(self, **kw):
            assert kw["schema"] == live_smoke.SCHEMA and kw["role"] == "smoke"
            return answers[self.spec.name]

    monkeypatch.setattr(live_smoke, "make_provider", Fake)
    monkeypatch.delenv("AWS_MODEL", raising=False)
    monkeypatch.setattr(sys, "argv", ["live_smoke.py"])
    assert live_smoke.main() == 1
    out = capsys.readouterr().out
    assert "PASS  claude-reviewer" in out and HAIKU in out and "FAIL  glm-reviewer" in out and "refusal" in out
    assert "2/3 models answered" in out and "mara.test.yaml" in out
    answers["glm-reviewer"] = RawReply(STOP_END, answer_text='{"answer": 5, "note": "ok"}')
    assert live_smoke.main() == 0
