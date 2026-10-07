"""Claude on Bedrock and Gemini through the Gemini API, without network: Bedrock gets a fake
Anthropic client, Gemini an httpx.MockTransport. Same contract as the other providers: structured
JSON in, refusals and truncations told apart, provider failures raised as sanitised codes."""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace

import httpx
import pytest

from mara.config import ModelSpec
from mara.providers import make_provider
from mara.providers.bedrock_provider import BedrockProvider
from mara.providers.gemini_provider import GeminiProvider

SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}, "required": ["findings"]}
GOOD = {"findings": [{"title": "x"}]}


def _call(p):
    return p.complete(system="s", user="u", schema=SCHEMA, role="reviewer:xss")


# ------------------------------------------------------------------ Bedrock

def _bedrock_spec(**kw):
    d = {"name": "claude-reviewer", "family": "anthropic", "provider": "bedrock", "model": "global.anthropic.claude-opus-5-5",
         "region": "ap-southeast-1", "data_residency": "vendor_api_zdr"}
    d.update(kw)
    return ModelSpec(**d)


def _fake_client(stop_reason="end_turn", text=json.dumps(GOOD), raises=None):
    msg = SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)],
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


def test_bedrock_uses_the_anthropic_request_shape_with_the_profile_id():
    client, stream = _fake_client()
    c = _call(BedrockProvider(_bedrock_spec(), client=client))
    assert c.data == GOOD and not c.refused and not c.truncated
    assert stream.kwargs["model"] == "global.anthropic.claude-opus-5-5"
    assert stream.kwargs["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}


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
    _answer("", finish="SAFETY"), _answer(None, finish="PROHIBITED_CONTENT"), _answer("   "),
    httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}),
])
def test_gemini_blocks_and_empty_answers_are_refusals(response):
    c = _call(_gemini(lambda req: response))
    assert c.refused and not c.truncated and c.data is None


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
