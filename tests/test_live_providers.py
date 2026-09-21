"""The two live providers against fake endpoints: truncation, invalid JSON, HTTP and transport errors.

No network. The OpenAI-compatible provider takes an httpx.Client on a MockTransport; the Anthropic
provider's SDK stream is replaced by a stub that returns a final message shaped like the SDK's.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from mara.agents import base as agent_base
from mara.config import ModelSpec
from mara.providers.anthropic_provider import AnthropicProvider
from mara.providers.openai_compatible import OpenAICompatibleProvider

SCHEMA = {"type": "object", "properties": {"findings": {"type": "array"}}, "required": ["findings"]}
GOOD = {"findings": [{"title": "x"}]}
TRUNCATED_TEXT = json.dumps(GOOD)[:-6]  # cut inside the object: never parses


def _spec(**kw) -> ModelSpec:
    d = {"name": "deepseek-reviewer", "family": "deepseek", "provider": "openai_compatible", "model": "deepseek-v3.2",
         "base_url": "http://vllm.internal:8000/v1", "data_residency": "on_prem"}
    d.update(kw)
    return ModelSpec(**d)


def _oai(handler) -> OpenAICompatibleProvider:
    spec = _spec()
    return OpenAICompatibleProvider(spec, client=httpx.Client(base_url=spec.base_url, transport=httpx.MockTransport(handler)))


def _chat(content, finish_reason="stop", usage=None):
    body = {"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": finish_reason}],
            "usage": usage or {"prompt_tokens": 11, "completion_tokens": 7}}
    return httpx.Response(200, json=body)


def _call(p):
    return p.complete(system="s", user="u", schema=SCHEMA, role="reviewer:xss")


# ------------------------------------------------------------------ OpenAI-compatible (vLLM / NIM)

def test_openai_compatible_happy_path_sends_json_schema_and_parses():
    seen = {}

    def handler(req: httpx.Request):
        seen["path"] = req.url.path
        seen["body"] = json.loads(req.content)
        return _chat(json.dumps(GOOD))

    c = _call(_oai(handler))
    assert c.data == GOOD and not c.refused and not c.truncated and (c.input_tokens, c.output_tokens) == (11, 7)
    assert seen["path"].endswith("/chat/completions")
    assert seen["body"]["response_format"]["json_schema"]["schema"] == SCHEMA and seen["body"]["temperature"] == 0.0


def test_openai_compatible_length_finish_is_truncation_not_refusal():
    c = _call(_oai(lambda req: _chat(TRUNCATED_TEXT, finish_reason="length")))
    assert c.truncated and not c.refused and c.data is None and c.raw_text == TRUNCATED_TEXT
    assert (c.input_tokens, c.output_tokens) == (11, 7), "token usage is kept so the cost of a truncated call is still accounted"


def test_openai_compatible_invalid_json_with_stop_finish_is_truncation():
    c = _call(_oai(lambda req: _chat("Sure! Here is the JSON: {\"findings\": [")))
    assert c.truncated and not c.refused and c.data is None


def test_openai_compatible_content_filter_and_empty_are_refusals():
    assert _call(_oai(lambda req: _chat("", finish_reason="content_filter"))).refused
    empty = _call(_oai(lambda req: _chat("   ")))
    assert empty.refused and not empty.truncated


@pytest.mark.parametrize("status,body", [(500, "upstream exploded"), (401, "bad token"), (429, "slow down"), (503, "loading weights")])
def test_openai_compatible_http_errors_raise_with_model_name_and_status(status, body):
    with pytest.raises(RuntimeError, match=rf"deepseek-reviewer: HTTP {status}: {body}"):
        _call(_oai(lambda req: httpx.Response(status, text=body)))


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("600s"), httpx.RemoteProtocolError("peer closed")])
def test_openai_compatible_transport_errors_become_runtime_errors(exc):
    def handler(req):
        raise exc

    with pytest.raises(RuntimeError, match=rf"deepseek-reviewer: {type(exc).__name__}"):
        _call(_oai(handler))


@pytest.mark.parametrize("payload", [{"error": {"message": "model not found"}}, {"choices": []}, {"choices": [{"text": "no message key"}]}, "not json at all"])
def test_openai_compatible_error_shaped_2xx_bodies_raise_instead_of_keyerror(payload):
    resp = httpx.Response(200, json=payload) if not isinstance(payload, str) else httpx.Response(200, text=payload)
    with pytest.raises(RuntimeError, match="deepseek-reviewer: malformed completion payload"):
        _call(_oai(lambda req: resp))


def test_openai_compatible_requires_base_url_and_reads_key_from_env(monkeypatch):
    with pytest.raises(ValueError, match="base_url required"):
        OpenAICompatibleProvider(_spec(base_url=None))
    monkeypatch.setenv("DEEPSEEK_LOCAL_KEY", "k-123")
    p = OpenAICompatibleProvider(_spec(api_key_env="DEEPSEEK_LOCAL_KEY"))
    assert p.client.headers["authorization"] == "Bearer k-123"


# ------------------------------------------------------------------ Anthropic SDK

def _anthropic(stop_reason, text, usage=(11, 7)):
    spec = _spec(name="claude-reviewer", family="anthropic", provider="anthropic", model="claude-opus-5", base_url=None,
                 data_residency="vendor_api_zdr")
    p = AnthropicProvider.__new__(AnthropicProvider)
    p.spec = spec
    content = [SimpleNamespace(type="thinking", thinking="…")] + ([SimpleNamespace(type="text", text=text)] if text is not None else [])
    msg = SimpleNamespace(stop_reason=stop_reason, content=content, usage=SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1]))

    @contextmanager
    def fake_stream(**kwargs):
        fake_stream.kwargs = kwargs
        yield SimpleNamespace(get_final_message=lambda: msg)

    p.client = SimpleNamespace(messages=SimpleNamespace(stream=fake_stream))
    return p, fake_stream


def test_anthropic_happy_path_uses_structured_output_and_first_text_block():
    p, stream = _anthropic("end_turn", json.dumps(GOOD))
    c = _call(p)
    assert c.data == GOOD and not c.refused and not c.truncated and (c.input_tokens, c.output_tokens) == (11, 7)
    assert stream.kwargs["output_config"]["format"] == {"type": "json_schema", "schema": SCHEMA}
    assert stream.kwargs["thinking"] == {"type": "adaptive"} and stream.kwargs["model"] == "claude-opus-5"


def test_anthropic_max_tokens_is_truncation_not_refusal_and_does_not_raise():
    p, _ = _anthropic("max_tokens", TRUNCATED_TEXT)
    c = _call(p)
    assert c.truncated and not c.refused and c.data is None and c.raw_text == TRUNCATED_TEXT


def test_anthropic_refusal_stop_reason_is_a_refusal():
    p, _ = _anthropic("refusal", None)
    c = _call(p)
    assert c.refused and not c.truncated and c.data is None


def test_anthropic_invalid_json_in_text_block_does_not_crash_the_review():
    p, _ = _anthropic("end_turn", "{\"findings\": [")
    c = _call(p)
    assert c.truncated and c.data is None


def test_anthropic_sdk_errors_are_wrapped_as_runtime_errors():
    import anthropic

    p, _ = _anthropic("end_turn", "{}")
    req = httpx.Request("POST", "https://api.anthropic.com/v1/messages")

    @contextmanager
    def boom(**kwargs):
        raise anthropic.APIStatusError("overloaded", response=httpx.Response(529, request=req), body=None)
        yield  # pragma: no cover

    p.client.messages.stream = boom
    with pytest.raises(RuntimeError, match="anthropic API error 529"):
        _call(p)

    @contextmanager
    def down(**kwargs):
        raise anthropic.APIConnectionError(request=req)
        yield  # pragma: no cover

    p.client.messages.stream = down
    with pytest.raises(RuntimeError, match="anthropic connection error"):
        _call(p)


# ------------------------------------------------------------------ what the agent layer makes of it

def test_agent_layer_treats_truncation_as_empty_but_reviewer_audit_tells_it_apart():
    from mara.agents.reviewer import review_dimension
    from mara.context.repo_map import RepoContext

    trunc = _oai(lambda req: _chat(TRUNCATED_TEXT, finish_reason="length"))
    refused = _oai(lambda req: _chat("", finish_reason="content_filter"))
    comp = _call(trunc)
    assert agent_base.parse_items(comp, dict) == ([], ["refused_or_empty"])
    ctx = RepoContext(root=Path("."))
    canary = agent_base.Canary()
    _, a1 = review_dimension(trunc, ctx, "xss", canary)
    _, a2 = review_dimension(refused, ctx, "xss", canary)
    assert (a1["truncated"], a1["refused"]) == (True, False) and (a2["truncated"], a2["refused"]) == (False, True)
