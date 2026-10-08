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
         "base_url": "https://vllm.internal:8000/v1", "data_residency": "on_prem"}
    d.update(kw)
    return ModelSpec(**d)


def _oai(handler, sleeps: list | None = None) -> OpenAICompatibleProvider:
    spec = _spec()
    sleeps = [] if sleeps is None else sleeps
    return OpenAICompatibleProvider(spec, client=httpx.Client(base_url=spec.base_url, transport=httpx.MockTransport(handler)),
                                    sleep=sleeps.append)  # never really sleeps; the delays are asserted instead


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
    assert seen["body"]["response_format"]["json_schema"]["strict"] is True
    assert seen["body"]["max_tokens"] == 32768, "reasoning models need room: GLM ran out at 16000 as skeptic"


def test_openai_compatible_moves_max_length_out_of_the_wire_schema_and_clips_the_answer():
    """A constrained decoder enforces maxLength by cutting the string mid-sentence, and the model then
    closes the whole answer early (GLM-5.3 as skeptic returned one verdict for two findings). The bound
    travels as a description and is applied afterwards, so callers still never see a longer string."""
    import copy

    from mara.agents.skeptic import SKEPTIC_SCHEMA

    before = copy.deepcopy(SKEPTIC_SCHEMA)
    seen = {}
    long_reason = "x" * 936
    answer = {"items": [{"finding_id": "F-0001", "verdict": "stands", "reason": long_reason, "sanitizer_or_control": "none found"},
                        {"finding_id": "F-0002", "verdict": "stands", "reason": "short", "sanitizer_or_control": "y" * 500}]}

    def handler(req: httpx.Request):
        seen["schema"] = json.loads(req.content)["response_format"]["json_schema"]["schema"]
        return _chat(json.dumps(answer))

    c = _oai(handler).complete(system="s", user="u", schema=SKEPTIC_SCHEMA, role="skeptic")
    assert "maxLength" not in json.dumps(seen["schema"])
    item = seen["schema"]["properties"]["items"]["items"]["properties"]
    assert "At most 600 characters." in item["reason"]["description"] and item["verdict"]["enum"] == ["refuted", "weakened", "stands"]
    assert [len(i["reason"]) for i in c.data["items"]] == [600, 5] and len(c.data["items"][1]["sanitizer_or_control"]) == 300
    assert SKEPTIC_SCHEMA == before, "the shared module-level schema is not mutated"
    assert long_reason in c.raw_text, "raw_text stays what the model said (the canary check reads it)"


def test_strict_schema_false_sends_the_schema_as_guidance_and_tolerates_one_fence():
    """GLM-5.3 answered the skeptic with an empty list under constrained decoding, every time; with the
    schema as guidance it answered every finding. strict_schema: false asks for exactly that."""
    seen = []

    def handler(req: httpx.Request):
        seen.append(json.loads(req.content)["response_format"]["json_schema"]["strict"])
        return _chat("```json\n" + json.dumps(GOOD) + "\n```")

    spec = _spec(strict_schema=False)
    p = OpenAICompatibleProvider(spec, client=httpx.Client(base_url=spec.base_url, transport=httpx.MockTransport(handler)))
    assert _call(p).data == GOOD and seen == [False]
    assert _call(_oai(lambda req: _chat("```json\n" + json.dumps(GOOD) + "\n```"))).data == GOOD
    # anything else around the JSON is still unusable output
    assert _call(_oai(lambda req: _chat("Here you go:\n```json\n" + json.dumps(GOOD) + "\n```"))).truncated
    assert _call(_oai(lambda req: _chat("```json\n{}\n```\n```json\n{}\n```"))).truncated


def test_the_cvss_pattern_means_the_same_to_a_full_match_decoder_and_to_json_schema():
    """'^CVSS:4\\.0/' as a JSON Schema pattern is a prefix search, but a grammar-constrained decoder
    full-matches it and admitted only 'CVSS:4.0/': every finding from the gateway failed validation."""
    import re

    from mara.agents.reviewer import FINDING_SCHEMA
    from mara.scoring.cvss4 import score

    pattern = FINDING_SCHEMA["properties"]["findings"]["items"]["properties"]["cvss4_vector"]["pattern"]
    for v in ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
              "CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:P/U:Amber/MSI:S"):
        assert re.fullmatch(pattern, v) and re.search(pattern, v)
        score(v)
    for v in ("CVSS:4.0/", "CVSS:4.0/AV:N/AC:L", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"):
        assert not re.fullmatch(pattern, v) and not re.search(pattern, v)


def test_openai_compatible_length_finish_is_truncation_not_refusal():
    c = _call(_oai(lambda req: _chat(TRUNCATED_TEXT, finish_reason="length")))
    assert c.truncated and not c.refused and c.data is None and c.raw_text == TRUNCATED_TEXT
    assert (c.input_tokens, c.output_tokens) == (11, 7), "token usage is kept so the cost of a truncated call is still accounted"


def test_openai_compatible_empty_content_at_the_length_limit_is_truncation_not_refusal():
    # a reasoning model (DeepSeek-R1 behind vLLM's reasoning parser) can spend max_tokens thinking and
    # return no content at all: the budget ran out, the model did not decline
    for content in ("", None):
        c = _call(_oai(lambda req, content=content: _chat(content, finish_reason="length")))
        assert c.truncated and not c.refused and c.data is None


def test_openai_compatible_ignores_proxy_environment_variables(monkeypatch):
    """The endpoints are on-prem: HTTP(S)_PROXY must never route the source code (and the bearer key)
    through a proxy, least of all in cleartext for an approved http://127.0.0.1 endpoint."""
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(var, "http://proxy.corp.example:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    for url in ("http://127.0.0.1:8000/v1", "https://vllm.internal:8000/v1"):
        p = OpenAICompatibleProvider(_spec(base_url=url))
        transport = p.client._transport_for_url(httpx.URL(url + "/chat/completions"))
        assert isinstance(transport, httpx.HTTPTransport) and transport._pool.__class__.__name__ == "ConnectionPool", url
    # contrast: a default client on the same environment would have picked the proxy
    default = httpx.Client()
    assert default._transport_for_url(httpx.URL("http://127.0.0.1:8000/v1"))._pool.__class__.__name__ == "HTTPProxy"


def test_openai_compatible_invalid_json_with_stop_finish_is_truncation():
    c = _call(_oai(lambda req: _chat("Sure! Here is the JSON: {\"findings\": [")))
    assert c.truncated and not c.refused and c.data is None


def test_openai_compatible_content_filter_and_empty_are_refusals():
    assert _call(_oai(lambda req: _chat("", finish_reason="content_filter"))).refused
    empty = _call(_oai(lambda req: _chat("   ")))
    assert empty.refused and not empty.truncated


@pytest.mark.parametrize("status,body", [(500, "upstream exploded"), (401, "bad token"), (429, "slow down"), (503, "loading weights")])
def test_openai_compatible_http_errors_raise_a_sanitised_code_with_the_status(status, body):
    with pytest.raises(RuntimeError, match=rf"^provider_http_error:{status}$"):  # status only: the body never leaks
        _call(_oai(lambda req: httpx.Response(status, text=body)))


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("600s"), httpx.RemoteProtocolError("peer closed")])
def test_openai_compatible_transport_errors_become_runtime_errors(exc):
    def handler(req):
        raise exc

    with pytest.raises(RuntimeError, match=r"^provider_connection_failed$"):
        _call(_oai(handler))


@pytest.mark.parametrize("payload", [{"error": {"message": "model not found"}}, {"choices": []}, {"choices": [{"text": "no message key"}]}, "not json at all"])
def test_openai_compatible_error_shaped_2xx_bodies_raise_instead_of_keyerror(payload):
    resp = httpx.Response(200, json=payload) if not isinstance(payload, str) else httpx.Response(200, text=payload)
    with pytest.raises(RuntimeError, match=r"^provider_malformed_payload$"):
        _call(_oai(lambda req: resp))


def _sequence(*steps):
    """A handler that plays `steps` in order (a Response, or an exception to raise) and counts calls."""
    calls = []

    def handler(req):
        step = steps[min(len(calls), len(steps) - 1)]
        calls.append(req)
        if isinstance(step, Exception):
            raise step
        return step
    return handler, calls


@pytest.mark.parametrize("first", [httpx.Response(429, text="slow down"), httpx.Response(503, text="loading"), httpx.Response(529),
                                   httpx.ReadTimeout("600s"), httpx.ConnectError("refused")])
def test_openai_compatible_retries_a_transient_failure_then_succeeds(first):
    handler, calls = _sequence(first, _chat(json.dumps(GOOD)))
    sleeps = []
    c = _call(_oai(handler, sleeps))
    assert c.data == GOOD and not c.error and len(calls) == 2
    assert len(sleeps) == 1 and 2.0 <= sleeps[0] < 3.0, "first backoff: 2 s plus up to 1 s of jitter"


def test_openai_compatible_gives_up_after_three_attempts_with_growing_backoff():
    handler, calls = _sequence(httpx.Response(503, text="still loading"))
    sleeps = []
    with pytest.raises(RuntimeError, match=r"^provider_http_error:503$"):
        _call(_oai(handler, sleeps))
    assert len(calls) == 3 and len(sleeps) == 2 and 2.0 <= sleeps[0] < 3.0 and 4.0 <= sleeps[1] < 5.0
    handler, calls = _sequence(httpx.ReadTimeout("600s"))
    with pytest.raises(RuntimeError, match=r"^provider_connection_failed$"):
        _call(_oai(handler))
    assert len(calls) == 3


@pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 501])
def test_openai_compatible_does_not_retry_a_request_or_configuration_error(status):
    handler, calls = _sequence(httpx.Response(status, text="no"))
    sleeps = []
    with pytest.raises(RuntimeError, match=rf"^provider_http_error:{status}$"):
        _call(_oai(handler, sleeps))
    assert len(calls) == 1 and sleeps == []


@pytest.mark.parametrize("header,expected", [("7", 7.0), ("0", 0.0), ("999", 30.0), ("-5", 0.0)])
def test_openai_compatible_honours_retry_after_seconds_capped(header, expected):
    handler, _ = _sequence(httpx.Response(429, headers={"retry-after": header}), _chat(json.dumps(GOOD)))
    sleeps = []
    assert _call(_oai(handler, sleeps)).data == GOOD and sleeps == [expected]
    handler, _ = _sequence(httpx.Response(429, headers={"retry-after": "Wed, 21 Oct 2026 07:28:00 GMT"}), _chat(json.dumps(GOOD)))
    sleeps = []
    assert _call(_oai(handler, sleeps)).data == GOOD and 2.0 <= sleeps[0] < 3.0, "an HTTP date falls back to the backoff"


def test_openai_compatible_requires_base_url_and_reads_key_from_env(monkeypatch):
    with pytest.raises(ValueError, match="base_url required|requires a host"):  # ModelSpec now validates the URL first
        OpenAICompatibleProvider(_spec(base_url=None))
    monkeypatch.setenv("DEEPSEEK_LOCAL_KEY", "k-123")
    p = OpenAICompatibleProvider(_spec(api_key_env="DEEPSEEK_LOCAL_KEY"))
    assert p.client.headers["authorization"] == "Bearer k-123"


# ------------------------------------------------------------------ Anthropic SDK

def _anthropic(stop_reason, text, usage=(11, 7), served="claude-opus-5-5"):
    spec = _spec(name="claude-reviewer", family="anthropic", provider="anthropic", model="claude-opus-5-5", base_url=None,
                 data_residency="vendor_api_zdr")
    p = AnthropicProvider.__new__(AnthropicProvider)
    p.spec = spec
    content = [SimpleNamespace(type="thinking", thinking="…")] + ([SimpleNamespace(type="text", text=text)] if text is not None else [])
    msg = SimpleNamespace(stop_reason=stop_reason, content=content, model=served,
                          usage=SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1]))

    @contextmanager
    def fake_stream(**kwargs):
        fake_stream.kwargs = kwargs
        yield SimpleNamespace(get_final_message=lambda: msg)

    p.client = SimpleNamespace(messages=SimpleNamespace(stream=fake_stream))
    return p, fake_stream


def test_anthropic_happy_path_uses_structured_output_and_first_text_block():
    import anthropic

    p, stream = _anthropic("end_turn", json.dumps(GOOD))
    c = _call(p)
    assert c.data == GOOD and not c.refused and not c.truncated and (c.input_tokens, c.output_tokens) == (11, 7)
    assert stream.kwargs["output_config"]["format"] == {"type": "json_schema", "schema": anthropic.transform_schema(SCHEMA)}
    assert stream.kwargs["thinking"] == {"type": "adaptive"} and stream.kwargs["model"] == "claude-opus-5-5"
    # thinking counts against max_tokens: the streamed request leaves room for it after a 400k-char batch
    assert stream.kwargs["max_tokens"] == 64000
    assert stream.kwargs["output_config"]["effort"] == "high", "Opus 5.5 defaults to medium: effort must stay explicit"


_UNSUPPORTED_SCHEMA_KEYWORDS = {"minLength", "maxLength", "minimum", "maximum", "pattern", "maxItems"}


def _schema_keywords(node) -> set[str]:
    if isinstance(node, dict):
        props = node.get("properties", {})
        own = {k for k in node if k != "properties"}
        return own.union(*(_schema_keywords(v) for k, v in node.items() if k != "properties"),
                         *(_schema_keywords(v) for v in props.values()))
    if isinstance(node, list):
        return set().union(*(_schema_keywords(v) for v in node))
    return set()


def test_anthropic_sends_every_agent_schema_without_unsupported_keywords():
    """Structured outputs reject minLength, maximum, pattern, maxItems...; a raw dict schema is not
    rewritten by the SDK, so the provider must transform each agent schema before sending it."""
    import copy

    from mara.agents.context_agent import CONTEXT_SCHEMA
    from mara.agents.judge import JUDGE_SCHEMA
    from mara.agents.redteam import REDTEAM_SCHEMA
    from mara.agents.reviewer import FINDING_SCHEMA
    from mara.agents.skeptic import SKEPTIC_SCHEMA

    schemas = [FINDING_SCHEMA, CONTEXT_SCHEMA, JUDGE_SCHEMA, REDTEAM_SCHEMA, SKEPTIC_SCHEMA]
    assert any(_schema_keywords(sc) & _UNSUPPORTED_SCHEMA_KEYWORDS for sc in schemas)  # the bounds exist in the source
    for schema in schemas:
        before = copy.deepcopy(schema)
        p, stream = _anthropic("end_turn", json.dumps(GOOD))
        p.complete(system="s", user="u", schema=schema, role="reviewer:xss")
        assert not _schema_keywords(stream.kwargs["output_config"]["format"]["schema"]) & _UNSUPPORTED_SCHEMA_KEYWORDS
        assert schema == before  # the shared module-level schema (also sent to the gateway) is not mutated


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
    with pytest.raises(RuntimeError, match=r"^provider_http_error:529$"):
        _call(p)

    @contextmanager
    def down(**kwargs):
        raise anthropic.APIConnectionError(request=req)
        yield  # pragma: no cover

    p.client.messages.stream = down
    with pytest.raises(RuntimeError, match=r"^provider_connection_failed$"):
        _call(p)


# ------------------------------------------------------------------ what the agent layer makes of it

def test_agent_layer_treats_truncation_as_empty_but_reviewer_audit_tells_it_apart():
    from mara.agents.reviewer import review_dimension
    from mara.context.repo_map import RepoContext

    trunc = _oai(lambda req: _chat(TRUNCATED_TEXT, finish_reason="length"))
    refused = _oai(lambda req: _chat("", finish_reason="content_filter"))
    comp = _call(trunc)
    assert agent_base.parse_items(comp, dict) == ([], ["empty"])  # truncated output is unusable, not an abstention
    assert agent_base.parse_items(_call(refused), dict) == ([], ["refused"])  # content_filter is an abstention
    ctx = RepoContext(root=Path("."))
    canary = agent_base.Canary()
    _, a1 = review_dimension(trunc, ctx, "xss", canary)
    _, a2 = review_dimension(refused, ctx, "xss", canary)
    assert (a1["truncated"], a1["refused"]) == (True, False) and (a2["truncated"], a2["refused"]) == (False, True)


class _Raises(OpenAICompatibleProvider):
    def __init__(self, exc):
        self.spec, self.exc = _spec(), exc

    def complete(self, **kwargs):
        raise self.exc


@pytest.mark.parametrize("exc,code", [(RuntimeError("provider_http_error:429"), "provider_http_error:429"),
                                      (RuntimeError("provider_connection_failed"), "provider_connection_failed"),
                                      (RuntimeError("provider_http_error:429 body=secret-token"), "provider_call_failed:RuntimeError"),
                                      (ValueError("sk-live-123 leaked in a message"), "provider_call_failed:ValueError")])
def test_agent_layer_records_provider_failures_as_errors_not_refusals(exc, code):
    from mara.agents.reviewer import review_dimension
    from mara.context.repo_map import RepoContext

    comp = agent_base.call(_Raises(exc), system_extra="", user="u", schema=SCHEMA, role="reviewer:xss")
    assert comp.error == code and not comp.refused and not comp.truncated and comp.data is None and comp.raw_text == ""
    assert agent_base.parse_items(comp, dict) == ([], [code])
    _, audit = review_dimension(_Raises(exc), RepoContext(root=Path(".")), "xss", agent_base.Canary())
    assert (audit["errored"], audit["refused"], audit["truncated"]) == (True, False, False)


def test_an_unexpected_provider_exception_is_logged_without_its_message(caplog):
    """`except Exception` turned programming errors inside a provider into an anonymous provider_call_failed
    with no trace anywhere; the type and the raising frame are now logged, the message (possibly a key) never."""
    class Buggy(_Raises):
        def complete(self, **kwargs):
            return {}["missing"]  # a bug, not a provider failure

    with caplog.at_level("ERROR", logger="mara.providers"):
        comp = agent_base.call(Buggy(ValueError("unused")), system_extra="", user="u", schema=SCHEMA, role="judge")
    assert comp.error == "provider_call_failed:KeyError"
    [rec] = caplog.records
    assert "KeyError" in rec.getMessage() and "test_live_providers.py" in rec.getMessage() and "in complete" in rec.getMessage()
    with caplog.at_level("ERROR", logger="mara.providers"):
        agent_base.call(_Raises(ValueError("sk-live-123 leaked in a message")), system_extra="", user="u", schema=SCHEMA, role="judge")
    assert all("sk-live-123" not in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------ served model

def test_anthropic_records_the_model_the_response_names_even_on_refusal():
    assert _call(_anthropic("end_turn", json.dumps(GOOD))[0]).served_model == "claude-opus-5-5"
    # a vendor-side fallback answers under another id: the completion carries that id, not the configured one
    assert _call(_anthropic("refusal", None, served="claude-opus-4-8")[0]).served_model == "claude-opus-4-8"


def test_openai_compatible_records_the_served_model_from_the_payload():
    def handler(request):
        r = _chat(json.dumps(GOOD))
        body = r.json() | {"model": "deepseek-ai/DeepSeek-V4-Pro"}
        return httpx.Response(200, json=body)
    assert _call(_oai(handler)).served_model == "deepseek-ai/DeepSeek-V4-Pro"
    assert _call(_oai(lambda request: _chat(json.dumps(GOOD)))).served_model == "", "absent model field stays empty"


def test_agent_call_collects_served_models_on_the_provider():
    p, _ = _anthropic("end_turn", json.dumps(GOOD), served="claude-opus-4-8")
    p.served_models = set()
    agent_base.call(p, system_extra="", user="u", schema=SCHEMA, role="reviewer:xss")
    assert p.served_models == {"claude-opus-4-8"}
