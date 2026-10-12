"""Provider for self-hosted models exposing an OpenAI-compatible /v1/chat/completions
endpoint (vLLM, NVIDIA NIM, SGLang). Used for DeepSeek and Nemotron weights that run
inside the organisation's perimeter. Plain httpx; no vendor SDK required.

Structured output is requested via `response_format: json_schema` where the server
supports it; the returned text is always re-validated by the caller. String `maxLength` is not
sent as a constraint: a grammar-constrained decoder enforces it by cutting the string off
mid-sentence, and the model then closes the whole answer early (GLM-5.3 as skeptic, 2026-10-07:
one verdict for two findings, every time). The bound travels in the description and is applied
to the answer afterwards (mara.exchange), so the caller sees the same shape strict decoding
promises. `strict_schema: false` turns the constrained decoding off for a model that answers
worse under it (GLM-5.3: an empty skeptic list after ~15k reasoning tokens, three times out of
three; with the schema as guidance only, every finding answered); a single ```json fence is tolerated
for every family (mara.exchange).

Transient failures (timeouts and other transport errors, 408, 429, 500, 502, 503, 504, 529) are retried
up to MAX_ATTEMPTS calls in total, with exponential backoff plus jitter, or the server's Retry-After in
seconds, capped at RETRY_AFTER_CAP. Any other status is a configuration or request error and fails at
once. After the last attempt the sanitised code is raised as before, and the agent layer records it as
a provider error, not a refusal. (The Anthropic SDK retries on its own, so that provider adds nothing.)
"""

from __future__ import annotations

import os
import random
import ssl
import time
from collections.abc import Callable

import certifi
import httpx

from ..config import ModelSpec
from .base import STOP_END, STOP_MAX_TOKENS, STOP_REFUSAL, Provider, RawReply, wire_schema

MAX_ATTEMPTS = 3
BACKOFF_BASE = 2.0  # seconds before the second attempt; doubled for each further one, plus up to 1 s of jitter
RETRY_AFTER_CAP = 30.0
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})
# Reasoning models (GLM-5.3, DeepSeek) spend most of the budget thinking, and it counts against max_tokens:
# GLM as skeptic over six findings ran out at 16000 and finished at 13861 with room (2026-10-07). The
# gateway's models accept a 1M-token context, so a 400k-character batch plus this cap still fits.
MAX_TOKENS = 32768


def retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait after failed attempt `attempt` (1-based): Retry-After seconds if given, else backoff."""
    if retry_after is not None:
        try:
            return min(max(float(retry_after), 0.0), RETRY_AFTER_CAP)
        except ValueError:
            pass  # an HTTP date or garbage: fall back to our own backoff
    return min(BACKOFF_BASE * 2 ** (attempt - 1) + random.random(), RETRY_AFTER_CAP)  # nosec B311 - jitter, not crypto


def _trust(ca_bundle: str | None) -> ssl.SSLContext | bool:
    """Verification stays on: the default trust (certifi, or SSL_CERT_FILE / SSL_CERT_DIR), plus the
    organisation's CA chain when the endpoint is signed by an internal CA (ModelSpec.ca_bundle)."""
    if not ca_bundle:
        return True
    from ..workspace import resolve

    path = resolve(os.path.expanduser(ca_bundle))
    ctx = ssl.create_default_context(cafile=os.environ.get("SSL_CERT_FILE") or certifi.where())
    ctx.load_verify_locations(cafile=str(path))
    return ctx


class OpenAICompatibleProvider(Provider):
    def __init__(self, spec: ModelSpec, timeout: float = 600.0, client: httpx.Client | None = None,
                 max_attempts: int = MAX_ATTEMPTS, sleep: Callable[[float], None] = time.sleep):
        super().__init__(spec)
        self.max_attempts, self.sleep = max(1, max_attempts), sleep
        if not spec.base_url:
            raise ValueError(f"model {spec.name}: base_url required for openai_compatible provider")
        key = os.environ.get(spec.api_key_env, "") if spec.api_key_env else ""
        headers = ({spec.api_key_header: key} if spec.api_key_header else {"Authorization": f"Bearer {key}"}) if key else {}
        # `client` is for tests (httpx.MockTransport); production always builds its own from the spec.
        # An explicit transport switches off httpx's HTTP_PROXY/HTTPS_PROXY/ALL_PROXY handling (the
        # transport still honours SSL_CERT_FILE / SSL_CERT_DIR for an internal CA): these endpoints are
        # on-prem, and a proxy in between would receive the source code - in cleartext for the
        # loopback-only http:// case that ModelSpec approved as never leaving the host.
        self.client = client or httpx.Client(base_url=spec.base_url, headers=headers, timeout=timeout,
                                             transport=httpx.HTTPTransport(verify=_trust(spec.ca_bundle)))

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = MAX_TOKENS) -> RawReply:
        body = {
            "model": self.spec.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": "mara", "schema": wire_schema(schema), "strict": self.spec.strict_schema}},
        }
        for attempt in range(1, self.max_attempts + 1):
            last = attempt == self.max_attempts
            try:
                r = self.client.post("/chat/completions", json=body)
            except httpx.HTTPError:  # connect/read timeouts, connection refused, protocol errors; no message leaks
                if last:
                    raise RuntimeError("provider_connection_failed") from None
                self.sleep(retry_delay(attempt, None))
                continue
            if r.status_code in RETRY_STATUSES and not last:
                self.sleep(retry_delay(attempt, r.headers.get("retry-after")))
                continue
            break
        if r.status_code >= 400:
            raise RuntimeError(f"provider_http_error:{r.status_code}")
        try:
            payload = r.json()
            choice = payload["choices"][0]
            message = choice["message"]
        except (ValueError, KeyError, IndexError, TypeError):
            # error-shaped or non-JSON body behind a 2xx; the body itself never reaches a log or report
            raise RuntimeError("provider_malformed_payload") from None
        text = message.get("content") or ""
        finish = choice.get("finish_reason", "")
        usage = payload.get("usage", {}) or {}
        tokens = {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0),
                  "served_model": str(payload.get("model") or "")[:200]}
        if finish == "length":
            # The server stopped at max_tokens: the JSON is cut off, or never started when a reasoning
            # model spent the whole budget thinking (vLLM's reasoning parser then returns empty content).
            # A truncation even with empty text: never a refusal (mara.exchange).
            return RawReply(STOP_MAX_TOKENS, answer_text=text, **tokens)
        if finish == "content_filter":
            return RawReply(STOP_REFUSAL, answer_text=text, **tokens)
        return RawReply(STOP_END, answer_text=text, **tokens)
