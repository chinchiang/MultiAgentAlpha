"""Provider for self-hosted models exposing an OpenAI-compatible /v1/chat/completions
endpoint (vLLM, NVIDIA NIM, SGLang). Used for DeepSeek and Nemotron weights that run
inside the organisation's perimeter. Plain httpx; no vendor SDK required.

Structured output is requested via `response_format: json_schema` where the server
supports it; the returned text is always re-validated by the caller.

Transient failures (timeouts and other transport errors, 408, 429, 500, 502, 503, 504, 529) are retried
up to MAX_ATTEMPTS calls in total, with exponential backoff plus jitter, or the server's Retry-After in
seconds, capped at RETRY_AFTER_CAP. Any other status is a configuration or request error and fails at
once. After the last attempt the sanitised code is raised as before, and the agent layer records it as
a provider error, not a refusal. (The Anthropic SDK retries on its own, so that provider adds nothing.)
"""

from __future__ import annotations

import json
import os
import random
import time
from collections.abc import Callable

import httpx

from ..config import ModelSpec
from .base import Completion, Provider

MAX_ATTEMPTS = 3
BACKOFF_BASE = 2.0  # seconds before the second attempt; doubled for each further one, plus up to 1 s of jitter
RETRY_AFTER_CAP = 30.0
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})


def retry_delay(attempt: int, retry_after: str | None) -> float:
    """Seconds to wait after failed attempt `attempt` (1-based): Retry-After seconds if given, else backoff."""
    if retry_after is not None:
        try:
            return min(max(float(retry_after), 0.0), RETRY_AFTER_CAP)
        except ValueError:
            pass  # an HTTP date or garbage: fall back to our own backoff
    return min(BACKOFF_BASE * 2 ** (attempt - 1) + random.random(), RETRY_AFTER_CAP)  # nosec B311 - jitter, not crypto


class OpenAICompatibleProvider(Provider):
    def __init__(self, spec: ModelSpec, timeout: float = 600.0, client: httpx.Client | None = None,
                 max_attempts: int = MAX_ATTEMPTS, sleep: Callable[[float], None] = time.sleep):
        super().__init__(spec)
        self.max_attempts, self.sleep = max(1, max_attempts), sleep
        if not spec.base_url:
            raise ValueError(f"model {spec.name}: base_url required for openai_compatible provider")
        key = os.environ.get(spec.api_key_env, "") if spec.api_key_env else ""
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        # `client` is for tests (httpx.MockTransport); production always builds its own from the spec.
        self.client = client or httpx.Client(base_url=spec.base_url, headers=headers, timeout=timeout)

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        body = {
            "model": self.spec.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "response_format": {"type": "json_schema", "json_schema": {"name": "mara", "schema": schema, "strict": True}},
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
        tokens = {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0)}
        if finish == "content_filter" or not text.strip():
            return Completion(data=None, raw_text=text, refused=True, **tokens)
        if finish == "length":
            # The server stopped at max_tokens: the JSON is cut off. Never count this as a refusal
            # (the bias audit would misread a too-small budget as model reluctance).
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        return Completion(data=data, raw_text=text, **tokens)
