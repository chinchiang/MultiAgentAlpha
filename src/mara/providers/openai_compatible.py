"""Provider for self-hosted models exposing an OpenAI-compatible /v1/chat/completions
endpoint (vLLM, NVIDIA NIM, SGLang). Used for DeepSeek and Nemotron weights that run
inside the organisation's perimeter. Plain httpx; no vendor SDK required.

Structured output is requested via `response_format: json_schema` where the server
supports it; the returned text is always re-validated by the caller.
"""

from __future__ import annotations

import json
import os

import httpx

from ..config import ModelSpec
from .base import Completion, Provider


class OpenAICompatibleProvider(Provider):
    def __init__(self, spec: ModelSpec, timeout: float = 600.0, client: httpx.Client | None = None):
        super().__init__(spec)
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
        try:
            r = self.client.post("/chat/completions", json=body)
        except httpx.HTTPError:  # connect/read timeouts, connection refused, protocol errors; no message leaks
            raise RuntimeError("provider_connection_failed") from None
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
