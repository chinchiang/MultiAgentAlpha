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
    def __init__(self, spec: ModelSpec, timeout: float = 600.0):
        super().__init__(spec)
        if not spec.base_url:
            raise ValueError(f"model {spec.name}: base_url required for openai_compatible provider")
        key = os.environ.get(spec.api_key_env, "") if spec.api_key_env else ""
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        self.client = httpx.Client(base_url=spec.base_url, headers=headers, timeout=timeout)

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        body = {
            "model": self.spec.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "response_format": {"type": "json_schema", "json_schema": {"name": "mara", "schema": schema, "strict": True}},
        }
        r = self.client.post("/chat/completions", json=body)
        if r.status_code >= 400:
            raise RuntimeError(f"provider_http_error:{r.status_code}")
        payload = r.json()
        choice = payload["choices"][0]
        text = choice["message"].get("content") or ""
        finish = choice.get("finish_reason", "")
        usage = payload.get("usage", {})
        if finish == "content_filter" or not text.strip():
            return Completion(data=None, raw_text=text, refused=True)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = None
        return Completion(data=data, raw_text=text, input_tokens=usage.get("prompt_tokens", 0),
                          output_tokens=usage.get("completion_tokens", 0))
