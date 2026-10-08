"""Google Gemini through the Gemini API (generativelanguage.googleapis.com), plain httpx.

Structured output is requested with `responseMimeType: application/json` and `responseJsonSchema`;
the returned text is always re-validated by the caller. The key is sent in the `x-goog-api-key`
header, never in the URL, so it cannot end up in a proxy or access log.

Outcome mapping (Completion): `finishReason` MAX_TOKENS is a truncation even with empty text; a
blocked prompt (`promptFeedback.blockReason`) or a SAFETY / RECITATION / PROHIBITED_CONTENT /
BLOCKLIST / SPII finish is a refusal; an empty answer that did not hit the limit is a refusal too.
Thought parts (thinking models) are skipped. Transient failures (timeouts and other transport
errors, 408, 429, 500, 502, 503, 504) are retried exactly like the OpenAI-compatible provider.

Data handling: the paid Gemini API tier does not train on prompts but keeps them for a limited time
for abuse monitoring, so such a model is `vendor_api_retained` and policy P5 admits it only with a
`retention_approval_ref`.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable

import httpx

from ..config import ModelSpec
from .base import Completion, Provider, clip_strings
from .openai_compatible import MAX_ATTEMPTS, RETRY_STATUSES, retry_delay

API_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_KEY_ENV = "GEMINI_API_KEY"
REFUSAL_FINISHES = frozenset({"SAFETY", "RECITATION", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "IMAGE_SAFETY"})


class GeminiProvider(Provider):
    def __init__(self, spec: ModelSpec, timeout: float = 600.0, client: httpx.Client | None = None,
                 max_attempts: int = MAX_ATTEMPTS, sleep: Callable[[float], None] = time.sleep):
        super().__init__(spec)
        self.max_attempts, self.sleep = max(1, max_attempts), sleep
        key = os.environ.get(spec.api_key_env or DEFAULT_KEY_ENV, "")
        headers = {"x-goog-api-key": key} if key else {}
        # `client` is for tests (httpx.MockTransport)
        self.client = client or httpx.Client(base_url=API_BASE, headers=headers, timeout=timeout)

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"temperature": 0.0, "maxOutputTokens": max_tokens,
                                 "responseMimeType": "application/json", "responseJsonSchema": schema},
        }
        path = f"/models/{self.spec.model}:generateContent"
        for attempt in range(1, self.max_attempts + 1):
            last = attempt == self.max_attempts
            try:
                r = self.client.post(path, json=body)
            except httpx.HTTPError:
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
            usage = payload.get("usageMetadata") or {}
            candidates = payload.get("candidates") or []
            blocked = (payload.get("promptFeedback") or {}).get("blockReason")
        except (ValueError, AttributeError):
            raise RuntimeError("provider_malformed_payload") from None
        tokens = {"input_tokens": usage.get("promptTokenCount", 0),
                  "output_tokens": usage.get("candidatesTokenCount", 0) + usage.get("thoughtsTokenCount", 0),
                  # the model version that answered, e.g. an alias resolved to a dated release
                  "served_model": str(payload.get("modelVersion") or "")[:200]}
        if blocked or not candidates:
            return Completion(data=None, raw_text="", refused=True, **tokens)
        cand = candidates[0]
        finish = cand.get("finishReason", "")
        parts = (cand.get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and not p.get("thought"))
        if finish == "MAX_TOKENS":
            # the output budget ran out (thinking models may spend it before any text): never a refusal
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        if finish in REFUSAL_FINISHES or not text.strip():
            return Completion(data=None, raw_text=text, refused=True, **tokens)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        return Completion(data=clip_strings(data, schema), raw_text=text, **tokens)
