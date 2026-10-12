"""Anthropic provider using the official SDK with structured outputs.

Defaults: claude-opus-5-5, adaptive thinking (always on for Opus 5.5), effort high set explicitly
(Opus 5.5 defaults to medium),
output_config.format json_schema so the first text block is guaranteed-valid JSON.
Refusals (stop_reason == "refusal") are surfaced, never silently swallowed: a
reviewer that refuses is recorded as an abstention, which Krippendorff's alpha
tolerates and the bias audit counts.

Structured outputs accept a JSON Schema subset: minLength/maxLength, minimum/maximum,
pattern and maxItems are not supported, and the SDK only rewrites a schema it derives
from a type (output_format=...), never a raw dict passed in output_config. The agent
schemas carry those bounds (the OpenAI-compatible endpoints enforce them), so they are
passed through anthropic.transform_schema, which moves each unsupported keyword into
the field's description; the answer's strings are clipped to their maxLength afterwards
(providers.base.clip_strings) and the agents' pydantic models enforce every other bound.
"""

from __future__ import annotations

import json
import os
from typing import Any

import anthropic

from ..config import ModelSpec
from .base import Completion, Provider, clip_strings

# Adaptive thinking counts against max_tokens, and a review batch is up to 400k characters of
# source: 16k leaves too little room after thinking at effort high. Streaming keeps a large cap
# clear of HTTP timeouts.
MAX_TOKENS = 64000
# Claude models without adaptive thinking or the effort parameter (Bedrock ValidationException "adaptive thinking is not
# supported on this model" / "does not support the effort parameter", Haiku 4.5 and Sonnet 4.5, 2026-10-08): extended
# thinking with an explicit budget, and no effort.
BUDGET_THINKING_MODELS = ("haiku-4-5", "sonnet-4-5")
THINKING_BUDGET = 8192


def thinking_for(model: str) -> tuple[dict, dict]:
    """(thinking, the effort part of output_config) the model accepts."""
    if any(m in model.lower() for m in BUDGET_THINKING_MODELS):
        return {"type": "enabled", "budget_tokens": THINKING_BUDGET}, {}
    return {"type": "adaptive"}, {"effort": "high"}


class AnthropicProvider(Provider):
    def __init__(self, spec: ModelSpec, client: anthropic.Anthropic | anthropic.AnthropicBedrock | None = None):
        super().__init__(spec)
        if client is not None:  # BedrockProvider and tests
            self.client = client
            return
        api_key = os.environ.get(spec.api_key_env) if spec.api_key_env else None
        # Zero-arg client also resolves ANTHROPIC_API_KEY / `ant auth login` profiles.
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def _request(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        thinking, effort = thinking_for(self.spec.model)
        return {
            "model": self.spec.model,
            "max_tokens": max_tokens,
            "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": user}],
            "thinking": thinking,
            "output_config": {**effort, "format": {"type": "json_schema", "schema": anthropic.transform_schema(schema)}},
        }

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = MAX_TOKENS) -> Completion:
        try:
            with self.client.messages.stream(**self._request(system=system, user=user, schema=schema, max_tokens=max_tokens)) as stream:
                msg = stream.get_final_message()
        except anthropic.RateLimitError:
            raise RuntimeError("provider_rate_limited") from None
        except anthropic.APIStatusError as e:
            raise RuntimeError(f"provider_http_error:{e.status_code}") from None
        except anthropic.APIConnectionError:
            raise RuntimeError("provider_connection_failed") from None
        tokens: dict[str, Any] = {"input_tokens": msg.usage.input_tokens, "output_tokens": msg.usage.output_tokens,
                  # Top-level `model` names the model that produced the message (a vendor-side fallback changes it).
                  "served_model": getattr(msg, "model", "") or ""}
        if msg.stop_reason == "refusal":
            return Completion(data=None, raw_text="", refused=True, **tokens)
        return self._answer(msg, schema, tokens)

    def _answer(self, msg, schema: dict, tokens: dict) -> Completion:
        text = next((b.text for b in msg.content if b.type == "text"), "")
        if msg.stop_reason == "max_tokens":
            # Output budget exhausted: the JSON text block is cut off. Distinguished from a refusal so
            # the bias audit does not attribute a too-small max_tokens to the model.
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        if not text:
            return Completion(data=None, raw_text="", **tokens)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return Completion(data=None, raw_text=text, truncated=True, **tokens)
        return Completion(data=clip_strings(data, schema), raw_text=text, **tokens)
