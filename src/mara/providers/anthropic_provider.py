"""Anthropic provider using the official SDK with structured outputs.

Defaults: claude-opus-5-5, adaptive thinking (always on for Opus 5.5), effort high set explicitly
(Opus 5.5 defaults to medium),
output_config.format json_schema so the first text block is guaranteed-valid JSON.
Refusals (stop_reason == "refusal") are surfaced, never silently swallowed: a
reviewer that refuses is recorded as an abstention, which Krippendorff's alpha
tolerates and the bias audit counts.
"""

from __future__ import annotations

import json
import os

import anthropic

from ..config import ModelSpec
from .base import Completion, Provider


class AnthropicProvider(Provider):
    def __init__(self, spec: ModelSpec):
        super().__init__(spec)
        api_key = os.environ.get(spec.api_key_env) if spec.api_key_env else None
        # Zero-arg client also resolves ANTHROPIC_API_KEY / `ant auth login` profiles.
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        try:
            with self.client.messages.stream(
                model=self.spec.model,
                max_tokens=max_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user}],
                thinking={"type": "adaptive"},
                output_config={"effort": "high", "format": {"type": "json_schema", "schema": schema}},
            ) as stream:
                msg = stream.get_final_message()
        except anthropic.RateLimitError:
            raise RuntimeError("provider_rate_limited") from None
        except anthropic.APIStatusError as e:
            raise RuntimeError(f"provider_http_error:{e.status_code}") from None
        except anthropic.APIConnectionError:
            raise RuntimeError("provider_connection_failed") from None
        tokens_in, tokens_out = msg.usage.input_tokens, msg.usage.output_tokens
        # Top-level `model` names the model that produced the message (a vendor-side fallback changes it).
        served = getattr(msg, "model", "") or ""
        if msg.stop_reason == "refusal":
            return Completion(data=None, raw_text="", refused=True, input_tokens=tokens_in, output_tokens=tokens_out,
                              served_model=served)
        text = next((b.text for b in msg.content if b.type == "text"), "")
        if msg.stop_reason == "max_tokens":
            # Output budget exhausted: the JSON text block is cut off. Distinguished from a refusal so
            # the bias audit does not attribute a too-small max_tokens to the model.
            return Completion(data=None, raw_text=text, truncated=True, input_tokens=tokens_in, output_tokens=tokens_out,
                              served_model=served)
        if not text:
            return Completion(data=None, raw_text="", input_tokens=tokens_in, output_tokens=tokens_out, served_model=served)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return Completion(data=None, raw_text=text, truncated=True, input_tokens=tokens_in, output_tokens=tokens_out,
                              served_model=served)
        return Completion(data=data, raw_text=text, input_tokens=tokens_in, output_tokens=tokens_out, served_model=served)
