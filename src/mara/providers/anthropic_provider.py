"""Anthropic provider using the official SDK with structured outputs.

Defaults: claude-opus-5, adaptive thinking (on by default for Opus 5), effort high,
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
        except anthropic.RateLimitError as e:
            raise RuntimeError(f"anthropic rate limit: {e}") from e
        except anthropic.APIStatusError as e:
            raise RuntimeError(f"anthropic API error {e.status_code}: {e.message}") from e
        except anthropic.APIConnectionError as e:
            raise RuntimeError(f"anthropic connection error: {e}") from e
        if msg.stop_reason == "refusal":
            return Completion(data=None, raw_text="", refused=True,
                              input_tokens=msg.usage.input_tokens, output_tokens=msg.usage.output_tokens)
        text = next((b.text for b in msg.content if b.type == "text"), "")
        return Completion(
            data=json.loads(text) if text else None,
            raw_text=text,
            input_tokens=msg.usage.input_tokens,
            output_tokens=msg.usage.output_tokens,
        )
