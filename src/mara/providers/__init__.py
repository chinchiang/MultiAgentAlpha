from __future__ import annotations

from ..config import ModelSpec
from .base import Provider


def make_provider(spec: ModelSpec, fixtures_dir: str | None = None) -> Provider:
    if spec.provider == "anthropic":
        from .anthropic_provider import AnthropicProvider

        return AnthropicProvider(spec)
    if spec.provider == "openai_compatible":
        from .openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(spec)
    if spec.provider == "mock":
        from .mock import MockProvider

        return MockProvider(spec, fixtures_dir=fixtures_dir)
    raise ValueError(spec.provider)
