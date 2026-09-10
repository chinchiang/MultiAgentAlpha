"""Provider interface: one structured completion, validated against a JSON schema."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

from ..config import ModelSpec


@dataclass
class Completion:
    data: Any
    raw_text: str
    input_tokens: int = 0
    output_tokens: int = 0
    refused: bool = False


class Provider(abc.ABC):
    def __init__(self, spec: ModelSpec):
        self.spec = spec

    @property
    def family(self):
        return self.spec.family

    @property
    def model(self) -> str:
        return self.spec.model

    @abc.abstractmethod
    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        """Return JSON matching `schema`. `role` is a hint ('reviewer:xss', 'judge', ...) for mocks/logging."""
