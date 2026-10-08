"""Provider interface: one structured completion, validated against a JSON schema."""

from __future__ import annotations

import abc
import copy
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
    truncated: bool = False  # output hit max_tokens (or was not valid JSON): not a refusal, data is None
    error: str = ""  # sanitised provider failure code (provider_http_error:429, ...): no model answer, not a refusal
    served_model: str = ""  # model the response names as its producer; can differ from the configured id
    aside: str = ""  # prose the model wrote outside the structured answer (Bedrock tool call); part of raw_text too


class Provider(abc.ABC):
    def __init__(self, spec: ModelSpec):
        self.spec = spec
        self.served_models: set[str] = set()  # every served_model seen this run, for the provider manifest

    @property
    def family(self):
        return self.spec.family

    @property
    def model(self) -> str:
        return self.spec.model

    def bind_target(self, root) -> None:  # noqa: B027 - optional hook
        """Called by the pipeline before a review; lets a provider know which repo is under review."""

    @abc.abstractmethod
    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
        """Return JSON matching `schema`. `role` is a hint ('reviewer:xss', 'judge', ...) for mocks/logging."""


def wire_schema(schema: dict) -> dict:
    """The schema as sent to a grammar-constrained decoder: every string maxLength moved into the field's description."""
    out = copy.deepcopy(schema)

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if node.get("type") == "string" and "maxLength" in node:
                n = node.pop("maxLength")
                node["description"] = (node.get("description", "") + f" At most {n} characters.").strip()
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(out)
    return out


def clip_strings(data: Any, schema: dict) -> Any:
    """Cut every string of `data` to the maxLength its schema node declares (objects and arrays walked in step).

    No provider sends maxLength as a hard constraint (structured outputs and tool schemas only carry it as
    guidance, constrained decoders cut strings mid-sentence), so a model may overrun a bound in prose; one
    overlong reason would otherwise discard a whole skeptic or red-team batch. Clipping only shortens text:
    a quote stays a verbatim prefix, and a control citation cut off makes a refutation unverifiable, which
    downgrades it."""
    if isinstance(data, str):
        n = schema.get("maxLength")
        return data[:n] if isinstance(n, int) else data
    if isinstance(data, dict):
        props = schema.get("properties", {})
        return {k: clip_strings(v, props[k]) if k in props else v for k, v in data.items()}
    if isinstance(data, list) and isinstance(schema.get("items"), dict):
        return [clip_strings(v, schema["items"]) for v in data]
    return data
