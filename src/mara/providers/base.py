"""Provider interface: one structured completion, returned as the vendor gave it (RawReply)."""

from __future__ import annotations

import abc
import copy
from dataclasses import dataclass
from typing import Any

from ..config import ModelSpec

STOP_END = "end"  # the model finished its answer
STOP_MAX_TOKENS = "max_tokens"  # the vendor stopped it at the output limit
STOP_REFUSAL = "refusal"  # the vendor or the model declined (refusal stop, content filter, blocked prompt)
STOPS = (STOP_END, STOP_MAX_TOKENS, STOP_REFUSAL)


@dataclass
class RawReply:
    """What a provider adapter saw, before anyone judged it: the adapter maps its vendor's stop reason to one of
    STOPS and hands over the text, and mara.exchange classifies the reply (docs/adr/0001-reply-outcome-accounting.md).
    An adapter never parses JSON, clips strings or decides whether a reply was truncated or unusable."""

    stop: str
    answer_text: str = ""  # the text that should hold the structured answer (parsed by mara.exchange)
    structured: Any = None  # an answer the vendor already delivered as structured data (Bedrock tool call)
    aside: str = ""  # everything else the model wrote around the answer (other text blocks, prose around a tool call)
    input_tokens: int = 0
    output_tokens: int = 0
    served_model: str = ""  # model the response names as its producer; can differ from the configured id

    def __post_init__(self) -> None:
        if self.stop not in STOPS:
            raise ValueError(f"unknown stop {self.stop!r}; one of {STOPS}")


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
    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> RawReply:
        """Ask for JSON matching `schema`; return the reply as the vendor gave it. `role` is a hint ('reviewer:xss',
        'judge', ...) for mocks/logging. A failed call raises RuntimeError with a sanitised provider_* code."""


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
