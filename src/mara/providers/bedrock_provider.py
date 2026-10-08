"""Claude on Amazon Bedrock, through the Anthropic SDK's Bedrock client.

Same refusal, max_tokens truncation and error handling as AnthropicProvider; the transport is
SigV4-signed calls to bedrock-runtime in `spec.region`, with credentials from the AWS default chain
(AWS_PROFILE / SSO, instance role, ...). `spec.model` is a Bedrock model or inference-profile id,
e.g. `global.anthropic.claude-opus-5-5`. Requires boto3 (the `bedrock` extra of the anthropic package).

The structured answer differs: Bedrock refuses `output_config.format` and a forced `tool_choice`
("tool" / "any") for Claude Opus 5 and 5.5 (ValidationException "Extra inputs are not permitted" /
"not supported for this model", verified 2026-10-07), so every call failed with HTTP 400. The
schema is therefore the input_schema of the one tool the model is told to call, with tool_choice
auto; `effort` and adaptive thinking are accepted as on the Anthropic API. That JSON is not
grammar-constrained: the agents' pydantic models enforce it, exactly as for the OpenAI-compatible
endpoints. Text blocks around the call are kept in `raw_text` and `aside`, so the canary check sees them.

A credential failure - no credentials, an expired SSO session - is raised as the sanitised code
`provider_auth_failed`, so the agent layer records a provider error, never a refusal.
"""

from __future__ import annotations

import json

import anthropic

from ..config import ModelSpec
from .anthropic_provider import MAX_TOKENS, AnthropicProvider
from .base import Completion, clip_strings

SUBMIT_TOOL = "submit_result"
TOOL_INSTRUCTION = (f"Deliver your answer by calling the {SUBMIT_TOOL} tool exactly once. Its input is the complete JSON "
                    "object the instructions above describe. Do not put the answer in plain text.")


class BedrockProvider(AnthropicProvider):
    def __init__(self, spec: ModelSpec, client: anthropic.AnthropicBedrock | None = None):
        super().__init__(spec, client=client or anthropic.AnthropicBedrock(aws_region=spec.region))

    def _request(self, *, system: str, user: str, schema: dict, max_tokens: int) -> dict:
        req = super()._request(system=system, user=user, schema=schema, max_tokens=max_tokens)
        req["system"].append({"type": "text", "text": TOOL_INSTRUCTION})
        req["tools"] = [{"name": SUBMIT_TOOL, "description": "Submit the complete answer as one JSON object.",
                         "input_schema": anthropic.transform_schema(schema)}]
        req["tool_choice"] = {"type": "auto"}
        req["output_config"] = {"effort": "high"}
        return req

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = MAX_TOKENS) -> Completion:
        try:
            return super().complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)
        except RuntimeError:
            raise
        except Exception as e:
            # botocore signals missing or expired credentials with its own exception types (NoCredentialsError,
            # TokenRetrievalError, UnauthorizedSSOTokenError ...); their messages may name the profile or the
            # cache path, so only the code leaves this layer
            if type(e).__module__.startswith("botocore"):
                raise RuntimeError("provider_auth_failed") from None
            raise

    def _answer(self, msg, schema: dict, tokens: dict) -> Completion:
        texts = [b.text for b in msg.content if b.type == "text" and b.text]
        call = next((b for b in msg.content if b.type == "tool_use" and b.name == SUBMIT_TOOL), None)
        # raw_text carries everything the model said, so the canary check also sees prose around the call
        raw = "\n".join(texts + ([json.dumps(call.input, ensure_ascii=False)] if call is not None else []))
        if msg.stop_reason == "max_tokens":
            return Completion(data=None, raw_text=raw, truncated=True, **tokens)
        if call is not None:
            if not isinstance(call.input, dict):
                return Completion(data=None, raw_text=raw, truncated=True, **tokens)
            return Completion(data=clip_strings(call.input, schema), raw_text=raw, aside="\n".join(texts), **tokens)
        # no tool call: a bare JSON answer is accepted, anything else is unusable output (not a refusal)
        if not texts:
            return Completion(data=None, raw_text="", **tokens)
        try:
            data = json.loads(texts[0])
        except json.JSONDecodeError:
            return Completion(data=None, raw_text=raw, truncated=True, **tokens)
        return Completion(data=clip_strings(data, schema), raw_text=raw, **tokens)
