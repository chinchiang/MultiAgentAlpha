"""Claude on Amazon Bedrock, through the Anthropic SDK's Bedrock client.

Same request and response handling as AnthropicProvider (structured output, refusal, max_tokens
truncation); only the transport differs: SigV4-signed calls to bedrock-runtime in `spec.region`,
with credentials from the AWS default chain (AWS_PROFILE / SSO, instance role, ...). `spec.model` is
a Bedrock model or inference-profile id, e.g. `global.anthropic.claude-opus-5-5`. Requires boto3
(the `bedrock` extra of the anthropic package).

A credential failure - no credentials, an expired SSO session - is raised as the sanitised code
`provider_auth_failed`, so the agent layer records a provider error, never a refusal.
"""

from __future__ import annotations

import anthropic

from ..config import ModelSpec
from .anthropic_provider import AnthropicProvider
from .base import Completion


class BedrockProvider(AnthropicProvider):
    def __init__(self, spec: ModelSpec, client: anthropic.AnthropicBedrock | None = None):
        super().__init__(spec, client=client or anthropic.AnthropicBedrock(aws_region=spec.region))

    def complete(self, *, system: str, user: str, schema: dict, role: str, max_tokens: int = 16000) -> Completion:
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
