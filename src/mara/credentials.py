"""Which environment variable a model's key is read from.

One answer for the provider adapters, the garak and CyberSecEval evaluation, and the workbench's environment page. It
names the variable and never reads it: reading (and what a missing key means) stays with each caller. A provider with no
default of its own - openai_compatible - gets no variable unless its `api_key_env` names one, so another vendor's key
(ANTHROPIC_API_KEY once went to a self-hosted base_url) is never the fallback. Pure, standard library only.
"""

from __future__ import annotations

# The vendor APIs' own variables. bedrock (the AWS credential chain) and mock need none.
VENDOR_KEY_ENV = {"anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY"}


def key_env(provider: str, api_key_env: str | None) -> str | None:
    """`api_key_env` when set, else the provider's own default; None when it has neither."""
    return api_key_env or VENDOR_KEY_ENV.get(provider)
