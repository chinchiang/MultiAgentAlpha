"""Render untrusted content as literal, single-line text in Markdown (also safe in code spans)."""
from __future__ import annotations

import html


def literal(value) -> str:
    text = " ".join(str(value).split())
    # Encode each source character once; later replacements must not re-encode the
    # '#' in an entity emitted for an earlier backtick or bracket.
    return "".join(f"&#{ord(char)};" if char in "\\`*_[]()#|~!+-" else html.escape(char, quote=True) for char in text)
