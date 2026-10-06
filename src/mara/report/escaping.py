"""Render untrusted content as literal, single-line text in Markdown.

literal() is for running text; code() is for code spans. They are not interchangeable: Markdown
decodes character references in running text but not inside code spans, so literal()'s `&#40;`
shows up verbatim between backticks (`cursor.execute&#40;&quot;SELECT &#42;...`).
"""
from __future__ import annotations

import html
import re


def literal(value) -> str:
    text = " ".join(str(value).split())
    # Encode each source character once; later replacements must not re-encode the
    # '#' in an entity emitted for an earlier backtick or bracket.
    return "".join(f"&#{ord(char)};" if char in "\\`*_[]()#|~!+-" else html.escape(char, quote=True) for char in text)


def code(value) -> str:
    """Untrusted content as a single-line code span, shown verbatim.

    Nothing inside a code span is interpreted except its closing fence, so the text needs no
    escaping, only a fence it cannot contain: a backtick run one longer than the longest run in the
    text, padded with a space when the text starts or ends with a backtick (CommonMark strips one
    space from each side). The content can therefore never close the span early."""
    text = " ".join(str(value).split())
    fence = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if not text or text[0] == "`" or text[-1] == "`" else ""
    return f"{fence}{pad}{text}{pad}{fence}"
