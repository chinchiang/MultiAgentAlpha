"""Rewrap the one paragraph of a Markdown file that holds a phrase, greedily at a width, keeping its indent and its words.

  .venv/bin/python scripts/reflow.py <file.md> --containing <phrase> [--width 120]

For a paragraph an edit left ragged (docs/agents/pr-flow.md, step 3): the repository wraps by hand (CODING_STANDARDS.md,
"Lines are wrapped by hand"), and this rewraps one paragraph, not a whole file.

The phrase must be on one line of the file, and that line not in a code fence, nor a table row (`|`), a heading (`#` to
`######` then a space or the line's end), a block quote (`>`), an HTML line (`<`), a thematic break (three or more of
`-`, `*` or `_`, spaces between them allowed) or a setext underline (a line of `=` or of `-`; one of `-` alone may be
either). Refused too: a paragraph indented 4 or more whose first line is no list item, as it may be an indented code
block; one whose first line is a list item's marker alone; and one the line after it may underline as a setext heading's
text. The paragraph is the run of lines around that line that share its text's indent, bounded by a blank line, a code
fence, one of those lines, a line that starts a list item (`-`, `*`, `+`, `<n>.` or `<n>)`, then spaces or the line's
end, after its indent) or a line of another indent. A list item's first line opens a paragraph whose other lines take
the item's text indent, where its marker and the spaces after it end (a hanging indent, as pr-flow's steps have it); a
nested list item bounds the paragraph and is left as it is. A list item with no blank line in it is one paragraph,
however its lines were broken: the whole of it is rewrapped.

The paragraph's words, and their order, are kept, the lines joined by a space, then cut into units, words no line break
may part: greedily, as many units go on a line as fit in the width, counted in characters, as scripts/line_width.py
counts them, a unit wider than the width staying whole on a line of its own. A line's trailing spaces go. A unit holds
two words where a line break between them would change more than the lines: words parted by more than one space (the
spaces kept); a word that, first on a line, Markdown would read as the start of a block (a list item's marker, `#` to
`######`, a word starting `>`, `|`, `<`, a fence's three backticks or tildes, or a word of `-`, `=`, `*` and `_` alone)
and the word before it, so no line but the first starts a block; a word ending in a backslash and the word after it,
which would be a hard line break; two East Asian wide characters a space parts; and, first in the paragraph, the words
that would start a block and the first word after them that would not, so the first line starts no block of its own. A
line holding such a unit may run past the width. A paragraph this has rewrapped, rewrapped again at the same width, is
unchanged. It refuses a paragraph whose wrapping would change more than its line breaks and spaces: one with a hard line
break (a line, not its last, ending in two spaces or a backslash), and one where a line ends and the next begins with an
East Asian wide character, which a space would part.

It writes the file in place and prints `<file>: lines <a>-<b> rewrapped`, the paragraph's lines before it was
rewrapped, or `already wrapped` when nothing changed (`line <a>` for a paragraph of one line). Exit 0 then; 2, with
`ERROR: <file>: <why>` on stderr and the file left as it was, for a file that is not Markdown (not `.md`) or not there,
or a phrase or a paragraph it refuses (reflow).

GLOSSARY.md terms: none. Not pure: main reads and writes the file; reflow is pure.
"""

from __future__ import annotations

import argparse
import re
import sys
import unicodedata
from pathlib import Path
from typing import NamedTuple

WIDTH = 120  # as the docs/agents files are wrapped
ITEM = re.compile(r"^( *)([-*+]|\d+[.)])( +|$)")  # a list item's first line: its indent, its marker, the spaces after it
CODE_FENCE = re.compile(r"^ *(```|~~~)")
HEADING = re.compile(r"^ *#{1,6}( |$)")
TABLE_ROW = re.compile(r"^ *\|")
QUOTE = re.compile(r"^ *>")
HTML = re.compile(r"^ *<")
THEMATIC_BREAK = re.compile(r"^ *(?:(?:-[ -]*){3,}|(?:\*[ *]*){3,}|(?:_[ _]*){3,})$")
DASHES = re.compile(r"^ *-+ *$")  # a thematic break, three or more, or a setext underline
EQUALS = re.compile(r"^ *=+ *$")  # a setext underline
NO_PARAGRAPH = ((HEADING, "a heading"), (TABLE_ROW, "a table row"), (QUOTE, "a block quote"), (HTML, "an HTML line"),
                (DASHES, "a thematic break or a setext underline"), (THEMATIC_BREAK, "a thematic break"),
                (EQUALS, "a setext underline"))  # lines in no paragraph; why the phrase's line is refused
BLOCK_WORD = re.compile(r"(?:[-*+]|\d+[.)]|#{1,6})$|[>|<]|```|~~~|[-=*_]+$")  # a word that, first on a line, starts a block
HARD_BREAK = re.compile(r"(  |\\)$")
SPACES = re.compile(r"( +)")
CODE_INDENT = 4  # the indent of an indented code block


class Refused(ValueError):
    """Why a paragraph cannot be rewrapped safely, in words a person reads."""


class Reflowed(NamedTuple):
    text: str  # the whole text, the paragraph rewrapped
    first: int  # the paragraph's first line in the text given, counted from 1
    last: int  # its last line in the text given


def _text_indent(line: str) -> int:
    """Where a line's text starts: after its indent, and after its marker and the spaces after it for a list item's
    first line."""
    m = ITEM.match(line)
    return len(m[0]) if m else len(line) - len(line.lstrip(" "))


def _in_code_fence(lines: list[str]) -> list[bool]:
    """Whether each line is in a code fence, the fence's own lines included."""
    inside, out = False, []
    for line in lines:
        if CODE_FENCE.match(line):
            out.append(True)
            inside = not inside
        else:
            out.append(inside)
    return out


def _in_no_paragraph(line: str, in_fence: bool) -> bool:
    """Whether a line belongs to no paragraph: in a code fence, blank, or one of NO_PARAGRAPH."""
    return in_fence or not line.strip() or any(pattern.match(line) for pattern, _ in NO_PARAGRAPH)


def _span(lines: list[str], in_fence: list[bool], at: int) -> tuple[int, int]:
    """The first and the last line of the paragraph that holds line `at`."""
    indent = _text_indent(lines[at])

    def continues(k: int, *, item: bool = False) -> bool:  # line k goes on this paragraph: its item, when `item`
        return (0 <= k < len(lines) and not _in_no_paragraph(lines[k], in_fence[k])
                and bool(ITEM.match(lines[k])) == item and _text_indent(lines[k]) == indent)

    start = at
    if not ITEM.match(lines[at]):
        while continues(start - 1):
            start -= 1
        if continues(start - 1, item=True):
            start -= 1  # the item whose continuation this is
    end = at
    while continues(end + 1):
        end += 1
    return start, end


def _wide(char: str) -> bool:
    return unicodedata.east_asian_width(char) in ("W", "F")


def _held(before: str, word: str, *, before_is_first: bool) -> bool:
    """Whether no line break may part `word` from the unit `before` it, `before_is_first` when that unit is the
    paragraph's first (the module's docstring)."""
    return (bool(BLOCK_WORD.match(word)) or before.endswith("\\") or (_wide(before[-1]) and _wide(word[0]))
            or (before_is_first and all(BLOCK_WORD.match(w) for w in before.split())))


def _units(text: str) -> list[str]:
    """The units of `text`: its words, those no line break may part kept as one, with the spaces between them."""
    tokens = SPACES.split(text.strip())  # word, spaces, word, ...
    units = [tokens[0]]
    for gap, word in zip(tokens[1::2], tokens[2::2], strict=True):
        if len(gap) > 1 or _held(units[-1], word, before_is_first=len(units) == 1):
            units[-1] += gap + word
        else:
            units.append(word)
    return units


def _greedy(units: list[str], first_width: int, rest_width: int) -> list[list[str]]:
    """`units` as rows of units, as many on each as fit in its width (`first_width` for the first row), greedily."""
    rows: list[list[str]] = [[]]
    for unit in units:
        row = rows[-1]
        if row and len(" ".join([*row, unit])) > (first_width if len(rows) == 1 else rest_width):
            rows.append([unit])
        else:
            row.append(unit)
    return rows


def _fill(first_prefix: str, rest_prefix: str, text: str, width: int) -> list[str]:
    """The units of `text` as lines, greedily at `width`, the first after `first_prefix`, the others after
    `rest_prefix`."""
    rows = _greedy(_units(text), width - len(first_prefix), width - len(rest_prefix))
    return [first_prefix + " ".join(rows[0])] + [rest_prefix + " ".join(row) for row in rows[1:]]


def reflow(text: str, phrase: str, width: int = WIDTH) -> Reflowed:
    """`text` with the paragraph that holds `phrase` rewrapped at `width`, as the module's docstring says, with that
    paragraph's first line and last in `text`; Refused for a phrase or a paragraph the docstring says it refuses."""
    lines = text.split("\n")
    hits = [n for n, line in enumerate(lines) if phrase in line]
    if not hits:
        raise Refused(f"no line holds {phrase!r}")
    if len(hits) > 1:
        raise Refused(f"lines {', '.join(str(n + 1) for n in hits)} hold {phrase!r}")
    at, in_fence = hits[0], _in_code_fence(lines)
    if in_fence[at]:
        raise Refused(f"line {at + 1} is in a code fence")
    for pattern, why in NO_PARAGRAPH:
        if pattern.match(lines[at]):
            raise Refused(f"line {at + 1} is {why}")
    start, end = _span(lines, in_fence, at)
    if end + 1 < len(lines) and (DASHES.match(lines[end + 1]) or EQUALS.match(lines[end + 1])):
        raise Refused(f"line {end + 2} may underline the paragraph as a heading")
    indent, item = _text_indent(lines[start]), ITEM.match(lines[start])
    if item and not item[3]:
        raise Refused(f"line {start + 1} is a list item's marker alone")
    if indent >= CODE_INDENT and not item:
        raise Refused(f"line {start + 1} is indented {indent}, as an indented code block may be")
    for n in range(start, end):
        if HARD_BREAK.search(lines[n]):
            raise Refused(f"line {n + 1} ends in a hard line break")
        if lines[n].rstrip() and _wide(lines[n].rstrip()[-1]) and _wide(lines[n + 1][indent:].lstrip()[:1] or " "):
            raise Refused(f"lines {n + 1} and {n + 2} join East Asian text, which a space would part")
    joined = " ".join(line[indent:].rstrip() for line in lines[start:end + 1])
    filled = _fill(lines[start][:indent], " " * indent, joined, width)
    return Reflowed("\n".join(lines[:start] + filled + lines[end + 1:]), start + 1, end + 1)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("file", type=Path, help="a Markdown file")
    p.add_argument("--containing", required=True, help="a phrase on one line of the paragraph to rewrap")
    p.add_argument("--width", type=int, default=WIDTH, help=f"the width to wrap at, in characters (default {WIDTH})")
    a = p.parse_args(argv)
    if a.file.suffix != ".md":
        print(f"ERROR: {a.file}: not a Markdown file", file=sys.stderr)
        return 2
    if not a.file.is_file():
        print(f"ERROR: {a.file}: no such file", file=sys.stderr)
        return 2
    text = a.file.read_text(encoding="utf-8")
    try:
        new, start, end = reflow(text, a.containing, a.width)
    except Refused as e:
        print(f"ERROR: {a.file}: {e}", file=sys.stderr)
        return 2
    if new != text:
        a.file.write_text(new, encoding="utf-8")
    lines = f"line {start}" if start == end else f"lines {start}-{end}"
    print(f"{a.file}: {lines} {'rewrapped' if new != text else 'already wrapped'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
