"""scripts/reflow.py: the one paragraph of a Markdown file that holds a phrase is rewrapped greedily at a width, its
indent, its words and their order kept, and what it cannot rewrap safely is refused. The tests of the paragraph call
reflow.reflow on text; those of the command line run main on a file in tmp_path."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import reflow  # noqa: E402


def test_a_ragged_paragraph_is_rewrapped_greedily_at_the_width_and_the_lines_around_it_are_left():
    text = "# Title\n\nbefore\n\none two\nthree four five six\nseven\n\nafter\n"
    assert reflow.reflow(text, "four", 15).text == "# Title\n\nbefore\n\none two three\nfour five six\nseven\n\nafter\n"


def test_an_indented_paragraph_keeps_its_indent():
    text = "   one two\n   three four five six seven\n"
    assert reflow.reflow(text, "one", 16).text == "   one two three\n   four five six\n   seven\n"


def test_a_list_item_s_paragraph_takes_a_hanging_indent_and_a_nested_item_after_it_is_left():
    text = ("3. **Make it** one\n   two three four five\n   six\n   - a nested item that is long enough to wrap\n"
            "4. next\n")
    assert reflow.reflow(text, "four", 22).text == (
        "3. **Make it** one two\n   three four five six\n   - a nested item that is long enough to wrap\n4. next\n")


def test_a_continuation_line_finds_its_item_above_it():
    text = "- first\n  second third fourth\n"
    assert reflow.reflow(text, "fourth", 30).text == "- first second third fourth\n"


def test_a_line_of_another_indent_bounds_the_paragraph():
    text = "one two\nthree four\n  an indented line\n"
    assert reflow.reflow(text, "two", 30).text == "one two three four\n  an indented line\n"


def test_a_line_holds_the_width_and_no_more():
    assert reflow.reflow("aaaa bbbb\n", "aaaa", 9).text == "aaaa bbbb\n", "nine characters in a width of nine"
    assert reflow.reflow("aaaa bbbbb\n", "aaaa", 9).text == "aaaa\nbbbbb\n", "ten would not fit"


@pytest.mark.parametrize("after", ["# A heading", "| a | table row |", "```", "> a quote"],
                         ids=["a heading", "a table row", "a fence", "a block quote"])
def test_a_block_right_after_the_paragraph_bounds_it(after):
    text = f"one two\nthree\n{after}\n"
    assert reflow.reflow(text, "two", 30).text == f"one two three\n{after}\n"


def test_a_line_that_starts_with_an_issue_number_is_no_heading():
    text = "see the issue\n#459 for more\n"
    assert reflow.reflow(text, "issue", 30).text == "see the issue #459 for more\n"


def test_an_item_whose_marker_is_followed_by_several_spaces_keeps_them_and_takes_its_continuation():
    text = "-   foo\n    bar\n"
    assert reflow.reflow(text, "foo", 30).text == "-   foo bar\n"


def test_no_line_starts_with_a_word_markdown_would_read_as_a_block():
    """`3.` first on a line would open a list item: the word before it stays with it, past the width if need be."""
    assert reflow.reflow("as in step 3. Then the next one\n", "step", 12).text == "as in\nstep 3. Then\nthe next one\n"
    assert reflow.reflow("aaaaaaaaaa - b\n", "a", 5).text == "aaaaaaaaaa -\nb\n", "past the width"


@pytest.mark.parametrize("text, width, expected", [
    ("aaaa - 3. b\n", 6, "aaaa - 3.\nb\n"),
    ("aaaa >=3 b\n", 5, "aaaa >=3\nb\n"),
    ("aaaa |a| b\n", 5, "aaaa |a|\nb\n"),
    ("foo bar --- bazzzzzzzzz\n", 8, "foo\nbar ---\nbazzzzzzzzz\n"),
    ("foo bar === baz\n", 8, "foo\nbar ===\nbaz\n"),
    ("see <https://x.y> now\n", 6, "see <https://x.y>\nnow\n"),
    ("one two ~~~ three\n", 8, "one\ntwo ~~~\nthree\n"),
    ("one two ```json three\n", 8, "one\ntwo ```json\nthree\n"),
    ("a b c - - - - d\n", 3, "a b\nc - - - -\nd\n"),
    ("start *** a b\n", 9, "start ***\na b\n"),
], ids=["a chain of words that start a block", "a quote's mark", "a table's mark", "a thematic break",
        "a setext underline", "an HTML start", "a fence of tildes", "a fence of backticks", "a run of markers",
        "a break that would be left alone on a line"])
def test_a_word_that_would_start_a_block_stays_on_the_line_of_the_word_before_it(text, width, expected):
    assert reflow.reflow(text, text.split()[0], width).text == expected


def test_a_word_ending_in_a_backslash_keeps_the_next_word_on_its_line_so_a_second_run_changes_nothing():
    once = reflow.reflow("path C:\\ then more\n", "path", 8).text
    assert once == "path\nC:\\ then\nmore\n"
    assert reflow.reflow(once, "path", 8).text == once


def test_east_asian_words_a_space_parts_stay_on_one_line_so_a_second_run_changes_nothing():
    once = reflow.reflow("寫 中文 字 here\n", "寫", 4).text
    assert once == "寫 中文 字\nhere\n"
    assert reflow.reflow(once, "寫", 4).text == once


def test_words_first_in_the_paragraph_that_would_start_a_block_keep_the_next_word_that_would_not_on_their_line():
    assert reflow.reflow("- *** a b c\n", "a", 6).text == "- *** a\n  b c\n"
    assert reflow.reflow("- <b> a b c\n", "a", 6).text == "- <b> a\n  b c\n", "the next word only"
    assert reflow.reflow("- - - x y\n", "x", 5).text == "- - - x\n  y\n", "a run of them"
    assert reflow.reflow("_ _ _ x y\n", "x", 5).text == "_ _ _ x\ny\n", "a run of them, in no list item"


def test_a_run_of_spaces_is_no_place_to_break_so_a_second_run_changes_nothing():
    once = reflow.reflow("aaaa  b c\n", "aaaa", 6).text
    assert once == "aaaa  b\nc\n"
    assert reflow.reflow(once, "aaaa", 6).text == once


def test_a_continuation_line_of_another_indent_than_its_item_s_text_does_not_join_it():
    text = "- a\n   b c\n"
    assert reflow.reflow(text, "b c", 30).text == text


def test_an_html_line_a_thematic_break_and_a_setext_underline_bound_the_paragraph():
    text = "<!-- a note -->\nThe text\nmore here\n***\n"
    assert reflow.reflow(text, "The text", 30).text == "<!-- a note -->\nThe text more here\n***\n"
    text = "Title\n===\nThe text\nmore here\n"
    assert reflow.reflow(text, "The text", 30).text == "Title\n===\nThe text more here\n", "an underline above"


def test_a_word_longer_than_the_width_stays_whole_on_its_own_line():
    text = "a `scripts/a_very_long_name_indeed.py` b\n"
    assert reflow.reflow(text, "long", 10).text == "a\n`scripts/a_very_long_name_indeed.py`\nb\n"


def test_a_run_of_spaces_between_two_words_on_one_line_is_kept():
    text = "the line `+ <rule>  <file>:<line>` and\nmore\n"
    assert reflow.reflow(text, "rule", 120).text == "the line `+ <rule>  <file>:<line>` and more\n"


def test_a_paragraph_already_wrapped_greedily_at_the_width_is_unchanged():
    text = "one two three\nfour five six\nseven\n"
    assert reflow.reflow(text, "five", 15).text == text


REFUSED = [
    ("one\ntwo\n", "three", "no line holds 'three'"),
    ("one two\n\ntwo three\n", "two", "lines 1, 3 hold 'two'"),
    ("```\ncode two\n```\n", "two", "line 2 is in a code fence"),
    ("| a | two |\n", "two", "line 1 is a table row"),
    ("# two\n", "two", "line 1 is a heading"),
    ("> two\n", "two", "line 1 is a block quote"),
    ("one two  \nthree\n", "two", "line 1 ends in a hard line break"),
    ("版本\n規則\n", "版本", "lines 1 and 2 join East Asian text, which a space would part"),
    ("<!-- two -->\n", "two", "line 1 is an HTML line"),
    ("one\n\n***\n", "***", "line 3 is a thematic break"),
    ("one\n\n===\n", "===", "line 3 is a setext underline"),
    ("Title\n---\n", "---", "line 2 is a thematic break or a setext underline"),
    ("Title words\n===\n", "Title", "line 2 may underline the paragraph as a heading"),
    ("*\n foo bar\n", "foo", "line 1 is a list item's marker alone"),
    ("    two\n    three\n", "two", "line 1 is indented 4, as an indented code block may be"),
]
REFUSED_IDS = ["no line", "two lines", "a fence", "a table row", "a heading", "a block quote", "a hard break",
               "East Asian text", "an HTML line", "a thematic break", "a setext underline", "a line of dashes",
               "a setext heading", "a marker alone", "an indented code block"]


@pytest.mark.parametrize("text, phrase, why", REFUSED, ids=REFUSED_IDS)
def test_what_cannot_be_rewrapped_safely_is_refused(text, phrase, why):
    with pytest.raises(reflow.Refused) as caught:
        reflow.reflow(text, phrase, 120)
    assert str(caught.value) == why


def test_the_command_line_rewraps_the_file_in_place_and_says_which_lines(tmp_path, capsys):
    path = tmp_path / "doc.md"
    path.write_text("one two\nthree four\n", encoding="utf-8")
    assert reflow.main([str(path), "--containing", "four", "--width", "30"]) == 0
    assert path.read_text(encoding="utf-8") == "one two three four\n"
    assert capsys.readouterr().out == f"{path}: lines 1-2 rewrapped\n"


def test_the_command_line_says_so_when_nothing_changes(tmp_path, capsys):
    path = tmp_path / "doc.md"
    path.write_text("one two three four\n", encoding="utf-8")
    assert reflow.main([str(path), "--containing", "four"]) == 0
    assert capsys.readouterr().out == f"{path}: line 1 already wrapped\n"


@pytest.mark.parametrize("name, text, phrase, why", [("doc.py", "one two\n", "two", "not a Markdown file"),
                                                  *(("doc.md", *case) for case in REFUSED)],
                         ids=["not markdown", *REFUSED_IDS])
def test_the_command_line_refuses_with_exit_2_and_leaves_the_file(tmp_path, capsys, name, text, phrase, why):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    assert reflow.main([str(path), f"--containing={phrase}"]) == 2  # = for a phrase that looks like an option (---)
    assert path.read_text(encoding="utf-8") == text
    assert capsys.readouterr().err == f"ERROR: {path}: {why}\n"


def test_the_command_line_refuses_a_file_that_is_not_there(tmp_path, capsys):
    path = tmp_path / "gone.md"
    assert reflow.main([str(path), "--containing", "two"]) == 2
    assert capsys.readouterr().err == f"ERROR: {path}: no such file\n"
