"""A finding carries its finders once, as `Finding.finder_families`, which the reviewer round (mara.reviewer_round)
fills; the ballot round (mara.ballot_round) and the jury's scoring (mara.scoring.jury) read them from the finding
(GLOSSARY.md: finding, ballot round, jury). A finding without finders is refused rather than judged as if every
family were independent of it."""

from __future__ import annotations

import pytest

from mara.context.repo_map import RepoContext
from mara.schemas import ModelFamily
from tests import scored_rows
from tests.fake_panel import Panel


def _unfound(fid: str = "F-1"):
    return scored_rows.finding(fid).model_copy(update={"finder_families": []})


def test_the_ballot_round_refuses_a_finding_without_finders_before_asking_any_model(tmp_path):
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    panel = Panel()
    with pytest.raises(ValueError, match="F-2"):
        panel.run(ctx, [scored_rows.finding("F-1"), _unfound("F-2")])
    assert panel.exchanges == []


def test_the_jury_refuses_to_score_a_finding_without_finders():
    with pytest.raises(ValueError, match="F-2"):
        scored_rows.score([scored_rows.finding("F-1"), _unfound("F-2")], scored_rows.votes("F-2", {ModelFamily.DEEPSEEK: "true_positive"}))
