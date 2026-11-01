"""Who may judge and the quorum count differently, deliberately (docs/adr/0005-jury-outcome.md, amended 2026-11-01):
the ballot round plans the judges from the config's judge seats before any reply, while the jury's quorum counts only
the families that voted validly in both passes (GLOSSARY.md: jury, ballot round). A voided reply of an independent judge
therefore starts no fallback to the finder's own family; the quorum fails and the finding needs a human."""

from __future__ import annotations

from mara.context.repo_map import RepoContext
from mara.schemas import ModelFamily
from mara.scoring import jury
from mara.scoring.outcome import INSUFFICIENT_INDEPENDENT_JUDGES
from tests import scored_rows
from tests.fake_panel import REFUSAL, Panel


def test_a_voided_independent_judge_starts_no_fallback_so_the_quorum_fails_and_a_human_decides(tmp_path):
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    (f,) = scored_rows.found_by([scored_rows.finding("F-1")], ModelFamily.ANTHROPIC)  # the mock panel's judges: anthropic,
    # deepseek and nemotron
    panel = Panel().always("judge", REFUSAL, family=ModelFamily.DEEPSEEK)  # every deepseek judge reply, its retry too
    ballots = panel.run(ctx, [f])
    # the plan: two seats independent of the finder, the quorum's two, so the finder's own family is never asked
    assert panel.asked("judge", ModelFamily.DEEPSEEK) and panel.asked("judge", ModelFamily.NEMOTRON)
    assert panel.asked("judge", ModelFamily.ANTHROPIC) == [] and panel.audit["self_family_fallback_votes"] == 0
    # the result: only nemotron voted validly, one independent family short of the quorum
    assert {v.judge_family for v in ballots.votes} == {ModelFamily.NEMOTRON}
    (row,) = jury.score([f], ballots, [], jury=jury.Jury.from_config(panel.cfg), policy=scored_rows.policy(panel.cfg)).rows
    assert row.needs_human and INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


def test_with_too_few_independent_seats_the_finders_families_judge_at_a_discount_and_the_quorum_still_fails(tmp_path):
    """The fallback of docs/adr/0005-jury-outcome.md ("Who judges"): found by two of the three judge families, one
    independent seat is left, below the two the quorum needs, so the finders' families judge it too, their votes
    marked self_family (weighed at the jury's discount), and the quorum fails all the same."""
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    (f,) = scored_rows.found_by([scored_rows.finding("F-1")], ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK)
    panel = Panel()
    ballots = panel.run(ctx, [f])
    assert panel.asked("judge", ModelFamily.ANTHROPIC) and panel.asked("judge", ModelFamily.DEEPSEEK)
    assert panel.audit["self_family_fallback_votes"] == 2  # one fallback finding for each finder family's judge
    (row,) = jury.score([f], ballots, [], jury=jury.Jury.from_config(panel.cfg), policy=scored_rows.policy(panel.cfg)).rows
    assert {v.judge_family for v in ballots.votes} == {ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON}
    assert all(v.self_family == (v.judge_family in f.finder_families) for v in ballots.votes)
    assert row.needs_human and INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons
