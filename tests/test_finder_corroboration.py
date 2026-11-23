"""Finder corroboration (GLOSSARY.md; docs/adr/0005-jury-outcome.md, amended 2026-11-22): with `gate.finder_corroboration`
on, a finding two or more families found reaches its quorum on the judge families independent of them, fewer than the
quorum asks for, when every one of those voted true positive in both passes and a skeptic outside its finders neither
refuted it nor abstained. It can only accept. The ballot round then asks none of the finders' families to judge it
(mara.ballot_round), and jury scoring says whether it was borne out (mara.scoring.jury)."""

from __future__ import annotations

from pathlib import Path

import pytest

from mara.config import MaraConfig, load_config
from mara.context.repo_map import RepoContext
from mara.pipeline import Pipeline
from mara.schemas import ModelFamily, SkepticVerdict
from mara.scoring import jury
from mara.scoring.outcome import INSUFFICIENT_INDEPENDENT_JUDGES
from mara.workspace import Workspace  # noqa: E402
from tests import scored_rows
from tests.fake_panel import REFUSAL, Panel, items

ROOT = Path(__file__).resolve().parents[1]
A, D, N, M = ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON, ModelFamily.MISTRAL


def _on(cfg: MaraConfig = scored_rows.MOCK) -> MaraConfig:
    return cfg.model_copy(update={"gate": cfg.gate.model_copy(update={"finder_corroboration": True})})


ON = _on()


def _skeptic(fid: str, family: ModelFamily = N, verdict: str = "stands") -> dict[str, SkepticVerdict]:
    return {fid: SkepticVerdict(finding_id=fid, verdict=verdict, reason="r", sanitizer_or_control="", source_family=family,
                                source_model="m")}


def _found_by(*families: ModelFamily):
    (f,) = scored_rows.found_by([scored_rows.finding("F-1")], *families)
    return f


def _row(f, verdicts: dict[ModelFamily, str], *, cfg: MaraConfig = ON, skeptic=None, votes=None):
    """The consensus row of `f` on `verdicts` (each family's verdict in both passes), challenged by a nemotron skeptic
    whose verdict stands unless `skeptic` says otherwise."""
    (row,) = scored_rows.score([f], votes if votes is not None else scored_rows.votes(f.id, verdicts), cfg=cfg,
                               skeptic=_skeptic(f.id) if skeptic is None else skeptic).rows
    return row


# ---------------------------------------------------------------- jury scoring


def test_found_by_two_families_and_confirmed_by_the_one_independent_judge_it_is_accepted():
    row = _row(_found_by(A, D), {N: "true_positive"})
    assert row.finder_corroborated and row.independent_judges == 1
    assert (row.jury_outcome, row.human_reasons, row.tier.value, row.weighted_score) == ("accepted", [], "B", 1.0)
    assert row.agreement_proxy is None, "one judge family: no agreement to measure, and none is asked for"


def test_with_the_setting_off_the_same_votes_leave_it_one_judge_short():
    row = _row(_found_by(A, D), {N: "true_positive"}, cfg=scored_rows.MOCK)
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"
    assert row.human_reasons == [INSUFFICIENT_INDEPENDENT_JUDGES]


@pytest.mark.parametrize("verdict", ["false_positive", "needs_human"])
def test_an_independent_judge_that_does_not_confirm_it_sends_it_to_a_human_and_never_drops_it(verdict):
    """Two families found it: one judge may not put it out. Scored with the finders' discounted votes, as the
    fallback did, a true positive from the independent judge against two false positives of the finders scored 0.5
    at tier D with no reason, which is dropped."""
    row = _row(_found_by(A, D), {N: verdict})
    assert not row.finder_corroborated
    assert row.jury_outcome == "needs_human" and INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


def test_an_independent_judge_that_says_a_human_must_decide_is_not_a_confirmation_at_any_accept_threshold():
    """A needs_human vote scores 0.5: with gate.accept_threshold at 0.5 the score alone would carry the finding."""
    low = ON.model_copy(update={"gate": ON.gate.model_copy(update={"accept_threshold": 0.5})})
    row = _row(_found_by(A, D), {N: "needs_human"}, cfg=low)
    assert row.weighted_score == 0.5 >= low.gate.accept_threshold
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"
    assert _row(_found_by(A, D), {N: "true_positive"}, cfg=low).finder_corroborated


def test_an_independent_judge_whose_two_passes_differ_sends_it_to_a_human():
    f = _found_by(A, D)
    forward, reverse = scored_rows.votes(f.id, {N: "true_positive"})
    row = _row(f, {}, votes=[forward, reverse.model_copy(update={"verdict": "false_positive"})])
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"


def test_an_independent_judge_with_one_pass_missing_sends_it_to_a_human():
    f = _found_by(A, D)
    row = _row(f, {}, votes=scored_rows.votes(f.id, {N: "true_positive"})[:1])
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"
    assert INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


def test_with_no_valid_vote_of_its_independent_judge_it_is_not_corroborated_at_any_accept_threshold():
    """No vote scores 0: with gate.accept_threshold at 0 nothing but the seat's own valid vote stands in the way."""
    zero = ON.model_copy(update={"gate": ON.gate.model_copy(update={"accept_threshold": 0.0})})
    row = _row(_found_by(A, D), {}, cfg=zero, votes=[])
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"
    assert INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


def test_a_vote_of_a_finders_family_in_its_score_leaves_it_short():
    """The ballot round asks none of them; a vote of one that is there all the same (a report scored again, a plan that
    changed) is not what corroboration rests on."""
    row = _row(_found_by(A, D), {N: "true_positive", A: "true_positive"})
    assert not row.finder_corroborated and INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


@pytest.mark.parametrize("why, skeptic", [
    ("refuted", _skeptic("F-1", verdict="refuted")),
    ("from a family that found it", _skeptic("F-1", family=A)),
    ("none", {}),
])
def test_without_a_skeptic_outside_its_finders_that_let_it_stand_it_goes_to_a_human(why, skeptic):
    row = _row(_found_by(A, D), {N: "true_positive"}, skeptic=skeptic)
    assert not row.finder_corroborated and row.jury_outcome == "needs_human", why


def test_a_weakened_verdict_of_the_skeptic_is_not_a_refutation():
    assert _row(_found_by(A, D), {N: "true_positive"}, skeptic=_skeptic("F-1", verdict="weakened")).finder_corroborated


def test_a_finding_the_skeptic_abstained_on_goes_to_a_human():
    from mara.ballot_round import Ballots

    f = _found_by(A, D)
    ballots = Ballots(skeptic=_skeptic(f.id), unchallenged=frozenset({f.id}), redteam={}, votes=scored_rows.votes(f.id, {N: "true_positive"}))
    (row,) = jury.score([f], ballots, [], jury=jury.Jury.from_config(ON), policy=scored_rows.policy(ON)).rows
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"


def test_found_by_every_judge_family_it_still_goes_to_a_human():
    row = _row(_found_by(A, D, N), {A: "true_positive", D: "true_positive", N: "true_positive"})
    assert not row.finder_corroborated and row.independent_judges == 0
    assert row.jury_outcome == "needs_human" and INSUFFICIENT_INDEPENDENT_JUDGES in row.human_reasons


def test_a_finding_one_family_found_is_judged_as_before():
    confirmed = _row(_found_by(A), {D: "true_positive", N: "true_positive"})
    one_judge = _row(_found_by(A), {N: "true_positive"})
    assert (confirmed.finder_corroborated, confirmed.jury_outcome) == (False, "accepted")
    assert (one_judge.finder_corroborated, one_judge.jury_outcome) == (False, "needs_human")


def test_where_enough_independent_judges_remain_the_quorum_is_the_ordinary_one():
    """A fourth judge family: found by two, two seats stay independent, the quorum's two. One of them voting false
    positive is then a split the jury reads as it always did, not a corroboration that failed."""
    four = _on(scored_rows.FOUR_JUDGE_PANEL)
    f = _found_by(A, D)
    both = _row(f, {N: "true_positive", M: "true_positive"}, cfg=four)
    assert (both.finder_corroborated, both.independent_judges, both.jury_outcome) == (False, 2, "accepted")
    one_voided = _row(f, {N: "true_positive"}, cfg=four)
    assert not one_voided.finder_corroborated and INSUFFICIENT_INDEPENDENT_JUDGES in one_voided.human_reasons, \
        "a voided second seat is not forgiven"


@pytest.mark.parametrize("finders, seats, quorum, enabled, expected", [
    (2, 1, 2, True, True), (3, 1, 2, True, True), (2, 2, 3, True, True),
    (2, 1, 2, False, False),  # the setting is off
    (1, 1, 2, True, False),   # one finder
    (2, 0, 2, True, False),   # no independent seat
    (2, 2, 2, True, False),   # the quorum is reachable as it is
])
def test_which_findings_may_reach_their_quorum_by_corroboration(finders, seats, quorum, enabled, expected):
    assert jury.corroborable(finders, seats, quorum, enabled) is expected


# ---------------------------------------------------------------- the ballot round


def _confirming(panel: Panel) -> Panel:
    return panel.always("judge", items(lambda _i: {"verdict": "true_positive", "severity_band": "High", "reason": "confirmed"}))


def test_the_ballot_round_asks_none_of_the_finders_families_to_judge_it(tmp_path):
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    f = _found_by(A, D)
    panel = _confirming(Panel(ON))
    ballots = panel.run(ctx, [f])
    assert panel.asked("judge", N) and panel.asked("judge", A) == [] and panel.asked("judge", D) == []
    assert panel.audit["self_family_fallback_votes"] == 0 and panel.audit["self_preference_exclusions"] == 2
    assert {v.judge_family for v in ballots.votes} == {N} and not any(v.self_family for v in ballots.votes)
    (row,) = jury.score([f], ballots, [], jury=jury.Jury.from_config(ON), policy=scored_rows.policy(ON)).rows
    assert ballots.skeptic[f.id].source_family == N, "the skeptic is the family outside its finders too"
    assert ballots.skeptic[f.id].verdict != "refuted", "the mock skeptic lets this finding stand: the row below is the corroborated one"
    assert row.finder_corroborated and row.jury_outcome == "accepted"


def test_a_voided_reply_of_the_independent_judge_sends_it_to_a_human(tmp_path):
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    f = _found_by(A, D)
    panel = Panel(ON).always("judge", REFUSAL, family=N)
    ballots = panel.run(ctx, [f])
    assert ballots.votes == [] and panel.asked("judge", A) == []
    (row,) = jury.score([f], ballots, [], jury=jury.Jury.from_config(ON), policy=scored_rows.policy(ON)).rows
    assert not row.finder_corroborated and row.jury_outcome == "needs_human"


def test_found_by_every_family_the_fallback_still_asks_them_at_a_discount(tmp_path):
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()\n"}, content_hash="h")
    panel = _confirming(Panel(ON))
    ballots = panel.run(ctx, [_found_by(A, D, N)])
    assert {v.judge_family for v in ballots.votes} == {A, D, N} and all(v.self_family for v in ballots.votes)
    assert panel.audit["self_family_fallback_votes"] == 3


# ---------------------------------------------------------------- a whole review


def test_a_review_of_the_seeded_fixture_accepts_what_two_families_found_and_one_confirmed_and_drops_nothing_for_it(tmp_path):
    def review(cfg: MaraConfig, out: str):
        pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / out)
        return pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock")

    mock = load_config(ROOT / "config" / "mara.mock.yaml", Workspace(ROOT))
    assert not mock.gate.finder_corroboration, "the mock config keeps the fallback, which its position-flip finding shows"
    off, on = review(mock, "off"), review(_on(mock), "on")
    finders = {f.id: len(f.finder_families) for f in on.findings}
    before = {c.finding_id: c for c in off.consensus}
    corroborated = [c for c in on.consensus if c.finder_corroborated]
    assert corroborated and on.bias_audit["finder_corroborated_quorums"] == len(corroborated)
    assert off.bias_audit["finder_corroborated_quorums"] == 0
    assert all(finders[c.finding_id] == 2 for c in corroborated)
    for c in on.consensus:
        was = before[c.finding_id].jury_outcome
        if c.finder_corroborated:
            # the quorum is met; what else sends a finding to a human (an unverified quote) still does
            assert was == "needs_human" and c.jury_outcome in ("accepted", "needs_human"), c.finding_id
            assert INSUFFICIENT_INDEPENDENT_JUDGES not in c.human_reasons
        elif finders[c.finding_id] == 2:
            assert c.jury_outcome == "needs_human", f"{c.finding_id}: found by two and not confirmed, it is neither accepted nor put out"
        else:
            assert c.jury_outcome == was, f"{c.finding_id}: a finding of one family or of all three is judged as before"
    assert sum(c.jury_outcome == "accepted" for c in on.consensus) > sum(c.jury_outcome == "accepted" for c in off.consensus)
    # the report says how such a finding met its quorum, on the finding itself
    from mara.report.markdown_out import render_markdown

    accepted = next(c for c in corroborated if c.final_outcome == "accepted")
    section = render_markdown(on).split(f"### {accepted.finding_id} ")[1].split("###")[0]
    assert "quorum by finder corroboration (1 independent judge(s))" in section
    assert "finder corroboration" not in render_markdown(off)
    assert len(on.human_queue) < len(off.human_queue)


# ---------------------------------------------------------------- the values the agreement proxy takes


@pytest.mark.parametrize("families, values", [(0, ()), (1, ()), (2, (0.25, 1.0)), (3, (0.0, 0.5, 1.0)), (4, (0.25, 0.625, 1.0))])
def test_the_agreement_proxy_takes_few_values(families, values):
    assert jury.attainable_agreement(families) == values
    if families >= 2:
        labels = ("true_positive", "false_positive", "needs_human")
        import itertools

        seen = set()
        for combo in itertools.product(labels, repeat=families):
            votes = [v for i, verdict in enumerate(combo) for v in scored_rows.votes("F-1", {list(ModelFamily)[i]: verdict})]
            seen.add(jury._agreement_proxy(votes))
        assert tuple(sorted(seen)) == values, "exactly the values the proxy gives over every way the families can vote"
