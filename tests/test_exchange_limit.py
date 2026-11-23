"""The exchange limit (GLOSSARY.md; mara.providers.budget, `limits.max_exchanges`): the exchanges one review may make.
A review whose context and reviewer calls would pass it makes none of them, and one that reaches it later has the
calls left refused where every call is made; either way the review is incomplete with `exchange_limit_reached`, no
finding is accepted or put out for want of a vote, and nothing counts as checked that was not."""

from __future__ import annotations

from pathlib import Path

import pytest

from mara.config import MaraConfig, load_config
from mara.pipeline import Pipeline
from mara.providers.base import STOP_END, Provider, RawReply
from mara.providers.budget import LIMIT_REACHED, ExchangeBudget, Limited
from mara.review_status import EXCHANGE_LIMIT_REACHED
from mara.workspace import Workspace  # noqa: E402
from tests.fake_panel import Panel

ROOT = Path(__file__).resolve().parents[1]
FIXTURE, SARIF = ROOT / "fixtures" / "vuln-sample", ROOT / "fixtures" / "vuln-sample-sarif"


def _cfg(limit: int | None) -> MaraConfig:
    cfg = load_config(ROOT / "config" / "mara.mock.yaml", Workspace(ROOT))
    return cfg.model_copy(update={"limits": cfg.limits.model_copy(update={"max_exchanges": limit})})


def _review(tmp_path, limit: int | None, out: str = "out"):
    pipe = Pipeline(_cfg(limit), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / out)
    panel = Panel.seated_in(pipe)  # records every exchange that reaches a model
    return pipe, panel, pipe.run(FIXTURE, sarif_dir=SARIF, provider_mode="mock")


def _calls(report) -> int:
    return sum(v for k, v in report.bias_audit.items() if k.endswith("_calls") and "[" not in k)


@pytest.fixture(scope="module")
def unlimited(tmp_path_factory):
    return _review(tmp_path_factory.mktemp("unlimited"), None)


def test_without_a_limit_a_review_is_as_it_was(unlimited):
    pipe, panel, report = unlimited
    assert pipe.budget.limit is None and not any(isinstance(p, Limited) for p in pipe.providers.values())
    assert EXCHANGE_LIMIT_REACHED not in report.incomplete_reasons and "exchanges_refused_at_limit" not in report.bias_audit
    assert len(panel.exchanges) == _calls(report) == 53, "the seeded fixture: 1 context, 33 reviewer and 19 ballot exchanges"


def test_a_limit_the_review_stays_within_changes_nothing(tmp_path, unlimited):
    _, _, base = unlimited
    pipe, panel, report = _review(tmp_path, 53)
    assert (pipe.budget.used, pipe.budget.refused, pipe.budget.left) == (53, 0, 0)
    assert report.incomplete_reasons == base.incomplete_reasons and EXCHANGE_LIMIT_REACHED not in report.incomplete_reasons
    assert [c.model_dump() for c in report.consensus] == [c.model_dump() for c in base.consensus]


@pytest.mark.parametrize("limit", [0, 1, 33])
def test_a_review_whose_context_and_reviewer_calls_would_pass_the_limit_makes_none_of_them(tmp_path, limit):
    """34 are needed: the fixture is one batch, so 1 context exchange and 11 dimensions x 3 reviewers. Asked in part, the
    round would have spent the limit on a review in which some reviewer never read some dimension."""
    pipe, panel, report = _review(tmp_path, limit)
    assert panel.exchanges == [] and pipe.budget.used == 0 and _calls(report) == 0
    assert report.review_status == "incomplete" and EXCHANGE_LIMIT_REACHED in report.incomplete_reasons
    assert "context_view_incomplete" not in report.incomplete_reasons, "no context call was made: the view did not fail"
    assert report.findings == [] and report.overall_score is None and not report.gate_passed
    assert any("the exchange limit is" in line for line in pipe.log)


def test_the_context_agent_is_counted_once_for_each_batch_like_the_reviewers(tmp_path, monkeypatch):
    """The context agent asks once for each batch of the bundle, as every reviewer does. Counted once in all, a bundle
    of three batches passed the check with 100 exchanges planned, the context agent took 3, and the last 2 reviewer
    exchanges were refused: the round was asked in part, at the cost of the 98 before them."""
    import mara.context.repo_map as repo_map
    from mara import reviewer_round
    from mara.context.repo_map import build_context

    monkeypatch.setattr(repo_map, "MAX_TOTAL_CHARS", 3000)
    cfg = _cfg(None)
    batches = sum(1 for _ in build_context(FIXTURE).batches())
    assert batches > 1, "the fixture must be more than one batch at this size for the test to mean anything"
    planned = reviewer_round.planned_exchanges(build_context(FIXTURE), cfg)
    assert planned == batches * (1 + len(cfg.dimensions) * len(cfg.roles.reviewers))

    pipe, panel, report = _review(tmp_path, planned - 1, "short")
    assert panel.exchanges == [] and EXCHANGE_LIMIT_REACHED in report.incomplete_reasons, "one exchange short: none is made"

    pipe, panel, report = _review(tmp_path, planned, "exact")
    asked = [ex.role for ex in panel.exchanges]
    assert asked.count("context") == batches and asked.count("reviewer") == planned - batches
    assert report.bias_audit["reviewer_errors"] == 0 and report.bias_audit["context_errors"] == 0, "the whole round was asked"


def test_a_review_that_reaches_the_limit_in_the_ballot_round_has_the_calls_left_refused_and_decides_nothing_for_it(tmp_path, unlimited):
    _, _, base = unlimited
    pipe, panel, report = _review(tmp_path, 40)  # the 34 context and reviewer exchanges, and 6 of the 19 ballot ones
    assert len(panel.exchanges) == 40 == pipe.budget.used, "not one call reached a model past the limit"
    assert pipe.budget.refused > 0 and report.bias_audit["exchanges_refused_at_limit"] == pipe.budget.refused
    assert report.review_status == "incomplete" and EXCHANGE_LIMIT_REACHED in report.incomplete_reasons
    assert [f.id for f in report.findings] == [f.id for f in base.findings], "the reviewer round was whole"
    before = {c.finding_id: c.jury_outcome for c in base.consensus}
    for c in report.consensus:
        # a finding short of votes needs a human; none is accepted, rejected or dropped that was not before
        assert c.jury_outcome in ("needs_human", before[c.finding_id]), c.finding_id
    assert sum(c.jury_outcome == "needs_human" for c in report.consensus) > sum(o == "needs_human" for o in before.values())
    assert not any(c.jury_outcome in ("dropped", "rejected") and before[c.finding_id] not in ("dropped", "rejected")
                   for c in report.consensus)


def test_a_refused_call_is_a_provider_error_that_is_not_asked_again(tmp_path):
    """The ballot round asks once more after a voided reply, never after an error: a refused call must not be retried
    against the same spent budget, and must not read as a refusal or an empty reply of the model."""
    pipe, panel, report = _review(tmp_path, 40)
    errors = sum(v for k, v in report.bias_audit.items() if k.endswith("_errors") and "[" not in k)
    retries = sum(v for k, v in report.bias_audit.items() if k.endswith("_retries") and "[" not in k)
    assert errors == pipe.budget.refused and retries == 0
    assert not any(v for k, v in report.bias_audit.items() if k.endswith("_refusals") and "[" not in k and k != "reviewer_refusals")


class _Counting(Provider):
    def __init__(self, spec):
        super().__init__(spec)
        self.calls = 0

    def complete(self, **kwargs):
        self.calls += 1
        self.served_models.add("served-1")
        return RawReply(STOP_END, answer_text="{}")


def test_a_provider_under_a_budget_is_refused_once_it_is_spent_and_is_otherwise_the_provider():
    spec = _cfg(None).models[0]
    inner, budget = _Counting(spec), ExchangeBudget(2)
    limited = Limited(inner, budget)
    ask = dict(system="s", user="u", schema={}, role="judge")
    assert limited.complete(**ask).stop == STOP_END and limited.complete(**ask).stop == STOP_END
    for _ in range(3):
        with pytest.raises(RuntimeError, match=f"^{LIMIT_REACHED}$"):
            limited.complete(**ask)
    assert (inner.calls, budget.used, budget.refused, budget.left) == (2, 2, 3, 0)
    assert (limited.spec, limited.family, limited.model) == (inner.spec, inner.family, inner.model)
    assert limited.served_models is inner.served_models and limited.served_models == {"served-1"}


def test_a_budget_says_what_it_still_covers():
    none, three = ExchangeBudget(None), ExchangeBudget(3)
    assert none.covers(10 ** 9) and none.left is None and none.take() and (none.used, none.refused) == (1, 0)
    assert three.covers(3) and not three.covers(4)
    assert three.take() and three.covers(2) and not three.covers(3) and three.left == 2
    assert not ExchangeBudget(0).covers(1) and ExchangeBudget(0).covers(0)


def test_the_limit_is_a_number_of_exchanges_or_none():
    assert _cfg(None).limits.max_exchanges is None
    raw = _cfg(None).model_dump(mode="json")
    for bad in (-1, "many", 1.5):
        raw["limits"] = {"max_exchanges": bad}
        with pytest.raises(ValueError, match="max_exchanges"):
            MaraConfig.model_validate(raw)
    raw["limits"] = {"max_exchanges": 0, "max_tokens": 1}
    with pytest.raises(ValueError, match="max_tokens"):
        MaraConfig.model_validate(raw)
