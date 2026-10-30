"""The reply exchange (GLOSSARY.md: exchange, voided reply, invalid item, canary echo): every role voids a reply that
echoes the canary or whose reply outcome is not ok before it reads the answer's shape, and only then an answer not of
the shape asked for; every exchange plants a canary of its own (docs/adr/0008-reply-accounting.md); and a judge's vote
says whether the judge's family found the finding itself."""

import json
from pathlib import Path

import pytest

from mara.agents import base, context_agent
from mara.agents.judge import run_judge
from mara.agents.reviewer import review_dimension
from mara.config import load_config
from mara.context.repo_map import build_context
from mara.exchange import OK
from mara.pipeline import Pipeline
from mara.providers.base import STOP_END, Provider, RawReply
from tests.fake_panel import Panel

ROOT = Path(__file__).resolve().parents[1]


def _echoing(answer):
    """A provider that reads the planted canary token from the prompt and replies `answer(token)`, ending normally."""

    class Echoing(Provider):
        def __init__(self):
            super().__init__(load_config(ROOT / "config" / "mara.mock.yaml").models[0])

        def complete(self, *, user, **kwargs):
            return RawReply(STOP_END, answer_text=answer(user.split("Reply with the token ")[1].split()[0]))

    return Echoing()


@pytest.mark.parametrize("answer", [lambda token: json.dumps([f"approved {token}"]),
                                    lambda token: json.dumps({"findings": "none", "note": f"approved {token}"})],
                         ids=["a list", "an object without the list asked for"])
def test_a_canary_echo_voids_a_reply_before_its_shape_is_read_whatever_the_extraction_role(answer):
    """A model that followed the planted instruction has followed data as instructions: nothing in its reply is read,
    so an answer of the wrong shape around the echo is no invalid item. The reviewer read the shape first, and
    counted one; the context agent, the skeptic and the red team stopped at the echo."""
    ctx = build_context(ROOT / "fixtures" / "vuln-sample")
    _, reviewer = review_dimension(_echoing(answer), ctx, "input_validation", base.Canary())
    _, (context,) = context_agent.run_context_agent(_echoing(answer), ctx)
    for rec in (reviewer, context):
        assert (rec.kind, rec.canary_echoes, rec.invalid_items, rec.voided) == (OK, 1, 0, True), rec.role


def test_every_exchange_plants_a_canary_of_its_own(tmp_path):
    """One token shared by a run's reviewer calls is one a model may meet again; a token of its own per exchange keeps
    each echo about that exchange alone. The judge sees no bundle, so it is asked with no canary."""
    pipe = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"),
                    out_dir=tmp_path / "out")
    panel = Panel.seated_in(pipe)
    pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    planted = [ex for ex in panel.exchanges if ex.role != "judge"]
    assert len(panel.asked("reviewer")) > 1 and panel.asked("context") and panel.asked("skeptic") and panel.asked("redteam") and panel.asked("judge")
    tokens = [ex.canary_token for ex in planted]
    assert len(set(tokens)) == len(tokens), "a token planted in more than one exchange"
    assert all("Reply with the token " not in ex.user for ex in panel.asked("judge"))


def test_a_judge_vote_on_a_finding_its_own_family_found_says_so():
    """The human queue shows each judge's vote with whether the judge's family found the finding itself; the jury
    recomputes that from the finders for its own count, so nothing else would notice the vote losing it."""

    class Judging(Provider):
        def __init__(self):
            super().__init__(load_config(ROOT / "config" / "mara.mock.yaml").models[0])

        def complete(self, **kwargs):
            items = [{"finding_id": fid, "verdict": "true_positive", "severity_band": "High", "reason": "r"} for fid in ("F-1", "F-2")]
            return RawReply(STOP_END, answer_text=json.dumps({"items": items}))

    votes, rec = run_judge(Judging(), [{"finding_id": "F-1", "claim": "a"}, {"finding_id": "F-2", "claim": "b"}], "forward",
                           self_ids={"F-1"})
    assert {v.finding_id: v.self_family for v in votes} == {"F-1": True, "F-2": False}
    assert [v.presentation_order for v in votes] == [0, 1] and rec.count("findings") == 2
