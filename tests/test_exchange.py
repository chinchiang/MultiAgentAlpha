"""mara.exchange: one reply classification for every family (docs/adr/0001-reply-outcome-accounting.md), and what the
pipeline counts from it."""

import json
from pathlib import Path

import pytest

from mara import exchange
from mara.config import load_config
from mara.pipeline import Pipeline
from mara.providers.base import STOP_END, STOP_MAX_TOKENS, STOP_REFUSAL, Provider, RawReply

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = {"type": "object", "properties": {"note": {"type": "string", "maxLength": 5}}}


@pytest.mark.parametrize("raw,kind", [
    (RawReply(STOP_END, answer_text='{"note": "ok"}'), exchange.OK),
    (RawReply(STOP_END, answer_text='```json\n{"note": "ok"}\n```'), exchange.OK),       # one code fence, any family
    (RawReply(STOP_END, structured={"note": "ok"}), exchange.OK),                        # Bedrock tool call
    (RawReply(STOP_END, structured=["not", "an", "object"]), exchange.UNPARSEABLE),
    (RawReply(STOP_END, answer_text="Sure! {"), exchange.UNPARSEABLE),                    # ended normally, no answer
    (RawReply(STOP_END, answer_text="   "), exchange.EMPTY),
    (RawReply(STOP_END), exchange.EMPTY),
    (RawReply(STOP_MAX_TOKENS, answer_text='{"note": "o'), exchange.TRUNCATION),          # the output limit, even when it parses:
    (RawReply(STOP_MAX_TOKENS, answer_text='{"note": "ok"}'), exchange.TRUNCATION),       # the answer may be incomplete
    (RawReply(STOP_MAX_TOKENS), exchange.TRUNCATION),
    (RawReply(STOP_REFUSAL, answer_text="I can't help with that."), exchange.REFUSAL),
])
def test_one_classification_from_stop_reason_and_text(raw, kind):
    assert exchange.classify(raw, SCHEMA).kind == kind


def test_an_ok_reply_is_clipped_and_keeps_the_full_answer_and_every_text():
    o = exchange.classify(RawReply(STOP_END, answer_text='{"note": "too long"}', aside="prose", input_tokens=3, output_tokens=4,
                                   served_model="m-1"), SCHEMA)
    assert o.data == {"note": "too l"} and o.full_data == {"note": "too long"}
    assert "too long" in o.text and "prose" in o.text and o.aside == "prose"
    assert (o.input_tokens, o.output_tokens, o.served_model) == (3, 4, "m-1")
    with pytest.raises(ValueError):
        RawReply("stop")
    with pytest.raises(ValueError):
        exchange.Outcome("cut_off")


def test_extraction_roles_read_an_empty_reply_as_an_abstention_and_ballots_as_invalid():
    empty = exchange.classify(RawReply(STOP_END), SCHEMA)
    assert exchange.extraction_flags(empty) == {"refused": True, "truncated": False, "errored": False, "unparseable": False}
    assert exchange.parse_items(empty, dict) == ([], ["empty"])
    unparseable = exchange.classify(RawReply(STOP_END, answer_text="no"), SCHEMA)
    assert exchange.extraction_flags(unparseable)["unparseable"] and not exchange.extraction_flags(unparseable)["refused"]


class _BallotReply(Provider):
    """The wrapped mock provider, except that calls for `role` get `raw` back."""

    def __init__(self, inner, role, raw):
        super().__init__(inner.spec)
        self.inner, self.role, self.raw = inner, role, raw

    def bind_target(self, root):
        self.inner.bind_target(root)

    def complete(self, *, system, user, schema, role, max_tokens=16000):
        if role == self.role:
            return self.raw
        return self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)


def _run(tmp_path, role, raw):
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"),
                    out_dir=tmp_path / "out")
    pipe.providers = {n: _BallotReply(p, role, raw) for n, p in pipe.providers.items()}
    return pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")


@pytest.mark.parametrize("role", ["skeptic", "redteam", "judge"])
def test_a_truncated_ballot_is_a_truncation_not_invalid_output_and_still_blocks(tmp_path, role):
    """A ballot truncation used to reach parse_items as "empty": invalid output, charged to the model."""
    report = _run(tmp_path, role, RawReply(STOP_MAX_TOKENS, answer_text='{"items": ['))
    audit = report.bias_audit
    assert audit[f"{role}_truncations"] > 0 and audit.get(f"{role}_invalid_items", 0) == 0
    assert f"{role}_truncations" in report.incomplete_reasons and not report.gate_passed
    assert audit[f"{role}_retries"] > 0, "retried once, as before (the retry policy is unchanged)"
    assert audit["exchange_version"] == exchange.EXCHANGE_VERSION, "every report names its accounting"


def test_an_unparseable_ballot_is_invalid_output_with_its_own_count(tmp_path):
    report = _run(tmp_path, "skeptic", RawReply(STOP_END, answer_text="All findings look fine to me."))
    audit = report.bias_audit
    assert audit["skeptic_unparseable_replies"] > 0 and audit["skeptic_invalid_items"] == audit["skeptic_unparseable_replies"]
    assert audit.get("skeptic_truncations", 0) == 0 and "skeptic_invalid_items" in report.incomplete_reasons


def test_an_unparseable_reviewer_reply_keeps_the_run_incomplete(tmp_path):
    report = _run(tmp_path, "reviewer:vulnerabilities", RawReply(STOP_END, answer_text="Looks fine."))
    audit = report.bias_audit
    assert audit["reviewer_unparseable_replies"] > 0 and audit["invalid_findings_dropped"] >= audit["reviewer_unparseable_replies"]
    assert audit["reviewer_truncations"] == 0 and "invalid_findings_dropped" in report.incomplete_reasons


def test_calibration_trends_compare_only_one_exchange_version(tmp_path):
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import calibrate

    runs = [("s1", {"bias_audit": {"exchange_version": 2}}, [])]
    assert calibrate.exchange_version(runs) == 2
    assert calibrate.exchange_version([("s1", {"bias_audit": {}}, [])]) == 1, "reports without it are version 1"
    with pytest.raises(SystemExit, match="different exchange versions"):
        calibrate.exchange_version(runs + [("s2", {"bias_audit": {}}, [])])
    hist = tmp_path / "history.json"
    hist.write_text(json.dumps([{"date": "2026-10-08", "mode": "live", "global_alpha": 0.7, "judge_agreement": {}}]))
    calibrate.append_history(hist, "2026-10-20", "live", 0.65, {"a~b": 0.8}, version=2)
    rows = calibrate.load_history(hist)
    assert [r.get("exchange_version") for r in rows] == [None, 2]
    assert [r["date"] for r in calibrate.comparable_history(rows, 2)] == ["2026-10-20"]
    assert [r["date"] for r in calibrate.comparable_history(rows, 1)] == ["2026-10-08"]
