"""mara.audit: counters kept in total and per family by one call, every reply record counted by one table, and the
counters that make a review incomplete derived from it (docs/adr/0008-reply-accounting.md)."""

from pathlib import Path

import pytest

from mara import exchange
from mara.audit import INCOMPLETE_COUNTERS, ROLES, Audit, ReplyRecord, by_family, log_tags, worth_retrying
from mara.config import load_config
from mara.pipeline import Pipeline
from mara.providers.base import Provider
from tests.reply_records import ballot, extraction

ROOT = Path(__file__).resolve().parents[1]


def test_add_counts_total_and_family_and_the_incomplete_list_is_read_in_order():
    a = Audit()
    a.add("judge_refusals", "glm")
    a.add("judge_refusals", "gemini", 2)
    a.add("skeptic_errors", "glm", 0)
    assert (a["judge_refusals"], a["judge_refusals[glm]"], a["judge_refusals[gemini]"]) == (3, 1, 2)
    assert a.incomplete_reasons() == ["judge_refusals"]
    assert all(k in a for k in INCOMPLETE_COUNTERS), "every completeness counter is in the report, 0 or not"


# INCOMPLETE_COUNTERS as written by hand before it was derived from ROLES (EXCHANGE_VERSION 4)
_V4_INCOMPLETE_COUNTERS = (
    "reviewer_refusals", "reviewer_truncations", "reviewer_errors", "invalid_findings_dropped", "canary_echoes",
    "context_refusals", "context_truncations", "context_errors", "context_invalid_items", "context_unverified_items",
    "skeptic_refusals", "skeptic_truncations", "skeptic_errors", "skeptic_invalid_items", "skeptic_canary_echoes",
    "redteam_refusals", "redteam_truncations", "redteam_errors", "redteam_invalid_items", "redteam_canary_echoes",
    "redteam_exploit_code_stripped",
    "judge_refusals", "judge_truncations", "judge_errors", "judge_invalid_items",
)
CANARY_ROLES = tuple(role for role, counters in ROLES.items() if counters.canary)  # the roles whose prompt holds a canary


def _record(role, kind=exchange.OK, **fields):
    """A record of `role` as its agent writes it; a ballot's is over one finding (tests/reply_records.py)."""
    if ROLES[role].role_type == "ballot":
        return ballot(role, "glm", 1, kind, **fields)
    return extraction(role, "glm", kind, **fields)


@pytest.mark.parametrize("role", list(ROLES))
@pytest.mark.parametrize("kind", exchange.KINDS)
def test_every_reply_but_an_ok_one_makes_the_review_incomplete(role, kind):
    """The completeness rule used to be checked by a test reading pipeline.py as text."""
    a = Audit()
    a.record(_record(role, kind))
    assert bool(a.incomplete_reasons()) == (kind != exchange.OK), a.incomplete_reasons()
    assert all(k in a for k in INCOMPLETE_COUNTERS), "every completeness counter is in the report, 0 or not"


@pytest.mark.parametrize("role", CANARY_ROLES)
def test_a_canary_echo_makes_the_review_incomplete_and_a_report_does_not(role):
    echo, report = Audit(), Audit()
    echo.record(_record(role, canary_echoes=1))
    report.record(_record(role, canary_reports=1))
    assert len(echo.incomplete_reasons()) == 1 and not report.incomplete_reasons()


def test_a_count_the_table_does_not_declare_is_refused():
    with pytest.raises(ValueError, match="declares no count"):
        ReplyRecord(role="judge", family="glm", kind=exchange.OK, counts={"refuted": 1})
    with pytest.raises(ValueError, match="carries no canary"):
        ReplyRecord(role="judge", family="glm", kind=exchange.OK, canary_echoes=1)
    assert set(ROLES) - set(CANARY_ROLES) == {"judge"}, "a judge sees no bundle, so it gets no canary"



def test_a_count_is_read_by_a_name_the_table_declares():
    """The pipeline read the skeptic's and red team's own counts with dict.get, so a misspelt name read 0 unnoticed."""
    rec = ballot("skeptic", "glm", 2, counts={"refuted": 1})
    assert (rec.count("refuted"), rec.count("unverified_controls"), rec.count("findings")) == (1, 0, 2)
    assert ballot("skeptic", "glm", 2, exchange.UNPARSEABLE).count("refuted") == 0, "a voided reply wrote no counts of its own"
    with pytest.raises(ValueError, match="declares no count"):
        rec.count("unverified_control")

def test_only_the_extraction_roles_count_their_tokens():
    a = Audit()
    a.record(extraction("reviewer", "glm", input_tokens=5, output_tokens=2))
    a.record(extraction("context", "glm", exchange.TRUNCATION, input_tokens=3, output_tokens=1))
    a.record(ballot("judge", "glm", 1, input_tokens=7, output_tokens=7))
    assert (a["input_tokens"], a["output_tokens"]) == (8, 3), "a ballot role's tokens are not counted"

def test_the_incomplete_counters_are_the_old_ones_in_their_old_order_and_the_context_canary_echoes():
    assert set(INCOMPLETE_COUNTERS) == set(_V4_INCOMPLETE_COUNTERS) | {"context_canary_echoes"}
    assert len(INCOMPLETE_COUNTERS) == len(set(INCOMPLETE_COUNTERS))
    assert tuple(k for k in INCOMPLETE_COUNTERS if k in _V4_INCOMPLETE_COUNTERS) == _V4_INCOMPLETE_COUNTERS


def test_a_failed_call_is_never_invalid_output_and_never_retried():
    for code in ("provider_http_error:503", "provider_connection_failed", "provider_call_failed:KeyError"):
        assert exchange.is_provider_error(code)
        rec = ReplyRecord.of(exchange.Outcome(exchange.ERROR, error=code), "skeptic", "glm", voided=True, counts={"findings": 1})
        a = Audit()
        a.record(rec)
        assert (a["skeptic_errors"], a["skeptic_invalid_items"], rec.log_codes) == (1, 0, (code,))
        assert not worth_retrying(rec), "a bug in a provider would only repeat"
    assert not exchange.is_provider_error("invalid_item:missing")


class _FailRole(Provider):
    def __init__(self, inner, role, exc):
        super().__init__(inner.spec)
        self.inner, self.role, self.exc = inner, role, exc

    def bind_target(self, root):
        self.inner.bind_target(root)

    def complete(self, *, system, user, schema, role, max_tokens=16000):
        if role == self.role:
            raise self.exc
        return self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)


@pytest.mark.parametrize("role", ["skeptic", "redteam", "judge"])
@pytest.mark.parametrize("exc", [RuntimeError("provider_http_error:503"), KeyError("bug")])
def test_a_ballot_provider_failure_is_counted_as_an_error_and_blocks(tmp_path, role, exc):
    """Ballot provider failures used to be counted as the model's invalid items, and an unexpected exception
    (provider_call_failed:<type>) was retried."""
    pipe = Pipeline(load_config(ROOT / "config/mara.mock.yaml"), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"),
                    out_dir=tmp_path / "out")
    pipe.providers = {n: _FailRole(p, role, exc) for n, p in pipe.providers.items()}
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    audit = report.bias_audit
    assert audit[f"{role}_errors"] > 0 and audit[f"{role}_invalid_items"] == 0 and audit.get(f"{role}_retries", 0) == 0
    assert f"{role}_errors" in report.incomplete_reasons and not report.gate_passed


def test_a_voided_ballot_reply_is_worth_one_more_call_unless_refused_failed_or_echoed():
    """GLM as skeptic answered four verdicts for three findings on one call and exactly three on the next
    (2026-10-08). Refusals and canary echoes are signals; providers retry their own failures."""
    for role in ("skeptic", "redteam", "judge"):
        assert all(worth_retrying(ballot(role, "glm", 1, k)) for k in (exchange.TRUNCATION, exchange.UNPARSEABLE, exchange.EMPTY))
        assert worth_retrying(ballot(role, "glm", 1, missing=1)), "an ok reply that did not cover every finding"
        assert not any(worth_retrying(ballot(role, "glm", 1, k)) for k in (exchange.REFUSAL, exchange.ERROR))
        assert not worth_retrying(ballot(role, "glm", 1)), "a reply that was used"
    assert not worth_retrying(ballot("skeptic", "glm", 1, canary_echoes=1))
    assert not worth_retrying(extraction("reviewer", "glm", exchange.TRUNCATION)), "an extraction role is never asked again"
    a = Audit()
    a.retried(ballot("judge", "glm", 1, exchange.UNPARSEABLE))
    assert (a["judge_retries"], a["judge_retries[glm]"], a.incomplete_reasons()) == (1, 1, [])


def test_the_log_tags_say_what_the_record_counts():
    def tags(role, kind, **fields):
        return log_tags(_record(role, kind, **fields))

    assert tags("reviewer", exchange.OK) == ""
    assert tags("reviewer", exchange.EMPTY) == " [REFUSED]", "an extraction role abstains by saying nothing"
    assert tags("judge", exchange.EMPTY) == "", "a ballot cannot: invalid output, which the counters show"
    assert tags("skeptic", exchange.REFUSAL) == " [REFUSED]"
    assert tags("context", exchange.TRUNCATION) == " [TRUNCATED]"
    assert tags("redteam", exchange.ERROR) == " [PROVIDER ERROR]"
    assert tags("reviewer", exchange.OK, canary_echoes=1, canary_reports=1) == " [CANARY ECHOED] [CANARY REPORTED]"


def test_the_per_family_counters_are_read_back_from_their_names():
    a = Audit()
    a.add("judge_refusals", "glm", 2)
    a.add("judge_refusals", "gemini")
    a.record(extraction("context", "gemini", canary_echoes=1))
    a["judge_agreement[glm~gemini]"] = 0.5  # a pair of families, not one
    a["rollout_phase"] = "shadow"
    fams = by_family(dict(a))
    assert set(fams) == {"glm", "gemini"}
    assert fams["glm"] == {"judge_refusals": 2}
    assert fams["gemini"]["judge_refusals"] == 1 and fams["gemini"]["context_canary_echoes"] == 1
    assert "canary_echoes" not in fams["gemini"]
