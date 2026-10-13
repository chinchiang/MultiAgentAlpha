"""mara.audit: counters kept in total and per family by one call, and one list of the counters that make a review
incomplete (architecture review candidate 4)."""

import re
from pathlib import Path

import pytest

from mara import exchange
from mara.audit import INCOMPLETE_COUNTERS, Audit
from mara.config import load_config
from mara.pipeline import Pipeline, _count_invalid, _retryable
from mara.providers.base import Provider

ROOT = Path(__file__).resolve().parents[1]
FAILURE = re.compile(r"_(refusals|truncations|errors|invalid_items|canary_echoes)$")
NOT_BLOCKING = {"canary_reports"}  # reports are resistance, not failure


def test_add_counts_total_and_family_and_the_incomplete_list_is_read_in_order():
    a = Audit()
    a.add("judge_refusals", "glm")
    a.add("judge_refusals", "gemini", 2)
    a.add("skeptic_errors", "glm", 0)
    assert (a["judge_refusals"], a["judge_refusals[glm]"], a["judge_refusals[gemini]"]) == (3, 1, 2)
    assert a.incomplete_reasons() == ["judge_refusals"]
    assert all(k in a for k in INCOMPLETE_COUNTERS), "every completeness counter is in the report, 0 or not"


def test_every_failure_counter_the_pipeline_writes_makes_the_review_incomplete():
    """The completeness list used to be a hand-kept mirror of counter names written elsewhere: nothing ensured that
    a new counter was listed. Every counter written under a failure name, literally or as f"{role}_...", must be."""
    src = (ROOT / "src" / "mara" / "pipeline.py").read_text(encoding="utf-8")
    written = set(re.findall(r'(?:audit\.add\(|self\.audit\[)f?"([a-z_{}]+?)(?:\[\{fam\}\])?"', src))
    names = set()
    for w in written:
        if "{role}" in w:
            # the canary counters are written only for the roles that carry one: a judge sees no bundle (Q6)
            roles = ("skeptic", "redteam") if "canary" in w else ("skeptic", "redteam", "judge")
            names |= {w.replace("{role}", role) for role in roles}
        else:
            names.add(w)
    names |= {counter for _, counter in re.findall(r'\("(\w+)", "(\w+)"\)', src)}  # the (audit key, counter) tables of L1/L2
    failures = {n for n in names if FAILURE.search(n) and n not in NOT_BLOCKING}
    assert failures, "the scan found the counters"
    assert failures <= set(INCOMPLETE_COUNTERS), sorted(failures - set(INCOMPLETE_COUNTERS))
    assert {"skeptic_errors", "redteam_errors", "judge_errors", "reviewer_errors", "context_errors"} <= failures


def test_a_failed_call_is_never_invalid_output_and_never_retried():
    for code in ("provider_http_error:503", "provider_connection_failed", "provider_call_failed:KeyError"):
        assert exchange.is_provider_error(code)
        assert _count_invalid([code, "incomplete_or_duplicate_response"]) == 0
        assert not _retryable([code, "incomplete_or_duplicate_response"]), "a bug in a provider would only repeat"
    assert not exchange.is_provider_error("invalid_item:missing") and _count_invalid(["invalid_item:missing"]) == 1
    assert _retryable(["unparseable", "incomplete_or_duplicate_response"])


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
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    audit = report.bias_audit
    assert audit[f"{role}_errors"] > 0 and audit[f"{role}_invalid_items"] == 0 and audit.get(f"{role}_retries", 0) == 0
    assert f"{role}_errors" in report.incomplete_reasons and not report.gate_passed
