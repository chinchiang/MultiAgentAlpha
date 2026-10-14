"""The jury outcome is decided in one place, from the signals scoring has computed and the policy in force
(docs/adr/0005-jury-outcome.md): accepted, rejected, dropped, or needing a human, with the reasons."""

import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.config import load_config  # noqa: E402
from mara.schemas import ConsensusResult, EvidenceTier  # noqa: E402
from mara.scoring.outcome import OutcomePolicy, OutcomeSignals, decide  # noqa: E402

POLICY = OutcomePolicy(accept_threshold=0.6, alpha_threshold=0.4, exclude_tier_c=False, tier_c_min_severity="High",
                       unsupervised_reject_allowed=False)

# a tier B finding three judge families confirmed in both passes: nothing about it needs a human
SUPPORTED = OutcomeSignals(tier=EvidenceTier.B, score=0.9, severity="High", provenance_verified=True, skeptic_refuted=False,
                           skeptic_abstained=False, quorum_ok=True, passes_complete=True, alpha=1.0, votes_tp=6, votes_fp=0,
                           votes_human=0, position_consistent=True)


def test_a_supported_finding_is_accepted_with_no_reasons():
    out = decide(SUPPORTED, POLICY)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("accepted", (), False)


def test_a_finding_with_evidence_the_jury_did_not_carry_is_rejected():
    allowed = replace(POLICY, unsupervised_reject_allowed=True)
    out = decide(replace(SUPPORTED, score=0.4, votes_tp=2, votes_fp=4), allowed)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("rejected", (), False)


def test_until_the_aat_passes_a_rejected_finding_goes_to_rejection_review_and_stays_rejected():
    out = decide(replace(SUPPORTED, score=0.4, votes_tp=2, votes_fp=4), POLICY)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("rejected", (), True)


def test_a_tier_d_finding_with_verified_provenance_is_dropped_and_not_sent_to_rejection_review():
    out = decide(replace(SUPPORTED, tier=EvidenceTier.D, score=0.3, votes_tp=1, votes_fp=5), POLICY)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("dropped", (), False)


def test_a_finding_whose_provenance_is_unverified_needs_a_human_not_dropped():
    out = decide(replace(SUPPORTED, tier=EvidenceTier.D, provenance_verified=False), POLICY)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("needs_human", ("unverified_provenance",), False)


@pytest.mark.parametrize("change, reason", [
    ({"skeptic_abstained": True}, "skeptic_abstained"),
    ({"quorum_ok": False}, "insufficient_independent_judges"),
    ({"passes_complete": False}, "invalid_or_incomplete_judge_passes"),
    ({"alpha": 0.39}, "agreement_below_threshold"),
    ({"votes_tp": 2, "votes_fp": 1, "votes_human": 3}, "majority_needs_human"),
    ({"position_consistent": False}, "position_inconsistent"),
])
def test_what_the_jury_could_not_settle_goes_to_a_human(change, reason):
    out = decide(replace(SUPPORTED, **change), POLICY)
    assert (out.value, out.reasons, out.unsupervised_reject_unverified) == ("needs_human", (reason,), False)


@pytest.mark.parametrize("severity", ["High", "Critical"])
def test_a_tier_c_finding_at_or_above_the_floor_goes_to_a_human(severity):
    out = decide(replace(SUPPORTED, tier=EvidenceTier.C, severity=severity), POLICY)
    assert (out.value, out.reasons) == ("needs_human", ("tier_c_high",))


def test_a_tier_c_finding_below_the_floor_or_while_the_queue_is_tightened_is_left_to_the_jury():
    assert decide(replace(SUPPORTED, tier=EvidenceTier.C, severity="Medium"), POLICY).value == "accepted"
    tightened = replace(POLICY, exclude_tier_c=True)
    assert decide(replace(SUPPORTED, tier=EvidenceTier.C, severity="Critical"), tightened).value == "accepted"


def test_a_refuted_finding_the_jury_carried_goes_to_a_human_and_one_it_did_not_is_dropped():
    carried = decide(replace(SUPPORTED, tier=EvidenceTier.A, skeptic_refuted=True), POLICY)
    assert (carried.value, carried.reasons) == ("needs_human", ("skeptic_refuted_jury_overrode",))
    not_carried = decide(replace(SUPPORTED, tier=EvidenceTier.D, skeptic_refuted=True, score=0.3), POLICY)
    assert (not_carried.value, not_carried.reasons) == ("dropped", ())


def test_the_thresholds_are_inclusive_and_an_undefined_agreement_or_no_vote_raises_nothing():
    assert decide(replace(SUPPORTED, score=0.6), POLICY).value == "accepted"
    assert decide(replace(SUPPORTED, alpha=0.4), POLICY).reasons == ()
    assert decide(replace(SUPPORTED, alpha=None), POLICY).reasons == ()
    unvoted = replace(SUPPORTED, score=0.0, votes_tp=0, position_consistent=False)
    assert decide(unvoted, POLICY).reasons == ()


def test_every_reason_that_applies_is_kept_in_order_and_a_finding_awaiting_a_human_is_not_under_rejection_review():
    s = replace(SUPPORTED, tier=EvidenceTier.D, provenance_verified=False, skeptic_abstained=True, quorum_ok=False, score=0.2)
    out = decide(s, POLICY)
    assert out.reasons == ("unverified_provenance", "skeptic_abstained", "insufficient_independent_judges")
    assert not out.unsupervised_reject_unverified


def test_a_tier_c_finding_of_unknown_severity_goes_to_a_human_even_under_the_highest_floor():
    out = decide(replace(SUPPORTED, tier=EvidenceTier.C, severity="unknown"), replace(POLICY, tier_c_min_severity="Critical"))
    assert out.reasons == ("tier_c_high",)


def test_the_policy_is_the_config_in_force_with_the_alpha_threshold_and_tier_c_exclusion_after_tightening():
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    cfg = cfg.model_copy(update={
        "gate": cfg.gate.model_copy(update={"accept_threshold": 0.7, "human_threshold_alpha": 0.3, "unsupervised_reject_allowed": True}),
        "human_queue": cfg.human_queue.model_copy(update={"queue_tier_c_min_severity": "Critical"}),
    })
    assert OutcomePolicy.from_config(cfg, alpha_threshold=0.5, exclude_tier_c=True) == OutcomePolicy(
        accept_threshold=0.7, alpha_threshold=0.5, exclude_tier_c=True, tier_c_min_severity="Critical",
        unsupervised_reject_allowed=True)



# ---------------------------------------------------------------- persisted in report.json and read back

def _row(tier: EvidenceTier, **fields) -> ConsensusResult:
    return ConsensusResult(finding_id="F-1", weighted_score=0.5, votes_tp=3, votes_fp=3, votes_human=0, families_agreeing=[],
                           tool_corroborated=False, skeptic_refuted=False, position_consistent=True, tier=tier, cvss4_score=7.5,
                           cvss4_severity="High", ssvc_decision="Attend", **fields)


ROUND_TRIP = {
    "accepted": (SUPPORTED, POLICY),
    "rejected": (replace(SUPPORTED, score=0.4), replace(POLICY, unsupervised_reject_allowed=True)),
    "rejected under rejection review": (replace(SUPPORTED, score=0.4), POLICY),
    "dropped": (replace(SUPPORTED, tier=EvidenceTier.D, score=0.3), POLICY),
    "dropped after the skeptic refuted it": (replace(SUPPORTED, tier=EvidenceTier.D, skeptic_refuted=True, score=0.3), POLICY),
    "needs a human, tier D": (replace(SUPPORTED, tier=EvidenceTier.D, provenance_verified=False), POLICY),
    "needs a human, tier C": (replace(SUPPORTED, tier=EvidenceTier.C), POLICY),
}


@pytest.mark.parametrize("case", ROUND_TRIP)
def test_the_jury_outcome_read_back_from_a_report_is_the_one_decided(case):
    signals, policy = ROUND_TRIP[case]
    out = decide(signals, policy)
    row = ConsensusResult.model_validate_json(_row(signals.tier, **out.consensus_fields()).model_dump_json())
    assert (row.jury_outcome, row.human_reasons, row.unsupervised_reject_unverified) == (
        out.value, list(out.reasons), out.unsupervised_reject_unverified)


def test_a_report_written_before_rejection_review_was_recorded_reads_as_not_under_review():
    old = _row(EvidenceTier.B, accepted=False).model_dump(exclude={"unsupervised_reject_unverified"})
    row = ConsensusResult.model_validate(old)
    assert (row.jury_outcome, row.unsupervised_reject_unverified) == ("rejected", False)
