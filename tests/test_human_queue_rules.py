"""mara.human_queue (GLOSSARY.md: human queue, human reason, queue tightening, usable decision): every human reason in
one vocabulary, the tightening as one value, and how usable decisions settle the findings they bind to."""

import itertools

from mara.decisions import Decision, Selection
from mara.human_queue import DECISION_NOT_USABLE, HUMAN_REASONS, UNSUPERVISED_REJECT_UNVERIFIED, queue_key, settle, tightening
from mara.schemas import EvidenceTier, QueueTightening
from mara.scoring.outcome import JURY_HUMAN_REASONS, OutcomeSignals, decide
from tests.scored_rows import MOCK, finding, policy, row

TARGET, REVISION, CONTEXT = "t" * 64, "r1", "c" * 64


def test_every_human_reason_is_the_jury_s_or_the_queue_s():
    assert HUMAN_REASONS == set(JURY_HUMAN_REASONS) | {UNSUPERVISED_REJECT_UNVERIFIED, DECISION_NOT_USABLE}
    assert len(JURY_HUMAN_REASONS) == len(set(JURY_HUMAN_REASONS))


def test_the_jury_writes_only_its_own_human_reasons_in_their_order_and_can_write_each():
    """Every combination of the signals decide() reads: the reasons it writes are JURY_HUMAN_REASONS in that order, and
    each of them is written by some combination, so the vocabulary is neither short nor padded."""
    written: set[str] = set()
    order = {r: i for i, r in enumerate(JURY_HUMAN_REASONS)}
    for (verified, refuted, abstained, quorum, passes, alpha, votes, consistent, tier, severity,
         excluded) in itertools.product((True, False), (True, False), (True, False), (True, False), (True, False),
                                        (None, 0.0, 1.0), ((2, 0, 0), (0, 0, 2), (0, 0, 0)), (True, False), list(EvidenceTier),
                                        ("High", "Low"), (True, False)):
        s = OutcomeSignals(tier=tier, score=0.9, severity=severity, provenance_verified=verified, skeptic_refuted=refuted,
                           skeptic_abstained=abstained, quorum_ok=quorum, passes_complete=passes, alpha=alpha, votes_tp=votes[0],
                           votes_fp=votes[1], votes_human=votes[2], position_consistent=consistent)
        reasons = decide(s, policy(exclude_tier_c=excluded)).reasons
        assert set(reasons) <= set(JURY_HUMAN_REASONS), reasons
        assert [order[r] for r in reasons] == sorted(order[r] for r in reasons), reasons
        written |= set(reasons)
    assert written == set(JURY_HUMAN_REASONS)


def test_the_tightening_is_one_value_and_the_report_records_it():
    base, step = MOCK.gate.human_threshold_alpha, MOCK.human_queue.tighten_alpha_step
    over = tightening(MOCK, MOCK.human_queue.backlog_limit + 1)
    assert over.tightened and over.backlog == MOCK.human_queue.backlog_limit + 1
    assert over.alpha_threshold == min(1.0, round(base + step, 4)) and over.exclude_tier_c == MOCK.human_queue.tighten_exclude_tier_c
    assert over.record() == QueueTightening(backlog=over.backlog, tightened=True, alpha_threshold=over.alpha_threshold)
    unknown = tightening(MOCK, None)
    assert unknown.record() == QueueTightening(backlog=None, tightened=False, alpha_threshold=base) and not unknown.exclude_tier_c
    high = MOCK.model_copy(update={"gate": MOCK.gate.model_copy(update={"human_threshold_alpha": 0.95})})
    assert tightening(high, 10_000).alpha_threshold == 1.0, "the agreement a finding needs never exceeds 1"
    off = MOCK.model_copy(update={"human_queue": MOCK.human_queue.model_copy(update={"enabled": False})})
    assert not tightening(off, 10_000).tightened, "a disabled queue never tightens"


def _decision(f, verdict="false_positive", *, by="alice", target_id=TARGET):
    p = f.provenance[0]
    return Decision(key=queue_key(p.file, p.line, f.cwe, target_id=target_id, revision=REVISION, context_hash=CONTEXT),
                    target_id=target_id, revision=REVISION, context_hash=CONTEXT, file=p.file, line=p.line, cwe=f.cwe,
                    decision=verdict, decision_event_id=1, decided_by=by, decided_at="2026-10-01T08:00:00Z", issue=7)


def _settle(rows, findings, selection):
    return settle(findings, rows, selection, target_id=TARGET, revision=REVISION, context_hash=CONTEXT)


def test_a_usable_decision_settles_its_finding_and_the_jury_outcome_stays():
    f, c = finding("F-1"), row("all_needs_human")
    d = _decision(f)
    assert _settle([c], [f], Selection(usable=[d], excluded=[])) == 1
    assert c.human_decision == {"decision": "false_positive", "key": d.key, "issue": 7, "decided_by": "alice",
                                "decided_at": "2026-10-01T08:00:00Z"}
    assert c.final_outcome == "rejected" and c.needs_human, "the jury outcome stays as the pipeline concluded it"


def test_a_decision_that_is_not_usable_says_why_on_a_finding_that_still_needs_a_human():
    f, waiting, decided = finding("F-1"), row("all_needs_human"), row("accepted")
    d = _decision(f, by="bob")
    assert _settle([waiting], [f], Selection(usable=[], excluded=[(d, "untrained")])) == 0
    assert waiting.human_decision is None and waiting.human_reasons[-1] == f"{DECISION_NOT_USABLE}:untrained"
    before = list(decided.human_reasons)
    _settle([decided], [f], Selection(usable=[], excluded=[(d, "untrained")]))
    assert decided.human_reasons == before, "a finding the jury decided needs no reason to wait"


def test_a_decision_on_other_content_settles_nothing_and_says_nothing():
    f, c = finding("F-1"), row("all_needs_human")
    before = list(c.human_reasons)
    other = _decision(f, target_id="o" * 64)
    assert _settle([c], [f], Selection(usable=[other], excluded=[(_decision(f), "unbound")])) == 0
    assert c.human_decision is None and c.human_reasons == before


def test_the_jury_outcome_runs_under_the_tightening_the_report_records(tmp_path, monkeypatch):
    """The report's record and the outcome policy come from one tightening; before the rework the record read the policy
    back, which is what kept a policy without the tightening from passing unnoticed."""
    import json

    from mara.pipeline import Pipeline

    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    (tmp_path / "calib" / "decisions").mkdir(parents=True)
    (tmp_path / "calib" / "decisions" / "backlog.json").write_text(json.dumps({"open": MOCK.human_queue.backlog_limit + 1}))
    pipe = Pipeline(MOCK, out_dir=tmp_path / "out")
    assert pipe.tightening.tightened and pipe.tightening.alpha_threshold > MOCK.gate.human_threshold_alpha
    assert pipe.outcome_policy.alpha_threshold == pipe.tightening.alpha_threshold
    assert pipe.outcome_policy.exclude_tier_c == pipe.tightening.exclude_tier_c
