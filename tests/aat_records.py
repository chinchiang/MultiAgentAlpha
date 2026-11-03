"""The inputs of the Alternative Annotator Test (scripts/calibrate.py) as the tests build them: the run a calibration
read (one report's findings and consensus rows), the Decision an Adjudicator made on a finding, the posterior the
unsupervised labeller gave it, and the register that makes an Adjudicator trained (G-13). The rejected finding is the
Jury outcome that policy P8 unlocks (docs/adr/0005-jury-outcome.md); a Decision binds to a finding by its key
(docs/adr/0002-usable-decisions.md). Pure: each function returns a value and writes nothing."""

from __future__ import annotations

import datetime as dt

from mara.decisions import Decision, TrainingRequirement
from mara.human_queue import queue_key
from mara.reviewed_content import ReviewedContent
from mara.training import Record, Register
from tests import scored_rows


def aat_run(sample, findings, consensus=()):
    return (sample, {"target_id": "target-s9", "revision": "rev", "coverage": {"content_hash": "ctx"}, "findings": findings,
                     "consensus": list(consensus)}, [])


def aat_decision(file, line, cwe, decision, trained=True):
    return Decision.parse({"key": queue_key(file, line, cwe, ReviewedContent("target-s9", "rev", "ctx")),
                           "decision": decision, "file": file, "line": line, "cwe": cwe, "issue": line,
                           "decided_by": "alice" if trained else "mallory", "decided_at": "2026-10-01T08:00:00Z",
                           "target_id": "target-s9", "revision": "rev", "context_hash": "ctx", "decision_event_id": line})


def trained_register():
    """G-13: alice holds a valid adjudicator record; mallory has none."""
    alice = Record("alice", "adjudicator", "2026-09", dt.date(2026, 9, 1), dt.date(2027, 9, 1), None, "quiz", "quiz")
    return TrainingRequirement(required=True, register=Register("2026-09", 365, 0.8, [alice]))


def aat_posterior(sample, fid, argmax):
    p = [0.1, 0.1, 0.1]
    p[argmax] = 0.7
    return (sample, fid), p


def aat_finding(i, cwe="CWE-79"):
    return {"id": f"F-{i}", "cwe": cwe, "provenance": [{"file": "app.py", "line": i * 10}]}


def _row(i, state):
    """The consensus row jury scoring writes for F-i in `state` (tests/scored_rows.py), as report.json holds it."""
    return scored_rows.row(state, f"F-{i}").model_dump(mode="json")


def rejected_row(i):
    """A rejected finding, the rejection P8 unlocks: a tool corroborates it (tier A) and one of three independent judge
    families confirmed it. Only tier A can be rejected, and only with a fourth judge family on the mock panel
    (docs/adr/0005-jury-outcome.md)."""
    return _row(i, "rejected")


def accepted_row(i):
    return _row(i, "accepted")


def dropped_row(i):
    """A dropped finding: every family called it a false positive, so it is tier D, out on the evidence rather than the vote."""
    return _row(i, "dropped")
