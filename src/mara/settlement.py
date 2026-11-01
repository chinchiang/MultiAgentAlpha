"""Settlement (GLOSSARY.md: final outcome, blocking finding, usable decision, reviewed content, jury outcome): a review's
consensus rows are finished in one order. The usable decisions on the reviewed content settle the findings they bind
to (mara.human_queue.settle, docs/adr/0003-human-resolution.md), which gives each row its final outcome; then each
blocking finding's row records why it blocks (mara.review_status.blocking_reasons,
docs/adr/0007-review-status-and-gate.md), a reason that depends on the final outcome and so comes second. The jury
outcome of a row stays as the jury concluded it (docs/adr/0005-jury-outcome.md). Pure, except that finish() records the
decisions and the blocking reasons on the consensus rows it is given: the pipeline reads the decision files and writes
the audit.
"""

from __future__ import annotations

from .decisions import Selection
from .human_queue import settle
from .review_status import GatePolicy, blocking_reasons
from .reviewed_content import ReviewedContent
from .schemas import ConsensusResult, Finding
from .scoring.outcome import OutcomePolicy


def finish(findings: list[Finding], rows: list[ConsensusResult], selection: Selection, content: ReviewedContent, *,
           outcome_policy: OutcomePolicy, gate_policy: GatePolicy) -> int:
    """`rows`, the consensus rows of `findings` as jury scoring wrote them, finished: the usable decisions in
    `selection` settle the findings they bind to on `content`, then every row records why it blocks the gate under the
    policies, or none. Returns how many rows a decision was recorded on (two findings at one place count twice)."""
    applied = settle(findings, rows, selection, content)
    reasons = blocking_reasons(rows, outcome_policy, gate_policy)
    for c in rows:
        c.blocking_reason = reasons.get(c.finding_id)
    return applied
