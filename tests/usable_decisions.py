"""Usable decisions, as mara.decisions holds them once selected against reviewed content (GLOSSARY.md: usable decision,
reviewed content, queue key): a decision bound to a finding's place in a reviewed content, under the queue key
mara.human_queue gives that place, and the selection of such decisions that `settle` and `finish` take. A decision
written by hand can hold a key no review writes."""

from __future__ import annotations

from mara.decisions import Decision, Selection
from mara.human_queue import queue_key
from mara.reviewed_content import ReviewedContent
from mara.schemas import Finding


def decision(f: Finding, verdict: str = "false_positive", *, content: ReviewedContent, by: str = "alice") -> Decision:
    """A decision `by` someone that `verdict` is the ruling on `f`, bound to `f`'s place in `content`."""
    p = f.provenance[0]
    return Decision(key=queue_key(p.file, p.line, f.cwe, content), target_id=content.target_id, revision=content.revision,
                    context_hash=content.content_hash, file=p.file, line=p.line, cwe=f.cwe, decision=verdict,
                    decision_event_id=1, decided_by=by, decided_at="2026-10-01T08:00:00Z", issue=7)


def usable(*decisions: Decision) -> Selection:
    """The selection in which all of `decisions` are usable."""
    return Selection(usable=list(decisions), excluded=[])
