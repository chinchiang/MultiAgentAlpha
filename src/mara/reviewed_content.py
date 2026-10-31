"""Reviewed content (GLOSSARY.md: reviewed content, queue key, bound decision): the exact target, revision and content
bundle one review examined, as one value. The pipeline takes it from the bundle; a report, a human queue item and a
decision record carry its three parts as fields of their own, and each is read back into it here. Decisions and human
queue items bind to it (docs/adr/0002-usable-decisions.md, docs/adr/0003-human-resolution.md). Pure.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .context.repo_map import RepoContext


@dataclass(frozen=True)
class ReviewedContent:
    """The target's id (a hash of its identity, mara.context.repo_map.target_identity), the revision and the bundle's
    content hash. A report keeps them as target_id, revision and coverage.content_hash; a human queue item and a
    decision record as target_id, revision and context_hash."""

    target_id: str
    revision: str
    content_hash: str

    @classmethod
    def of_bundle(cls, ctx: RepoContext) -> ReviewedContent:
        """What a review of the bundle `ctx` examines: its target named by repository and path below the top level
        for a committed git target (so CI, every clone and every calibration run name it the same way), its revision
        and its content hash."""
        return cls(hashlib.sha256(ctx.identity.encode()).hexdigest(), ctx.revision, ctx.content_hash)

    @classmethod
    def of_report(cls, report: Mapping) -> ReviewedContent | None:
        """The reviewed content of a review report read as JSON, or None when any of its three parts is missing, empty
        or not a string: such a report binds no decision."""
        parts = (report.get("target_id"), report.get("revision"), (report.get("coverage") or {}).get("content_hash"))
        if not all(isinstance(x, str) and x for x in parts):
            return None
        return cls(*parts)  # type: ignore[arg-type]

    @classmethod
    def of_record(cls, record: Mapping) -> ReviewedContent:
        """The reviewed content a human queue item or a decision record names, its parts as the record has them."""
        return cls(record.get("target_id") or "", record.get("revision") or "", record.get("context_hash") or "")

    @property
    def known(self) -> bool:
        """Whether every part is known. A queue key needs all three: without one it is the legacy key, which no
        decision is synced under."""
        return bool(self.target_id and self.revision and self.content_hash)
