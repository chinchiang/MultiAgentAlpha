"""Reply records as the agents write them (mara.audit.ReplyRecord), for tests of what reads them: a record here states
only what an agent can produce (docs/adr/0008-reply-accounting.md). A reply of any kind but ok, or with a canary echo,
is voided; an ok ballot reply is voided only when it held invalid items or missed findings; a ballot record carries the
findings it was asked about, which the judge counts on its forward pass only."""

from __future__ import annotations

from mara.audit import ROLES, ReplyRecord
from mara.exchange import OK


def extraction(role: str, family: str, kind: str = OK, **fields) -> ReplyRecord:
    """A reviewer's or the context agent's record."""
    assert ROLES[role].form == "extraction", role
    voided = kind != OK or bool(fields.get("canary_echoes"))
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, **fields)  # type: ignore[arg-type]


def ballot(role: str, family: str, findings: int, kind: str = OK, *, missing: int = 0, pass_id: str = "forward",
           counts: dict[str, int] | None = None, **fields) -> ReplyRecord:
    """A skeptic's, red team's or judge's record for one call over `findings` findings. `missing`: the findings an ok
    reply ruled on not at all, each an invalid item that voids it."""
    assert ROLES[role].form == "ballot", role
    assert kind == OK or not missing, "a reply without a list is not checked for coverage"
    voided = kind != OK or bool(fields.get("canary_echoes")) or bool(missing)
    asked = 0 if role == "judge" and pass_id == "reverse" else findings
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, invalid_items=missing,  # type: ignore[arg-type]
                       counts={"findings": asked, **(counts or {})}, details=("missing_verdict",) * missing, **fields)
