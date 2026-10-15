"""Reply records as the agents write them (mara.audit.ReplyRecord), for tests of what reads them: a record here states
only what an agent can produce (docs/adr/0008-reply-accounting.md). A reply of any kind but ok, or with a canary echo,
is voided; an ok ballot reply is voided only when it held invalid items or missed findings; a ballot record carries the
findings it was asked about, which the judge counts on its forward pass only. An error carries its provider code, and
every record the counts its agent writes on that path, 0 unless given."""

from __future__ import annotations

from mara.audit import ROLES, ReplyRecord, Role
from mara.exchange import ERROR, OK
from mara.schemas import PassId

PROVIDER_ERROR = "provider_http_error:503"  # what exchange.call gives a failed call

# the counts each agent writes on every reply (extraction) or on a reply it used (ballot), besides `findings`
_COUNTS: dict[Role, tuple[str, ...]] = {"reviewer": ("unverified_quotes",), "context": ("unverified",),
                                        "skeptic": ("unverified_controls", "refuted"), "redteam": ("exploit_code_stripped",), "judge": ()}


def _details(kind: str, fields: dict) -> tuple[str, ...]:
    return ((PROVIDER_ERROR,) if kind == ERROR else ()) + tuple(fields.pop("details", ()))


def extraction(role: Role, family: str, kind: str = OK, *, counts: dict[str, int] | None = None, **fields) -> ReplyRecord:
    """A reviewer's or the context agent's record."""
    if ROLES[role].form != "extraction":
        raise ValueError(f"{role} is a ballot role")
    voided = kind != OK or bool(fields.get("canary_echoes"))
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, details=_details(kind, fields),
                       counts={**dict.fromkeys(_COUNTS[role], 0), **(counts or {})}, **fields)


def ballot(role: Role, family: str, findings: int, kind: str = OK, *, missing: int = 0, pass_id: PassId = "forward",
           counts: dict[str, int] | None = None, **fields) -> ReplyRecord:
    """A skeptic's, red team's or judge's record for one call over `findings` findings. `missing`: the findings an ok
    reply ruled on not at all, each an invalid item that voids it."""
    if ROLES[role].form != "ballot":
        raise ValueError(f"{role} is an extraction role")
    if missing and kind != OK:
        raise ValueError("a reply without a list is not checked for coverage")
    voided = kind != OK or bool(fields.get("canary_echoes")) or bool(missing)
    asked = 0 if role == "judge" and pass_id == "reverse" else findings
    # the role's own counts are written only for a reply the agent used
    own = {} if voided else dict.fromkeys(_COUNTS[role], 0)
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, invalid_items=missing,
                       counts={"findings": asked, **own, **(counts or {})},
                       details=_details(kind, fields) + ("missing_verdict",) * missing, **fields)
