"""Reply records as the agents write them (mara.audit.ReplyRecord), for tests of what reads them: a record here states
only what an agent can produce (docs/adr/0008-reply-accounting.md). A reply of any kind but ok, or with a canary echo,
is voided; an ok ballot reply is voided only when it held invalid items or missed findings; a ballot record carries the
findings it was asked about, which the judge counts on its forward pass only. An error carries its provider code, and
every record carries the counts its agent writes on that path, 0 unless given. A canary echo is never in a truncation or
an error, and a ballot's echo record holds nothing else: no invalid items, no canary reports."""

from __future__ import annotations

from mara.audit import ROLES, ReplyRecord, Role
from mara.exchange import ERROR, OK, TRUNCATION
from mara.schemas import PassId

PROVIDER_ERROR = "provider_http_error:503"  # what exchange.call gives a failed call

# the counts each agent writes on every reply (extraction) or on a reply it used (ballot), besides `findings`
_COUNTS: dict[Role, tuple[str, ...]] = {"reviewer": ("unverified_quotes",), "context": ("unverified",),
                                        "skeptic": ("unverified_controls", "refuted"), "redteam": ("exploit_code_stripped",), "judge": ()}


def _provider_code(kind: str) -> tuple[str, ...]:
    """The detail code exchange.call gives the reply: the provider's code for an error, none otherwise."""
    return (PROVIDER_ERROR,) if kind == ERROR else ()


def _check_echo(kind: str, fields: dict) -> None:
    # a truncation is never an echo (exchange.Canary), and a failed call has no text to echo
    if fields.get("canary_echoes") and kind in (TRUNCATION, ERROR):
        raise ValueError(f"a reply of kind {kind} carries no canary echo")


def extraction(role: Role, family: str, kind: str = OK, *, counts: dict[str, int] | None = None, details: tuple[str, ...] = (),
               **fields) -> ReplyRecord:
    """A reviewer's or the context agent's record."""
    if ROLES[role].form != "extraction":
        raise ValueError(f"{role} is a ballot role")
    _check_echo(kind, fields)
    voided = kind != OK or bool(fields.get("canary_echoes"))
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, details=_provider_code(kind) + details,
                       counts={**dict.fromkeys(_COUNTS[role], 0), **(counts or {})}, **fields)


def ballot(role: Role, family: str, findings: int, kind: str = OK, *, missing: int = 0, pass_id: PassId = "forward",
           counts: dict[str, int] | None = None, details: tuple[str, ...] = (), **fields) -> ReplyRecord:
    """A skeptic's, red team's or judge's record for one call over `findings` findings. `missing`: the findings an ok
    reply ruled on not at all, each an invalid item that voids it."""
    if ROLES[role].form != "ballot":
        raise ValueError(f"{role} is an extraction role")
    if missing and kind != OK:
        raise ValueError("a reply without a list is not checked for coverage")
    _check_echo(kind, fields)
    # the skeptic and red team stop at an echo, before the reports and the coverage check (agents.skeptic, agents.redteam)
    if fields.get("canary_echoes") and (missing or fields.get("canary_reports")):
        raise ValueError("a ballot's echo record holds no invalid items and no canary reports")
    voided = kind != OK or bool(fields.get("canary_echoes")) or bool(missing)
    asked = 0 if role == "judge" and pass_id == "reverse" else findings
    # the role's own counts are written only for a reply the agent used
    own = {} if voided else dict.fromkeys(_COUNTS[role], 0)
    return ReplyRecord(role=role, family=family, kind=kind, voided=voided, invalid_items=missing,
                       counts={"findings": asked, **own, **(counts or {})},
                       details=_provider_code(kind) + details + ("missing_verdict",) * missing, **fields)
