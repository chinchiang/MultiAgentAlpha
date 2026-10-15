"""Reply accounting: every exchange's reply record turned into the review's audit counters (the report's bias_audit),
and the rule of which of them make a review incomplete (docs/adr/0008-reply-accounting.md).

Every counter is kept twice, in total and per model family (`name` and `name[family]`): `Audit.add` writes both,
so no call site can update one and forget the other. ROLES is the one table of what each role's records count and
under which persisted names; INCOMPLETE_COUNTERS, every counter any non-zero value of which marks the review
incomplete (fail closed), is derived from it.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from .exchange import EMPTY, ERROR, KINDS, REFUSAL, TRUNCATION, UNPARSEABLE

Role = Literal["reviewer", "context", "skeptic", "redteam", "judge"]


@dataclass(frozen=True)
class RoleCounters:
    """The persisted counter names of one role. An extraction role (reviewer, context) reads an empty reply as an
    abstention, counted with the refusals; a ballot role (skeptic, red team, judge) cannot abstain by saying nothing,
    so an empty reply is invalid output. `local` maps each of the role's own counts to (counter, whether a non-zero
    value makes the review incomplete). A role without canary counters carries no canary."""

    form: Literal["extraction", "ballot"]
    calls: str
    refusals: str
    truncations: str
    errors: str
    unparseable: str
    invalid: str
    canary_echoes: str | None = None
    canary_reports: str | None = None
    retries: str | None = None
    local: Mapping[str, tuple[str, bool]] = field(default_factory=dict)
    tokens: bool = False  # the ballot roles do not count their tokens

    def blocking(self) -> tuple[str, ...]:
        """This role's counters that make the review incomplete, in the order the review status lists them."""
        fixed = (self.refusals, self.truncations, self.errors, self.invalid, self.canary_echoes)
        return tuple(c for c in fixed if c) + tuple(name for name, blocks in self.local.values() if blocks)


def _ballot(role: str, *, canary: bool, local: Mapping[str, tuple[str, bool]]) -> RoleCounters:
    return RoleCounters(form="ballot", calls=f"{role}_calls", refusals=f"{role}_refusals", truncations=f"{role}_truncations",
                        errors=f"{role}_errors", unparseable=f"{role}_unparseable_replies", invalid=f"{role}_invalid_items",
                        canary_echoes=f"{role}_canary_echoes" if canary else None,
                        canary_reports=f"{role}_canary_reports" if canary else None, retries=f"{role}_retries",
                        local={"findings": (f"{role}_items", False), **local})


ROLES: Mapping[Role, RoleCounters] = {
    # the reviewers' counters keep the names they had before the other roles existed
    "reviewer": RoleCounters(form="extraction", calls="reviewer_calls", refusals="reviewer_refusals",
                             truncations="reviewer_truncations", errors="reviewer_errors",
                             unparseable="reviewer_unparseable_replies", invalid="invalid_findings_dropped",
                             canary_echoes="canary_echoes", canary_reports="canary_reports",
                             local={"unverified_quotes": ("findings_with_unverified_quotes", False)}, tokens=True),
    "context": RoleCounters(form="extraction", calls="context_calls", refusals="context_refusals",
                            truncations="context_truncations", errors="context_errors",
                            unparseable="context_unparseable_replies", invalid="context_invalid_items",
                            canary_echoes="context_canary_echoes", canary_reports="context_canary_reports",
                            local={"unverified": ("context_unverified_items", True)}, tokens=True),
    "skeptic": _ballot("skeptic", canary=True, local={"unverified_controls": ("skeptic_unverified_controls", False),
                                                      "refuted": ("skeptic_refuted", False)}),
    "redteam": _ballot("redteam", canary=True, local={"exploit_code_stripped": ("redteam_exploit_code_stripped", True)}),
    "judge": _ballot("judge", canary=False, local={}),
}

INCOMPLETE_COUNTERS = tuple(name for counters in ROLES.values() for name in counters.blocking())


@dataclass(frozen=True)
class ReplyRecord:
    """What one exchange's reply counts for: its role and family, the reply outcome kind (exchange.KINDS), its canary
    echoes and reports, the invalid items it held, whether it was voided as a whole, the role's own counts under the
    local names ROLES declares, its tokens, and detail codes only the log reads."""

    role: Role
    family: str
    kind: str
    canary_echoes: int = 0
    canary_reports: int = 0
    invalid_items: int = 0
    voided: bool = False
    counts: Mapping[str, int] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    details: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; one of {tuple(ROLES)}")
        if self.kind not in KINDS:
            raise ValueError(f"unknown reply outcome kind {self.kind!r}; one of {KINDS}")
        counters = ROLES[self.role]
        undeclared = sorted(set(self.counts) - set(counters.local))
        if undeclared:
            raise ValueError(f"{self.role} declares no count {', '.join(undeclared)}; its counts are {tuple(counters.local)}")
        if counters.canary_echoes is None and (self.canary_echoes or self.canary_reports):
            raise ValueError(f"{self.role} carries no canary")


def worth_retrying(rec: ReplyRecord) -> bool:
    """A ballot reply voided as malformed, cut off or not covering every finding exactly once is worth one more call.
    A refusal and a canary echo are signals, never retried; providers retry their own failures, and any other
    exception in a provider is a bug a second call would only repeat. The retry depends on whether the reply was
    well-formed, never on what it concluded."""
    return (ROLES[rec.role].form == "ballot" and rec.voided and rec.kind not in (REFUSAL, ERROR)
            and not rec.canary_echoes)


def _abstained(rec: ReplyRecord) -> bool:
    return rec.kind == REFUSAL or (rec.kind == EMPTY and ROLES[rec.role].form == "extraction")


def log_tags(rec: ReplyRecord) -> str:
    """The pipeline log's tags for one reply, as its counters read it ([REFUSED] for an abstention, ...)."""
    flags = ((_abstained(rec), "REFUSED"), (rec.kind == TRUNCATION, "TRUNCATED"), (rec.kind == ERROR, "PROVIDER ERROR"),
             (rec.canary_echoes, "CANARY ECHOED"), (rec.canary_reports, "CANARY REPORTED"))
    return "".join(f" [{tag}]" for on, tag in flags if on)


class Audit(defaultdict[str, Any]):
    """Counters (default 0) plus a few labels and nested tables."""

    def __init__(self) -> None:
        super().__init__(int)

    def add(self, key: str, family: str, n: int = 1) -> None:
        """Count `n` under `key`, in total and for `family`."""
        self[key] += n
        self[f"{key}[{family}]"] += n

    def record(self, rec: ReplyRecord) -> None:
        """Count one reply: the call, how its outcome kind counts for its role, its canary echoes and reports, its
        invalid items and its own counts. Every counter of the role is written, 0 when nothing was counted."""
        c, fam, kind = ROLES[rec.role], rec.family, rec.kind
        # an unparseable reply, and a ballot's empty one, is invalid output: one per reply
        # (docs/adr/0001-reply-outcome-accounting.md)
        invalid_reply = kind == UNPARSEABLE or (kind == EMPTY and c.form == "ballot")
        self.add(c.calls, fam)
        self.add(c.refusals, fam, int(_abstained(rec)))
        self.add(c.truncations, fam, int(kind == TRUNCATION))
        self.add(c.errors, fam, int(kind == ERROR))
        self.add(c.unparseable, fam, int(kind == UNPARSEABLE))
        self.add(c.invalid, fam, int(invalid_reply) + rec.invalid_items)
        if c.canary_echoes and c.canary_reports:
            self.add(c.canary_echoes, fam, rec.canary_echoes)
            self.add(c.canary_reports, fam, rec.canary_reports)
        for local, (name, _) in c.local.items():
            self.add(name, fam, rec.counts.get(local, 0))
        if c.tokens:
            self["input_tokens"] += rec.input_tokens
            self["output_tokens"] += rec.output_tokens

    def retried(self, rec: ReplyRecord) -> None:
        """Count a reply discarded for one more call (worth_retrying): only the answer used counts otherwise."""
        retries = ROLES[rec.role].retries
        if retries is None:
            raise ValueError(f"{rec.role} is never asked again")
        self.add(retries, rec.family)

    def incomplete_reasons(self) -> list[str]:
        """The counters of INCOMPLETE_COUNTERS that are non-zero, in that order. Every one of them is then present
        in the audit (0 when nothing was counted), so a report always shows the whole list."""
        return [k for k in INCOMPLETE_COUNTERS if self[k]]


def by_family(bias_audit: Mapping[str, Any]) -> dict[str, dict[str, float]]:
    """The per-family counters of a report's bias_audit, read back from `name[family]`: family -> name -> value.
    A key naming a pair of families (judge_agreement[a~b]) or holding no number is not one family's counter."""
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for k, v in bias_audit.items():
        name, sep, rest = k.partition("[")
        if sep and rest.endswith("]") and "[" not in rest and "~" not in rest and isinstance(v, (int, float)):
            out[rest[:-1]][name] = v
    return dict(out)
