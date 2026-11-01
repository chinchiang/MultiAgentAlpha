"""Reply accounting: every exchange's reply record turned into the review's audit counters (the report's bias_audit),
and the rule of which of them make a review incomplete (docs/adr/0008-reply-accounting.md).

Every counter is kept twice, in total and per model family (`name` and `name[family]`): `Audit.add` writes both,
so no call site can update one and forget the other. ROLES is the one table of what each role's records count and
under which persisted names; INCOMPLETE_COUNTERS, every counter any non-zero value of which marks the review
incomplete (fail closed), is derived from it.

The audit holds every name a report's `bias_audit` carries, no other: those of ROLES and the members of `Count`
(COUNTER_NAMES). A name has one shape, a plain number, a number per model family (`name[family]`), per pair of
families (`name[a~b]`) or per reason (`name[why]`); `Audit` writes each through the entry of its shape and refuses a
name it does not hold, on a write and on a read, and the module reads a report's `bias_audit` back by name (`read`,
`by_family`, `by_pair`, `by_reason`, `alpha`). A report written before a counter existed reads 0 for it. The names a
report holds do not change (docs/adr/0008-reply-accounting.md).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal, TypeGuard

from .exchange import EMPTY, ERROR, KINDS, REFUSAL, TRUNCATION, UNPARSEABLE, Kind, Outcome

Role = Literal["reviewer", "context", "skeptic", "redteam", "judge"]


@dataclass(frozen=True)
class CanaryCounters:
    """A role's canary counters: an echo makes the review incomplete, a report does not."""

    echoes: str
    reports: str


@dataclass(frozen=True)
class RoleCounters:
    """The persisted counter names of one role. An extraction role (reviewer, context) reads an empty reply as an
    abstention, counted with the refusals; a ballot role (skeptic, red team, judge) cannot abstain by saying nothing,
    so an empty reply is invalid output. `local` maps each of the role's own counts to (counter, whether a non-zero
    value makes the review incomplete). A role without canary counters carries no canary."""

    role_type: Literal["extraction", "ballot"]
    calls: str
    refusals: str
    truncations: str
    errors: str
    unparseable: str
    invalid: str
    canary: CanaryCounters | None = None
    retries: str | None = None
    local: Mapping[str, tuple[str, bool]] = field(default_factory=dict)
    tokens: bool = False  # the ballot roles do not count their tokens

    def names(self) -> tuple[str, ...]:
        """Every persisted name of this role, whether or not it makes the review incomplete."""
        fixed = (self.calls, self.refusals, self.truncations, self.errors, self.unparseable, self.invalid, self.retries)
        canary = (self.canary.echoes, self.canary.reports) if self.canary else ()
        return tuple(n for n in fixed if n) + canary + tuple(name for name, _ in self.local.values())

    def incomplete_counters(self) -> tuple[str, ...]:
        """This role's counters that make the review incomplete, in the order the review status lists them."""
        fixed = (self.refusals, self.truncations, self.errors, self.invalid, self.canary.echoes if self.canary else None)
        return tuple(c for c in fixed if c) + tuple(name for name, makes_incomplete in self.local.values() if makes_incomplete)


def _ballot(role: str, *, canary: bool, local: Mapping[str, tuple[str, bool]]) -> RoleCounters:
    return RoleCounters(role_type="ballot", calls=f"{role}_calls", refusals=f"{role}_refusals", truncations=f"{role}_truncations",
                        errors=f"{role}_errors", unparseable=f"{role}_unparseable_replies", invalid=f"{role}_invalid_items",
                        canary=CanaryCounters(f"{role}_canary_echoes", f"{role}_canary_reports") if canary else None,
                        retries=f"{role}_retries",
                        local={"findings": (f"{role}_items", False), **local})


ROLES: Mapping[Role, RoleCounters] = {
    # the reviewers' counters keep the names they had before the other roles existed
    "reviewer": RoleCounters(role_type="extraction", calls="reviewer_calls", refusals="reviewer_refusals",
                             truncations="reviewer_truncations", errors="reviewer_errors",
                             unparseable="reviewer_unparseable_replies", invalid="invalid_findings_dropped",
                             canary=CanaryCounters("canary_echoes", "canary_reports"),
                             local={"unverified_quotes": ("findings_with_unverified_quotes", False)}, tokens=True),
    "context": RoleCounters(role_type="extraction", calls="context_calls", refusals="context_refusals",
                            truncations="context_truncations", errors="context_errors",
                            unparseable="context_unparseable_replies", invalid="context_invalid_items",
                            canary=CanaryCounters("context_canary_echoes", "context_canary_reports"),
                            local={"unverified": ("context_unverified_items", True)}, tokens=True),
    "skeptic": _ballot("skeptic", canary=True, local={"unverified_controls": ("skeptic_unverified_controls", False),
                                                      "refuted": ("skeptic_refuted", False)}),
    "redteam": _ballot("redteam", canary=True, local={"exploit_code_stripped": ("redteam_exploit_code_stripped", True)}),
    "judge": _ballot("judge", canary=False, local={}),
}

INCOMPLETE_COUNTERS = tuple(name for counters in ROLES.values() for name in counters.incomplete_counters())


class Count(StrEnum):
    """The persisted names of the audit that are not a role's: the value of each member is the name a report holds."""

    BUNDLE_FILES_CHANGED = "bundle_files_changed"
    BUNDLE_FILES_RELATED = "bundle_files_related"
    CONTEXT_VIEW_ITEMS = "context_view_items"
    EXCHANGE_VERSION = "exchange_version"
    FINDINGS_DEDUPED = "findings_deduped"
    FINDINGS_RAW = "findings_raw"
    GLOBAL_KRIPPENDORFF_ALPHA = "global_krippendorff_alpha"  # a number, or "n/a" when the jury had none
    HUMAN_DECISIONS_APPLIED = "human_decisions_applied"
    HUMAN_DECISIONS_NOT_USABLE = "human_decisions_not_usable"  # per reason: human_decisions_not_usable[<why>]
    INPUT_TOKENS = "input_tokens"
    JUDGE_AGREEMENT = "judge_agreement"  # per pair of families: judge_agreement[a~b]
    OUTPUT_TOKENS = "output_tokens"
    POSITION_FLIPS = "position_flips"
    REDTEAM_SAME_FAMILY = "redteam_same_family"
    SECRET_PREFLIGHT_CALIBRATION_EXEMPTED = "secret_preflight_calibration_exempted"
    SELF_FAMILY_FALLBACK_VOTES = "self_family_fallback_votes"
    SELF_PREFERENCE_EXCLUSIONS = "self_preference_exclusions"
    SKEPTIC_SAME_FAMILY = "skeptic_same_family"
    STANDARD_REFS_STRIPPED = "standard_refs_stripped"
    TIER_C_BLOCKED_WHILE_TIGHTENED = "tier_c_blocked_while_tightened"
    UNKNOWN_CWE = "unknown_cwe"


PAIR_COUNTS = frozenset({Count.JUDGE_AGREEMENT})
REASON_COUNTS = frozenset({Count.HUMAN_DECISIONS_NOT_USABLE})
ROLE_COUNTERS = tuple(name for counters in ROLES.values() for name in counters.names())  # per model family
PLAIN_COUNTS = frozenset(Count) - PAIR_COUNTS - REASON_COUNTS - {Count.GLOBAL_KRIPPENDORFF_ALPHA}
COUNTER_NAMES = ROLE_COUNTERS + tuple(str(m) for m in Count)  # every name a report's bias_audit holds
_HELD = frozenset(COUNTER_NAMES)


def _held(name: str) -> str:
    """`name` when the audit holds it (a key `name[...]` is held when its name is), else KeyError."""
    if str(name).partition("[")[0] not in _HELD:
        raise KeyError(f"the audit holds no counter {str(name).partition('[')[0]!r}")
    return str(name)


def _shaped(name: str, shapes: frozenset[Count], shape: str) -> str:
    if name not in shapes:
        raise ValueError(f"{name} is not {shape}")
    return str(name)


def _number(v: Any) -> TypeGuard[int | float]:
    return isinstance(v, int | float) and not isinstance(v, bool)


@dataclass(frozen=True)
class ReplyRecord:
    """What one exchange's reply counts for: its role and family, the reply outcome kind (exchange.KINDS), its canary
    echoes and reports, the invalid items it held, whether it was voided as a whole, the role's own counts under the
    local names ROLES declares, its tokens, and log codes only the log reads."""

    role: Role
    family: str
    kind: Kind
    canary_echoes: int = 0
    canary_reports: int = 0
    invalid_items: int = 0
    voided: bool = False
    counts: Mapping[str, int] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    log_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role!r}; one of {tuple(ROLES)}")
        if self.kind not in KINDS:
            raise ValueError(f"unknown reply outcome kind {self.kind!r}; one of {KINDS}")
        counters = ROLES[self.role]
        undeclared = sorted(set(self.counts) - set(counters.local))
        if undeclared:
            raise ValueError(f"{self.role} declares no count {', '.join(undeclared)}; its counts are {tuple(counters.local)}")
        if counters.canary is None and (self.canary_echoes or self.canary_reports):
            raise ValueError(f"{self.role} carries no canary")

    def count(self, local: str) -> int:
        """The role's own count under a local name ROLES declares for it, 0 when the reply did not write it (a voided
        ballot reply writes only its findings); a name the table does not declare is an error, not 0."""
        if local not in ROLES[self.role].local:
            raise ValueError(f"{self.role} declares no count {local}; its counts are {tuple(ROLES[self.role].local)}")
        return self.counts.get(local, 0)

    @classmethod
    def of(cls, outcome: Outcome, role: Role, family: str, *, log_codes: tuple[str, ...] = (), **fields: Any) -> ReplyRecord:
        """The record of one classified reply: its kind, tokens and provider error code come from the outcome, the
        rest from `fields`."""
        return cls(role=role, family=family, kind=outcome.kind, input_tokens=outcome.input_tokens,
                   output_tokens=outcome.output_tokens, log_codes=((outcome.error,) if outcome.error else ()) + log_codes, **fields)


def worth_retrying(rec: ReplyRecord) -> bool:
    """A ballot reply voided as unparseable, empty, cut off, holding invalid items or not covering every finding exactly
    once is worth one more exchange.
    A refusal and a canary echo are signals, never retried; providers retry their own failures, and any other
    exception in a provider is a bug a second call would only repeat. The retry depends on whether the reply was
    well-formed, never on what it concluded."""
    return (ROLES[rec.role].role_type == "ballot" and rec.voided and rec.kind not in (REFUSAL, ERROR)
            and not rec.canary_echoes)


def _abstained(rec: ReplyRecord) -> bool:
    return rec.kind == REFUSAL or (rec.kind == EMPTY and ROLES[rec.role].role_type == "extraction")


def log_tags(*records: ReplyRecord) -> str:
    """The pipeline log's tags for one or more replies, as their counters read them: [REFUSED] when any abstained, ..."""
    flags = ((any(_abstained(r) for r in records), "REFUSED"), (any(r.kind == TRUNCATION for r in records), "TRUNCATED"),
             (any(r.kind == ERROR for r in records), "PROVIDER ERROR"), (any(r.canary_echoes for r in records), "CANARY ECHOED"),
             (any(r.canary_reports for r in records), "CANARY REPORTED"))
    return "".join(f" [{tag}]" for on, tag in flags if on)


class Audit(defaultdict[str, Any]):
    """The counters of a review (default 0), written through the entry of each name's shape: `add` (a role's counter, in
    total and per family), `set` and `count` (a plain number), `set_reason`, `set_pair`, `set_alpha`. A key whose name
    the audit does not hold is refused, on a write and on a read (COUNTER_NAMES)."""

    def __init__(self) -> None:
        super().__init__(int)

    def __setitem__(self, key: str, value: Any) -> None:
        # a read of a key not there stores the default (0) through this method, so a name not held is refused on a read too
        super().__setitem__(_held(key), value)

    def add(self, key: str, family: str, n: int = 1) -> None:
        """Count `n` under `key`, in total and for `family`."""
        self[key] += n
        self[f"{key}[{family}]"] += n

    def set(self, name: str, value: float) -> None:
        """Set a plain number (a member of Count that is neither per pair nor per reason nor the alpha)."""
        self[_shaped(name, PLAIN_COUNTS, "a plain count")] = value

    def count(self, name: str, n: int = 1) -> None:
        """Count `n` more under a plain name."""
        self[_shaped(name, PLAIN_COUNTS, "a plain count")] += n

    def set_reason(self, name: str, reason: str, n: int) -> None:
        """Set the count of one reason of a name that counts by reason."""
        self[f"{_shaped(name, REASON_COUNTS, 'a count by reason')}[{reason}]"] = n

    def set_pair(self, name: str, pair: str, value: float) -> None:
        """Set the value of one pair of families (`a~b`) of a name that is read by pair."""
        self[f"{_shaped(name, PAIR_COUNTS, 'a value by pair of families')}[{pair}]"] = value

    def set_alpha(self, alpha: float | None) -> None:
        """Set the jury's global alpha; without one, "n/a", as reports have always held it."""
        self[Count.GLOBAL_KRIPPENDORFF_ALPHA] = "n/a" if alpha is None else alpha

    def record(self, rec: ReplyRecord) -> None:
        """Count one reply: its exchange, how its outcome kind counts for its role, its canary echoes and reports, its
        invalid items and its own counts. Every counter of the role is written, 0 when nothing was counted."""
        c, fam, kind = ROLES[rec.role], rec.family, rec.kind
        # an unparseable reply, and a ballot's empty one, is invalid output: one per reply
        # (docs/adr/0001-reply-outcome-accounting.md)
        invalid_reply = kind == UNPARSEABLE or (kind == EMPTY and c.role_type == "ballot")
        self.add(c.calls, fam)
        self.add(c.refusals, fam, int(_abstained(rec)))
        self.add(c.truncations, fam, int(kind == TRUNCATION))
        self.add(c.errors, fam, int(kind == ERROR))
        self.add(c.unparseable, fam, int(kind == UNPARSEABLE))
        self.add(c.invalid, fam, int(invalid_reply) + rec.invalid_items)
        if c.canary:
            self.add(c.canary.echoes, fam, rec.canary_echoes)
            self.add(c.canary.reports, fam, rec.canary_reports)
        for local, (name, _) in c.local.items():
            self.add(name, fam, rec.counts.get(local, 0))
        if c.tokens:
            self[Count.INPUT_TOKENS] += rec.input_tokens
            self[Count.OUTPUT_TOKENS] += rec.output_tokens

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


def read(bias_audit: Mapping[str, Any], name: str) -> float:
    """A report's count under `name`; 0 for a report written before the counter existed or holding no number there. A
    name the audit does not hold is an error, not 0."""
    v = bias_audit.get(_held(name), 0)
    return v if _number(v) else 0


def by_family(bias_audit: Mapping[str, Any]) -> dict[str, dict[str, float]]:
    """The per-family counters of a report's bias_audit, read back from `name[family]`: family -> name -> value.
    A key naming a pair of families (judge_agreement[a~b]), a reason (human_decisions_not_usable[why]) or holding no
    number is not one family's counter."""
    out: dict[str, dict[str, float]] = defaultdict(dict)
    for k, v in bias_audit.items():
        name, sep, rest = k.partition("[")
        if (sep and rest.endswith("]") and "[" not in rest and "~" not in rest and _number(v)
                and name not in REASON_COUNTS and name not in PAIR_COUNTS):
            out[rest[:-1]][name] = v
    return dict(out)


def _bracketed(bias_audit: Mapping[str, Any], name: str) -> dict[str, float]:
    return {k[len(name) + 1:-1]: v for k, v in bias_audit.items() if k.startswith(f"{name}[") and k.endswith("]") and _number(v)}


def by_reason(bias_audit: Mapping[str, Any], name: str) -> dict[str, float]:
    """A report's counts of a name that counts by reason, read back from `name[reason]`: reason -> count."""
    return _bracketed(bias_audit, _shaped(name, REASON_COUNTS, "a count by reason"))


def by_pair(bias_audit: Mapping[str, Any], name: str) -> dict[str, float]:
    """A report's values of a name read by pair of families, read back from `name[a~b]`: pair -> value."""
    return _bracketed(bias_audit, _shaped(name, PAIR_COUNTS, "a value by pair of families"))


def alpha(bias_audit: Mapping[str, Any]) -> float | None:
    """The jury's global alpha a report holds; None when it holds none ("n/a", or a report without the key)."""
    v = bias_audit.get(Count.GLOBAL_KRIPPENDORFF_ALPHA)
    return float(v) if _number(v) else None
