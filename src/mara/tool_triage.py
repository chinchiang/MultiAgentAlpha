"""Tool triage (GLOSSARY.md: tool triage, triaged alert, tool alert; docs/adr/0010-tool-triage.md): a person's dated
ruling that one tool alert on one target is a false positive or an accepted risk, kept in the MARA workspace and never
read from the target. A triaged alert stays in the report with its ruling and no longer keeps the review incomplete;
one ruled a false positive no longer corroborates a finding either (mara.tools.evidence).

An entry counts only while it is usable: for this target, for a tool that may be triaged, decided no later than today,
not expired, with no more than the configured number of days between its decision and its expiry, by a trained
adjudicator whenever training is required, and not contradicted by another usable entry on the same alert. Anything
else leaves the alert as it was, blocking.

Pure, except that load() reads the file it is given and apply() records the ruling on the tool results it is given.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .identity import norm_path
from .tools.evidence import is_alert
from .tools.sarif import ToolResult
from .training import is_trained

if TYPE_CHECKING:
    from .decisions import TrainingRequirement

FALSE_POSITIVE = "false_positive"
ACCEPTED_RISK = "accepted_risk"
VERDICTS = (FALSE_POSITIVE, ACCEPTED_RISK)
# A secret is removed and rotated, never accepted; and gitleaks' alerts also decide whether source may leave the host
# (mara.review_status.secret_preflight), which no triage may touch.
UNTRIAGEABLE_TOOLS = frozenset({"gitleaks"})
ADJUDICATOR = "adjudicator"  # the training role a ruling needs, as a human decision does (mara.decisions)

# why a well-formed entry for this target is not usable; the audit counts each (tool_triage_not_usable[<why>])
EXPIRED = "expired"
DECIDED_IN_FUTURE = "decided_in_future"
WINDOW_TOO_LONG = "window_too_long"
UNTRIAGEABLE_TOOL = "untriageable_tool"
UNTRAINED = "untrained"
CONTRADICTED = "contradicted"
MALFORMED = "malformed"

_TEXT_FIELDS = ("target_id", "tool", "rule", "file", "verdict", "reason", "decided_by")
MIN_REASON = 20  # characters: a reason says why, "fp" does not


@dataclass(frozen=True)
class Entry:
    """One ruling: the target (a review report's target_id), the alert's tool, rule and file as the report gives them,
    the verdict and why, who decided and when, the day it stops counting, and for an accepted risk the approval it
    rests on."""

    target_id: str
    tool: str
    rule: str
    file: str
    verdict: str
    reason: str
    decided_by: str
    decided_on: dt.date
    expires: dt.date
    approval_ref: str = ""

    @property
    def alert(self) -> tuple[str, str, str]:
        """The alert it rules on: tool, rule and normalised file."""
        return self.tool, self.rule, norm_path(self.file)

    def record(self) -> dict:
        """What a triaged tool result carries in a report."""
        out = {"verdict": self.verdict, "reason": self.reason, "decided_by": self.decided_by,
               "decided_on": self.decided_on.isoformat(), "expires": self.expires.isoformat()}
        if self.approval_ref:
            out["approval_ref"] = self.approval_ref
        return out


@dataclass
class Loaded:
    """The entries of a triage file that are well-formed, and for each that is not, what is wrong with it."""

    entries: list[Entry] = field(default_factory=list)
    malformed: list[str] = field(default_factory=list)


@dataclass
class Applied:
    """What applying a triage file to one review's tool results did: the alerts triaged, the entries for this target
    that are not usable by why, and the usable ones that matched no alert (stale)."""

    triaged: int = 0
    not_usable: dict[str, int] = field(default_factory=dict)
    stale: int = 0


def _day(value: object) -> dt.date | None:
    """A date as YAML reads one (a date, never a datetime) or as ISO text; anything else is no date."""
    if isinstance(value, dt.datetime):
        return None
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def parse(raw: object) -> Entry | str:
    """The entry `raw` holds, or what is wrong with it. Every part is checked by type: the file is written by hand."""
    if not isinstance(raw, dict):
        return "an entry is a mapping"
    unknown = sorted(set(raw) - set(_TEXT_FIELDS) - {"decided_on", "expires", "approval_ref"}, key=str)
    if unknown:
        return f"unknown key(s) {', '.join(map(str, unknown))}"
    for name in _TEXT_FIELDS:
        if not isinstance(raw.get(name), str) or not raw[name].strip():
            return f"{name} is missing or not text"
    if raw["verdict"] not in VERDICTS:
        return f"verdict is not one of {', '.join(VERDICTS)}"
    if len(raw["reason"].strip()) < MIN_REASON:
        return f"reason is shorter than {MIN_REASON} characters"
    decided_on, expires = _day(raw.get("decided_on")), _day(raw.get("expires"))
    if decided_on is None or expires is None:
        return "decided_on and expires are dates (YYYY-MM-DD)"
    if expires < decided_on:
        return "expires is before decided_on"
    approval = raw.get("approval_ref", "")
    if not isinstance(approval, str):
        return "approval_ref is not text"
    if raw["verdict"] == ACCEPTED_RISK and not approval.strip():
        return "an accepted risk names its approval_ref"
    return Entry(target_id=raw["target_id"].strip(), tool=raw["tool"].strip(), rule=raw["rule"].strip(), file=raw["file"].strip(),
                 verdict=raw["verdict"], reason=raw["reason"].strip(), decided_by=raw["decided_by"].strip(),
                 decided_on=decided_on, expires=expires, approval_ref=approval.strip())


def load(path: Path | str) -> Loaded:
    """The triage file at `path`: `entries`, a list. No file is no entry; a file that cannot be read, is not YAML or
    is not that shape is one malformed entry, so it is reported and triages nothing."""
    import yaml

    p = Path(path)
    if not p.is_file():
        return Loaded()
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError) as e:
        return Loaded(malformed=[f"{p.name}: unreadable ({type(e).__name__})"])
    if data is None:
        return Loaded()
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list) or set(data) != {"entries"}:
        return Loaded(malformed=[f"{p.name}: not a mapping with the one key `entries`, a list"])
    out = Loaded()
    for i, raw in enumerate(data["entries"], 1):
        parsed = parse(raw)
        if isinstance(parsed, Entry):
            out.entries.append(parsed)
        else:
            out.malformed.append(f"entry {i}: {parsed}")
    return out


def usable(e: Entry, *, today: dt.date, max_days: int, training: TrainingRequirement) -> str:
    """Why the entry `e` is not usable today, or an empty string when it is. The checks run in this order."""
    if e.tool in UNTRIAGEABLE_TOOLS:
        return UNTRIAGEABLE_TOOL
    if e.decided_on > today:
        return DECIDED_IN_FUTURE
    if e.expires < today:
        return EXPIRED
    if (e.expires - e.decided_on).days > max_days:
        return WINDOW_TOO_LONG
    if training.required and not is_trained(training.register, e.decided_by, ADJUDICATOR, e.decided_on):
        return UNTRAINED
    return ""


def apply(results: Iterable[ToolResult], loaded: Loaded, *, target_id: str, today: dt.date, max_days: int,
          training: TrainingRequirement) -> Applied:
    """Record on each tool alert of `results` the usable entry of `loaded` that rules on it for the target `target_id`
    (ToolResult.triage), and say what was done. An entry for another target is not this review's and is not counted.
    Two usable entries on one alert that disagree are both set aside."""
    out = Applied()
    why_not: Counter[str] = Counter({MALFORMED: len(loaded.malformed)} if loaded.malformed else {})
    by_alert: dict[tuple[str, str, str], list[Entry]] = {}
    for e in loaded.entries:
        if e.target_id != target_id:
            continue
        why = usable(e, today=today, max_days=max_days, training=training)
        if why:
            why_not[why] += 1
        else:
            by_alert.setdefault(e.alert, []).append(e)
    rulings: dict[tuple[str, str, str], Entry] = {}
    for alert, entries in by_alert.items():
        if len({e.verdict for e in entries}) > 1:
            why_not[CONTRADICTED] += len(entries)
        else:
            rulings[alert] = max(entries, key=lambda e: (e.decided_on, e.expires))
    matched: set[tuple[str, str, str]] = set()
    for t in results:
        if not is_alert(t.level):
            continue
        alert = (t.tool, t.rule_id, norm_path(t.file))
        e = rulings.get(alert)
        if e is not None:
            t.triage = e.record()
            matched.add(alert)
            out.triaged += 1
    out.stale = len(set(rulings) - matched)
    out.not_usable = dict(sorted(why_not.items()))
    return out
