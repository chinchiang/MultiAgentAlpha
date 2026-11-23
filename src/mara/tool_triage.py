"""Tool triage (GLOSSARY.md: tool triage, triaged alert, tool alert; docs/adr/0010-tool-triage.md): a person's dated
ruling that one tool alert on one target is a false positive or an accepted risk, kept in the MARA workspace and never
read from the target. A triaged alert stays in the report with its ruling and no longer keeps the review incomplete;
one ruled a false positive no longer corroborates a finding either (mara.tools.evidence).

An entry counts only while it is usable: for this target, which must have a name of its own (a git repository with an
origin), for an alert that is not a secret, decided no later than today, not expired, with no more than the configured
number of days between its decision and its expiry, by a trained adjudicator whenever training is required, and not
contradicted by another usable entry on the same alert. It rules on the alerts whose fingerprint it lists and on no
other: an alert of the same rule in the same file that the person did not read, or whose line has changed since,
blocks. Anything else leaves the alert as it was, blocking.

Pure, except that load() reads the file it is given, and stamp() and apply() record the fingerprint and the ruling on
the tool results they are given.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections import Counter
from collections.abc import Iterable, Mapping
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
# (mara.review_status.secret_preflight), which no triage may touch. A pre-recorded gitleaks file is named after its
# stem (gitleaks-history), and semgrep's registry rules for secrets sit under a `secrets` part of the rule id.
SECRET_TOOL_PREFIX = "gitleaks"
SECRET_RULE_PART = "secrets"
FINGERPRINT_RE = re.compile(r"[0-9a-f]{16}")
MAX_FINGERPRINTS = 50
_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
ADJUDICATOR = "adjudicator"  # the training role a ruling needs, as a human decision does (mara.decisions)

# why a well-formed entry for this target is not usable; the audit counts each (tool_triage_not_usable[<why>])
EXPIRED = "expired"
DECIDED_IN_FUTURE = "decided_in_future"
WINDOW_TOO_LONG = "window_too_long"
SECRET_ALERT = "secret_alert"
UNTRAINED = "untrained"
CONTRADICTED = "contradicted"
UNNAMED_TARGET = "unnamed_target"
FILE_INSIDE_TARGET = "file_inside_target"  # written by the pipeline, which knows where the target lies
MALFORMED = "malformed"

_TEXT_FIELDS = ("target_id", "tool", "rule", "file", "verdict", "reason", "decided_by")
MIN_REASON = 20  # characters: a reason says why, "fp" does not


@dataclass(frozen=True)
class Entry:
    """One ruling: the target (a review report's target_id), the alert's tool, rule and file as the report gives them
    and the fingerprints of the alerts read, the verdict and why, who decided and when, the day it stops counting, and
    for an accepted risk the approval it rests on."""

    target_id: str
    tool: str
    rule: str
    file: str
    verdict: str
    reason: str
    decided_by: str
    decided_on: dt.date
    expires: dt.date
    fingerprints: tuple[str, ...] = ()
    approval_ref: str = ""

    @property
    def alerts(self) -> list[tuple[str, str, str, str, str]]:
        """The alerts it rules on, one per fingerprint: target, tool, rule, normalised file and fingerprint."""
        return [(self.target_id, self.tool, self.rule, norm_path(self.file), fp) for fp in self.fingerprints]

    def record(self) -> dict:
        """What a triaged tool result carries in a report."""
        out: dict = {"verdict": self.verdict, "reason": self.reason, "decided_by": self.decided_by,
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
    that are not usable by why (and the malformed ones of the file), and the usable entries none of whose fingerprints
    matched an alert (stale)."""

    triaged: int = 0
    not_usable: dict[str, int] = field(default_factory=dict)
    stale: int = 0


def _day(value: object) -> dt.date | None:
    """A date as YAML reads one (a date, never a datetime) or as the text YYYY-MM-DD; anything else is no date."""
    if isinstance(value, dt.datetime):
        return None
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str) and _DAY_RE.fullmatch(value):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def parse(raw: object) -> Entry | str:
    """The entry `raw` holds, or what is wrong with it. Every part is checked by type: the file is written by hand."""
    if not isinstance(raw, dict):
        return "an entry is a mapping"
    unknown = sorted(set(raw) - set(_TEXT_FIELDS) - {"decided_on", "expires", "approval_ref", "fingerprints"}, key=str)
    if unknown:
        return f"unknown key(s) {', '.join(map(str, unknown))}"
    for name in _TEXT_FIELDS:
        if not isinstance(raw.get(name), str) or not raw[name].strip():
            return f"{name} is missing or not text"
    if not norm_path(raw["file"].strip()):
        return "file names no file"
    prints = raw.get("fingerprints")
    if (not isinstance(prints, list) or not 1 <= len(prints) <= MAX_FINGERPRINTS
            or not all(isinstance(x, str) and FINGERPRINT_RE.fullmatch(x) for x in prints)):
        return f"fingerprints is a list of 1 to {MAX_FINGERPRINTS} alert fingerprints, as a report gives them"
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
                 decided_on=decided_on, expires=expires, fingerprints=tuple(dict.fromkeys(prints)), approval_ref=approval.strip())


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


def secret_alert(tool: str, rule: str) -> bool:
    """Whether an alert of `tool` under `rule` reports a secret: any gitleaks run, and a rule with a `secrets` part
    (semgrep's generic.secrets.…). Such an alert cannot be triaged."""
    return tool.lower().startswith(SECRET_TOOL_PREFIX) or SECRET_RULE_PART in re.split(r"[.\-_/:]", rule.lower())


def fingerprint(t: ToolResult, content: Mapping[str, str], prefix: str = "") -> str:
    """What ties a ruling to the alert a person read: a digest of the text of the line the alert names, stripped, in
    the bundle `content` (the file as the tool names it, or below the target's `prefix` in its repository), so a
    shifted line keeps its ruling and a changed one loses it. An alert on a file the bundle does not hold, or on a
    line with no text, is tied to its message instead (a lockfile advisory names its package and version there)."""
    path = norm_path(t.file)
    text = content.get(path)
    if text is None and prefix and path.startswith(prefix + "/"):
        text = content.get(path[len(prefix) + 1:])
    line = ""
    if text is not None and t.line >= 1:
        lines = text.splitlines()
        line = lines[t.line - 1].strip() if t.line <= len(lines) else ""
    basis = "line:" + line if line else "message:" + t.message
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def stamp(results: Iterable[ToolResult], content: Mapping[str, str], prefix: str = "") -> None:
    """Record its fingerprint on each tool alert of `results` (ToolResult.fingerprint)."""
    for t in results:
        if is_alert(t.level):
            t.fingerprint = fingerprint(t, content, prefix)


def usable(e: Entry, *, today: dt.date, max_days: int, training: TrainingRequirement) -> str:
    """Why the entry `e` is not usable today, or an empty string when it is. The checks run in this order."""
    if secret_alert(e.tool, e.rule):
        return SECRET_ALERT
    if e.decided_on > today:
        return DECIDED_IN_FUTURE
    if e.expires < today:
        return EXPIRED
    if (e.expires - e.decided_on).days > max_days:
        return WINDOW_TOO_LONG
    if training.required and not is_trained(training.register, e.decided_by, ADJUDICATOR, e.decided_on):
        return UNTRAINED
    return ""


def contradicted(entries: Iterable[Entry]) -> list[Entry]:
    """Those of `entries` that rule on an alert another of them rules on with the other verdict; each is set aside
    whole, for every alert it names."""
    held = list(entries)
    verdicts: dict[tuple[str, str, str, str, str], set[str]] = {}
    for e in held:
        for alert in e.alerts:
            verdicts.setdefault(alert, set()).add(e.verdict)
    return [e for e in held if any(len(verdicts[a]) > 1 for a in e.alerts)]


def apply(results: Iterable[ToolResult], loaded: Loaded, *, target_id: str, target_named: bool, today: dt.date, max_days: int,
          training: TrainingRequirement) -> Applied:
    """Record on each tool alert of `results` the usable entry of `loaded` that rules on it for the target `target_id`
    (ToolResult.triage): the entry names its tool, rule and file and lists its fingerprint (stamp() gives the alerts
    theirs). An entry for another target is not this review's and is not counted. A target with no name of its own
    (`target_named` false: its id is a hash of where it lies, which another project can come to share) takes no ruling.
    Usable entries that disagree on one alert are set aside whole. Returns what was done."""
    out = Applied()
    why_not: Counter[str] = Counter({MALFORMED: len(loaded.malformed)} if loaded.malformed else {})
    mine = [e for e in loaded.entries if e.target_id == target_id]
    held: list[Entry] = []
    for e in mine:
        why = UNNAMED_TARGET if not target_named else usable(e, today=today, max_days=max_days, training=training)
        if why:
            why_not[why] += 1
        else:
            held.append(e)
    apart = contradicted(held)
    why_not[CONTRADICTED] += len(apart)
    rulings: dict[tuple[str, str, str, str, str], Entry] = {}
    for e in sorted((e for e in held if e not in apart), key=lambda e: (e.decided_on, e.expires)):
        for alert in e.alerts:
            rulings[alert] = e  # of entries that agree, the latest decided
    matched: list[Entry] = []
    for t in results:
        if not is_alert(t.level) or not t.fingerprint:
            continue
        ruling = rulings.get((target_id, t.tool, t.rule_id, norm_path(t.file), t.fingerprint))
        if ruling is not None and not secret_alert(t.tool, t.rule_id):
            t.triage = ruling.record()
            matched.append(ruling)
            out.triaged += 1
    out.stale = sum(1 for e in held if e not in apart and e not in matched)
    out.not_usable = {why: n for why, n in sorted(why_not.items()) if n}
    return out
