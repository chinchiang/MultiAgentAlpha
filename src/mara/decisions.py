"""Human decisions (G-11 write-back, G-13): the one rule for when a decision counts.

A decision is one adjudicator's true/false-positive ruling on one human-queue key, mirrored from a
closed ticket into calib/decisions/<key>.json by scripts/human_queue_issues.py --sync-decisions.
This module defines that record and the two levels of trust in it (docs/adr/0002-usable-decisions.md):

- well-formed: the record is consistent with itself (a ruling, a decision event, and a key that is
  both its file name and the v2 queue key of its own fields). A well-formed decision answers its
  ticket: the key is not queued again.
- usable: well-formed, bound to the report it is compared with (same target, revision and
  context), not contradicted on its key, and - whenever training is required - made by an
  adjudicator holding a valid training record on the decision day. Only a usable decision is
  ground truth: calibration labels, the Alternative Annotator Test, false-positive rates.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .report.human_queue_out import queue_key
from .training import Register, is_trained

if TYPE_CHECKING:
    from .config import TrainingConfig

VERDICTS = ("true_positive", "false_positive")
BACKLOG_FILE = "backlog.json"

# fields the rule reads; everything else a record carries (url, finding_id, decision_label, the sync's
# training snapshot) travels along unchanged
_CORE = ("key", "target_id", "revision", "context_hash", "file", "line", "cwe", "decision", "decision_event_id",
         "decided_by", "decided_at", "issue")


@dataclass(frozen=True)
class Decision:
    key: str
    target_id: str
    revision: str
    context_hash: str
    file: str
    line: int
    cwe: str
    decision: str
    decision_event_id: int | str
    decided_by: str
    decided_at: str
    issue: int | None = None
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    @classmethod
    def parse(cls, record: object) -> Decision | str:
        """The decision a record holds, or why it is not well-formed."""
        if not isinstance(record, dict):
            return "not a JSON object"
        r = record
        if r.get("decision") not in VERDICTS:
            return f"decision {r.get('decision')!r} is not one of {', '.join(VERDICTS)}"
        for name in ("key", "target_id", "revision", "context_hash", "file", "cwe", "decided_by", "decided_at"):
            if not isinstance(r.get(name), str) or not r[name].strip():
                return f"{name} is missing or empty"
        if not r.get("decision_event_id"):
            return "no decision event id"
        try:
            line = int(r.get("line"))  # type: ignore[arg-type]
            dt.datetime.fromisoformat(r["decided_at"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return "line or decided_at is unreadable"
        if line < 1:
            return "line is not a positive number"
        if r["key"] != queue_key(r["file"], line, r["cwe"], target_id=r["target_id"], revision=r["revision"],
                                 context_hash=r["context_hash"]):
            return "key is not the v2 queue key of the record's own fields"
        issue = r.get("issue")
        return cls(key=r["key"], target_id=r["target_id"], revision=r["revision"], context_hash=r["context_hash"],
                   file=r["file"], line=line, cwe=r["cwe"], decision=r["decision"], decision_event_id=r["decision_event_id"],
                   decided_by=r["decided_by"], decided_at=r["decided_at"], issue=issue if isinstance(issue, int) else None,
                   extra={k: v for k, v in r.items() if k not in _CORE})

    def to_record(self) -> dict:
        core = {"key": self.key, "target_id": self.target_id, "revision": self.revision, "context_hash": self.context_hash,
                "file": self.file, "line": self.line, "cwe": self.cwe, "decision": self.decision,
                "decision_event_id": self.decision_event_id, "decided_by": self.decided_by, "decided_at": self.decided_at}
        if self.issue is not None:
            core["issue"] = self.issue
        return {**self.extra, **core}

    @property
    def day(self) -> dt.date:
        """The decision day: training is judged on it."""
        return dt.datetime.fromisoformat(self.decided_at.replace("Z", "+00:00")).date()


@dataclass
class Loaded:
    decisions: list[Decision]
    malformed: list[tuple[Path, str]]


def read(path: Path) -> Decision | str:
    """The well-formed decision in one calib/decisions/<key>.json file, or why there is none."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"unreadable: {e}"
    parsed = Decision.parse(raw)
    if isinstance(parsed, Decision) and path.name != f"{parsed.key}.json":
        return f"file name is not the record's key {parsed.key}"
    return parsed


def load(directory: Path | str) -> Loaded:
    """Every decision record in `directory` (the backlog file is not one), split into well-formed
    decisions and damaged records with the reason."""
    out = Loaded([], [])
    d = Path(directory)
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        if p.name == BACKLOG_FILE:
            continue
        parsed = read(p)
        if isinstance(parsed, Decision):
            out.decisions.append(parsed)
        else:
            out.malformed.append((p, parsed))
    return out


@dataclass(frozen=True)
class TrainingRequirement:
    """G-13: whether a decision needs a trained adjudicator to count, and the register that says who is
    trained. Required with no readable register means nobody is trained (fail closed); `problem` says why."""

    required: bool = True
    register: Register | None = None
    problem: str = ""

    @classmethod
    def from_config_file(cls, path: Path | str) -> TrainingRequirement:
        """From a MARA config's `training` block; the register resolves against the workspace. A config
        that cannot be read keeps training required."""
        import yaml

        from .config import TrainingConfig
        from .training import load_register
        from .workspace import resolve

        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
            cfg = TrainingConfig.model_validate((raw.get("training") if isinstance(raw, dict) else None) or {})
        except (OSError, ValueError) as e:
            cfg, why = TrainingConfig(), f"config {path} unreadable ({e}); training stays required"
        else:
            why = ""
        if not cfg.require_trained_adjudicator:
            return cls(required=False)
        register_path = resolve(cfg.register_file)
        try:
            return cls(required=True, register=load_register(register_path), problem=why)
        except (OSError, ValueError, KeyError, TypeError) as e:
            return cls(required=True, problem=f"{why}; " * bool(why) + f"training register {cfg.register_file} unavailable ({e})")

    @classmethod
    def from_config(cls, cfg: TrainingConfig) -> TrainingRequirement:
        """From an already loaded `training` block; the register resolves against the workspace."""
        from .training import load_register
        from .workspace import resolve

        if not cfg.require_trained_adjudicator:
            return cls(required=False)
        try:
            return cls(required=True, register=load_register(resolve(cfg.register_file)))
        except (OSError, ValueError, KeyError, TypeError) as e:
            return cls(required=True, problem=f"training register {cfg.register_file} unavailable ({e})")

    def satisfied_by(self, d: Decision) -> bool:
        return not self.required or is_trained(self.register, d.decided_by, "adjudicator", d.day)


@dataclass
class Selection:
    usable: list[Decision]
    excluded: list[tuple[Decision, str]]

    def by_reason(self) -> dict[str, int]:
        """Excluded keys per reason: a key contradicted by three records is one item that cannot be used."""
        keys: dict[str, set[str]] = {}
        for d, why in self.excluded:
            keys.setdefault(why, set()).add(d.key)
        return {why: len(k) for why, k in sorted(keys.items())}


def binding(report: dict) -> tuple[str, str, str] | None:
    """(target id, revision, context hash) of a review report, or None when any is missing: such a
    report binds no decision."""
    ident = (report.get("target_id"), report.get("revision"), (report.get("coverage") or {}).get("content_hash"))
    return ident if all(isinstance(x, str) and x for x in ident) else None  # type: ignore[return-value]


def select(decisions: list[Decision], report: dict, training: TrainingRequirement) -> Selection:
    """The usable decisions for `report`, and every other decision with why it is not usable: 'unbound'
    (another target, revision or context), then 'untrained', then 'contradictory' (the remaining
    decisions on a key disagree; all of them are excluded). Agreeing records of one key count once."""
    ident = binding(report)
    sel = Selection([], [])
    candidates: dict[str, list[Decision]] = {}
    for d in decisions:
        if ident is None or (d.target_id, d.revision, d.context_hash) != ident:
            sel.excluded.append((d, "unbound"))
        elif not training.satisfied_by(d):
            sel.excluded.append((d, "untrained"))
        else:
            candidates.setdefault(d.key, []).append(d)
    for ds in candidates.values():
        if len({d.decision for d in ds}) > 1:
            sel.excluded += [(d, "contradictory") for d in ds]
        else:
            sel.usable.append(ds[0])
    return sel
