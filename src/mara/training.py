"""G-13: AI-literacy training register for the people who operate the review pipeline.

EU AI Act Article 4 (applicable since 2025-02-02) requires deployers to ensure the people operating an
AI system have sufficient AI literacy. For MARA that means developers reading its findings, the
security team tuning it and the adjudicators deciding human-queue tickets understand evidence tiers,
the bias audit and "a pass is not a proof of security". This module holds the register format, the
validity rules and the quiz grading; scripts/training_register.py is the CLI, the human-queue sync
and calibration consult `is_trained`, and governance check G-13 reads `coverage`.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path

ROLES = ("developer", "security", "adjudicator")
DEFAULT_VALIDITY_DAYS = 365
DEFAULT_PASS_MARK = 0.8
EXPIRY_WARNING_DAYS = 30


@dataclass(frozen=True)
class Record:
    person: str            # GitHub login (the identity the human queue sees on a decision label)
    role: str
    curriculum_version: str
    date: dt.date
    expires: dt.date
    score: float | None
    assessor: str
    evidence: str

    def valid_on(self, day: dt.date, version: str | None = None) -> bool:
        if version is not None and self.curriculum_version != version:
            return False
        return self.date <= day <= self.expires


@dataclass
class Register:
    curriculum_version: str
    validity_days: int
    pass_mark: float
    records: list[Record]
    path: Path | None = None

    def valid(self, day: dt.date, role: str | None = None) -> list[Record]:
        return [r for r in self.records if r.valid_on(day, self.curriculum_version) and (role is None or r.role == role)]

    def expiring(self, day: dt.date, within_days: int = EXPIRY_WARNING_DAYS) -> list[Record]:
        return [r for r in self.valid(day) if (r.expires - day).days <= within_days]


def _date(v) -> dt.date:
    return v if isinstance(v, dt.date) else dt.date.fromisoformat(str(v))


def load_register(path: Path | str) -> Register:
    import yaml

    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    version = str(raw.get("curriculum_version", ""))
    validity = int(raw.get("validity_days", DEFAULT_VALIDITY_DAYS))
    records = []
    for r in raw.get("records", []) or []:
        role = str(r.get("role", ""))
        if role not in ROLES:
            raise ValueError(f"record for {r.get('person')}: unknown role {role!r} (allowed: {', '.join(ROLES)})")
        date = _date(r["date"])
        expires = _date(r["expires"]) if r.get("expires") else date + dt.timedelta(days=validity)
        records.append(Record(str(r["person"]), role, str(r.get("curriculum_version", version)), date, expires,
                              None if r.get("score") is None else float(r["score"]), str(r.get("assessor", "")), str(r.get("evidence", ""))))
    return Register(version, validity, float(raw.get("pass_mark", DEFAULT_PASS_MARK)), records, p)


def save_register(reg: Register, path: Path | str | None = None) -> None:
    import yaml

    p = Path(path or reg.path)
    text = p.read_text(encoding="utf-8") if p.exists() else ""
    head = text.split("records:")[0].rstrip("\n") if "records:" in text else ""
    body = yaml.safe_dump({"records": [{
        "person": r.person, "role": r.role, "curriculum_version": r.curriculum_version, "date": r.date.isoformat(),
        "expires": r.expires.isoformat(), "score": r.score, "assessor": r.assessor, "evidence": r.evidence} for r in reg.records]},
        sort_keys=False, allow_unicode=True)
    if not head:
        head = yaml.safe_dump({"curriculum_version": reg.curriculum_version, "validity_days": reg.validity_days, "pass_mark": reg.pass_mark},
                              sort_keys=False).rstrip("\n")
    p.write_text(head + "\n" + body, encoding="utf-8")


def add_record(reg: Register, person: str, role: str, date: dt.date, *, score: float | None, assessor: str, evidence: str) -> Record:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r} (allowed: {', '.join(ROLES)})")
    rec = Record(person, role, reg.curriculum_version, date, date + dt.timedelta(days=reg.validity_days), score, assessor, evidence)
    reg.records.append(rec)
    return rec


def is_trained(reg: Register | None, person: str, role: str, day: dt.date) -> bool:
    if reg is None or not person:
        return False
    return any(r.person.lower() == person.lower() and r.role == role for r in reg.valid(day))


def coverage(reg: Register, roles: tuple[str, ...] | list[str], day: dt.date) -> dict[str, list[Record]]:
    return {role: reg.valid(day, role) for role in roles}


# ---------------------------------------------------------------- quiz

def load_quiz(path: Path | str) -> list[dict]:
    import yaml

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    qs = raw.get("questions", []) or []
    ids = [q["id"] for q in qs]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate question id in quiz")
    for q in qs:
        if q["answer"] not in q["options"]:
            raise ValueError(f"{q['id']}: answer {q['answer']!r} is not one of its options")
    return qs


def questions_for(quiz: list[dict], role: str) -> list[dict]:
    return [q for q in quiz if role in (q.get("roles") or list(ROLES))]


def grade(quiz: list[dict], role: str, answers: dict[str, str]) -> tuple[float, list[str]]:
    """Fraction correct over the role's questions and the ids answered wrongly or not at all."""
    qs = questions_for(quiz, role)
    if not qs:
        raise ValueError(f"no questions for role {role!r}")
    wrong = [q["id"] for q in qs if str(answers.get(q["id"], "")).strip().lower() != str(q["answer"]).lower()]
    return round(1 - len(wrong) / len(qs), 3), wrong
