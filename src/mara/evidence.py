"""The Evidence record (GLOSSARY.md): the dated file a live calibration or evaluation leaves for a policy or governance
check to read. This module says when one stands: it is not dated in the future, is at most `MAX_AGE_DAYS` old, is live,
and covers the families asked of it. It judges one record and reports every problem it finds, the date's first, then the
mode's, then the families'; what to do about them, and in which words, is the caller's. It reads a record's header out of
the JSON object or the front matter a caller has parsed, reads a Markdown report's front matter, and gives a writer the
header fields to put first. Pure, except that `read_front_matter` reads the file it is given; no clock, `today` is the
caller's."""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_AGE_DAYS = 90
LIVE = "live"
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
MODES = (LIVE, "mock", "dry-run")  # the modes a run has: a live one, a mock panel's, an evaluation that ran on fixtures


@dataclass(frozen=True)
class Header:
    """What an Evidence record says of itself: its date, its mode and the families it covers. `None` is a record that
    does not say."""

    date: dt.date | None
    mode: str | None
    families: tuple[str, ...] | None

    @classmethod
    def from_json(cls, record: Any) -> Header:
        """The header of a JSON record such as calib/latest.json. Whatever is not what a header holds reads as the record
        not saying it: a date that is not an ISO date, a mode that is not text, families that are not a list (the
        strings of a list are kept)."""
        if not isinstance(record, dict):
            return cls(None, None, None)
        return cls(_date(record.get("date")), _text(record.get("mode")), _families(record.get("families")))

    @classmethod
    def from_front_matter(cls, meta: dict[str, Any], date: dt.date | None) -> Header:
        """The header of a Markdown report's front matter, dated by the caller (a report is dated by its file name). The
        mode is kept as written: only `live` is live."""
        return cls(date, _text(meta.get("mode")), _families(meta.get("families")))


def _date(value: Any) -> dt.date | None:
    """`YYYY-MM-DD` and nothing else: date.fromisoformat also takes `20261008`, `2026W41` and a trailing `.5`."""
    if not isinstance(value, str) or not _ISO_DATE.fullmatch(value):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _families(value: Any) -> tuple[str, ...] | None:
    return tuple(f for f in value if isinstance(f, str)) if isinstance(value, list | tuple) else None


@dataclass(frozen=True)
class NoDate:
    """The record has no valid date."""


@dataclass(frozen=True)
class Future:
    """The record is dated after today."""

    date: dt.date


@dataclass(frozen=True)
class Stale:
    """The record is older than `limit` days."""

    age_days: int
    limit: int


@dataclass(frozen=True)
class NotLive:
    """The record's mode is anything but `live`; `mode` is what it says, `None` when it says nothing."""

    mode: str | None


@dataclass(frozen=True)
class MissingFamilies:
    """The families asked for that the record does not cover, in the order they were asked for."""

    families: tuple[str, ...]


Problem = NoDate | Future | Stale | NotLive | MissingFamilies


def standing(header: Header, today: dt.date, families: Sequence[str] | None = None) -> list[Problem]:
    """The problems that keep `header` from standing at `today`, none when it stands. `families` are the ones the record
    must cover; `None` asks for no coverage, so a record that names none is not checked."""
    problems: list[Problem] = []
    if header.date is None:
        problems.append(NoDate())
    else:
        age = (today - header.date).days
        if age < 0:
            problems.append(Future(header.date))
        elif age > MAX_AGE_DAYS:
            problems.append(Stale(age, MAX_AGE_DAYS))
    if header.mode != LIVE:
        problems.append(NotLive(header.mode))
    if families is not None:
        covered = set(header.families or ())
        missing = tuple(f for f in families if f not in covered)
        if missing:
            problems.append(MissingFamilies(missing))
    return problems


def header_fields(date: str, mode: str, families: Iterable[str]) -> dict[str, Any]:
    """The fields a writer puts first in a record, in the order date, mode, families, the families sorted and as a list
    (what YAML and JSON write). A mode no run has is refused."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}, not {mode!r}")
    return {"date": date, "mode": mode, "families": sorted(families)}


def read_front_matter(path: Path | str) -> tuple[dict, str]:
    """(front matter dict, body) for a Markdown file starting with a `---` YAML block."""
    import yaml

    text = Path(path).read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    meta = yaml.safe_load(text[4:end]) or {}
    return (meta if isinstance(meta, dict) else {}), text[end + 5:]
