"""Minimal SARIF 2.1.0 reader for deterministic-tool output (L0): the results and the completeness that make up a tool's
scan in its tool evidence (GLOSSARY.md, "Tool evidence"). Before any reader reads a document, shape_problem checks the
type of each part the readers read into or take as text or a number; a document with one of another type, though it is
JSON, is not shaped as SARIF, and each reader takes it as a report it cannot read. Pure, except that error_notifications
and read_sarif read the file at the path they are given."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CWE_RE = re.compile(r"CWE-\d{1,5}", re.I)


@dataclass
class ToolResult:
    tool: str
    rule_id: str
    level: str
    message: str
    file: str
    line: int
    cwe: str | None = None          # first CWE the rule names (display / compatibility)
    cwes: list[str] = field(default_factory=list)  # every CWE the rule names; corroboration matches any of them


NOTIFICATION_KEYS = ("toolExecutionNotifications", "toolConfigurationNotifications")  # where an invocation says what went wrong


class NotShapedAsSarif(ValueError):
    """read_sarif's refusal of a file that is JSON but not shaped as SARIF (shape_problem), naming the file and the part."""


_EXPECTED: dict[type, str] = {dict: "an object", list: "an array", str: "a string", int: "an integer"}
_JSON_KINDS: dict[type, str] = {dict: "an object", list: "an array", str: "a string"}


def _what(value: object) -> str:
    """What `value` is, as one of the values json.loads gives."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    return _JSON_KINDS.get(type(value), f"a {type(value).__name__}")


class _Shape:
    """A walk of a document that records each part of it not shaped as SARIF, in the order it meets them."""

    def __init__(self) -> None:
        self.problems: list[str] = []

    def of(self, value: object, kind: type, where: str) -> bool:
        """Whether `value` is of `kind` (a boolean is not an integer); when it is not, the part at `where` is recorded."""
        if isinstance(value, kind) and not (kind is int and isinstance(value, bool)):
            return True
        self.problems.append(f"{where} is {_what(value)}, not {_EXPECTED[kind]}")
        return False

    def member(self, obj: dict, key: str, kind: type, where: str, *, nullable: bool = False) -> Any:
        """The member `key` of `obj` when it is of `kind`, else None: when it is absent, when it is null and the readers
        take a null for its absence (`nullable`), or when it is of another kind, which is recorded."""
        if key not in obj or (nullable and obj[key] is None):
            return None
        return obj[key] if self.of(obj[key], kind, f"{where}.{key}" if where else key) else None

    def items(self, obj: dict, key: str, where: str, *, nullable: bool = False, first_only: bool = False) -> Iterator[tuple[dict, str]]:
        """Each item of the array `key` of `obj` that is an object, with where it is; any other item is recorded. With
        `first_only`, the first item alone, the one the readers read."""
        array = self.member(obj, key, list, where, nullable=nullable) or []
        at = f"{where}.{key}" if where else key
        for i, item in enumerate(array[:1] if first_only else array):
            if self.of(item, dict, f"{at}[{i}]"):
                yield item, f"{at}[{i}]"


def _check_location(shape: _Shape, loc: dict, where: str, *, region: bool) -> None:
    """A location's physical location and its artifact's uri, and with `region` its start line, as a result's is read."""
    physical = shape.member(loc, "physicalLocation", dict, where)
    if physical is None:
        return
    at = f"{where}.physicalLocation"
    if (artifact := shape.member(physical, "artifactLocation", dict, at)) is not None:
        shape.member(artifact, "uri", str, f"{at}.artifactLocation")
    if region and (lines := shape.member(physical, "region", dict, at)) is not None:
        shape.member(lines, "startLine", int, f"{at}.region")


def _check_message(shape: _Shape, obj: dict, where: str, *, nullable: bool) -> None:
    """A message and its text."""
    if (message := shape.member(obj, "message", dict, where, nullable=nullable)) is not None:
        shape.member(message, "text", str, f"{where}.message")


def _check_rule(shape: _Shape, rule: dict, where: str) -> None:
    """A rule's id and name, its tags and its default level."""
    for key in ("id", "name"):
        shape.member(rule, key, str, where)
    if (properties := shape.member(rule, "properties", dict, where)) is not None:
        shape.member(properties, "tags", list, f"{where}.properties")
    if (config := shape.member(rule, "defaultConfiguration", dict, where)) is not None:
        shape.member(config, "level", str, f"{where}.defaultConfiguration")


def _check_invocation(shape: _Shape, invocation: dict, where: str) -> None:
    """Each notification of both kinds, its descriptor, its message and every location it names."""
    for key in NOTIFICATION_KEYS:
        for notification, at in shape.items(invocation, key, where, nullable=True):
            shape.member(notification, "descriptor", dict, at, nullable=True)
            _check_message(shape, notification, at, nullable=True)
            for loc, at_loc in shape.items(notification, "locations", at, nullable=True):
                _check_location(shape, loc, at_loc, region=False)


def _check_result(shape: _Shape, result: dict, where: str) -> None:
    """A result's rule id, rule, level, message, suppressions and first location."""
    for key in ("ruleId", "level"):
        shape.member(result, key, str, where)
    if (rule := shape.member(result, "rule", dict, where)) is not None:
        shape.member(rule, "id", str, f"{where}.rule")
    _check_message(shape, result, where, nullable=False)
    for _suppression in shape.items(result, "suppressions", where):
        pass  # an object each; its status is only compared
    for loc, at in shape.items(result, "locations", where, nullable=True, first_only=True):
        _check_location(shape, loc, at, region=True)


def _check_run(shape: _Shape, run: dict, where: str) -> None:
    """A run's driver and its rules, its invocations and its results."""
    if (tool := shape.member(run, "tool", dict, where)) is not None:
        if (driver := shape.member(tool, "driver", dict, f"{where}.tool")) is not None:
            shape.member(driver, "name", str, f"{where}.tool.driver")
            for rule, at in shape.items(driver, "rules", f"{where}.tool.driver"):
                _check_rule(shape, rule, at)
    for invocation, at in shape.items(run, "invocations", where):
        _check_invocation(shape, invocation, at)
    for result, at in shape.items(run, "results", where):
        _check_result(shape, result, at)


def shape_problem(doc: object) -> str | None:
    """The first part of `doc` not shaped as SARIF, as where it is and what it is ("runs[0].invocations[0] is a number,
    not an object"), or None. The parts checked are those the readers below, semgrep_rules.normalize_sarif and
    semgrep_rules.timeouts read into or take as text or a number: the objects, the arrays (of a result's locations, the
    first, the one read), the strings and a start line, an integer. A part they only compare (an invocation's
    executionSuccessful, a notification's level and its descriptor's id, a suppression's status, a tag) is not checked,
    and no value is: this is not a check against SARIF's schema. A member that is absent is fine; one that is null is
    not, but where every reader of it takes a null for its absence (an invocation's notifications, a notification's
    descriptor, message and locations, a result's locations)."""
    shape = _Shape()
    if isinstance(doc, dict):
        for run, at in shape.items(doc, "runs", ""):
            _check_run(shape, run, at)
    else:
        shape.of(doc, dict, "the document")
    return shape.problems[0] if shape.problems else None


def _notifications(invocation: dict) -> list[dict]:
    return [n for key in NOTIFICATION_KEYS for n in invocation.get(key) or []]


def scan_complete(doc: dict) -> bool:
    """A report must contain runs and must not record a failed/partial invocation; one not shaped as SARIF
    (shape_problem) did not complete either, for it cannot be read."""
    if shape_problem(doc) is not None or not doc.get("runs"):
        return False
    for run in doc["runs"]:
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                return False
            if any(n.get("level") == "error" for n in _notifications(invocation)):
                return False
    return True


def notifications(path: Path | str) -> list[dict]:
    """Every notification of the SARIF at `path`, of both kinds `scan_complete` reads, in the order it records them;
    none when the file cannot be read, is not JSON, or is not shaped as SARIF (shape_problem)."""
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if shape_problem(doc) is not None:
        return []
    return [n for run in doc.get("runs") or [] for invocation in run.get("invocations") or [] for n in _notifications(invocation)]


def error_notifications(path: Path | str) -> list[str]:
    """Each error-level notification of the SARIF at `path` (notifications), as its message and the locations it names."""
    notes = []
    for n in notifications(path):
        if n.get("level") == "error":
            where = [loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "") for loc in n.get("locations") or []]
            notes.append(" ".join([(n.get("message") or {}).get("text", ""), *(f"({w})" for w in where if w)]))
    return notes


# SARIF driver names are product labels, not the lock's tool ids; normalize the known ones so
# TOOL_DIMENSIONS lookups (corroboration, dimension wiring) match whatever named the run.
TOOL_NAME_ALIASES = {
    "semgrep oss": "semgrep",
}


def read_sarif(path: str | Path, tool_hint: str = "") -> list[ToolResult]:
    """The results of the SARIF at `path`, but those its own triage suppressed. A file that cannot be read raises
    OSError; one that is not UTF-8, UnicodeDecodeError; one that is not JSON, JSONDecodeError; one not shaped as SARIF
    (shape_problem), NotShapedAsSarif naming the file and the part, and no result is returned."""
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    if (problem := shape_problem(doc)) is not None:
        raise NotShapedAsSarif(f"{path}: not shaped as SARIF ({problem})")
    out: list[ToolResult] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {}).get("name", "")
        # every internal caller passes the canonical tool id as the hint; the driver name is the
        # fallback for hint-less callers, normalized through the alias table
        tool = tool_hint or TOOL_NAME_ALIASES.get(driver.strip().lower(), driver or "unknown")
        rules = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            if any(s.get("status") == "accepted" for s in res.get("suppressions", [])):
                continue
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 1)
            rule = rules.get(res.get("ruleId"), {})
            tags = rule.get("properties", {}).get("tags", []) if rule else []
            # semgrep tags read "CWE-89: Improper Neutralization of ..." and a rule may name several CWEs
            # (tainted-sql-string lists CWE-704 and CWE-89) — keep only the identifiers so they compare equal
            # to a finding's cwe; a bare rule id such as CWE-79 (gitleaks-style) also counts
            cwes = [m.group(0).upper() for t in tags if (m := CWE_RE.match(str(t)))]
            if not cwes and (m := CWE_RE.match(res.get("ruleId", ""))):
                cwes = [m.group(0).upper()]
            cwe = cwes[0] if cwes else None
            # semgrep omits result.level and relies on the rule's defaultConfiguration
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
            out.append(ToolResult(tool=tool, rule_id=res.get("ruleId", ""), level=level,
                                  message=res.get("message", {}).get("text", ""), file=uri, line=int(line or 1), cwe=cwe, cwes=cwes))
    return out
