"""Score summary (CN-3; docs/adr/0004-score-summary.md): the only part of an in-country review that may go to a team
outside the country. Built from an allowlist of a written report, so a field added to ReviewReport later never
crosses the border by default; no finding detail (file, line, quote, title, claim, CWE, finding id)."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

from pydantic import ValidationError

from ..schemas import ReviewReport

SCHEMA = "mara-score-summary/1"  # mara-<name>/<n>, as psirt_out and psirt_ledger
REPORT_FIELDS = ("target_id", "revision", "review_scope", "generated_at", "provider_mode", "families_used", "config_hash",
                 "review_status", "incomplete_reasons", "gate_passed", "overall_score")
DIMENSION_FIELDS = ("dimension", "score", "accepted_findings", "rejected_findings", "human_queue", "tool_ran", "notes")


class SummaryRefused(ValueError):
    """The report may not be exported; nothing is written. `param_hint` names the argument at fault."""

    def __init__(self, message: str, param_hint: str = "REPORT"):
        super().__init__(message)
        self.param_hint = param_hint


def check_label(label: str) -> None:
    """An operator-given name for the target: one line of 1 to 80 printable characters. MARA cannot judge what it
    says; keeping finding detail out of it is the operator's responsibility (ADR 0004)."""
    if not 1 <= len(label) <= 80 or not label.isprintable():
        raise SummaryRefused("a label must be one line of 1 to 80 printable characters", "--label")


def load_report(source: bytes) -> ReviewReport:
    """The review report whose report.json bytes are `source`."""
    try:
        return ReviewReport.model_validate_json(source)
    except ValidationError as e:  # damaged, hand-edited or foreign: what crosses the border must come from a sound report
        raise SummaryRefused(f"not a valid MARA review report ({e.error_count()} validation error(s))") from e


def check_destination(out: Path, report_path: Path, report: ReviewReport) -> None:
    """The summary may neither replace the report it is made from (the evidence `source_report_sha256` names) nor
    land in the repository that was reviewed. Only the output is checked: the export reads no config and runs no tool."""
    dest, target = out.resolve(), Path(report.target).resolve()
    if dest == report_path.resolve():
        raise SummaryRefused("the summary may not overwrite the report it is made from", "--out")
    if target in dest.parents:
        raise SummaryRefused(f"the summary may not be written inside the reviewed target {target}", "--out")


def build_summary(report: ReviewReport, source: bytes, *, label: str | None = None, allow_mock: bool = False,
                  now: dt.datetime | None = None) -> dict:
    """The score summary of `report`, whose report.json bytes are `source`."""
    if label is not None:
        check_label(label)
    if report.provider_mode == "mock" and not allow_mock:
        # a mock review scores seeded material; abroad it would read as a site's real scores
        raise SummaryRefused("a mock-mode report is not exported without --allow-mock")
    data = json.loads(report.model_dump_json())
    return {
        "schema": SCHEMA,
        "source_report_sha256": hashlib.sha256(source).hexdigest(),
        "exported_at": (now or dt.datetime.now(dt.UTC)).isoformat(timespec="seconds"),
        "label": label,
        **{k: data[k] for k in REPORT_FIELDS},
        "dimensions": [{k: d[k] for k in DIMENSION_FIELDS} for d in data["dimensions"]],
    }


def write_summary(summary: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
