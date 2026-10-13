"""Score summary (CN-3; docs/adr/0004-score-summary.md): the only part of an in-country review that may go to a team
outside the country. Built from an allowlist of a written report, so a field added to ReviewReport later never
crosses the border by default; no finding detail (file, line, quote, title, claim, CWE, finding id)."""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import unicodedata
from pathlib import Path

from pydantic import ValidationError

from ..audit import INCOMPLETE_COUNTERS
from ..schemas import DIMENSION_LABELS, ModelFamily, ReviewReport

SCHEMA = "mara-score-summary/1"  # mara-<name>/<n>, as psirt_out and psirt_ledger
REPORT_FIELDS = ("review_scope", "generated_at", "provider_mode", "families_used", "config_hash", "review_status",
                 "incomplete_reasons", "gate_passed", "overall_score")
# no `notes`: free text, and what it says today follows from tool_ran
DIMENSION_FIELDS = ("dimension", "score", "accepted_findings", "rejected_findings", "human_queue", "tool_ran")


# Every incomplete-review code: the audit counters and the pipeline's own codes (pipeline.py, `incomplete.append`);
# tests/test_score_summary.py fails when the pipeline writes a code this list lacks.
INCOMPLETE_REASONS = frozenset(INCOMPLETE_COUNTERS) | {
    "context_coverage_incomplete", "source_egress_blocked_by_secret_preflight", "required_tool_incomplete",
    "ml_bom_signature_unverified", "context_view_incomplete", "unresolved_human_review", "unresolved_tool_findings"}
FAMILIES = frozenset(f.value for f in ModelFamily)
HEX64 = re.compile(r"[0-9a-f]{64}")


class SummaryRefused(ValueError):
    """The report may not be exported; nothing is written. `param_hint` names the argument at fault."""

    def __init__(self, message: str, param_hint: str = "REPORT"):
        super().__init__(message)
        self.param_hint = param_hint


def check_label(label: str) -> None:
    """An operator-given name for the target: 1 to 80 code points of letters, marks, numbers, punctuation, symbols and
    spaces (the full-width space too), with no space at either end; no control or format character (bidirectional
    controls and zero-width joiners included) and no line separator. MARA cannot judge what it says; keeping finding
    detail out of it is the operator's responsibility (ADR 0004)."""
    if (not 1 <= len(label) <= 80 or label != label.strip()
            or any(unicodedata.category(c)[0] not in "LMNPSZ" or unicodedata.category(c) in ("Zl", "Zp") for c in label)):
        raise SummaryRefused("a label must be 1 to 80 letters, marks, numbers, punctuation, symbols or spaces, with no "
                             "space at either end and no control or format character", "--label")


def load_report(source: bytes) -> ReviewReport:
    """The review report whose report.json bytes are `source`, if a summary may be made of it."""
    try:
        report = ReviewReport.model_validate_json(source)
    except ValidationError as e:  # damaged, hand-edited or foreign: what crosses the border must come from a sound report
        raise SummaryRefused(f"not a valid MARA review report ({e.error_count()} validation error(s))") from e
    if not report.target_id:  # every such report would get the one pseudonym of the empty id
        raise SummaryRefused("the report has no target_id, so its target cannot be told apart from any other")
    if not Path(report.target).is_absolute():  # mara review writes an absolute path
        raise SummaryRefused(f"the report's target {report.target!r} is a relative path, so where it lies cannot be checked")
    check_fields(report)
    return report


def check_fields(report: ReviewReport) -> None:
    """Apart from the label no free text crosses: each allowlisted string must have the shape its field always has.
    A hand-edited report validates as a ReviewReport with any text in these fields."""
    try:
        generated = dt.datetime.fromisoformat(report.generated_at)
    except ValueError:
        generated = None
    bad = [name for name, ok in (
        ("incomplete_reasons", set(report.incomplete_reasons) <= INCOMPLETE_REASONS),
        ("families_used", set(report.families_used) <= FAMILIES),
        ("provider_mode", report.provider_mode in ("live", "mock")),
        ("generated_at", generated is not None and generated.tzinfo is not None),
        ("config_hash", HEX64.fullmatch(report.config_hash) is not None),
        ("dimension", all(d.dimension in DIMENSION_LABELS for d in report.dimensions)),
    ) if not ok]
    if bad:
        raise SummaryRefused(f"the report holds values no MARA review writes in: {', '.join(bad)}")


def check_destination(out: Path, report_path: Path, report: ReviewReport) -> None:
    """The summary may neither replace the report it is made from (the evidence `source_report_sha256` names) nor
    land in the repository that was reviewed. Only the output is checked: the export reads no config and runs no tool."""
    dest, target = out.resolve(), Path(report.target).resolve()
    if dest == report_path.resolve():
        raise SummaryRefused("the summary may not overwrite the report it is made from", "--out")
    if target in dest.parents:
        raise SummaryRefused(f"the summary may not be written inside the reviewed target {target}", "--out")


def check_key(key: str) -> None:
    """The pseudonym key from MARA_SUMMARY_KEY: at least 32 characters with no surrounding whitespace (a newline read
    in from a key file would silently give other pseudonyms). It stays in the country; nothing exports without it."""
    if len(key) < 32 or key != key.strip():
        raise SummaryRefused("MARA_SUMMARY_KEY must hold the in-country pseudonym key: at least 32 characters, no surrounding "
                             "whitespace (e.g. openssl rand -hex 32)", "MARA_SUMMARY_KEY")


def pseudonyms(report: ReviewReport, key: str) -> dict:
    """Summary pseudonyms of the target and of its revision (bound to the target, so forks sharing a commit are not
    linked): the report's own ids are unkeyed and could be confirmed from a list of candidate repositories."""
    def mac(*parts: str) -> str:
        return hmac.new(key.encode(), "\0".join(parts).encode(), hashlib.sha256).hexdigest()

    return {
        "target_pseudonym": mac("target", report.target_id),
        "revision_pseudonym": mac("revision", report.target_id, report.revision) if report.revision else None,
        "pseudonym_key_id": hashlib.sha256(key.encode()).hexdigest()[:16],
    }


def build_summary(report: ReviewReport, source: bytes, *, key: str, label: str | None = None, allow_mock: bool = False,
                  now: dt.datetime | None = None) -> dict:
    """The score summary of `report`, whose report.json bytes are `source`."""
    check_key(key)
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
        **pseudonyms(report, key),
        **{k: data[k] for k in REPORT_FIELDS},
        "dimensions": [{k: d[k] for k in DIMENSION_FIELDS} for d in data["dimensions"]],
    }


def write_summary(summary: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
