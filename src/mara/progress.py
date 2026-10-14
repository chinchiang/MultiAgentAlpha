"""Live progress of one review, for the local workbench (docs/adr/0006-local-web-workbench.md).

`mara review --progress-file PATH` hands the pipeline a Progress that rewrites PATH at every stage boundary and
every pipeline log line, so `mara serve` can show where a running review is before any report exists
(`pipeline.log` is written only once the review has finished). The nine stages are the order in which
`Pipeline.run()` works; the workbench draws them as its pipeline stepper.

Progress is a view, never evidence: nothing reads it back into a report, and a progress file that cannot be
written is logged and skipped rather than failing the review it describes. Without a path every call is a no-op,
so the pipeline always has one and tests and other callers need not pass it.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any

_log = logging.getLogger("mara.progress")

PROGRESS_VERSION = 1

STAGES: tuple[str, ...] = ("bundle", "tools", "context", "reviewers", "skeptic", "redteam", "jury", "scoring", "report")
"""bundle: L1 repo map and file bundle; tools: L0 tools and the live secret preflight; context: L1 context agent;
reviewers: L2; skeptic and redteam: L3; jury: L4 (forward and reverse passes); scoring: L5 consensus, tiers,
dimension scores and gate; report: assembly of the report, the human queue and the PSIRT hand-off."""

STAGE_STATUSES = ("pending", "running", "done", "skipped", "failed")
RUN_STATUSES = ("running", "finished", "failed")
LOG_LINES = 400  # the newest pipeline log lines kept in the file; pipeline.log keeps them all
NOTE_CHARS = 300


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")


class Progress:
    """The progress of one review. `path` None: nothing is recorded or written."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._lock = threading.RLock()  # state change and file write happen together
        self._state: dict[str, Any] = {
            "version": PROGRESS_VERSION,
            "status": "running",
            "started_at": _now(),
            "finished_at": None,
            "error": "",
            "current": None,
            "stages": [{"id": s, "status": "pending", "started_at": None, "finished_at": None, "note": ""} for s in STAGES],
            "log": [],
        }
        self._write()

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def _stage(self, stage: str) -> dict[str, Any]:
        for s in self._state["stages"]:
            if s["id"] == stage:
                return s
        raise ValueError(f"unknown progress stage {stage!r}; expected one of {', '.join(STAGES)}")

    def _set(self, stage: str, status: str, note: str) -> None:
        if not self.enabled:
            self._stage(stage)  # an unknown stage name is a programming error with or without a file
            return
        with self._lock:
            s = self._stage(stage)
            now = _now()
            if status == "running":
                s["started_at"] = now
                self._state["current"] = stage
            else:
                s["started_at"] = s["started_at"] or now
                s["finished_at"] = now
                if self._state["current"] == stage:
                    self._state["current"] = None
            s["status"] = status
            if note:
                s["note"] = note[:NOTE_CHARS]
            self._write()

    def begin(self, stage: str, note: str = "") -> None:
        self._set(stage, "running", note)

    def done(self, stage: str, note: str = "") -> None:
        self._set(stage, "done", note)

    def skip(self, stage: str, note: str = "") -> None:
        self._set(stage, "skipped", note)

    def log(self, line: str) -> None:
        """One pipeline log line (Pipeline._say); only the newest LOG_LINES are kept."""
        if not self.enabled:
            return
        with self._lock:
            lines = self._state["log"]
            lines.append(line)
            del lines[:-LOG_LINES]
            self._write()

    def finish(self, ok: bool, error: str = "") -> None:
        """The review ended: `ok` after the reports were written, otherwise the stage then running is marked failed."""
        if not self.enabled:
            return
        with self._lock:
            now = _now()
            if not ok:
                for s in self._state["stages"]:
                    if s["status"] == "running":
                        s["status"] = "failed"
                        s["finished_at"] = now
            self._state["status"] = "finished" if ok else "failed"
            self._state["finished_at"] = now
            self._state["error"] = error[:NOTE_CHARS]
            self._state["current"] = None
            self._write()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def _write(self) -> None:
        if self.path is None:
            return
        with self._lock:
            text = json.dumps(self._state, ensure_ascii=False, indent=1)
            tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                tmp.write_text(text, encoding="utf-8")
                os.replace(tmp, self.path)  # a reader sees the old or the new file, never half of one
            except OSError as e:
                # a view of the review, never part of it: a reader holding the file open on Windows, a full disk
                _log.warning("progress file %s not written: %s", self.path, e)
                try:
                    tmp.unlink(missing_ok=True)
                except OSError:
                    pass


def read(path: Path) -> dict[str, Any] | None:
    """The progress file at `path`, or None when it is missing, unreadable or not a version-1 progress record."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("version") != PROGRESS_VERSION or not isinstance(data.get("stages"), list):
        return None
    return data
