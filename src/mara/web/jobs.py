"""Environment jobs of the workbench (GLOSSARY.md: workbench; docs/adr/0006-local-web-workbench.md): the workspace's
own maintenance scripts, started from the 工具與執行環境 page.

Each job is one of a fixed set of argv lists (no free-form command): install or update the pinned L0 tools
(`scripts/install_tools.py`, every SHA-256 and publisher signature checked as on the command line), download or
check the trivy offline database (`scripts/trivy_db.py`), or evaluate the policies of one config
(`mara check-config`). The scripts live in the workspace, not in the package, so a workspace without them offers no
such job. One job runs at a time; its output goes to `<out>/jobs/<job-id>/job.log`.

Not pure: it starts and stops children through `procs.Children`, whose waiter threads record each exit through it,
reads the workspace and reads and writes the files under `<out>/jobs/`.
"""

from __future__ import annotations

import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..invocation import ProviderMode
from ..tools import pins
from . import procs
from .admission import LaunchError
from .runs import resolve_config

JobKind = Literal["install_tools", "trivy_db_download", "trivy_db_status", "check_config"]
# How long a job may run before it is stopped and recorded timed_out. A tool install or a database download that has
# stalled (a held connection, a mirror that stopped answering) otherwise ran for good, and while it ran admission
# refused every review (mara.web.admission): only a restart of the server ended it.
TIMEOUT_SECONDS: dict[str, float] = {"install_tools": 30 * 60, "trivy_db_download": 30 * 60, "trivy_db_status": 5 * 60,
                                     "check_config": 5 * 60}
SCRIPTS = {"install_tools": "scripts/install_tools.py", "trivy_db_download": "scripts/trivy_db.py", "trivy_db_status": "scripts/trivy_db.py"}


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: JobKind
    only: list[str] = Field(default_factory=list, max_length=20, description="install_tools: these locked tools only")
    config: str = Field(default="", max_length=512, description="check_config: config/*.yaml or config/examples/*.yaml")


def locked_tools(root: Path) -> list[str]:
    """The tools the workspace's lock names (mara.tools.pins), sorted; none when it cannot be read."""
    return sorted(pins.locked_tools(pins.read_lock(root / pins.LOCK)))


def available(root: Path) -> dict[str, bool]:
    """Which jobs this workspace can run (the maintenance scripts are not part of an installed package)."""
    return {kind: (root / script).is_file() for kind, script in SCRIPTS.items()} | {"check_config": True}


class JobRegistry:
    def __init__(self, root: Path, out_dir: Path, *, start: Callable[..., Any] | None = None,
                 table: procs.ChildTable | None = None) -> None:
        self.root = root.resolve()
        self.jobs_dir = out_dir.resolve() / "jobs"
        self.children = procs.Children("job", self._record_exit, start=start, table=table)
        self.timeouts = dict(TIMEOUT_SECONDS)  # by kind; a test shortens one
        self._timers: dict[str, threading.Timer] = {}
        self._timed_out: set[str] = set()
        self._lock = threading.Lock()

    def argv(self, req: JobRequest) -> list[str]:
        if req.kind in SCRIPTS and not available(self.root)[req.kind]:
            raise LaunchError("job_unavailable", f"{SCRIPTS[req.kind]} is not in the workspace {self.root}")
        if req.kind == "install_tools":
            known = set(locked_tools(self.root))
            unknown = [t for t in req.only if t not in known]
            if unknown:
                raise LaunchError("unknown_tool", f"not in tools/versions.lock: {', '.join(unknown)}")
            return [sys.executable, str(self.root / SCRIPTS["install_tools"]), *(["--only", *req.only] if req.only else [])]
        if req.kind in ("trivy_db_download", "trivy_db_status"):
            return [sys.executable, str(self.root / SCRIPTS[req.kind]), "download" if req.kind == "trivy_db_download" else "status"]
        cfg = resolve_config(self.root, req.config, ProviderMode.live)
        return [sys.executable, "-m", "mara.cli", "check-config", str(cfg)]

    def create(self, req: JobRequest) -> dict[str, Any]:
        argv = self.argv(req)

        def record(job_id: str, _: Path) -> tuple[list[str], dict[str, Any]]:
            return argv, {"id": job_id, "kind": req.kind, "request": req.model_dump(), "argv": argv, "status": "running",
                          "started_at": procs.now(), "finished_at": None, "exit_code": None}

        job_id, job = self.children.launch(req.kind, self.jobs_dir, record="job.json", log="job.log", cwd=self.root,
                                           env=procs.child_env(self.root), prepare=record)
        timer = threading.Timer(self.timeouts[req.kind], self._time_out, [job_id])
        timer.daemon = True  # never keeps the server alive; the exit stops the job itself (ChildTable.shutdown)
        with self._lock:
            self._timers[job_id] = timer
        timer.start()
        if not self.children.running(job_id):  # it exited before its timer was there to be cancelled
            self._forget_timer(job_id)
        return self.get(job_id) or job

    def _forget_timer(self, job_id: str) -> None:
        with self._lock:
            timer = self._timers.pop(job_id, None)
        if timer is not None:
            timer.cancel()

    def _time_out(self, job_id: str) -> None:
        """Stop a job that ran for its kind's timeout; its exit is then recorded timed_out."""
        with self._lock:
            self._timed_out.add(job_id)
        if self.children.stop(job_id) != "stopped":  # it exited by itself meanwhile: recorded as it ended
            with self._lock:
                self._timed_out.discard(job_id)

    def cancel(self, job_id: str) -> dict[str, Any]:
        """Stop a running job and its process group, as a review is cancelled (RunRegistry.cancel); a job that is not
        running, or that exited by itself meanwhile, is refused with job_not_running (409)."""
        if not procs.ID_RE.match(job_id) or self.children.stop(job_id) != "stopped":
            raise LaunchError("job_not_running", f"job {job_id} is not running", status=409)
        return self.get(job_id) or {"id": job_id, "status": "cancelled"}

    def _record_exit(self, job_id: str, code: int, stopped: bool) -> None:
        """Record how a job ended: timed_out when its timeout stopped it, cancelled when anything else did (a cancel, the
        server's exit), else finished or failed by its exit code."""
        self._forget_timer(job_id)
        with self._lock:
            timed_out = job_id in self._timed_out
            self._timed_out.discard(job_id)
        d = self.jobs_dir / job_id
        job = procs.read_json(d / "job.json") or {"id": job_id}
        status = "timed_out" if timed_out else "cancelled" if stopped else "finished" if code == 0 else "failed"
        job.update(status=status, exit_code=code, finished_at=procs.now())
        procs.write_json(d / "job.json", job)

    def stop_survivors(self, grace: float = procs.STOP_GRACE_SECONDS) -> list[str]:
        """Stop every job a server that has ended left running (procs.left_by_a_server_that_ended) and record it interrupted; a job left
        running kept replacing the tools or the database under the reviews this server admitted. Returns the jobs
        stopped."""
        stopped = []
        for d in sorted(self.jobs_dir.iterdir()) if self.jobs_dir.is_dir() else []:
            job = procs.read_json(d / "job.json")
            if job is None or job.get("status") != "running" or self.children.running(d.name):
                continue
            if procs.left_by_a_server_that_ended(job) and procs.stop_survivor(job.get("pid"), job.get("argv"), grace):
                job.update(status="interrupted", finished_at=procs.now())
                procs.write_json(d / "job.json", job)
                stopped.append(d.name)
        return stopped

    def get(self, job_id: str, lines: int = 400) -> dict[str, Any] | None:
        if not procs.ID_RE.match(job_id):
            return None
        d = self.jobs_dir / job_id
        job, owned = self.children.read(job_id, d / "job.json")  # in one step under the lock its exit is recorded under
        if job is None:
            return None
        if job.get("status") == "running" and not owned:  # a job of an earlier server, or one whose waiter stopped
            job["status"] = "interrupted"
        job["log_tail"] = procs.tail(d / "job.log", lines=lines)
        return job

    def list(self) -> list[dict[str, Any]]:
        if not self.jobs_dir.is_dir():
            return []
        ids = sorted((d.name for d in self.jobs_dir.iterdir() if procs.ID_RE.match(d.name)), reverse=True)[:20]
        return [j for j in (self.get(i, lines=0) for i in ids) if j is not None]
