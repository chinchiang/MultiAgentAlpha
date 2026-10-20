"""Environment jobs of the workbench (GLOSSARY.md: workbench; docs/adr/0006-local-web-workbench.md): the workspace's
own maintenance scripts, started from the 工具與執行環境 page.

Each job is one of a fixed set of argv lists (no free-form command): install or update the pinned L0 tools
(`scripts/install_tools.py`, every SHA-256 and publisher signature checked as on the command line), download or
check the trivy offline database (`scripts/trivy_db.py`), or evaluate the policies of one config
(`mara check-config`). The scripts live in the workspace, not in the package, so a workspace without them offers no
such job. One job runs at a time; its output goes to `<out>/jobs/<job-id>/job.log`.

Not pure: it starts and stops children and waits for them on threads of its own, reads the workspace and reads and
writes the files under `<out>/jobs/`.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from . import procs
from .runs import LaunchError, RunRegistry

JobKind = Literal["install_tools", "trivy_db_download", "trivy_db_status", "check_config"]
SCRIPTS = {"install_tools": "scripts/install_tools.py", "trivy_db_download": "scripts/trivy_db.py", "trivy_db_status": "scripts/trivy_db.py"}
CHANGES_TOOLS = frozenset({"install_tools", "trivy_db_download"})  # never while a review executes the tools or reads the database


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: JobKind
    only: list[str] = Field(default_factory=list, max_length=20, description="install_tools: these locked tools only")
    config: str = Field(default="", max_length=512, description="check_config: config/*.yaml or config/examples/*.yaml")


def locked_tools(workspace: Path) -> list[str]:
    try:
        lock = yaml.safe_load((workspace / "tools" / "versions.lock").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    tools = lock.get("tools") if isinstance(lock, dict) else None
    return sorted(tools) if isinstance(tools, dict) else []


def available(workspace: Path) -> dict[str, bool]:
    """Which jobs this workspace can run (the maintenance scripts are not part of an installed package)."""
    return {kind: (workspace / script).is_file() for kind, script in SCRIPTS.items()} | {"check_config": True}


class JobRegistry:
    def __init__(self, workspace: Path, out_dir: Path, runs: RunRegistry) -> None:
        self.workspace = workspace.resolve()
        self.jobs_dir = out_dir.resolve() / "jobs"
        self.runs = runs  # for the config allowlist, whether a run is running (busy()) and the launch lock (launching)
        self._lock = threading.RLock()
        self._procs: dict[str, Any] = {}
        self._waiters: dict[str, threading.Thread] = {}
        self._kinds: dict[str, str] = {}

    def argv(self, req: JobRequest) -> list[str]:
        if req.kind in SCRIPTS and not available(self.workspace)[req.kind]:
            raise LaunchError("job_unavailable", f"{SCRIPTS[req.kind]} is not in the workspace {self.workspace}")
        if req.kind == "install_tools":
            known = set(locked_tools(self.workspace))
            unknown = [t for t in req.only if t not in known]
            if unknown:
                raise LaunchError("unknown_tool", f"not in tools/versions.lock: {', '.join(unknown)}")
            return [sys.executable, str(self.workspace / SCRIPTS["install_tools"]), *(["--only", *req.only] if req.only else [])]
        if req.kind in ("trivy_db_download", "trivy_db_status"):
            return [sys.executable, str(self.workspace / SCRIPTS[req.kind]), "download" if req.kind == "trivy_db_download" else "status"]
        cfg = self.runs.resolve_config(req.config, "live")
        return [sys.executable, "-m", "mara.cli", "check-config", str(cfg)]

    def create(self, req: JobRequest) -> dict[str, Any]:
        argv = self.argv(req)
        with self.runs.launching, self._lock:
            if any(w.is_alive() for w in self._waiters.values()):  # a job is running while its waiter is alive, as get() reads it
                raise LaunchError("busy", "an environment job is already running", status=409)
            if req.kind in CHANGES_TOOLS and self.runs.busy():
                raise LaunchError("busy", "a review is running with the installed tools; wait for it or cancel it", status=409)
            job_id = procs.new_id()
            d = self.jobs_dir / job_id
            d.mkdir(parents=True)
            job: dict[str, Any] = {"id": job_id, "kind": req.kind, "request": req.model_dump(), "argv": argv, "status": "running",
                                   "started_at": procs.now(), "finished_at": None, "exit_code": None}
            procs.write_json(d / "job.json", job)
            try:
                proc = procs.spawn(argv, cwd=self.workspace, log_path=d / "job.log", env=procs.child_env(self.workspace))
            except OSError as e:
                job.update(status="failed", finished_at=procs.now())
                procs.write_json(d / "job.json", job)
                raise LaunchError("spawn_failed", str(e), status=500) from e
            self._procs[job_id] = proc
            self._kinds[job_id] = req.kind
            waiter = threading.Thread(target=self._wait, args=(job_id, proc), name=f"mara-job-{job_id}", daemon=True)
            self._waiters[job_id] = waiter
            waiter.start()
        return self.get(job_id) or job

    def changing_tools(self) -> bool:
        """A running job that replaces the tools or the trivy database (a run must not start meanwhile)."""
        with self._lock:
            return any(w.is_alive() and self._kinds.get(j) in CHANGES_TOOLS for j, w in self._waiters.items())

    def _wait(self, job_id: str, proc: Any) -> None:
        code = proc.wait()
        d = self.jobs_dir / job_id
        with self._lock:
            job = procs.read_json(d / "job.json") or {"id": job_id}
            job.update(status="finished" if code == 0 else "failed", exit_code=code, finished_at=procs.now())
            procs.write_json(d / "job.json", job)
            self._procs.pop(job_id, None)

    def get(self, job_id: str, lines: int = 400) -> dict[str, Any] | None:
        if not procs.ID_RE.match(job_id):
            return None
        d = self.jobs_dir / job_id
        with self._lock:  # the waiter records a job's exit under the lock: read job.json and the waiter in one step
            job = procs.read_json(d / "job.json")
            waiter = self._waiters.get(job_id)
            owned = waiter is not None and waiter.is_alive()
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

    def shutdown(self) -> None:
        """Server exit: stop the child of every job whose child still runs, so that the job is recorded with the exit code
        the stop gave (failed, or finished if it is 0); then give the waiter of every job still running, one whose child
        exited by itself included, up to 15 s to record the exit."""
        with self._lock:
            waiters = [w for w in self._waiters.values() if w.is_alive()]
            to_stop = [p for p in self._procs.values() if p.poll() is None]
        for p in to_stop:
            procs.stop(p)
        for w in waiters:  # a waiter still alive after 15 s leaves job.json without the exit code
            w.join(timeout=15)
