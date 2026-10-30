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
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from ..invocation import ProviderMode
from . import admission, procs
from .runs import LaunchError, resolve_config

JobKind = Literal["install_tools", "trivy_db_download", "trivy_db_status", "check_config"]
SCRIPTS = {"install_tools": "scripts/install_tools.py", "trivy_db_download": "scripts/trivy_db.py", "trivy_db_status": "scripts/trivy_db.py"}


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
    def __init__(self, workspace: Path, out_dir: Path, *, start: Callable[..., Any] | None = None,
                 table: procs.ChildTable | None = None) -> None:
        self.workspace = workspace.resolve()
        self.jobs_dir = out_dir.resolve() / "jobs"
        self.children = procs.Children("job", self._record_exit, start=start, table=table)

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
        cfg = resolve_config(self.workspace, req.config, ProviderMode.live)
        return [sys.executable, "-m", "mara.cli", "check-config", str(cfg)]

    def create(self, req: JobRequest) -> dict[str, Any]:
        argv = self.argv(req)
        with self.children.held():  # the lock of every registry's children: the check and the start are one step
            if self.children.table.closed:  # the server exit took the children: before anything is written
                raise LaunchError("stopping", "the server is stopping: no review or job is started", status=503)
            if refused := admission.refusal(req.kind, self.children.table.running_tags()):
                raise LaunchError("busy", refused, status=409)
            job_id = procs.new_id()
            d = self.jobs_dir / job_id
            d.mkdir(parents=True)
            job: dict[str, Any] = {"id": job_id, "kind": req.kind, "request": req.model_dump(), "argv": argv, "status": "running",
                                   "started_at": procs.now(), "finished_at": None, "exit_code": None}
            procs.write_json(d / "job.json", job)
            try:
                self.children.start(job_id, argv, cwd=self.workspace, log_path=d / "job.log", env=procs.child_env(self.workspace),
                                    tag=req.kind)
            except OSError as e:
                job.update(status="failed", finished_at=procs.now())
                procs.write_json(d / "job.json", job)
                raise LaunchError("spawn_failed", str(e), status=500) from e
        return self.get(job_id) or job

    def _record_exit(self, job_id: str, code: int, stopped: bool) -> None:
        d = self.jobs_dir / job_id
        job = procs.read_json(d / "job.json") or {"id": job_id}
        job.update(status="finished" if code == 0 else "failed", exit_code=code, finished_at=procs.now())
        procs.write_json(d / "job.json", job)

    def get(self, job_id: str, lines: int = 400) -> dict[str, Any] | None:
        if not procs.ID_RE.match(job_id):
            return None
        d = self.jobs_dir / job_id
        with self.children.held():  # a job's exit is recorded under this lock: read job.json and whether it runs in one step
            job = procs.read_json(d / "job.json")
            owned = self.children.running(job_id)
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
