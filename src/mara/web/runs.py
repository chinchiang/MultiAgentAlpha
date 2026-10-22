"""Runs of the workbench (GLOSSARY.md: run, progress record, workbench; docs/adr/0006-local-web-workbench.md): one
`mara review` subprocess per run, one directory per run under `<out>/runs/<run-id>/`.

A launch is validated here exactly as the command line validates it (paths resolved, `workspace.check_outside`
with the config, output, evidence and progress paths, the config loaded under policies P1-P8, the provider mode
matching the config) so a browser gets a clear refusal instead of a failed run, and the subprocess repeats every
check anyway. `run.json` is the record of a run: the request as given, the argv, the roles and models of the
config at launch (the config file may change later, and the report keeps only the provider manifest), status
and exit code. The exit code alone is ambiguous (2 is a usage error and an enforced gate alike), so a run counts
as finished only when its progress record says the reports were written.

PSIRT hand-off options (`--notify-psirt`, `--psirt-event`) are not offered: they start EU CRA Article 14 clocks
and stay a deliberate command-line step.

Not pure: it starts and stops children through `procs.Children`, whose waiter threads record each exit through it,
reads the config and the workspace, and reads and writes the files under `<out>/runs/`.
"""

from __future__ import annotations

import re
import sys
import threading
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from .. import progress as progress_mod
from ..schemas import ReviewReport
from ..workspace import WorkspaceInsideTarget, check_outside
from . import admission, procs, views

ARTIFACTS = ("report.md", "report.json", "report.sarif", "human_queue.md", "human_queue.json", "context.json",
             "psirt-notifications.json", "pipeline.log", "run.log", "progress.json")
IMPORTED_ID = "workspace-out"  # a review written by `mara review` into <workspace>/out, shown read-only
BASE_REF_RE = re.compile(r"^[A-Za-z0-9._/@^~{}-]{1,200}$")
STATUSES = ("running", "finished", "failed", "cancelled", "interrupted")


class LaunchError(ValueError):
    """A request the workbench refuses; `code` is what the page translates, `message` the detail."""

    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message
        self.status = status


class LaunchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=1, max_length=4096, description="Directory to review, absolute or relative to the workspace")
    provider: Literal["mock", "live"] = "mock"
    config: str = Field(default="", max_length=512, description="config/*.yaml or config/examples/*.yaml; empty: the default for the provider")
    sarif_dir: str = Field(default="", max_length=4096, description="Pre-recorded L0 SARIF instead of running the tools (inside the workspace)")
    mock_fixtures: str = Field(default="", max_length=4096, description="Another set of mock responses (inside the workspace)")
    base: str = Field(default="", max_length=200, description="Incremental review against this git ref")
    fail_on_gate: bool = False
    calibration_sample: bool = False
    title: str = Field(default="", max_length=120)


def clean_title(text: str) -> str:
    """One line of printable text: control and format characters removed, whitespace collapsed."""
    kept = "".join(ch for ch in text if unicodedata.category(ch)[0] != "C")
    return " ".join(kept.split())[:120]


def config_dirs(workspace: Path) -> tuple[Path, Path]:
    return (workspace / "config").resolve(), (workspace / "config" / "examples").resolve()


def resolve_path(workspace: Path, value: str) -> Path:
    """`value` resolved, relative to `workspace` unless absolute; LaunchError bad_path when it is not a usable path."""
    try:
        p = Path(value.strip()).expanduser()
        return (p if p.is_absolute() else workspace / p).resolve()
    except (ValueError, RuntimeError, OSError) as e:  # a NUL byte, a symlink loop, an unknown ~user
        raise LaunchError("bad_path", f"{value[:200]!r}: not a usable path ({type(e).__name__})") from e


def resolve_config(workspace: Path, value: str, provider: str) -> Path:
    """The config file `value` names, or the provider's default when it is empty, if it is a YAML file under config/ or
    config/examples/ of `workspace`; LaunchError config_not_found otherwise (bad_path, from resolve_path)."""
    if value:
        cfg_path = resolve_path(workspace, value)
    else:
        cfg_path = (workspace / "config" / ("mara.mock.yaml" if provider == "mock" else "mara.yaml")).resolve()
    if cfg_path.parent not in config_dirs(workspace) or cfg_path.suffix not in (".yaml", ".yml") or not cfg_path.is_file():
        raise LaunchError("config_not_found", f"{value or cfg_path}: not a config file under config/ or config/examples/")
    return cfg_path


class RunRegistry:
    def __init__(self, workspace: Path, out_dir: Path, *, start: Callable[..., Any] | None = None,
                 table: procs.ChildTable | None = None) -> None:
        self.workspace = workspace.resolve()
        self.out_dir = out_dir.resolve()
        self.runs_dir = self.out_dir / "runs"
        self.children = procs.Children("run", self._record_exit, start=start, table=table)
        self._reports_lock = threading.Lock()
        self._reports: dict[str, tuple[int, int, ReviewReport]] = {}

    # ------------------------------------------------------------------ validation
    def _inside_workspace(self, p: Path) -> bool:
        return p == self.workspace or self.workspace in p.parents

    def prepare(self, req: LaunchRequest) -> tuple[list[str], dict[str, Any]]:
        """argv and the manifest fields of a valid request; LaunchError otherwise."""
        from ..config import load_config

        target = resolve_path(self.workspace, req.target)
        if not target.is_dir():
            raise LaunchError("target_not_dir", f"{target}: not a directory")
        cfg_path = resolve_config(self.workspace, req.config, req.provider)
        dirs: dict[str, Path] = {}
        inputs = (("--sarif-dir", req.sarif_dir, "sarif_dir_not_dir"), ("--mock-fixtures", req.mock_fixtures, "mock_fixtures_not_dir"))
        for flag, value, code in inputs:
            if value:
                p = resolve_path(self.workspace, value)
                if not p.is_dir():
                    raise LaunchError(code, f"{p}: not a directory")
                if not self._inside_workspace(p):
                    raise LaunchError("path_outside_workspace", f"{flag} {p}: evidence inputs must lie inside the workspace {self.workspace}")
                dirs[flag] = p
        base = req.base.strip()
        if base and (base.startswith("-") or not BASE_REF_RE.match(base)):
            raise LaunchError("bad_base_ref", f"{base!r}: not a git ref")
        try:
            check_outside(target, {f"the config file {cfg_path}": cfg_path, f"the output directory {self.runs_dir}": self.runs_dir,
                                   **{f"{flag} {p}": p for flag, p in dirs.items()}})
        except WorkspaceInsideTarget as e:
            raise LaunchError("inside_target", str(e)) from e
        try:
            cfg = load_config(cfg_path)
        except Exception as e:  # pydantic, YAML or policy refusal: the CLI would refuse the same file
            raise LaunchError("config_invalid", " ".join(str(e).split())[:800]) from e
        kinds = {m.provider for m in cfg.models}
        if (req.provider == "mock") != (kinds == {"mock"}) or (req.provider == "live" and "mock" in kinds):
            raise LaunchError("provider_mismatch", f"{cfg_path.name} has {sorted(kinds)} providers; provider {req.provider} needs "
                              + ("only mock models" if req.provider == "mock" else "no mock model"))
        models = [{"name": m.name, "family": m.family.value, "provider": m.provider, "model": m.model, "data_residency": m.data_residency,
                   "region": m.region, "api_key_env": m.api_key_env, "endpoint_host": urlparse(m.base_url).hostname if m.base_url else None}
                  for m in cfg.models]
        r = cfg.roles
        fields = {
            "target": str(target),
            "config": cfg_path.relative_to(self.workspace).as_posix(),
            "provider": req.provider,
            "roles": {"context": r.context, "reviewers": list(r.reviewers), "skeptic": r.skeptic, "redteam": r.redteam, "judges": list(r.judges)},
            "models": models,
            "dimensions": list(cfg.dimensions),
            "rollout_phase": cfg.rollout.phase,
            "gate": {"min_dimension_score": cfg.gate.min_dimension_score, "block_on_tiers": list(cfg.gate.block_on_tiers),
                     "block_on_severity": list(cfg.gate.block_on_severity), "accept_threshold": cfg.gate.accept_threshold},
        }
        argv = [sys.executable, "-m", "mara.cli", "review", str(target), "--provider", req.provider, "--config", str(cfg_path)]
        for flag, p in dirs.items():
            argv += [flag, str(p)]
        if base:
            argv.append(f"--base={base}")  # one argument: the ref can never be read as an option
        if req.fail_on_gate:
            argv.append("--fail-on-gate")
        if req.calibration_sample:
            argv.append("--calibration-sample")
        return argv, fields

    # ------------------------------------------------------------------ lifecycle
    def busy(self) -> bool:
        return self.children.any_running()

    def create(self, req: LaunchRequest) -> dict[str, Any]:
        argv, fields = self.prepare(req)
        with self.children.held():  # the lock of every registry's children: the check and the start are one step
            if self.children.table.closed:  # the server exit took the children: before anything is written
                raise LaunchError("stopping", "the server is stopping: no review or job is started", status=503)
            if refused := admission.refusal("run", self.children.table.running_tags()):
                raise LaunchError("busy", refused, status=409)
            run_id = procs.new_id()
            run_dir = self.runs_dir / run_id
            run_dir.mkdir(parents=True)
            argv = [*argv, "--out", str(run_dir), "--progress-file", str(run_dir / "progress.json")]
            manifest: dict[str, Any] = {
                "id": run_id,
                "title": clean_title(req.title) or Path(fields["target"]).name,
                **fields,
                "request": req.model_dump(),
                "argv": argv,
                "status": "running",
                "started_at": procs.now(),
                "finished_at": None,
                "exit_code": None,
                "pid": None,
                "gate_enforced": False,
                "psirt_failed": False,
            }
            procs.write_json(run_dir / "run.json", manifest)
            try:
                pid = self.children.start(run_id, argv, cwd=self.workspace, log_path=run_dir / "run.log",
                                          env=procs.child_env(self.workspace), tag="run")
            except OSError as e:
                manifest.update(status="failed", finished_at=procs.now(), error=type(e).__name__)
                procs.write_json(run_dir / "run.json", manifest)
                raise LaunchError("spawn_failed", str(e), status=500) from e
            manifest["pid"] = pid
            procs.write_json(run_dir / "run.json", manifest)
        return self.get(run_id) or manifest

    def _record_exit(self, run_id: str, code: int, stopped: bool) -> None:
        run_dir = self.runs_dir / run_id
        manifest = procs.read_json(run_dir / "run.json") or {"id": run_id}
        prog = progress_mod.read(run_dir / "progress.json")
        finished = bool(prog and prog.get("status") == "finished")
        status = "cancelled" if stopped else "finished" if finished else "failed"
        if not finished:
            progress_mod.close_abandoned(run_dir / "progress.json", "cancelled" if status == "cancelled" else f"exit {code}")
        manifest.update(status=status, exit_code=code, finished_at=procs.now(),
                        gate_enforced=finished and _gate_enforced(run_dir, code), psirt_failed=finished and code == 3)
        procs.write_json(run_dir / "run.json", manifest)

    def cancel(self, run_id: str) -> dict[str, Any]:
        # a run whose child exited by itself has nothing to stop and is not cancelled: stop() waits for its exit to be recorded
        if self.children.stop(run_id) != "stopped":
            raise LaunchError("not_running", f"run {run_id} is not running", status=409)
        return self.get(run_id) or {"id": run_id, "status": "cancelled"}

    def rerun(self, run_id: str) -> dict[str, Any]:
        manifest = self._manifest(run_id)
        if manifest is None or not isinstance(manifest.get("request"), dict):
            raise LaunchError("not_found", f"run {run_id} has no request to repeat", status=404)
        return self.create(LaunchRequest.model_validate(manifest["request"]))

    # ------------------------------------------------------------------ reading
    def run_dir(self, run_id: str) -> Path | None:
        if run_id == IMPORTED_ID:
            d = self.workspace / "out"
            return d if (d / "report.json").is_file() else None
        if not procs.ID_RE.match(run_id):
            return None
        d = self.runs_dir / run_id
        return d if (d / "run.json").is_file() else None

    def _manifest(self, run_id: str) -> dict[str, Any] | None:
        d = self.run_dir(run_id)
        if d is None:
            return None
        if run_id == IMPORTED_ID:
            return {"id": IMPORTED_ID, "imported": True, "title": "out/report.json", "status": "finished", "provider": None,
                    "target": None, "started_at": None, "finished_at": None, "exit_code": None, "argv": [], "roles": {}, "models": []}
        return procs.read_json(d / "run.json")

    def progress(self, run_id: str) -> dict[str, Any] | None:
        d = self.run_dir(run_id)
        return progress_mod.read(d / "progress.json") if d is not None else None

    def report(self, run_id: str) -> ReviewReport | None:
        """The run's report.json, validated (so the outcome properties are those of mara.schemas); None when absent or
        unreadable. Cached until the file changes."""
        d = self.run_dir(run_id)
        if d is None:
            return None
        path = d / "report.json"
        try:
            st = path.stat()
        except OSError:
            return None
        with self._reports_lock:
            cached = self._reports.get(run_id)
            if cached and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
                return cached[2]
        try:
            report = ReviewReport.model_validate_json(path.read_bytes())
        except (OSError, ValueError):
            return None
        with self._reports_lock:
            self._reports[run_id] = (st.st_mtime_ns, st.st_size, report)
        return report

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self.children.held():  # a run's exit is recorded under this lock: read run.json and whether it runs in one step
            manifest = self._manifest(run_id)
            owned = self.children.running(run_id)
        if manifest is None:
            return None
        prog = self.progress(run_id)
        if manifest.get("status") == "running" and not owned:
            # a run of an earlier server, or one whose waiter stopped without recording its exit: the progress record decides
            st = (prog or {}).get("status")
            manifest["status"] = "finished" if st == "finished" else "failed" if st == "failed" else "interrupted"
        manifest["current_stage"] = (prog or {}).get("current")
        manifest["stages_done"] = sum(1 for s in (prog or {}).get("stages", []) if s.get("status") in ("done", "skipped"))
        report = self.report(run_id)
        manifest["has_report"] = report is not None
        manifest["summary"] = views.summary(report) if report is not None else None
        if run_id == IMPORTED_ID and report is not None:
            manifest.update(target=report.target, provider=report.provider_mode, finished_at=report.generated_at,
                            started_at=report.generated_at)
        d = self.run_dir(run_id)
        manifest["artifacts"] = [n for n in ARTIFACTS if d is not None and (d / n).is_file()]
        return manifest

    def list(self) -> list[dict[str, Any]]:
        ids = []
        if self.runs_dir.is_dir():
            ids = sorted((d.name for d in self.runs_dir.iterdir() if procs.ID_RE.match(d.name) and (d / "run.json").is_file()), reverse=True)
        if self.run_dir(IMPORTED_ID) is not None:
            ids.append(IMPORTED_ID)
        return [m for m in (self.get(i) for i in ids) if m is not None]

    def view(self, run_id: str) -> dict[str, Any] | None:
        manifest = self.get(run_id)
        report = self.report(run_id)
        if manifest is None or report is None:
            return None
        return views.report_view(manifest, report, self.progress(run_id))

    def log(self, run_id: str, lines: int = 400) -> dict[str, Any] | None:
        d = self.run_dir(run_id)
        if d is None:
            return None
        prog = self.progress(run_id) or {}
        return {"run_log": procs.tail(d / "run.log", lines=lines), "pipeline_log": procs.tail(d / "pipeline.log", lines=lines),
                "progress_log": list(prog.get("log") or [])[-lines:]}

    def artifact(self, run_id: str, name: str) -> Path | None:
        d = self.run_dir(run_id)
        if d is None or name not in ARTIFACTS:
            return None
        p = d / name
        return p if p.is_file() else None


def _gate_enforced(run_dir: Path, code: int) -> bool:
    """Whether the finished review enforced its gate, as its report records it (docs/adr/0007-review-status-and-gate.md):
    the exit code cannot say, since a failed PSIRT hand-off's 3 outranks the gate's 2. Only a report written before the
    field leaves the exit code to go by."""
    report = procs.read_json(run_dir / "report.json") or {}
    recorded = report.get("gate_enforced")
    return recorded if isinstance(recorded, bool) else code == 2
