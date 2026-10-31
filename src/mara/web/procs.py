"""Child processes and small files of the workbench (GLOSSARY.md: workbench, run; docs/adr/0006-local-web-workbench.md):
one way to start, stop and read a run or an environment job, and to launch one with its record (Children.launch): the
closed table and the admission checked, the child's directory and record written, the child started and its pid recorded,
in one step under the table's lock.

Every child is an argv list started without a shell, from the MARA workspace, with MARA_HOME pointing at it and
the `mara` package the server itself runs on first on PYTHONPATH, so the child runs the `mara` the server was started
from. Nothing a browser sends reaches the environment; values reach argv only after the caller validated them.
Output goes to a log file, never through a pipe the server would have to drain.

Not pure: it starts and stops children and waits for them on threads of its own, copies the server's environment into
theirs, reads the clock (ids, timestamps and the deadlines of a stop) and a random source (ids and temporary file
names), creates a launched child's directory, and reads and writes the files it is given.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from . import admission
from .admission import LaunchError

ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
STOP_GRACE_SECONDS = 10.0
KILL_WAIT_SECONDS = 5.0  # how long a stop waits for the children it killed to exit
WAITER_JOIN_SECONDS = 15.0  # how long ChildTable.stop() and ChildTable.shutdown() wait for each waiter to record an exit


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="seconds")


def new_id() -> str:
    """Sortable by start time: YYYYMMDD-HHMMSS-<6 hex>."""
    return dt.datetime.now(dt.UTC).strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3)


def write_json(path: Path, data: Any) -> None:
    """Replace `path` atomically, so a concurrent reader sees the old or the new record, never half of one."""
    # one temporary name per writer: two request threads saving the same record must not share one
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.{secrets.token_hex(4)}.tmp")
    try:
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def package_root() -> Path:
    """The directory holding the `mara` package this server runs (src/ in a checkout, site-packages when installed)."""
    import mara

    return Path(mara.__file__).resolve().parents[1]


def child_env(workspace: Path) -> dict[str, str]:
    """The server's environment (provider keys and AWS credentials included: a live review needs them) plus the
    workspace, the package path and plain, unbuffered UTF-8 output for the log file."""
    env = dict(os.environ)
    env["MARA_HOME"] = str(workspace)
    pkg = str(package_root())
    env["PYTHONPATH"] = pkg + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.update({"NO_COLOR": "1", "TERM": "dumb", "COLUMNS": "160", "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"})
    return env


def spawn(argv: list[str], *, cwd: Path, log_path: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    """Start `argv` (no shell) with stdout and stderr appended to `log_path`, in its own process group so that a
    cancel reaches the tools it runs and a Ctrl-C meant for the server does not."""
    with open(log_path, "ab") as log:
        if sys.platform == "win32":
            return subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        return subprocess.Popen(argv, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)


def terminate(proc: subprocess.Popen[bytes]) -> None:
    """Ask the child and its process group to exit (SIGTERM; terminate() on Windows)."""
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def kill(proc: subprocess.Popen[bytes]) -> None:
    """Kill the child and its process group (SIGKILL; kill() on Windows)."""
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _wait_until(to_wait: list[subprocess.Popen[bytes]], deadline: float) -> None:
    for proc in to_wait:
        try:
            proc.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass


def _stop_all(to_stop: list[subprocess.Popen[bytes]], grace: float) -> None:
    """Terminate every child still running; kill those still running `grace` seconds later and give them up to
    KILL_WAIT_SECONDS more to exit, each wait one deadline for all."""
    running = [p for p in to_stop if p.poll() is None]
    for p in running:
        terminate(p)
    _wait_until(running, time.monotonic() + grace)
    to_kill = [p for p in running if p.poll() is None]
    for p in to_kill:
        kill(p)
    _wait_until(to_kill, time.monotonic() + KILL_WAIT_SECONDS)


def stop(proc: subprocess.Popen[bytes], grace: float = STOP_GRACE_SECONDS) -> None:
    """Terminate the child and its process group; kill it when it has not exited after `grace` seconds."""
    _stop_all([proc], grace)


@dataclass
class _Child:
    """One child in a table: its process (None once its waiter recorded the exit), its waiter, its tag, and whether it
    was stopped."""
    proc: Any
    waiter: threading.Thread
    tag: str | None
    stopped: bool = False


class ChildTable:
    """Every child of the registries that share one lock, each kept under its registry's name and its id, so that a
    launch of one checks what the others run (running_tags()) and all are stopped at once at server exit (shutdown()),
    which closes the table: a registry refuses every launch once `closed`, which it reads under the lock. start(),
    running(), stop() and any_running() take a registry's name and see that registry's children only; a registry calls
    them through its `Children`. A child is running while its waiter is alive: the waiter records the exit through the
    `on_exit(child_id, code, stopped)` given to start(), under the lock, so a registry that reads its record and asks
    running() under the lock reads a record without the exit code only as running, unless the waiter stopped without
    recording it (`wait()` or `on_exit` raised; tests/test_web_procs.py,
    test_a_child_whose_waiter_stopped_without_recording_its_exit_is_no_longer_running)."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.closed = False  # set once, by shutdown(), and never cleared
        self._children: dict[tuple[str, str], _Child] = {}  # by (registry name, child id)

    def start(self, name: str, child_id: str, argv: list[str], *, cwd: Path, log_path: Path, env: dict[str, str],
              tag: str | None, on_exit: Callable[[str, int, bool], None], starter: Callable[..., Any] | None) -> int:
        """Start `argv` through `starter`, else `spawn` as this module has it when called, and its waiter thread
        `mara-<name>-<child_id>`; the child's pid. An OSError of the starter propagates, and nothing is registered."""
        with self.lock:
            proc = (starter or spawn)(argv, cwd=cwd, log_path=log_path, env=env)
            waiter = threading.Thread(target=self._wait, args=(name, child_id, proc, on_exit), name=f"mara-{name}-{child_id}",
                                      daemon=True)
            self._children[(name, child_id)] = _Child(proc, waiter, tag)
            waiter.start()
            return int(proc.pid)

    def _wait(self, name: str, child_id: str, proc: Any, on_exit: Callable[[str, int, bool], None]) -> None:
        code = proc.wait()
        with self.lock:
            child = self._children[(name, child_id)]
            on_exit(child_id, code, child.stopped)
            child.proc = None

    def running(self, name: str, child_id: str) -> bool:
        with self.lock:
            child = self._children.get((name, child_id))
            return child is not None and child.waiter.is_alive()

    def stop(self, name: str, child_id: str) -> Literal["stopped", "exited", "unknown"]:
        """Stop a child still running, its exit then recorded as stopped ("stopped"); a child no longer running, one that
        exited by itself or was stopped before, is not stopped again ("exited"). Either way its waiter gets up to
        WAITER_JOIN_SECONDS to record the exit. "unknown": the registry `name` started no child of that id."""
        with self.lock:
            child = self._children.get((name, child_id))
            if child is None:
                return "unknown"
            to_stop = child.proc if child.proc is not None and child.proc.poll() is None else None
            if to_stop is not None:
                child.stopped = True
        if to_stop is not None:
            stop(to_stop)
        child.waiter.join(timeout=WAITER_JOIN_SECONDS)
        return "exited" if to_stop is None else "stopped"

    def any_running(self, name: str, tags: Collection[str] | None = None) -> bool:
        with self.lock:
            return any(n == name and c.waiter.is_alive() and (tags is None or c.tag in tags) for (n, _), c in self._children.items())

    def running_tags(self) -> set[str]:
        """The tags of every child running, whichever registry's it is."""
        with self.lock:
            return {c.tag for c in self._children.values() if c.waiter.is_alive() and c.tag is not None}

    def shutdown(self, grace: float = STOP_GRACE_SECONDS) -> None:
        """Server exit: stop every child still running, whichever registry's it is, its exit then recorded as stopped;
        then give the waiter of every child still running, one whose child exited by itself included, up to
        WAITER_JOIN_SECONDS each to record it. The children are stopped at once: each is terminated, those still
        running `grace` seconds later are killed, and those get up to KILL_WAIT_SECONDS more to exit. The table is
        closed in the same step as the children are taken, so a launch that gets the lock after it starts nothing."""
        with self.lock:
            self.closed = True
            waiters = [c.waiter for c in self._children.values() if c.waiter.is_alive()]
            to_stop = [c for c in self._children.values() if c.proc is not None and c.proc.poll() is None]
            for c in to_stop:
                c.stopped = True
        _stop_all([c.proc for c in to_stop], grace)
        for w in waiters:
            w.join(timeout=WAITER_JOIN_SECONDS)


class Children:
    """One registry's view of `table` (a table of its own when none is given): the registry's name, the `on_exit` its
    children's exits are recorded through and its starter, given to the table's operations, which see this registry's
    children only (ChildTable)."""

    def __init__(self, name: str, on_exit: Callable[[str, int, bool], None], *, start: Callable[..., Any] | None = None,
                 table: ChildTable | None = None) -> None:
        self.name, self.on_exit, self._start = name, on_exit, start
        self.table = table or ChildTable()

    def held(self) -> threading.RLock:
        """The table's lock (reentrant), shared by every registry in it and the one exits are recorded under: hold it
        to read a record and ask `running()` in one step, or to ask `admission.refusal()` about the table's running tags
        and start a child in one step."""
        return self.table.lock

    def start(self, child_id: str, argv: list[str], *, cwd: Path, log_path: Path, env: dict[str, str],
              tag: str | None = None) -> int:
        """ChildTable.start() through the starter given at construction."""
        return self.table.start(self.name, child_id, argv, cwd=cwd, log_path=log_path, env=env, tag=tag, on_exit=self.on_exit,
                                starter=self._start)

    def running(self, child_id: str) -> bool:
        return self.table.running(self.name, child_id)

    def launch(self, tag: str, parent: Path, *, record: str, log: str, cwd: Path, env: dict[str, str],
               prepare: Callable[[str, Path], tuple[list[str], dict[str, Any]]]) -> tuple[str, dict[str, Any]]:
        """Launch a child tagged `tag` and write its record, in one step under the table's lock, so the check and the
        start see the same children running. Refused, before anything is written, with LaunchError stopping (503) once
        the table is closed, or busy (409) when admission refuses `tag` beside the tags running. Otherwise a new id and
        its directory below `parent`; `prepare(id, directory)` gives the argv and the record, which is written to
        `record` in the directory before the child starts, its output going to `log` there. A start that fails with an
        OSError leaves the record failed, with finished_at and error (the exception's type), and is refused with
        spawn_failed (500); a started child's pid is added to the record. Returns the id and the record as written."""
        with self.held():
            if self.table.closed:  # the server exit took the children: before anything is written
                raise LaunchError("stopping", "the server is stopping: no review or job is started", status=503)
            if refused := admission.refusal(tag, self.table.running_tags()):
                raise LaunchError("busy", refused, status=409)
            child_id = new_id()
            d = parent / child_id
            d.mkdir(parents=True)
            argv, rec = prepare(child_id, d)
            write_json(d / record, rec)
            try:
                pid = self.start(child_id, argv, cwd=cwd, log_path=d / log, env=env, tag=tag)
            except OSError as e:
                rec.update(status="failed", finished_at=now(), error=type(e).__name__)
                write_json(d / record, rec)
                raise LaunchError("spawn_failed", str(e), status=500) from e
            rec["pid"] = pid
            write_json(d / record, rec)  # under the lock the exit is recorded under: never over the exit
        return child_id, rec

    def read(self, child_id: str, path: Path) -> tuple[dict[str, Any] | None, bool]:
        """The record at `path` (None when it is missing or unreadable) and whether the child `child_id` is running,
        read in one step under the table's lock, the one its exit is recorded under: a record without its exit code
        is read only beside a child still running, unless its waiter stopped without recording the exit."""
        with self.held():
            return read_json(path), self.running(child_id)

    def stop(self, child_id: str) -> Literal["stopped", "exited", "unknown"]:
        """ChildTable.stop()."""
        return self.table.stop(self.name, child_id)

    def any_running(self, tags: Collection[str] | None = None) -> bool:
        return self.table.any_running(self.name, tags)


def tail(path: Path, *, max_bytes: int = 256 * 1024, lines: int = 400) -> str:
    """The last `lines` lines within the last `max_bytes` bytes of a text file; '' when it does not exist."""
    if lines <= 0:
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - max_bytes))
            data = f.read()
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace")
    if size > max_bytes:
        text = text.split("\n", 1)[-1]  # the first line was cut by the byte window
    return "\n".join(text.splitlines()[-lines:])
