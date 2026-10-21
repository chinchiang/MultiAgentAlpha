"""Child processes and small files of the workbench (GLOSSARY.md: workbench, run; docs/adr/0006-local-web-workbench.md):
one way to start, stop and read a run or an environment job.

Every child is an argv list started without a shell, from the MARA workspace, with MARA_HOME pointing at it and
the `mara` package the server itself runs on first on PYTHONPATH, so the child runs the `mara` the server was started
from. Nothing a browser sends reaches the environment; values reach argv only after the caller validated them.
Output goes to a log file, never through a pipe the server would have to drain.

Not pure: it starts and stops children and waits for them on threads of its own, copies the server's environment into
theirs, reads the clock (ids, timestamps and the deadlines of a stop) and a random source (ids and temporary file
names), and reads and writes the files it is given.
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
from pathlib import Path
from typing import Any, Literal

ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
STOP_GRACE_SECONDS = 10.0
WAITER_JOIN_SECONDS = 15.0  # how long Children.stop() and ChildTable.shutdown() wait for each waiter to record an exit


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


def stop(proc: subprocess.Popen[bytes], grace: float = STOP_GRACE_SECONDS) -> None:
    """Terminate the child and its process group; kill it when it has not exited after `grace` seconds."""
    if proc.poll() is not None:
        return
    terminate(proc)
    _wait_until([proc], time.monotonic() + grace)
    if proc.poll() is None:
        kill(proc)
        _wait_until([proc], time.monotonic() + 5)


class ChildTable:
    """The children of the registries that share one lock, so that a launch of one checks what the others run."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self._members: list[Children] = []

    def running_tags(self) -> set[str]:
        """The tags of every child running, whichever registry's it is."""
        with self.lock:
            return {tag for children in self._members for tag in children._running_tags()}

    def shutdown(self, grace: float = STOP_GRACE_SECONDS) -> None:
        """Server exit: stop every child still running, whichever registry's it is, its exit then recorded as stopped;
        then give the waiter of every child still running, one whose child exited by itself included, up to
        WAITER_JOIN_SECONDS each to record it. The children are stopped at once: each is terminated, those still
        running `grace` seconds later are killed, and those get up to 5 s more to exit."""
        with self.lock:
            taken = [children._taken_for_shutdown() for children in self._members]
        to_stop = [p for _, ps in taken for p in ps]
        for p in to_stop:
            terminate(p)
        _wait_until(to_stop, time.monotonic() + grace)
        to_kill = [p for p in to_stop if p.poll() is None]
        for p in to_kill:
            kill(p)
        _wait_until(to_kill, time.monotonic() + 5)
        for waiters, _ in taken:
            for w in waiters:
                w.join(timeout=WAITER_JOIN_SECONDS)


class Children:
    """The children of one registry and their waiters, in `table` (a table of their own when none is given), whose
    lock, shared by every registry in the table, is the one exits are recorded under. Every method but `held()` sees
    this registry's children only. A child is running while its waiter is alive: the waiter records the exit through
    `on_exit(child_id, code, stopped)` under that lock, so a registry that reads its record and asks `running()` under
    `held()` reads a record without the exit code only as running, unless the waiter stopped without recording it
    (`wait()` or `on_exit` raised; tests/test_web_procs.py,
    test_a_child_whose_waiter_stopped_without_recording_its_exit_is_no_longer_running)."""

    def __init__(self, name: str, on_exit: Callable[[str, int, bool], None], *, start: Callable[..., Any] | None = None,
                 table: ChildTable | None = None) -> None:
        self.name, self.on_exit, self._start = name, on_exit, start
        self.table = table or ChildTable()
        self._lock = self.table.lock
        self._procs: dict[str, Any] = {}
        self._waiters: dict[str, threading.Thread] = {}
        self._tags: dict[str, str | None] = {}
        self._stopped: set[str] = set()
        with self._lock:
            self.table._members.append(self)

    def held(self) -> threading.RLock:
        """The table's lock (reentrant), shared by every registry in it and the one exits are recorded under: hold it
        to read a record and ask `running()` in one step, or to ask `admission.refusal()` about the table's running tags
        and start a child in one step."""
        return self._lock

    def start(self, child_id: str, argv: list[str], *, cwd: Path, log_path: Path, env: dict[str, str],
              tag: str | None = None) -> int:
        """Start `argv` through the starter given at construction, else `spawn` as this module has it when called, and its
        waiter thread `mara-<name>-<child_id>`; the child's pid. An OSError of the starter propagates, and nothing is
        registered."""
        with self._lock:
            proc = (self._start or spawn)(argv, cwd=cwd, log_path=log_path, env=env)
            self._procs[child_id] = proc
            self._tags[child_id] = tag
            waiter = threading.Thread(target=self._wait, args=(child_id, proc), name=f"mara-{self.name}-{child_id}", daemon=True)
            self._waiters[child_id] = waiter
            waiter.start()
            return int(proc.pid)

    def _wait(self, child_id: str, proc: Any) -> None:
        code = proc.wait()
        with self._lock:
            self.on_exit(child_id, code, child_id in self._stopped)
            self._procs.pop(child_id, None)

    def running(self, child_id: str) -> bool:
        with self._lock:
            waiter = self._waiters.get(child_id)
            return waiter is not None and waiter.is_alive()

    def stop(self, child_id: str) -> Literal["stopped", "exited", "unknown"]:
        """Stop a child still running, its exit then recorded as stopped ("stopped"); a child no longer running, one that
        exited by itself or was stopped before, is not stopped again ("exited"). Either way its waiter gets up to
        WAITER_JOIN_SECONDS to record the exit. "unknown": no child of that id was started."""
        with self._lock:
            waiter, proc = self._waiters.get(child_id), self._procs.get(child_id)
            if waiter is None:
                return "unknown"
            to_stop = proc if proc is not None and proc.poll() is None else None
            if to_stop is not None:
                self._stopped.add(child_id)
        if to_stop is not None:
            stop(to_stop)
        waiter.join(timeout=WAITER_JOIN_SECONDS)
        return "exited" if to_stop is None else "stopped"

    def _taken_for_shutdown(self) -> tuple[list[threading.Thread], list[Any]]:
        """Under the table's lock: every live waiter, and every child still running, now marked stopped
        (ChildTable.shutdown)."""
        waiters = [w for w in self._waiters.values() if w.is_alive()]
        to_stop = [(c, p) for c, p in self._procs.items() if p.poll() is None]
        self._stopped.update(c for c, _ in to_stop)
        return waiters, [p for _, p in to_stop]

    def _running_tags(self) -> set[str]:
        return {tag for c, w in self._waiters.items() if w.is_alive() and (tag := self._tags.get(c)) is not None}

    def any_running(self, tags: Collection[str] | None = None) -> bool:
        with self._lock:
            return any(w.is_alive() and (tags is None or self._tags.get(c) in tags) for c, w in self._waiters.items())


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
