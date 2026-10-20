"""Child processes and small files of the workbench: one way to start, stop and read a run or an environment job.

Every child is an argv list started without a shell, from the MARA workspace, with MARA_HOME pointing at it and
the `mara` package the server itself runs on first on PYTHONPATH, so the review is the one the server was started
from. Nothing a browser sends reaches the environment; values reach argv only after the caller validated them.
Output goes to a log file, never through a pipe the server would have to drain.
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
from pathlib import Path
from typing import Any

ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")
STOP_GRACE_SECONDS = 10.0


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


def stop(proc: subprocess.Popen[bytes], grace: float = STOP_GRACE_SECONDS) -> None:
    """Terminate the child and its process group; kill it when it has not exited after `grace` seconds."""
    if proc.poll() is not None:
        return
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if sys.platform != "win32":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


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
