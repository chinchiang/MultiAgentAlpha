"""A child an earlier workbench server left running (mara.web.procs.is_survivor, docs/adr/0006-local-web-workbench.md): the
server was killed, or its cleanup was cut short. The next server stops it before it admits anything, and a second
Ctrl-C no longer cuts the cleanup short (mara.web.server._signals_ignored). Real `python -c` children."""

import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from mara.web import procs
from mara.web import server as web_server
from mara.web.jobs import JobRegistry
from mara.web.runs import RunRegistry

needs_proc = pytest.mark.skipif(not Path("/proc/self/cmdline").is_file(), reason="a survivor is known by /proc/<pid>/cmdline")
SLEEP = "import time; time.sleep(120)"
# sleeps on although asked to exit, as a tool slow to honour SIGTERM does
IGNORES_SIGTERM = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)"


def _until(condition, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not condition():
        time.sleep(0.05)
    return condition()


@pytest.fixture
def child(tmp_path):
    """Starts children as the workbench does (procs.spawn: each the leader of its own process group) and kills what is
    left of them at the end. Gives (argv, process)."""
    started: list[subprocess.Popen] = []

    def start(code: str = SLEEP):
        argv = [sys.executable, "-c", code]
        proc = procs.spawn(argv, cwd=tmp_path, log_path=tmp_path / f"child-{len(started)}.log", env=dict(os.environ))
        started.append(proc)
        assert _until(lambda: procs.is_survivor(proc.pid, argv)), "the child is up, under its own command line"
        return argv, proc

    yield start
    for proc in started:
        procs.kill(proc)
        proc.wait(timeout=30)


def _left_running(directory: Path, record: str, pid, argv) -> Path:
    directory.mkdir(parents=True)
    procs.write_json(directory / record, {"id": directory.name, "status": "running", "pid": pid, "argv": argv,
                                          "started_at": procs.now(), "finished_at": None, "exit_code": None})
    return directory / record


@needs_proc
def test_a_survivor_is_a_live_pid_with_exactly_the_recorded_command_line(child):
    argv, proc = child()
    assert procs.is_survivor(proc.pid, argv)
    assert not procs.is_survivor(proc.pid, [*argv, "--other"]), "the pid now belongs to another command"
    assert not procs.is_survivor(proc.pid, argv[:-1])
    for not_a_child in (None, True, 0, 1, -1, "12", 2 ** 22 + 12345):
        assert not procs.is_survivor(not_a_child, argv)
    assert not procs.is_survivor(proc.pid, None) and not procs.is_survivor(proc.pid, [])
    procs.kill(proc)
    proc.wait(timeout=30)
    assert not procs.is_survivor(proc.pid, argv), "a child that has exited is no survivor"


@needs_proc
def test_the_next_server_stops_a_review_an_earlier_one_left_running_and_records_it_interrupted(tmp_path, child):
    argv, proc = child()
    runs = RunRegistry(tmp_path, tmp_path / "out", table=procs.ChildTable())
    record = _left_running(runs.runs_dir / procs.new_id(), "run.json", proc.pid, argv)
    assert runs.get(record.parent.name)["status"] == "interrupted" and not runs.busy(), "the page already said so, while it ran on"
    assert runs.stop_survivors(grace=5) == [record.parent.name]
    assert proc.wait(timeout=30) == -signal.SIGTERM
    written = procs.read_json(record)
    assert (written["status"], written["exit_code"]) == ("interrupted", None) and written["finished_at"]
    assert runs.stop_survivors(grace=5) == [], "nothing is left to stop"


@needs_proc
def test_a_survivor_that_ignores_sigterm_is_killed_after_the_grace(tmp_path, child):
    argv, proc = child(IGNORES_SIGTERM)
    jobs = JobRegistry(tmp_path, tmp_path / "out", table=procs.ChildTable())
    record = _left_running(jobs.jobs_dir / procs.new_id(), "job.json", proc.pid, argv)
    time.sleep(0.5)  # let it set its handler
    assert jobs.stop_survivors(grace=0.5) == [record.parent.name]
    assert proc.wait(timeout=30) == -signal.SIGKILL
    assert procs.read_json(record)["status"] == "interrupted"


@needs_proc
def test_a_recorded_pid_that_another_command_holds_now_is_left_alone(tmp_path, child):
    """A pid is reused: the record of a run long gone may name a process that is somebody else's."""
    argv, proc = child()
    runs = RunRegistry(tmp_path, tmp_path / "out", table=procs.ChildTable())
    record = _left_running(runs.runs_dir / procs.new_id(), "run.json", proc.pid, [sys.executable, "-m", "mara.cli", "review", "x"])
    finished = _left_running(runs.runs_dir / procs.new_id(), "run.json", proc.pid, argv)
    procs.write_json(finished, {**procs.read_json(finished), "status": "finished"})
    assert runs.stop_survivors(grace=1) == []
    assert proc.poll() is None, "neither the reused pid nor a run that is not recorded running was signalled"
    assert procs.read_json(record)["status"] == "running"


@pytest.mark.skipif(sys.platform == "win32", reason="os.kill(pid, SIGINT) ends a Windows process")
def test_a_second_ctrl_c_does_not_cut_the_cleanup_short():
    assert threading.current_thread() is threading.main_thread()
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    done = []
    try:
        with web_server._signals_ignored({signal.SIGTERM: signal.SIG_DFL}):
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(0.2)  # a KeyboardInterrupt would be raised here
            done.append("cleanup")
    except KeyboardInterrupt:
        pass  # caught, so that the assertion below says what happened instead of pytest ending
    assert done == ["cleanup"], "a second Ctrl-C interrupted the cleanup"
    assert {sig: signal.getsignal(sig) for sig in before} == before, "each handler is given back"
    with pytest.raises(KeyboardInterrupt):  # and Ctrl-C interrupts again
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(1)
