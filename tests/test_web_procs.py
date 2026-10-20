"""The children of one workbench registry (mara.web.procs.Children, docs/adr/0006-local-web-workbench.md): a child is
running while its waiter is alive, the waiter recording its exit through the registry's callback (or stopping without,
when the exit is lost), and the record and that answer are read under the lock the exit is recorded under. Real
`python -c` children, held back by tests/held_children.py."""

import os
import sys
import threading
import time

import pytest

from mara.web import procs
from tests.held_children import LostExit, UnrecordedExit


def _children(child_type, records):
    """Children recording each exit in `records`, and the list every child they start is appended to, wrapped."""
    made = []

    def start(argv, **kw):
        made.append(child_type(procs.spawn(argv, **kw)))
        return made[-1]

    return procs.Children("test", lambda child_id, code, stopped: records.append((child_id, code, stopped)), start=start), made


def _start(children, tmp_path, child_id="a", code="pass", tag=None):
    return children.start(child_id, [sys.executable, "-c", code], cwd=tmp_path, log_path=tmp_path / f"{child_id}.log",
                          env=dict(os.environ), tag=tag)


def _until(condition, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not condition():
        time.sleep(0.05)
    return condition()


def test_a_child_whose_exit_is_not_recorded_yet_is_still_running(tmp_path):
    records = []
    children, made = _children(UnrecordedExit, records)
    _start(children, tmp_path)
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    try:
        assert children.running("a")
        assert records == []
    finally:
        child.released.set()
    assert _until(lambda: not children.running("a"), 30)
    assert records == [("a", 0, False)]


def test_any_child_or_any_child_of_some_tags_is_running_until_its_exit_is_recorded(tmp_path):
    children, made = _children(UnrecordedExit, [])
    _start(children, tmp_path, tag="trivy_db_download")
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    try:
        assert children.any_running()
        assert children.any_running(tags={"install_tools", "trivy_db_download"})
        assert not children.any_running(tags={"install_tools"})
    finally:
        child.released.set()
    assert _until(lambda: not children.any_running(), 30)


def test_stopping_a_running_child_records_its_exit_as_stopped(tmp_path):
    records = []
    children, _ = _children(lambda proc: proc, records)
    _start(children, tmp_path, code="import time; time.sleep(60)")
    assert children.stop("a") == "stopped"
    assert not children.running("a")
    ((child_id, code, stopped),) = records
    assert (child_id, code != 0, stopped) == ("a", True, True)


def test_stopping_a_child_that_exited_by_itself_waits_for_its_exit_to_be_recorded_and_does_not_record_it_stopped(tmp_path):
    records = []
    children, made = _children(UnrecordedExit, records)
    _start(children, tmp_path)
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    release = threading.Timer(0.5, child.released.set)
    release.start()
    try:
        assert children.stop("a") == "exited"
        assert records == [("a", 0, False)]
    finally:
        release.cancel()
        child.released.set()


def test_stopping_a_child_never_started_answers_unknown():
    assert procs.Children("test", lambda *_: None).stop("never-started") == "unknown"


def test_shutting_down_stops_every_running_child_its_exit_recorded_as_stopped(tmp_path):
    records = []
    children, _ = _children(lambda proc: proc, records)
    _start(children, tmp_path, code="import time; time.sleep(60)")
    children.shutdown()
    assert _until(lambda: records, 10)
    ((child_id, code, stopped),) = records
    assert (child_id, code != 0, stopped) == ("a", True, True)


def test_shutting_down_waits_for_the_exit_of_a_child_that_exited_by_itself_and_does_not_record_it_stopped(tmp_path):
    records = []
    children, made = _children(UnrecordedExit, records)
    _start(children, tmp_path)
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    release = threading.Timer(0.5, child.released.set)
    release.start()
    try:
        children.shutdown()
        assert records == [("a", 0, False)]
    finally:
        release.cancel()
        child.released.set()


def test_while_the_lock_is_held_an_exit_is_neither_recorded_nor_read_as_no_longer_running(tmp_path):
    """A registry reads its record and asks running() under held(): the exit cannot be recorded between the two."""
    records = []
    children, made = _children(UnrecordedExit, records)
    _start(children, tmp_path)
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    with children.held():
        child.released.set()
        assert not _until(lambda: records, 2)  # the waiter records the exit unless the lock it records under is held
        assert children.running("a")
    assert _until(lambda: not children.running("a"), 30)
    assert records == [("a", 0, False)]


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_a_child_whose_waiter_stopped_without_recording_its_exit_is_no_longer_running(tmp_path):
    """Its record never gets the exit code; the registry reads it as one of an earlier server."""
    records = []
    children, made = _children(LostExit, records)
    _start(children, tmp_path)
    (child,) = made
    child.released.set()
    assert _until(lambda: not children.running("a"), 10)
    assert records == []


def test_a_child_that_cannot_be_started_is_not_registered(tmp_path):
    def start(argv, **kw):
        raise FileNotFoundError(argv[0])

    children = procs.Children("test", lambda *_: None, start=start)
    with pytest.raises(OSError):
        _start(children, tmp_path)
    assert not children.running("a")
    assert not children.any_running()
    assert children.stop("a") == "unknown"


@pytest.mark.parametrize("stopping", ["stop", "shutdown"])
def test_while_a_child_is_being_stopped_whether_it_runs_is_answered_at_once(tmp_path, stopping):
    """procs.stop waits for the child to exit, which may take its whole grace: it runs outside the lock reads take."""
    records = []
    children = procs.Children("test", lambda child_id, code, stopped: records.append((child_id, code, stopped)))
    ready = tmp_path / "ready"
    code = ("import signal, sys, time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, lambda *_: (time.sleep(2), sys.exit(0)))\nPath(sys.argv[1]).touch()\ntime.sleep(60)\n")
    children.start("a", [sys.executable, "-c", code, str(ready)], cwd=tmp_path, log_path=tmp_path / "a.log", env=dict(os.environ))
    assert _until(ready.exists, 30)
    stopper = threading.Thread(target=lambda: children.stop("a") if stopping == "stop" else children.shutdown())
    stopper.start()
    time.sleep(0.5)  # the child got SIGTERM and takes 2 s to exit
    asked = time.monotonic()
    assert children.running("a")
    waited = round(time.monotonic() - asked, 1)
    assert waited < 1
    stopper.join(30)
    assert records == [("a", 0, True)]
