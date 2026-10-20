"""The children of one workbench registry (mara.web.procs.Children, docs/adr/0006-local-web-workbench.md): a child is
running while its waiter is alive, so until its exit has been recorded through the registry's callback, and the record
and that answer are read under the lock the exit is recorded under. Real `python -c` children, held back by doubles."""

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
