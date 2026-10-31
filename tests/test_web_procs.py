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


# a child that touches the file argv[1] names once it ignores SIGTERM, then sleeps
_IGNORING_SIGTERM = ("import signal, sys, time\nfrom pathlib import Path\n"
                     "signal.signal(signal.SIGTERM, signal.SIG_IGN)\nPath(sys.argv[1]).touch()\ntime.sleep(60)\n")


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


def test_stopping_a_child_still_running_after_the_grace_kills_it(tmp_path):
    """What a cancel does through Children.stop(), with the grace shortened."""
    ready = tmp_path / "ready"
    proc = procs.spawn([sys.executable, "-c", _IGNORING_SIGTERM, str(ready)], cwd=tmp_path, log_path=tmp_path / "a.log",
                       env=dict(os.environ))
    try:
        assert _until(ready.exists, 30)
        began = time.monotonic()
        procs.stop(proc, grace=0.5)
        assert time.monotonic() - began < 5
        assert proc.poll() == -9
    finally:
        procs.kill(proc)  # a child left running when the test fails


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
    children.table.shutdown()
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
        children.table.shutdown()
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
    """Stopping waits for the child to exit, which may take its whole grace: it runs outside the lock reads take."""
    records = []
    children = procs.Children("test", lambda child_id, code, stopped: records.append((child_id, code, stopped)))
    ready = tmp_path / "ready"
    code = ("import signal, sys, time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, lambda *_: (time.sleep(2), sys.exit(0)))\nPath(sys.argv[1]).touch()\ntime.sleep(60)\n")
    children.start("a", [sys.executable, "-c", code, str(ready)], cwd=tmp_path, log_path=tmp_path / "a.log", env=dict(os.environ))
    assert _until(ready.exists, 30)
    stopper = threading.Thread(target=lambda: children.stop("a") if stopping == "stop" else children.table.shutdown())
    stopper.start()
    time.sleep(0.5)  # the child got SIGTERM and takes 2 s to exit
    asked = time.monotonic()
    assert children.running("a")
    waited = round(time.monotonic() - asked, 1)
    assert waited < 1
    stopper.join(30)
    assert records == [("a", 0, True)]


def test_children_of_one_table_share_its_lock(tmp_path):
    """The runs' and the jobs' children: holding one's lock holds back the other's exits too."""
    table, records = procs.ChildTable(), []
    runs = procs.Children("run", lambda *_: None, table=table)
    made = []

    def start(argv, **kw):
        made.append(UnrecordedExit(procs.spawn(argv, **kw)))
        return made[-1]

    jobs = procs.Children("job", lambda child_id, code, stopped: records.append((child_id, code, stopped)), start=start,
                          table=table)
    _start(jobs, tmp_path, "j")
    (child,) = made
    assert child.proc.wait(timeout=60) == 0
    with runs.held():
        child.released.set()
        assert not _until(lambda: records, 2)  # the job's waiter records the exit unless the runs' lock is the same
        assert jobs.running("j")
    assert _until(lambda: records, 30)
    assert records == [("j", 0, False)]


def test_a_table_stops_every_running_child_at_once(tmp_path):
    """Each child takes 2 s to exit after SIGTERM: stopped one by one, the second would get it only after the first exited."""
    table, records = procs.ChildTable(), []
    record = lambda child_id, code, stopped: records.append((child_id, code, stopped))  # noqa: E731
    runs, jobs = procs.Children("run", record, table=table), procs.Children("job", record, table=table)
    code = ("import signal, sys, time\nfrom pathlib import Path\n"
            "signal.signal(signal.SIGTERM, lambda *_: (Path(sys.argv[2]).touch(), time.sleep(2), sys.exit(0)))\n"
            "Path(sys.argv[1]).touch()\ntime.sleep(60)\n")
    for children, name in ((runs, "r"), (jobs, "j")):
        children.start(name, [sys.executable, "-c", code, str(tmp_path / f"{name}.ready"), str(tmp_path / f"{name}.term")],
                       cwd=tmp_path, log_path=tmp_path / f"{name}.log", env=dict(os.environ))
    assert _until(lambda: (tmp_path / "r.ready").exists() and (tmp_path / "j.ready").exists(), 30)
    stopper = threading.Thread(target=table.shutdown)
    stopper.start()
    assert _until(lambda: (tmp_path / "r.term").exists() and (tmp_path / "j.term").exists(), 1)
    stopper.join(30)
    assert sorted(records) == [("j", 0, True), ("r", 0, True)]


def test_a_child_still_running_after_the_grace_is_killed(tmp_path):
    records = []
    children = procs.Children("test", lambda child_id, code, stopped: records.append((child_id, code, stopped)))
    ready = tmp_path / "ready"
    children.start("a", [sys.executable, "-c", _IGNORING_SIGTERM, str(ready)], cwd=tmp_path, log_path=tmp_path / "a.log", env=dict(os.environ))
    assert _until(ready.exists, 30)
    began = time.monotonic()
    children.table.shutdown(grace=0.5)
    assert time.monotonic() - began < 5
    assert records == [("a", -9, True)]


def _start_in_table(codes, tmp_path, records):
    """A run's and a job's Children in one table, the first starting the first child of `codes` (name: code), the second
    the second, each child given a file it touches once ready (argv[1]), waiting until both are; the table and the pid
    of each child."""
    table = procs.ChildTable()
    record = lambda child_id, code, stopped: records.append((child_id, code, stopped))  # noqa: E731
    pids = {}
    for kind, (name, code) in zip(("run", "job"), codes.items(), strict=True):
        pids[name] = procs.Children(kind, record, table=table).start(
            name, [sys.executable, "-c", code, str(tmp_path / f"{name}.ready")], cwd=tmp_path, log_path=tmp_path / f"{name}.log",
            env=dict(os.environ))
    assert _until(lambda: all((tmp_path / f"{name}.ready").exists() for name in codes), 30)
    return table, pids


def test_children_still_running_after_the_grace_share_one_deadline(tmp_path):
    """Both ignore SIGTERM: a deadline for each child in turn would take twice the grace."""
    records = []
    table, _ = _start_in_table({"r": _IGNORING_SIGTERM, "j": _IGNORING_SIGTERM}, tmp_path, records)
    began = time.monotonic()
    table.shutdown(grace=1)
    waited = round(time.monotonic() - began, 1)
    assert waited < 1.8
    assert sorted(records) == [("j", -9, True), ("r", -9, True)]


def test_only_the_children_still_running_after_the_grace_are_killed(tmp_path, monkeypatch):
    """A child that exited on SIGTERM is not killed: its pid may be another process's by then."""
    killed, real = [], procs.kill

    def kill(proc):
        killed.append(proc.pid)
        real(proc)

    monkeypatch.setattr(procs, "kill", kill)
    records = []
    exits = "import sys, time\nfrom pathlib import Path\nPath(sys.argv[1]).touch()\ntime.sleep(60)\n"
    table, pids = _start_in_table({"e": exits, "i": _IGNORING_SIGTERM}, tmp_path, records)
    table.shutdown(grace=1)
    assert killed == [pids["i"]]
    assert sorted(records) == [("e", -15, True), ("i", -9, True)]


def test_a_table_tells_the_tags_of_every_child_running_and_each_registry_sees_only_its_own(tmp_path):
    table, made = procs.ChildTable(), []

    def start(argv, **kw):
        made.append(UnrecordedExit(procs.spawn(argv, **kw)))
        return made[-1]

    runs = procs.Children("run", lambda *_: None, start=start, table=table)
    jobs = procs.Children("job", lambda *_: None, start=start, table=table)
    _start(runs, tmp_path, "r", tag="run")
    _start(jobs, tmp_path, "j", tag="trivy_db_status")
    try:
        assert table.running_tags() == {"run", "trivy_db_status"}
        assert not runs.any_running(tags={"trivy_db_status"}) and jobs.any_running()
        assert not runs.running("j") and runs.stop("j") == "unknown"
    finally:
        for child in made:
            child.released.set()
    assert _until(lambda: not table.running_tags(), 30)


# ------------------------------------------------------------------ launch: a child and its record in one step

def _launching(records, start=None):
    return procs.Children("test", lambda child_id, code, stopped: records.append((child_id, code, stopped)),
                          start=start or (lambda argv, **kw: procs.spawn(argv, **kw)))


def _prepare(seen):
    """A prepare callback recording each (id, directory) it is given, the record naming its id."""
    def prepare(child_id, d):
        seen.append((child_id, d))
        return [sys.executable, "-c", "pass"], {"id": child_id, "status": "running", "exit_code": None}
    return prepare


def _launch(children, tmp_path, seen, tag="run"):
    return children.launch(tag, tmp_path / "children", record="child.json", log="child.log", cwd=tmp_path,
                           env=dict(os.environ), prepare=_prepare(seen))


def test_a_launch_once_the_table_is_closed_is_refused_as_stopping_and_writes_nothing(tmp_path):
    from mara.web.admission import LaunchError

    children, seen = _launching([]), []
    children.table.shutdown()
    with pytest.raises(LaunchError) as refused:
        _launch(children, tmp_path, seen)
    assert (refused.value.code, refused.value.status) == ("stopping", 503)
    assert seen == [] and not (tmp_path / "children").exists()


def test_a_launch_admission_refuses_is_refused_as_busy_and_writes_nothing(tmp_path, monkeypatch):
    from mara.web import admission

    asked = []
    monkeypatch.setattr(admission, "refusal", lambda kind, running: asked.append(kind) or f"{kind} waits")
    children, seen = _launching([]), []
    with pytest.raises(admission.LaunchError) as refused:
        _launch(children, tmp_path, seen, tag="install_tools")
    assert (refused.value.code, refused.value.status, refused.value.message) == ("busy", 409, "install_tools waits")
    assert asked == ["install_tools"] and seen == [] and not (tmp_path / "children").exists()


def test_a_launch_whose_child_cannot_start_leaves_its_record_failed_and_is_refused_as_spawn_failed(tmp_path):
    from mara.web.admission import LaunchError

    def unstartable(argv, **kw):
        raise FileNotFoundError("no such interpreter")

    children, seen = _launching([], start=unstartable), []
    with pytest.raises(LaunchError) as refused:
        _launch(children, tmp_path, seen)
    assert (refused.value.code, refused.value.status) == ("spawn_failed", 500)
    ((child_id, d),) = seen
    record = procs.read_json(d / "child.json")
    assert record["id"] == child_id and record["status"] == "failed" and record["error"] == "FileNotFoundError"
    assert record["finished_at"] and record["exit_code"] is None
    assert not children.running(child_id)


def test_a_launch_starts_the_child_prepare_gives_and_records_its_pid(tmp_path):
    records, seen, started = [], [], []

    def start(argv, **kw):
        started.append((argv, kw["log_path"], kw["cwd"]))
        return procs.spawn(argv, **kw)

    children = _launching(records, start=start)
    child_id, record = _launch(children, tmp_path, seen)
    ((seen_id, d),) = seen
    assert seen_id == child_id and d == tmp_path / "children" / child_id and procs.ID_RE.match(child_id)
    assert started == [([sys.executable, "-c", "pass"], d / "child.log", tmp_path)]
    assert isinstance(record["pid"], int) and record["pid"] > 0
    assert procs.read_json(d / "child.json")["pid"] == record["pid"]
    assert _until(lambda: records == [(child_id, 0, False)], 30)


def test_a_launch_writes_the_record_before_it_starts_the_child(tmp_path):
    """A server stopped between the start and the pid still leaves a record, which the next server reads as interrupted;
    without one, the child's directory would be no run or job at all (RunRegistry.run_dir needs run.json)."""
    on_disk = []

    def start(argv, **kw):
        on_disk.append(procs.read_json(kw["log_path"].with_name("child.json")))
        return procs.spawn(argv, **kw)

    children, seen = _launching([], start=start), []
    child_id, _ = _launch(children, tmp_path, seen)
    assert on_disk == [{"id": child_id, "status": "running", "exit_code": None}]
