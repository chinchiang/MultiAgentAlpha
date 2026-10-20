"""Children of the workbench whose exit is held back, for tests of mara.web.procs.Children and the registries built on
it (tests/test_web_procs.py, tests/test_web_server.py): each wraps a real `subprocess.Popen` started through the
injected starter and keeps its `pid` and `poll()`, so the child has exited while its exit is not yet recorded."""

import threading


class UnrecordedExit:
    """A child whose exit has not been recorded yet: poll() sees it exited, wait() holds until `released` is set."""

    def __init__(self, proc):
        self.proc, self.pid, self.released = proc, proc.pid, threading.Event()

    def poll(self):
        return self.proc.poll()

    def wait(self, timeout=None):
        self.released.wait(60)
        return self.proc.wait(timeout)


class LostExit(UnrecordedExit):
    """A child whose exit is never recorded: once released, wait() raises and the waiter stops."""

    def wait(self, timeout=None):
        self.released.wait(60)
        raise OSError("the exit is lost")
