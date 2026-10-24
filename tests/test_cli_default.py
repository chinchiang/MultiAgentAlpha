"""`mara` alone starts the local web workbench, as `mara serve` does with its defaults
(docs/adr/0006-local-web-workbench.md); a command given runs alone. The server is a recording double: these tests never
listen on a port or open a browser."""

import re
import sys

from typer.testing import CliRunner

from mara.cli import app
from mara.web import server
from tests import cli_output


def plain(text: str) -> str:
    """CLI output as `cli_output.plain` gives it, also without rich's box characters and backticks."""
    return cli_output.plain(re.sub(r"[│╭╮╰╯─`]", " ", text))


def recording(monkeypatch):
    """Replaces `mara.web.server.serve` with a double that takes keyword arguments only, as `cli.serve` passes them;
    the list it returns gets each call's arguments."""
    calls = []
    monkeypatch.setattr(server, "serve", lambda **kw: calls.append(kw))
    return calls


def test_mara_alone_starts_the_workbench_as_mara_serve_does(tmp_path, monkeypatch):
    """Whatever the process was started with: `serve` parses its own empty argument list, not `sys.argv`."""
    monkeypatch.setattr(sys, "argv", ["mara", "--not-a-serve-option"])
    calls = recording(monkeypatch)
    alone = CliRunner().invoke(app, [], env={"MARA_HOME": str(tmp_path)})
    serve = CliRunner().invoke(app, ["serve"], env={"MARA_HOME": str(tmp_path)})
    assert (alone.exit_code, serve.exit_code) == (0, 0), alone.output
    assert len(calls) == 2 and calls[0] == calls[1]
    started = {k: calls[0][k] for k in ("host", "port", "workspace", "out_dir", "open_browser")}
    assert started == {"host": "127.0.0.1", "port": 8765, "workspace": tmp_path.resolve(), "out_dir": tmp_path.resolve() / "out",
                       "open_browser": True}


def test_a_command_given_runs_alone_without_the_workbench(tmp_path, monkeypatch):
    calls = recording(monkeypatch)
    res = CliRunner().invoke(app, ["cvss", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"],
                             env={"MARA_HOME": str(tmp_path)})
    assert res.exit_code == 0 and '"score": 9.3' in res.output
    assert calls == [], "the workbench starts only when no command is given"


def test_mara_help_says_mara_alone_starts_the_workbench():
    res = CliRunner().invoke(app, ["--help"], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    assert "mara alone starts the local web workbench, as mara serve does." in plain(res.output)
