"""`mara` alone starts the local web workbench, as `mara serve` does with its defaults
(docs/adr/0006-local-web-workbench.md); a command given runs alone. The server is a recording double: these tests never
listen on a port or open a browser."""

import re

from typer.testing import CliRunner

from mara.cli import app
from mara.web import server


def plain(text: str) -> str:
    """CLI output as one line of words: without rich's colour codes (CI forces colour), its box characters, backticks
    or line breaks."""
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return " ".join(re.sub(r"[│╭╮╰╯─`]", " ", text).split())


def recording(monkeypatch):
    """Every call `mara` makes to start the workbench, by its keyword arguments."""
    calls = []
    monkeypatch.setattr(server, "serve", lambda **kw: calls.append(kw))
    return calls


def test_mara_alone_starts_the_workbench_as_mara_serve_does(tmp_path, monkeypatch):
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
