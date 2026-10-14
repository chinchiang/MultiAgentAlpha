"""`mara serve` listens on a loopback address only: finding detail must stay where the review ran (CN-3), and the
session token in the printed URL is the only key, so another interface would hand both to the network."""

import socket

import pytest
from typer.testing import CliRunner

from mara.cli import app
from mara.web.server import LOOPBACK_HOSTS, make_server


def test_help_lists_the_options():
    res = CliRunner().invoke(app, ["serve", "--help"], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    for opt in ("--host", "--port", "--out", "--no-browser"):
        assert opt in res.output


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.org"])
def test_a_non_loopback_host_is_refused(host, tmp_path):
    res = CliRunner().invoke(app, ["serve", "--host", host, "--no-browser", "--out", str(tmp_path)])
    assert res.exit_code == 2 and "loopback" in res.output
    with pytest.raises(ValueError, match="loopback"):
        make_server(host=host, port=0, workspace=tmp_path, out_dir=tmp_path)


def test_a_busy_port_is_an_error_not_a_traceback(tmp_path, root):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        res = CliRunner().invoke(app, ["serve", "--port", str(port), "--no-browser", "--out", str(tmp_path)], env={"MARA_HOME": str(root)})
    assert res.exit_code == 1 and "cannot listen" in res.output


def test_the_server_binds_only_where_it_is_told(tmp_path, root):
    assert set(LOOPBACK_HOSTS) == {"127.0.0.1", "localhost", "::1"}
    httpd = make_server(port=0, workspace=root, out_dir=tmp_path)
    try:
        assert httpd.server_address[0] == "127.0.0.1" and httpd.url == f"http://127.0.0.1:{httpd.port}/"
        assert httpd.cookie_name == f"mara_session_{httpd.port}" and len(httpd.token) >= 40 and httpd.token != httpd.csrf
    finally:
        httpd.server_close()
