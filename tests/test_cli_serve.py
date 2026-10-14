"""`mara serve` listens on a loopback address only: finding detail must stay where the review ran (CN-3), and the
session token in the printed URL is the only key, so another interface would hand both to the network."""

import http.client
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time

import pytest
from typer.testing import CliRunner

from mara.cli import app
from mara.web.server import LOOPBACK_HOSTS, make_server


def plain(text: str) -> str:
    """CLI output without rich's colour codes (CI forces colour, which splits `--host` into styled pieces)."""
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)


def test_help_lists_the_options():
    res = CliRunner().invoke(app, ["serve", "--help"], env={"COLUMNS": "200"})
    assert res.exit_code == 0
    for opt in ("--host", "--port", "--out", "--no-browser"):
        assert opt in plain(res.output)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "example.org"])
def test_a_non_loopback_host_is_refused(host, tmp_path):
    res = CliRunner().invoke(app, ["serve", "--host", host, "--no-browser", "--out", str(tmp_path)])
    assert res.exit_code == 2 and "loopback" in plain(res.output)
    with pytest.raises(ValueError, match="loopback"):
        make_server(host=host, port=0, workspace=tmp_path, out_dir=tmp_path)


def test_a_busy_port_is_an_error_not_a_traceback(tmp_path, root):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        res = CliRunner().invoke(app, ["serve", "--port", str(port), "--no-browser", "--out", str(tmp_path)], env={"MARA_HOME": str(root)})
    assert res.exit_code == 1 and "cannot listen" in plain(res.output)


def test_the_server_binds_only_where_it_is_told(tmp_path, root):
    assert set(LOOPBACK_HOSTS) == {"127.0.0.1", "localhost", "::1"}
    httpd = make_server(port=0, workspace=root, out_dir=tmp_path)
    try:
        assert httpd.server_address[0] == "127.0.0.1" and httpd.url == f"http://127.0.0.1:{httpd.port}/"
        assert len(httpd.token) >= 40 and not hasattr(httpd, "cookie_name") and httpd.RequestHandlerClass.timeout == 60
    finally:
        httpd.server_close()


def test_the_browser_is_started_on_a_private_file_never_on_the_token_url(tmp_path):
    """A process's arguments are readable by every local user, and the browser keeps its own as long as it runs."""
    from mara.web.server import open_file

    url = "http://127.0.0.1:8765/#token=abc&x=<y>"
    (tmp_path / ".mara-serve-8765.html").write_text("left by someone else")
    path = open_file(tmp_path, url, 8765)
    text = path.read_text(encoding="utf-8")
    assert "abc&amp;x=&lt;y&gt;" in text and "<y>" not in text and "left by someone else" not in text
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "token" not in path.as_uri()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
def test_sigterm_stops_the_server_like_ctrl_c(tmp_path, root):
    env = {k: v for k, v in os.environ.items() if k != "FORCE_COLOR"} | {"MARA_HOME": str(root), "NO_COLOR": "1", "COLUMNS": "300",
                                                                         "PYTHONUNBUFFERED": "1"}
    proc = subprocess.Popen([sys.executable, "-m", "mara.cli", "serve", "--port", "0", "--no-browser", "--out", str(tmp_path)],
                            cwd=str(root), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines: list[str] = []
    reader = threading.Thread(target=lambda: lines.extend(proc.stdout or []), daemon=True)  # a read never blocks the test
    reader.start()
    try:
        port = 0
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not port and proc.poll() is None:
            m = re.search(r"open: http://127\.0\.0\.1:(\d+)/#token=", plain("".join(lines)))
            port = int(m.group(1)) if m else 0
            time.sleep(0.1)
        assert port, f"the server printed its URL: {''.join(lines)!r}"
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{port}"})
        assert conn.getresponse().status == 200
        conn.close()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)
        reader.join(timeout=10)
        assert proc.returncode == 0 and "stopping" in plain("".join(lines))
    finally:
        if proc.poll() is None:
            proc.kill()
