"""The workbench's HTTP server (GLOSSARY.md: workbench, workbench demo, run; docs/adr/0006-local-web-workbench.md):
`http.server` on a loopback address, one page and a small JSON API.

Access: `mara serve` prints a URL whose fragment carries a random token that exists for this server's lifetime
(`#token=...`; a fragment never reaches a server, a log or a Referer). The page keeps it in this origin's
localStorage, which is scoped to scheme, host and port, and sends it in the `X-MARA-Token` header of every API
call. There is no cookie: a cookie would be sent to every service on 127.0.0.1 whatever its port, and another
user's listener there could collect it. A page on another origin can neither read the token nor send the header
without a CORS preflight, which is never granted, so the header is also the CSRF defence. The Host header must name
the loopback address the server listens on, which keeps DNS-rebinding pages out, and an Origin or Sec-Fetch-Site
naming another site is refused. The page itself holds no data and needs no token.

The page is assembled once at start-up from the packaged template, stylesheet, script and the two dictionaries;
its Content-Security-Policy allows exactly that script and that stylesheet by SHA-256, no other origin, and Trusted
Types, so the script can only build the DOM through text and element APIs (docs/adr/0006-local-web-workbench.md).
`render_page` also builds the workbench demo's page when `scripts/build_workbench_demo.py` gives it the demo's data.

Not pure: it listens on a socket, handles SIGTERM and SIGHUP while it serves, reads the clock, draws its token at
random, opens a browser and reads the packaged page; through `runs`, `jobs` and `env` it starts runs and jobs, cancels
runs and reads the workspace, and at exit it stops every child still running through the table the registries share
(`procs.ChildTable`); it creates the output directory and reads, writes and removes files in it, and reads the reports
`mara review` wrote into `<workspace>/out/`.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import signal
import socket
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .. import __version__
from . import env, procs, views
from .jobs import JobRegistry, JobRequest
from .runs import LaunchError, LaunchRequest, RunRegistry

LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_BODY = 64 * 1024
LANGUAGES = ("zh-TW", "en")
_PLACEHOLDER = re.compile(r"__MARA_(CSS|JS|I18N|VERSION|HEAD|DEMO)__")  # plain markers, not a template language


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str = Field(default="zh-TW", pattern=r"^(zh-TW|en)$")
    default_provider: str = Field(default="mock", pattern=r"^(mock|live)$")
    default_config: str = Field(default="", max_length=512)


def csp_source_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _json_for_script(data: Any) -> str:
    """JSON inside a <script type="application/json"> data block: nothing in it can end the element, and no `{{` or `{%`
    in a quoted string reads as a template (semgrep's template-injection rules; JSON's own syntax never has either)."""
    text = json.dumps(data, ensure_ascii=False, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return text.replace("{{", "\\u007b\\u007b").replace("{%", "\\u007b%")


def render_page(head: str = "", demo: Any = None) -> tuple[str, str, str]:
    """(document, script, stylesheet) from the packaged template. The served page passes neither argument: its policy
    travels in a header and its data comes from the API. scripts/build_workbench_demo.py passes a policy meta element
    and the data of the read-only demo, which the script then answers its API calls from."""
    static = resources.files("mara.web") / "static"
    css = (static / "app.css").read_text(encoding="utf-8")
    js = (static / "app.js").read_text(encoding="utf-8")
    dictionaries = {lang: json.loads((static / "i18n" / f"{lang}.json").read_text(encoding="utf-8")) for lang in LANGUAGES}
    if "</style" in css.lower() or "</script" in js.lower():
        raise RuntimeError("an inline asset would end its own element")
    block = f'<script type="application/json" id="demo">{_json_for_script(demo)}</script>' if demo is not None else ""
    parts = {"CSS": css, "JS": js, "I18N": _json_for_script(dictionaries), "VERSION": __version__, "HEAD": head, "DEMO": block}
    document = _PLACEHOLDER.sub(lambda m: parts[m.group(1)], (static / "index.html").read_text(encoding="utf-8"))
    return document, js, css


def build_page() -> tuple[bytes, str]:
    """(page, Content-Security-Policy). The policy is built here from the hashes of the exact inline texts."""
    document, js, css = render_page()
    policy = "; ".join((
        "default-src 'none'",
        f"script-src '{csp_source_hash(js)}'",
        f"style-src '{csp_source_hash(css)}'",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "require-trusted-types-for 'script'",
    ))
    return document.encode("utf-8"), policy


# Responses other than the page load nothing at all
_BARE_POLICY = "; ".join(("default-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"))


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # never share the port with another listener

    def __init__(self, address: tuple[str, int], *, workspace: Path, out_dir: Path, token: str | None = None) -> None:
        super().__init__(address, Handler)
        self._serving = False  # serve_forever() is running, on some thread; close() then has to shut it down
        self.workspace = workspace.resolve()
        self.out_dir = out_dir.resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.token = token or secrets.token_urlsafe(32)
        self.started_at = procs.now()
        self.runs = RunRegistry(self.workspace, self.out_dir)
        self.jobs = JobRegistry(self.workspace, self.out_dir, self.runs)
        self.table = self.runs.children.table  # the children of both registries, stopped together at exit
        self.page, self.csp = build_page()
        host = address[0]
        port = self.port
        names = {host, "127.0.0.1", "localhost"} if host != "::1" else {"::1", "localhost"}
        self.allowed_hosts = {f"[{n}]" if ":" in n else n for n in names}
        self.allowed_hosts |= {f"{n}:{port}" for n in self.allowed_hosts}

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    @property
    def url(self) -> str:
        raw = self.server_address[0]
        host = raw.decode() if isinstance(raw, bytes) else str(raw)
        shown = "127.0.0.1" if host in ("127.0.0.1", "localhost") else f"[{host}]"
        return f"http://{shown}:{self.port}/"

    def settings(self) -> dict[str, Any]:
        data = procs.read_json(self.out_dir / "web-settings.json") or {}
        try:
            return Settings.model_validate(data).model_dump()
        except ValidationError:
            return Settings().model_dump()

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        self._serving = True
        try:
            super().serve_forever(poll_interval)
        finally:
            self._serving = False

    def close(self) -> None:
        """Server exit, in this order: stop serving when serve_forever() still runs on another thread (socketserver's
        shutdown() would wait forever for one that never ran), so that no request is accepted while the children are
        stopped; stop every child still running and give the exits time to be recorded (ChildTable.shutdown says how
        long), a stopped run recorded cancelled, not orphaned, and a stopped job with the exit code the stop gave
        (failed, or finished if it is 0), a launch still being handled then refused, since the stop closes the table;
        then close the socket."""
        if self._serving:
            self.shutdown()
        self.table.shutdown()
        self.server_close()


class WorkbenchServer6(WorkbenchServer):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mara-workbench"
    timeout = 60  # an idle or stalled connection gives its thread back after a minute

    def version_string(self) -> str:
        return self.server_version  # no Python version in the Server header

    @property
    def app(self) -> WorkbenchServer:
        return cast(WorkbenchServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:
        return  # the console belongs to the operator; requests are not logged

    # ------------------------------------------------------------------ plumbing
    def _headers(self, status: int, ctype: str, length: int, *, page: bool = False, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", self.app.csp if page else _BARE_POLICY)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _send(self, status: int, body: bytes, ctype: str, **kw: Any) -> None:
        self._headers(status, ctype, len(body), **kw)
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, data: Any, extra: dict[str, str] | None = None) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", extra=extra)

    def _error(self, status: int, code: str, message: str = "") -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def _read_body(self) -> bytes | None:
        """The request body; None after an error response (the connection is then closed)."""
        raw = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._error(HTTPStatus.LENGTH_REQUIRED, "length_required", "chunked bodies are not accepted")
            return None
        try:
            length = int(raw) if raw is not None else 0
        except ValueError:
            self.close_connection = True
            self._error(HTTPStatus.BAD_REQUEST, "bad_request", "invalid Content-Length")
            return None
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            self._error(413, "body_too_large", f"at most {MAX_BODY} bytes")  # REQUEST_ENTITY_TOO_LARGE, renamed in 3.13
            return None
        return self.rfile.read(length) if length else b""

    def _token_ok(self) -> bool:
        sent = (self.headers.get("X-MARA-Token") or "").strip()
        return hmac.compare_digest(sent.encode("utf-8", "replace"), self.app.token.encode())

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").strip().lower() in self.app.allowed_hosts

    def _same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is not None and origin.lower() != f"http://{(self.headers.get('Host') or '').lower()}":
            return False
        site = self.headers.get("Sec-Fetch-Site")
        return site is None or site in ("same-origin", "none")

    # ------------------------------------------------------------------ dispatch
    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_HEAD(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        try:
            self._route(method)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:  # never a traceback to the client; the server keeps serving
            self.close_connection = True
            try:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "internal_error", type(e).__name__)
            except OSError:
                pass

    def _route(self, method: str) -> None:
        if not self._host_ok():
            self.close_connection = True
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "bad_host", "the Host header must name this loopback server")
            return
        url = urlsplit(self.path)
        path = url.path
        query = parse_qs(url.query)
        body = b""
        if method in ("POST", "PUT", "DELETE"):
            read = self._read_body()
            if read is None:
                return
            body = read
        elif self.headers.get("Content-Length", "0").strip() not in ("", "0") or self.headers.get("Transfer-Encoding"):
            self.close_connection = True  # a body on a GET is never read: the connection cannot carry another request
        if path == "/" and method == "GET":
            # the page holds no data (every number comes from the API); a token in a query string is not read
            self._send(HTTPStatus.OK, self.app.page, "text/html; charset=utf-8", page=True)
            return
        if path == "/api/health" and method == "GET":
            self._json(HTTPStatus.OK, {"ok": True, "version": __version__, "time": procs.now()})
            return
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        if not self._token_ok():
            self._error(HTTPStatus.UNAUTHORIZED, "unauthenticated", "open the URL printed by `mara`")
            return
        if method != "GET":
            if not self._same_origin():
                self._error(HTTPStatus.FORBIDDEN, "cross_origin")
                return
            if body and not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "json_required")
                return
        self._api(method, path, query, body)

    # ------------------------------------------------------------------ API
    def _api(self, method: str, path: str, query: dict[str, list[str]], body: bytes) -> None:
        app = self.app
        parts = [p for p in path.split("/") if p][1:]  # after "api"
        try:
            payload: Any = json.loads(body) if body else {}
        except ValueError:
            self._error(HTTPStatus.BAD_REQUEST, "bad_json")
            return
        if body and not isinstance(payload, dict):
            self._error(HTTPStatus.BAD_REQUEST, "bad_json", "the body must be a JSON object")
            return
        try:
            match method, parts:
                case "GET", ["session"]:
                    self._json(HTTPStatus.OK, {"version": __version__, "workspace": str(app.workspace), "out_dir": str(app.out_dir),
                                               "started_at": app.started_at, "settings": app.settings(), "python": sys.version.split()[0]})
                case "GET", ["runs"]:
                    self._json(HTTPStatus.OK, {"runs": app.runs.list(), "busy": app.runs.busy()})
                case "POST", ["runs"]:
                    created = app.runs.create(LaunchRequest.model_validate(payload))
                    self._json(HTTPStatus.CREATED, {"run": created})
                case "GET", ["runs", run_id]:
                    run = app.runs.get(run_id)
                    if run is None:
                        raise LaunchError("not_found", status=404)
                    self._json(HTTPStatus.OK, {"run": run, "progress": app.runs.progress(run_id),
                                               "panel": views.roles(run, app.runs.report(run_id))})
                case "GET", ["runs", run_id, "report"]:
                    if app.runs.get(run_id) is None:
                        raise LaunchError("not_found", status=404)
                    view = app.runs.view(run_id)
                    if view is None:
                        raise LaunchError("no_report", "the run has not written a readable report.json", status=404)
                    self._json(HTTPStatus.OK, view)
                case "GET", ["runs", run_id, "log"]:
                    lines = _int((query.get("tail") or ["400"])[0], 400, 1, 4000)
                    log = app.runs.log(run_id, lines)
                    if log is None:
                        raise LaunchError("not_found", status=404)
                    self._json(HTTPStatus.OK, log)
                case "GET", ["runs", run_id, "files", name]:
                    self._artifact(run_id, name)
                case "POST", ["runs", run_id, "cancel"]:
                    self._json(HTTPStatus.OK, {"run": app.runs.cancel(run_id)})
                case "POST", ["runs", run_id, "rerun"]:
                    self._json(HTTPStatus.CREATED, {"run": app.runs.rerun(run_id)})
                case "GET", ["env"]:
                    self._json(HTTPStatus.OK, env.environment(app.workspace, app.out_dir))
                case "GET", ["configs"]:
                    self._json(HTTPStatus.OK, {"configs": env.configs(app.workspace)})
                case "GET", ["jobs"]:
                    self._json(HTTPStatus.OK, {"jobs": app.jobs.list()})
                case "POST", ["jobs"]:
                    self._json(HTTPStatus.CREATED, {"job": app.jobs.create(JobRequest.model_validate(payload))})
                case "GET", ["jobs", job_id]:
                    job = app.jobs.get(job_id)
                    if job is None:
                        raise LaunchError("not_found", status=404)
                    self._json(HTTPStatus.OK, {"job": job})
                case "GET", ["settings"]:
                    self._json(HTTPStatus.OK, app.settings())
                case "PUT", ["settings"]:
                    settings = Settings.model_validate(payload)
                    procs.write_json(app.out_dir / "web-settings.json", settings.model_dump())
                    self._json(HTTPStatus.OK, settings.model_dump())
                case _:
                    self._error(HTTPStatus.NOT_FOUND, "not_found")
        except LaunchError as e:
            self._error(e.status, e.code, e.message)
        except ValidationError as e:
            fields = sorted({".".join(str(x) for x in err["loc"]) or "body" for err in e.errors()})
            self._error(HTTPStatus.BAD_REQUEST, "bad_request", f"invalid field(s): {', '.join(fields)}")

    def _artifact(self, run_id: str, name: str) -> None:
        path = self.app.runs.artifact(run_id, name)
        if path is None:
            raise LaunchError("not_found", status=404)
        data = path.read_bytes()
        ctype = {".json": "application/json", ".sarif": "application/sarif+json", ".md": "text/markdown", ".log": "text/plain"}.get(
            path.suffix, "application/octet-stream")
        stamp = run_id if run_id != "workspace-out" else dt.date.today().isoformat()
        self._send(HTTPStatus.OK, data, f"{ctype}; charset=utf-8",
                   extra={"Content-Disposition": f'attachment; filename="mara-{stamp}-{name}"'})


def _int(value: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except ValueError:
        return default


def make_server(*, host: str = "127.0.0.1", port: int = 8765, workspace: Path, out_dir: Path, token: str | None = None) -> WorkbenchServer:
    if host not in LOOPBACK_HOSTS:
        raise ValueError(f"{host}: the workbench listens on a loopback address only ({', '.join(LOOPBACK_HOSTS)})")
    cls = WorkbenchServer6 if host == "::1" else WorkbenchServer
    return cls((host, port), workspace=workspace, out_dir=out_dir, token=token)


def open_file(out_dir: Path, url: str, port: int) -> Path:
    """A redirect page only this user can read. The browser is started on the file, never on the URL: a process's
    arguments are visible to every local user, and the browser keeps its own for as long as it runs."""
    path = out_dir / f".mara-serve-{port}.html"
    path.unlink(missing_ok=True)  # O_EXCL below: never write through a file or link someone else left there
    target = html.escape(url, quote=True)
    page = (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0; url={target}">'
            f'<title>MARA</title></head><body><a href="{target}">MARA workbench</a></body></html>\n')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(page)
    return path


def _stop_on_signals() -> dict[int, Any]:
    """SIGTERM and SIGHUP (a `kill`, a service stop, a closed terminal) end the server like Ctrl-C does, so the runs and
    jobs it started are stopped as serve() says instead of running on unseen: they live in their own process groups and
    would not receive the signal themselves."""
    previous: dict[int, Any] = {}
    if threading.current_thread() is not threading.main_thread():
        return previous

    def stop(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            previous[sig] = signal.signal(sig, stop)
    return previous


def serve(*, host: str, port: int, workspace: Path, out_dir: Path, open_browser: bool, echo: Any = print) -> None:
    """Run until interrupted (Ctrl-C, SIGTERM, SIGHUP); then every child still running is stopped, and each run or job
    still running gets up to `procs.WAITER_JOIN_SECONDS` to be recorded: a stopped run cancelled, a stopped job with the
    exit code the stop gave (WorkbenchServer.close)."""
    httpd = make_server(host=host, port=port, workspace=workspace, out_dir=out_dir)
    url = f"{httpd.url}#token={httpd.token}"
    echo(f"MARA workbench {__version__} · workspace {httpd.workspace} · runs in {httpd.runs.runs_dir}")
    echo(f"open: {url}")
    echo("the link is the key to this server: do not share it; Ctrl-C stops the server and any running review or job")
    previous = _stop_on_signals()
    redirect: Path | None = None
    try:
        if open_browser:
            import webbrowser

            redirect = open_file(httpd.out_dir, url, httpd.port)
            webbrowser.open(redirect.as_uri())
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)  # a second signal must not cut the cleanup short
        echo("stopping: cancelling any running review and stopping any running job")
        httpd.close()
        if redirect is not None:
            redirect.unlink(missing_ok=True)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
