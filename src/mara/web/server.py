"""The workbench's HTTP server: `http.server` on a loopback address, one page and a small JSON API.

Access: `mara serve` prints a URL carrying a random token that exists for this server's lifetime; opening it sets
an HttpOnly, SameSite=Strict session cookie. Every API call needs the cookie, and every call that changes
something also needs the CSRF value `/api/session` returns, in the `X-MARA-CSRF` header; a page on another origin
can neither read that value (no CORS headers are ever sent) nor send the header without a preflight. The Host
header must name the loopback address the server listens on, which keeps DNS-rebinding pages out, and an Origin or
Sec-Fetch-Site naming another site is refused.

The page is assembled once at start-up from the packaged template, stylesheet, script and the two dictionaries;
its Content-Security-Policy allows exactly that script and that stylesheet by SHA-256, no other origin, and Trusted
Types, so the script can only build the DOM through text and element APIs (docs/adr/0006-local-web-workbench.md).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import secrets
import socket
import sys
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
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
_PLACEHOLDER = re.compile(r"__MARA_(CSS|JS|I18N|VERSION)__")  # plain markers, not a template language


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    language: str = Field(default="zh-TW", pattern=r"^(zh-TW|en)$")
    default_provider: str = Field(default="mock", pattern=r"^(mock|live)$")
    default_config: str = Field(default="", max_length=512)


def csp_source_hash(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _json_for_script(data: Any) -> str:
    """JSON inside a <script type="application/json"> data block: nothing in it can end the element."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def build_page() -> tuple[bytes, str]:
    """(page, Content-Security-Policy). The policy is built here from the hashes of the exact inline texts."""
    static = resources.files("mara.web") / "static"
    css = (static / "app.css").read_text(encoding="utf-8")
    js = (static / "app.js").read_text(encoding="utf-8")
    dictionaries = {lang: json.loads((static / "i18n" / f"{lang}.json").read_text(encoding="utf-8")) for lang in LANGUAGES}
    if "</style" in css.lower() or "</script" in js.lower():
        raise RuntimeError("an inline asset would end its own element")
    parts = {"CSS": css, "JS": js, "I18N": _json_for_script(dictionaries), "VERSION": __version__}
    html = _PLACEHOLDER.sub(lambda m: parts[m.group(1)], (static / "index.html").read_text(encoding="utf-8"))
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
    return html.encode("utf-8"), policy


# Responses other than the page load nothing at all
_BARE_POLICY = "; ".join(("default-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"))


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # never share the port with another listener

    def __init__(self, address: tuple[str, int], *, workspace: Path, out_dir: Path, token: str | None = None) -> None:
        super().__init__(address, Handler)
        self.workspace = workspace.resolve()
        self.out_dir = out_dir.resolve()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.token = token or secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.started_at = procs.now()
        self.runs = RunRegistry(self.workspace, self.out_dir)
        self.jobs = JobRegistry(self.workspace, self.out_dir, self.runs)
        self.page, self.csp = build_page()
        host = address[0]
        port = self.port
        names = {host, "127.0.0.1", "localhost"} if host != "::1" else {"::1", "localhost"}
        self.allowed_hosts = {f"[{n}]" if ":" in n else n for n in names}
        self.allowed_hosts |= {f"{n}:{port}" for n in self.allowed_hosts}
        self.cookie_name = f"mara_session_{port}"  # cookies ignore ports: one per server

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

    def shutdown_children(self) -> None:
        self.runs.shutdown()
        self.jobs.shutdown()


class WorkbenchServer6(WorkbenchServer):
    address_family = socket.AF_INET6


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "mara-workbench"

    def version_string(self) -> str:
        return self.server_version  # no Python version in the Server header

    @property
    def app(self) -> WorkbenchServer:
        return cast(WorkbenchServer, self.server)

    def log_message(self, format: str, *args: Any) -> None:
        return  # requests carry the session token in the first URL; nothing is logged

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

    def _text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

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

    def _cookie_ok(self) -> bool:
        try:
            jar = SimpleCookie(self.headers.get("Cookie", ""))
        except CookieError:
            return False
        morsel = jar.get(self.app.cookie_name)
        if morsel is None:
            return False
        return hmac.compare_digest(morsel.value.encode(), self.app.token.encode())

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
            self._page(query)
            return
        if path == "/api/health" and method == "GET":
            self._json(HTTPStatus.OK, {"ok": True, "version": __version__, "time": procs.now()})
            return
        if not path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "not_found")
            return
        if not self._cookie_ok():
            self._error(HTTPStatus.UNAUTHORIZED, "unauthenticated", "open the URL printed by `mara serve`")
            return
        if method != "GET":
            if not self._same_origin():
                self._error(HTTPStatus.FORBIDDEN, "cross_origin")
                return
            sent = self.headers.get("X-MARA-CSRF", "")
            if not hmac.compare_digest(sent.encode(), self.app.csrf.encode()):
                self._error(HTTPStatus.FORBIDDEN, "csrf", "missing or wrong X-MARA-CSRF header")
                return
            if body and not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "json_required")
                return
        self._api(method, path, query, body)

    def _page(self, query: dict[str, list[str]]) -> None:
        token = (query.get("token") or [""])[0]
        if token:
            if hmac.compare_digest(token.encode(), self.app.token.encode()):
                cookie = f"{self.app.cookie_name}={self.app.token}; HttpOnly; SameSite=Strict; Path=/"
                self._send(HTTPStatus.SEE_OTHER, b"", "text/plain; charset=utf-8", extra={"Location": "/", "Set-Cookie": cookie})
            else:
                self._text(HTTPStatus.FORBIDDEN, "MARA workbench: this link is not valid for the running server.\n"
                                                 "MARA 工作台：此連結不屬於目前執行中的服務。\n")
            return
        if not self._cookie_ok():
            self._text(HTTPStatus.UNAUTHORIZED, "MARA workbench: open the URL that `mara serve` printed (it carries the session token).\n"
                                                "MARA 工作台：請開啟 `mara serve` 印出的網址（內含本次工作階段的權杖）。\n")
            return
        self._send(HTTPStatus.OK, self.app.page, "text/html; charset=utf-8", page=True)

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
                    self._json(HTTPStatus.OK, {"version": __version__, "csrf": app.csrf, "workspace": str(app.workspace),
                                               "out_dir": str(app.out_dir), "started_at": app.started_at, "settings": app.settings(),
                                               "python": sys.version.split()[0]})
                case "POST", ["logout"]:
                    self._json(HTTPStatus.OK, {"ok": True},
                               extra={"Set-Cookie": f"{app.cookie_name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
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


def serve(*, host: str, port: int, workspace: Path, out_dir: Path, open_browser: bool, echo: Any = print) -> None:
    """Run until interrupted; reviews and jobs still running then are stopped and recorded as cancelled."""
    httpd = make_server(host=host, port=port, workspace=workspace, out_dir=out_dir)
    url = f"{httpd.url}?token={httpd.token}"
    echo(f"MARA workbench {__version__} · workspace {httpd.workspace} · runs in {httpd.runs.runs_dir}")
    echo(f"open: {url}")
    echo("the link is the session key for this server: do not share it; Ctrl-C stops the server and any running review")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown_children()
        httpd.server_close()
