"""Build docs/workbench/index.html: the read-only demo of the local web workbench on GitHub Pages.

The workbench itself is a loopback server (docs/adr/0006-local-web-workbench.md). The demo is the same page with a
"demo" data block holding the server's answers to every GET the page makes for one offline review of the seeded
fixture with the mock providers; the script answers its API calls from that block and refuses every change. Only
the synthetic fixture and the mock config are shown, so nothing of a real codebase or of the production panel
reaches docs/, which GitHub Pages publishes to everyone.

    python scripts/build_workbench_demo.py --refresh   # run a new mock review and capture it (a few minutes)
    python scripts/build_workbench_demo.py             # re-assemble the page around the captured data
    python scripts/build_workbench_demo.py --check     # exit 1 when the page is not what the sources give

Re-assemble (and commit) after any change to the page's script, stylesheet, dictionaries or the version: the
--check run in tests/test_workbench_demo.py fails until then.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "workbench" / "index.html"
DEMO_ID = "20261014-090000-0d3e00"
CAPTURED_AT = dt.datetime(2026, 10, 14, 9, 0, 0, tzinfo=dt.UTC)
WORKSPACE_LABEL = "~/MultiAgentAlpha"
DOWNLOADS = ("report.md", "report.sarif", "human_queue.md")  # small, text; report.json is the API's own data
REQUEST = {"target": "fixtures/vuln-sample", "provider": "mock", "config": "config/mara.mock.yaml",
           "sarif_dir": "fixtures/vuln-sample-sarif", "title": "合成示範 / Offline demo"}
_DATA_BLOCK = re.compile(r'<script type="application/json" id="demo">(.*?)</script>', re.S)
_ISO = re.compile(r"\b(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?\b")
# what a capture must never carry: this machine's paths (the scrub below replaces the ones it knows)
MACHINE_PATHS = ("/home/", "/root/", "/tmp/", "/Users/", "/private/var/", "\\Users\\", "site-packages")


def _client(httpd: Any) -> Any:
    def request(method: str, path: str, body: Any = None) -> Any:
        conn = http.client.HTTPConnection("127.0.0.1", httpd.port, timeout=60)
        headers = {"Host": f"127.0.0.1:{httpd.port}", "X-MARA-Token": httpd.token}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        res = conn.getresponse()
        payload = res.read()
        conn.close()
        if res.status >= 300:
            raise RuntimeError(f"{method} {path}: HTTP {res.status} {payload[:300]!r}")
        return payload
    return request


def capture(timeout: float = 900) -> dict[str, Any]:
    """Run the offline demo review through a real server and record what the page would read."""
    from mara.web.server import make_server

    os.environ["MARA_HOME"] = str(ROOT)
    with tempfile.TemporaryDirectory(prefix="mara-demo-") as tmp:
        out_dir = Path(tmp).resolve()
        httpd = make_server(port=0, workspace=ROOT, out_dir=out_dir)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            get = _client(httpd)
            run_id = json.loads(get("POST", "/api/runs", REQUEST))["run"]["id"]
            deadline = time.monotonic() + timeout
            while json.loads(get("GET", f"/api/runs/{run_id}"))["run"]["status"] == "running":
                if time.monotonic() > deadline:
                    raise RuntimeError("the mock review did not finish")
                time.sleep(1)
            routes = ["/api/health", "/api/session", "/api/runs", f"/api/runs/{run_id}", f"/api/runs/{run_id}/report",
                      f"/api/runs/{run_id}/log", "/api/env", "/api/configs", "/api/jobs", "/api/settings"]
            api = {r: json.loads(get("GET", r + ("?tail=600" if r.endswith("/log") else ""))) for r in routes}
            files = {n: get("GET", f"/api/runs/{run_id}/files/{n}").decode("utf-8") for n in DOWNLOADS}
        finally:
            httpd.close()
        raw = {"api": api, "files": files}
        return scrub(raw, run_id, out_dir)


def _strip_hosts(node: Any) -> Any:
    if isinstance(node, dict):
        return {k: (None if k in ("endpoint_host", "base_url") else _strip_hosts(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_strip_hosts(v) for v in node]
    return node


def scrub(raw: dict[str, Any], run_id: str, out_dir: Path) -> dict[str, Any]:
    api, files = raw["api"], raw["files"]
    # only the mock config: the others name the production panel's models, regions and credential variables
    api["/api/configs"]["configs"] = [c for c in api["/api/configs"]["configs"] if c.get("provider_mode") == "mock"]
    api["/api/env"]["actions"] = {k: False for k in api["/api/env"].get("actions", {})}
    api["/api/env"]["platform"] = "Linux-x86_64"  # the build host's kernel and libc are nobody's business
    api["/api/jobs"] = {"jobs": []}
    for run in [api[f"/api/runs/{run_id}"]["run"], *api["/api/runs"]["runs"]]:
        run["artifacts"] = [n for n in run.get("artifacts", []) if n in DOWNLOADS]
        run["pid"] = None
    api["/api/runs"]["runs"] = [r for r in api["/api/runs"]["runs"] if r.get("id") == run_id]
    text = json.dumps({"api": _strip_hosts(api), "files": {DEMO_ID: files}}, ensure_ascii=False, sort_keys=True)
    replacements = [(str(out_dir), WORKSPACE_LABEL + "/out"), (str(ROOT), WORKSPACE_LABEL), (sys.executable, "python3"),
                    (sys.prefix, "<python>"), (str(Path.home()), "~"), (run_id, DEMO_ID)]
    for old, new in replacements:
        text = text.replace(json.dumps(old)[1:-1], json.dumps(new)[1:-1]).replace(old, new)
    stamps = [_parse(m) for m in _ISO.finditer(text)]
    start = min((s for s in stamps if s), default=CAPTURED_AT)

    def shift(m: re.Match[str]) -> str:
        when = _parse(m)
        if when is None:
            return m.group(0)
        moved = CAPTURED_AT + (when - start)
        return moved.isoformat(timespec="seconds") if m.group(4) else moved.replace(tzinfo=None).isoformat(timespec="seconds")
    text = _ISO.sub(shift, text)
    data = json.loads(text)
    data["captured_at"] = CAPTURED_AT.isoformat(timespec="seconds")
    problems = check_data(data)
    if problems:
        raise RuntimeError("the capture is not publishable: " + "; ".join(problems))
    return data


def _parse(m: re.Match[str]) -> dt.datetime | None:
    try:
        when = dt.datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}{m.group(4) or ''}".replace("Z", "+00:00"))
    except ValueError:
        return None
    return when if when.tzinfo else when.replace(tzinfo=dt.UTC)


def check_data(data: dict[str, Any]) -> list[str]:
    """What would make the capture unfit for a world-readable page."""
    text = json.dumps(data, ensure_ascii=False)
    problems = [f"names a machine path ({p!r})" for p in MACHINE_PATHS if p in text]
    configs = data["api"]["/api/configs"]["configs"]
    if not configs or any(c.get("provider_mode") != "mock" for c in configs):
        problems.append("lists a config other than the mock one")
    if any(data["api"]["/api/env"]["actions"].values()):
        problems.append("offers an action")
    if '"endpoint_host": "' in text or '"base_url": "' in text:
        problems.append("names a model endpoint")
    return problems


def policy(script: str, style: str) -> str:
    """The meta-element policy: GitHub Pages sends no headers. frame-ancestors is ignored in a meta element, and the
    page makes no request at all, so there is no connect-src."""
    from mara.web.server import csp_source_hash

    return "; ".join(("default-src 'none'", f"script-src '{csp_source_hash(script)}'", f"style-src '{csp_source_hash(style)}'",
                      "base-uri 'none'", "form-action 'none'", "object-src 'none'", "require-trusted-types-for 'script'"))


def assemble(data: dict[str, Any]) -> str:
    from mara.web.server import render_page

    _, script, style = render_page()
    csp = policy(script, style)
    if any(ch in csp for ch in '"<>&'):  # written as is, like scripts/build_html.py: scanners read the attribute raw
        raise RuntimeError("the policy would need escaping")
    head = f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
    document, _, _ = render_page(head=head, demo=data)
    return document


def committed_data() -> dict[str, Any]:
    m = _DATA_BLOCK.search(OUT.read_text(encoding="utf-8"))
    if not m:
        raise RuntimeError(f"{OUT.relative_to(ROOT)} has no demo data block; run with --refresh")
    return json.loads(m.group(1))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--refresh", action="store_true", help="run a new offline mock review and capture it")
    mode.add_argument("--check", action="store_true", help="fail when the committed page is not current")
    args = ap.parse_args(argv)
    data = capture() if args.refresh else committed_data()
    page = assemble(data)
    if args.check:
        if OUT.read_text(encoding="utf-8") != page:
            print(f"{OUT.relative_to(ROOT)} is stale: run python scripts/build_workbench_demo.py", file=sys.stderr)
            return 1
        print(f"{OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(page.encode('utf-8')):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
