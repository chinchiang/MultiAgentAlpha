"""The read-only workbench demo on GitHub Pages (docs/workbench/index.html, scripts/build_workbench_demo.py).

docs/ is world-readable, so the demo may show only the seeded fixture reviewed by the mock providers: no other config,
no model endpoint, no path of the machine that captured it. It must also stay the page the workbench serves today:
a change to the script, stylesheet, dictionaries or version without a rebuild fails here, not on the public site."""

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_workbench_demo", ROOT / "scripts" / "build_workbench_demo.py")
assert spec and spec.loader
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)

PAGE = demo.OUT.read_text(encoding="utf-8")
DATA = demo.committed_data()


def test_the_published_demo_is_current():
    assert PAGE == demo.assemble(DATA), "run python scripts/build_workbench_demo.py and commit docs/workbench/index.html"


def test_its_policy_allows_exactly_its_own_script_and_style_and_no_request():
    from mara.web.server import csp_source_hash

    policy = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', PAGE).group(1)
    directives = dict(d.strip().split(" ", 1) for d in policy.split(";"))
    script = PAGE.split("<script>", 1)[1].split("</script>", 1)[0]
    style = PAGE.split("<style>", 1)[1].split("</style>", 1)[0]
    assert directives == {"default-src": "'none'", "script-src": f"'{csp_source_hash(script)}'", "style-src": f"'{csp_source_hash(style)}'",
                          "base-uri": "'none'", "form-action": "'none'", "object-src": "'none'", "require-trusted-types-for": "'script'"}
    assert PAGE.count("<script>") == 1 and "<script src" not in PAGE and "<link" not in PAGE


def test_it_shows_only_the_fixture_and_the_mock_config():
    assert demo.check_data(DATA) == []
    api = DATA["api"]
    assert [c["path"] for c in api["/api/configs"]["configs"]] == ["config/mara.mock.yaml"]
    (run,) = api["/api/runs"]["runs"]
    assert run["id"] == demo.DEMO_ID and run["provider"] == "mock" and run["target"].endswith("fixtures/vuln-sample")
    assert all(m["provider"] == "mock" for m in api[f"/api/runs/{demo.DEMO_ID}"]["run"]["models"])
    assert api["/api/jobs"] == {"jobs": []} and not any(api["/api/env"]["actions"].values())


def test_it_answers_every_route_the_page_reads_and_holds_its_downloads():
    rid = demo.DEMO_ID
    want = {"/api/health", "/api/session", "/api/runs", "/api/env", "/api/configs", "/api/jobs", "/api/settings",
            f"/api/runs/{rid}", f"/api/runs/{rid}/report", f"/api/runs/{rid}/log"}
    assert set(DATA["api"]) == want
    assert DATA["api"][f"/api/runs/{rid}"]["run"]["status"] == "finished"
    assert len(DATA["api"][f"/api/runs/{rid}/report"]["findings"]) > 0
    assert set(DATA["files"][rid]) == set(DATA["api"][f"/api/runs/{rid}"]["run"]["artifacts"]) == set(demo.DOWNLOADS)


def test_the_capture_scrub_replaces_this_machines_paths_and_times(tmp_path):
    out_dir = tmp_path / "mara-demo-x"
    raw = {"api": {
        "/api/configs": {"configs": [{"path": "config/mara.yaml", "provider_mode": "live"},
                                     {"path": "config/mara.mock.yaml", "provider_mode": "mock",
                                      "models": [{"endpoint_host": "llm.example", "provider": "mock"}]}]},
        "/api/env": {"actions": {"install_tools": True}, "platform": "Linux-6.1-custom", "workspace": str(demo.ROOT),
                     "python": {"executable": sys.executable}},
        "/api/jobs": {"jobs": [{"id": "x"}]},
        "/api/runs": {"runs": [{"id": "20990101-000000-abcdef", "artifacts": ["report.json", "report.md"], "pid": 7,
                                "started_at": "2099-01-01T00:00:00+00:00"}, {"id": "workspace-out"}]},
        "/api/runs/20990101-000000-abcdef": {"run": {"id": "20990101-000000-abcdef", "artifacts": ["report.md"], "pid": 7,
                                                      "finished_at": "2099-01-01T00:01:30+00:00", "out": str(out_dir / "runs")}}},
        "files": {"report.md": "# x"}}
    data = demo.scrub(raw, "20990101-000000-abcdef", out_dir)
    text = json.dumps(data)
    assert "20990101" not in text and "/tmp/" not in text and str(demo.ROOT) not in text and "llm.example" not in text
    assert [r["id"] for r in data["api"]["/api/runs"]["runs"]] == [demo.DEMO_ID]
    run = data["api"][f"/api/runs/{demo.DEMO_ID}"]["run"]
    assert run["finished_at"] == "2026-10-14T09:01:30+00:00" and run["pid"] is None
    assert run["out"] == "~/MultiAgentAlpha/out" + os.sep + "runs"
    assert data["api"]["/api/env"]["platform"] == "Linux-x86_64" and data["api"]["/api/jobs"] == {"jobs": []}


def test_a_capture_that_names_a_machine_path_is_refused():
    bad = json.loads(json.dumps(DATA))
    bad["api"]["/api/env"]["workspace"] = "/home/someone/MultiAgentAlpha"
    assert any("machine path" in p for p in demo.check_data(bad))


REAL_INSTALL = ROOT / ".mara-tools"


@pytest.mark.skipif(not os.path.isdir(REAL_INSTALL / "csp-evaluator"), reason="real csp-evaluator not installed")
def test_the_pinned_csp_evaluator_finds_nothing_in_the_demo_policy():
    """scripts/csp_ci.py grades this meta element in the repository scan too; this names the page if it fails."""
    from mara.tools import csp_eval

    node = csp_eval.node_exe()
    if not node:
        pytest.skip("node is not available")
    policy = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', PAGE).group(1)
    results, note = csp_eval.evaluate([csp_eval.CspPolicy(file="docs/workbench/index.html", line=1, policy=policy)],
                                      driver=REAL_INSTALL / csp_eval.PACKAGE_DIR / csp_eval.DRIVER_NAME, node=node)
    assert results is not None, note
    assert results[0]["parse_ok"] and results[0]["findings"] == [], results


def test_gitleaks_reads_a_human_queue_key_as_no_credential():
    """The demo's human queue shows each item's key ("key": "v2-<hex>"), which gitleaks' generic-api-key rule would
    otherwise report on every pull request that touches docs/workbench/."""
    import tomllib

    from mara.human_queue import queue_key
    from mara.reviewed_content import ReviewedContent

    allow = tomllib.loads((ROOT / ".gitleaks.toml").read_text(encoding="utf-8"))["allowlist"]["regexes"]
    key = queue_key("app.py", 3, "CWE-79", ReviewedContent("t", "r", "c"))
    assert any(re.fullmatch(r, key) for r in allow if "v2-" in r)
    assert not any(re.fullmatch(r, "v2-" + "0" * 23) or re.fullmatch(r, "ghp_" + "0" * 36) for r in allow if "v2-" in r)
