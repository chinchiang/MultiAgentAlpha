"""The workbench page (mara.web.static, docs/adr/0006-local-web-workbench.md): one self-contained page whose policy
allows exactly its own script and stylesheet by hash, a script that builds the DOM only through text and element
APIs, and two dictionaries that say the same things. A key missing from one language, a code the server can send
that the page cannot name, or a static file that the wheel would not ship fails here, not in a browser."""

import fnmatch
import json
import os
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "mara" / "web" / "static"
JS = (STATIC / "app.js").read_text(encoding="utf-8")
CSS = (STATIC / "app.css").read_text(encoding="utf-8")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
DICTS = {lang: json.loads((STATIC / "i18n" / f"{lang}.json").read_text(encoding="utf-8")) for lang in ("zh-TW", "en")}
STORAGE_KEYS = {"mara.lang", "mara.token"}


def _keys_used() -> set[str]:
    used = set(re.findall(r'"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"', JS)) - STORAGE_KEYS
    return used | set(re.findall(r'data-i18n(?:-aria)?="([^"]+)"', HTML))


def test_both_languages_have_the_same_keys_placeholders_and_no_empty_text():
    zh, en = DICTS["zh-TW"], DICTS["en"]
    assert set(zh) == set(en), sorted(set(zh) ^ set(en))
    for key in zh:
        assert zh[key].strip() and en[key].strip(), key
        assert set(re.findall(r"\{(\w+)\}", zh[key])) == set(re.findall(r"\{(\w+)\}", en[key])), key


def test_every_key_the_page_names_exists():
    missing = sorted(_keys_used() - set(DICTS["zh-TW"]))
    assert not missing, missing


def _literal_values(text: str, call: str) -> set[str]:
    return set(re.findall(call + r'\(\s*"([a-z_:]+)"', text))


def _enumerations() -> dict[str, set[str]]:
    from typing import get_args

    from mara import progress
    from mara.audit import INCOMPLETE_COUNTERS
    from mara.config import ModelSpec, RolloutConfig, load_config
    from mara.policy import evaluate_policies
    from mara.schemas import DIMENSIONS, JuryOutcomeValue
    from mara.web.jobs import JobKind

    src = ROOT / "src" / "mara"
    pipeline = (src / "pipeline.py").read_text(encoding="utf-8")
    outcome = (src / "scoring" / "outcome.py").read_text(encoding="utf-8")
    queue = (src / "report" / "human_queue_out.py").read_text(encoding="utf-8")
    web = "".join(p.read_text(encoding="utf-8") for p in (src / "web").glob("*.py"))
    errors = (set(re.findall(r'LaunchError\(\s*"([a-z_]+)"', web)) | set(re.findall(r'_error\([^,]+,\s*"([a-z_]+)"', web))
              | {"network", "target_required"})
    return {
        "dimension.": set(DIMENSIONS),
        "stage.": set(progress.STAGES),
        "stage_status.": set(progress.STAGE_STATUSES),
        "outcome.": set(get_args(JuryOutcomeValue)),
        "reason.": set(re.findall(r'incomplete\.append\("([a-z_]+)"\)', pipeline)) | set(INCOMPLETE_COUNTERS),
        "hreason.": _literal_values(outcome, r"reasons\.append") | _literal_values(queue, r"reasons\.append") | {"decision_not_usable"},
        "error.": errors,
        "provider.": set(get_args(ModelSpec.model_fields["provider"].annotation)),
        "residency.": set(get_args(ModelSpec.model_fields["data_residency"].annotation)),
        "rollout.": set(get_args(RolloutConfig.model_fields["phase"].annotation)),
        "policy.": {r.id for r in evaluate_policies(load_config(ROOT / "config" / "mara.mock.yaml"))},
        "job.": set(get_args(JobKind)),
        "severity.": {"Critical", "High", "Medium", "Low", "None"},
        "tier.desc.": {"A", "B", "C", "D"},
        "status.": {"running", "complete", "incomplete", "failed", "cancelled", "interrupted"},
        "mode.": {"mock", "live", "mixed"},
        "scope.": {"full", "incremental", "unknown"},
        "review_status.": {"complete", "incomplete", "error"},
    }


def test_every_code_the_server_or_the_report_can_send_has_a_name_in_both_languages():
    enums = _enumerations()
    assert len(enums["reason."]) > len(enums["hreason."]) > 5 and {"busy", "bad_path", "inside_target"} <= enums["error."]
    for prefix, values in enums.items():
        missing = sorted(prefix + v for v in values if prefix + v not in DICTS["zh-TW"])
        assert not missing, missing


def test_the_page_is_self_contained_and_carries_no_policy_of_its_own():
    assert "<script src" not in HTML and "<link" not in HTML and "http-equiv" not in HTML.lower()
    for name, text in (("index.html", HTML), ("app.css", CSS), ("app.js", JS)):
        urls = [u for u in re.findall(r"https?://[^\s\"'<>)]+", text) if u != "http://www.w3.org/2000/svg"]
        assert not urls, f"{name} names off-site resources: {urls}"
    assert not re.search(r"\son[a-z]+\s*=", HTML), "no inline event handlers"
    assert "@import" not in CSS and "url(" not in CSS
    assert HTML.count("__MARA_CSS__") == HTML.count("__MARA_JS__") == HTML.count("__MARA_I18N__") == 1


@pytest.mark.parametrize("sink", ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "new RegExp(",
                                  "setTimeout(\"", "setInterval(\"", "javascript:", ".setAttribute(\"style\"", "srcdoc"])
def test_the_script_never_builds_markup_from_strings(sink):
    """Repository-derived text (titles, quotes, arguments) reaches the DOM only as text; Trusted Types would refuse
    these sinks anyway, and semgrep's javascript/lang/security rules look for them."""
    assert sink not in JS


def test_children_are_replaced_only_through_the_null_safe_helper():
    """Element.replaceChildren(null) inserts the text "null": the script empties an element natively and fills it through
    fill(), which skips null and false like h() does (a stray "null" once showed under the model panel)."""
    assert re.findall(r"\.replaceChildren\((.)", JS) and set(re.findall(r"\.replaceChildren\((.)", JS)) == {")"}


def test_the_page_keeps_its_landmarks_and_language():
    assert '<html lang="zh-Hant">' in HTML
    assert '<a class="skip" href="#content"' in HTML and '<main id="content" tabindex="-1">' in HTML
    assert '<header class="topbar">' in HTML and re.search(r'<nav class="nav" id="main-nav"[^>]*aria-label=', HTML)
    assert 'role: "tablist"' in JS and '"aria-selected"' in JS and '"aria-current": s.status === "running" ? "step"' in JS
    assert 'role: "dialog", "aria-modal": "true"' in JS, "the findings drawer is a modal dialog"
    assert 'role: "region", "aria-label": label' in JS, "scrolling tables are labelled regions"



def test_the_assembled_page_is_allowed_exactly_its_own_script_and_style():
    from mara.web.server import build_page, csp_source_hash

    page, policy = build_page()
    html = page.decode("utf-8")
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    style = html.split("<style>", 1)[1].split("</style>", 1)[0]
    directives = dict(d.strip().split(" ", 1) for d in policy.split(";"))
    assert directives["default-src"] == "'none'" and directives["object-src"] == "'none'" and directives["base-uri"] == "'none'"
    assert directives["script-src"] == f"'{csp_source_hash(script)}'" and directives["style-src"] == f"'{csp_source_hash(style)}'"
    assert directives["require-trusted-types-for"] == "'script'" and directives["frame-ancestors"] == "'none'"
    assert "unsafe" not in policy and "*" not in policy and "http" not in policy
    data = html.split('<script type="application/json" id="i18n">', 1)[1].split("</script>", 1)[0]
    assert "<" not in data and json.loads(data) == DICTS
    assert "__MARA_" not in html


def test_every_static_file_ships_in_the_package():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    globs = meta["tool"]["setuptools"]["package-data"]["mara"]
    pkg = ROOT / "src" / "mara"
    files = [p.relative_to(pkg).as_posix() for p in STATIC.rglob("*") if p.is_file()]

    def shipped(path: str, glob: str) -> bool:  # setuptools globs: `*` stops at a slash, unlike fnmatch's
        parts, pattern = path.split("/"), glob.split("/")
        return len(parts) == len(pattern) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pattern, strict=True))

    unshipped = [f for f in files if not any(shipped(f, g) for g in globs)]
    assert files and not unshipped, unshipped
    assert not shipped("web/static/i18n/en.json", "web/static/*.json"), "a glob one level up must not count"


REAL_INSTALL = ROOT / ".mara-tools"


@pytest.mark.skipif(not os.path.isdir(REAL_INSTALL / "csp-evaluator"), reason="real csp-evaluator not installed")
def test_the_pinned_csp_evaluator_finds_nothing_in_the_served_policy():
    """scripts/csp_ci.py cannot see this policy (it is assembled at start-up), so the pinned evaluator grades it here."""
    from mara.tools import csp_eval
    from mara.web.server import build_page

    node = csp_eval.node_exe()
    if not node:
        pytest.skip("node is not available")
    _, policy = build_page()
    results, note = csp_eval.evaluate([csp_eval.CspPolicy(file="served", line=1, policy=policy)],
                                      driver=REAL_INSTALL / csp_eval.PACKAGE_DIR / csp_eval.DRIVER_NAME, node=node)
    assert results is not None, note
    assert results[0]["parse_ok"] and results[0]["findings"] == []
