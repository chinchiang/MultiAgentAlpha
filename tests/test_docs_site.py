"""docs/ is published as-is by GitHub Pages (Settings: deploy from branch main, folder /docs): .nojekyll keeps
Jekyll away from the non-ASCII report file name, and index.html is a self-contained redirect whose target
must be a real file under docs/, so renaming the report breaks this test before it breaks the site."""

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
INDEX = (DOCS / "index.html").read_text(encoding="utf-8")
SITE = "https://chinchiang.github.io/MultiAgentAlpha/"


def test_nojekyll_marker_exists():
    assert (DOCS / ".nojekyll").is_file()


def test_index_redirects_to_an_existing_report_file():
    refresh = re.search(r'http-equiv="refresh" content="0; url=([^"]+)"', INDEX)
    canonical = re.search(r'rel="canonical" href="([^"]+)"', INDEX)
    hrefs = re.findall(r'<a href="([^"]+)"', INDEX)
    assert refresh and canonical and hrefs
    target = unquote(refresh.group(1))
    assert target.endswith(".html") and (DOCS / target).is_file(), f"redirect target missing under docs/: {target}"
    assert canonical.group(1) == SITE + refresh.group(1)
    assert all(h == refresh.group(1) for h in hrefs), "fallback links must point at the same file"


def test_index_is_self_contained():
    assert "<script" not in INDEX
    external = [u for u in re.findall(r'https?://[^"\'\s<>]+', INDEX) if not u.startswith(SITE)]
    assert not external, f"index.html must not load or link off-site resources: {external}"


def test_report_keeps_the_keyboard_and_contrast_fixes():
    """Findings of the axe-core 4.11 run of 2026-09-24 (WCAG 2.1 AA): keep them fixed when the page is rebuilt."""
    report = (DOCS / unquote(re.search(r'url=([^"]+)"', INDEX).group(1))).read_text(encoding="utf-8")
    assert '<a class="skip" href="#content">' in report and '<main id="content" tabindex="-1">' in report
    assert '<header class="topbar">' in report, "the top bar must be a landmark"
    assert "<pre>" not in report and report.count("<pre tabindex=\"0\">") > 0, "scrollers need tabindex"
    labels = re.findall(r'class="tablewrap" tabindex="0" role="region" aria-label="([^"]+)"', report)
    assert labels and len(labels) == len(set(labels)) == report.count("<table>"), "table regions need unique labels"
    assert ".ev-src{margin-left:4px}" in report, "opacity on the evidence source drops it below 4.5:1"
    assert "scrollIntoView({block:'nearest'})" not in report, "moves the Tab starting point into the inert nav"
    assert 'lang="en"' in INDEX


def test_public_docs_never_name_the_internal_endpoints():
    """docs/ is world-readable even while the repository is private (GitHub Pages): the internal DNS zones and
    endpoint hosts the configs declare belong in the private tree only, never in the report or its notes."""
    from urllib.parse import urlparse

    from mara.config import load_config

    configs = [ROOT / "config" / "mara.yaml", *sorted((ROOT / "config" / "examples").glob("standby-for-*.yaml"))]
    needles = set()
    for cfg in map(load_config, configs):
        needles |= {z.lstrip(".") for z in cfg.private_dns_suffixes}
        needles |= {urlparse(m.base_url).hostname for m in cfg.models if m.base_url and m.data_residency == "on_prem"}
    assert "iec.inventec" in needles, "the production config declares its internal zone"
    leaks = [(p.relative_to(ROOT).as_posix(), n) for p in sorted(DOCS.rglob("*"))
             if p.is_file() and p.suffix in {".md", ".html", ".json", ".txt", ".yaml", ".yml"}
             for n in sorted(needles) if n in p.read_text(encoding="utf-8", errors="replace")]
    assert not leaks, leaks
