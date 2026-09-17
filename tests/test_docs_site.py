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
