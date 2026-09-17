"""SECURITY.md is the disclosure entry point for this repository's own code. The assertions mirror the four
OpenSSF Scorecard Security-Policy probes (present, links, enough text, disclosure wording) and the two
things this project must say: the private-reporting channel and that the seeded fixtures are out of scope."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / "SECURITY.md").read_text(encoding="utf-8")


def test_reporting_channel_is_github_private_vulnerability_reporting():
    assert "https://github.com/chinchiang/MultiAgentAlpha/security/advisories/new" in TEXT
    assert "public issue" in TEXT.lower(), "reporters are told not to open a public issue"


def test_disclosure_wording_links_and_text_length():
    low = TEXT.lower()
    assert "vulnerability" in low and "disclosure" in low
    links = re.findall(r"https?://[^\s)>]+", TEXT)
    assert len(links) >= 1
    prose = re.sub(r"https?://[^\s)>]+", "", TEXT)
    assert len(prose) > 500, "Scorecard wants real text, not only links"


def test_seeded_material_is_out_of_scope_and_psirt_hand_off_is_distinguished():
    assert "fixtures/vuln-sample/" in TEXT and "calib/samples/" in TEXT and "out of scope" in TEXT.lower()
    assert "docs/psirt-integration.md" in TEXT
    assert "not a contractual commitment" in TEXT, "the response clocks are targets, not promises"


def test_readme_points_to_the_policy():
    assert "[SECURITY.md](SECURITY.md)" in (ROOT / "README.md").read_text(encoding="utf-8")
