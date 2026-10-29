"""scripts/advisory_facts.py gathers the facts a new advisory on a hash-locked tool closure needs before it is relocked or
given a dated exception: the advisories on the pinned version and their first fix, which packages of the closure depend
on it and whether they accept the fix, what the fix's own requirements change, and the fix's wheel for the pinned
platform with its SHA-256. The answers of osv.dev and PyPI are recorded (tests/fixtures/advisory_facts/responses.json,
trimmed); a request the recording lacks fails the test, so nothing here touches the network."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import advisory_facts  # noqa: E402

RESPONSES = json.loads((ROOT / "tests" / "fixtures" / "advisory_facts" / "responses.json").read_text(encoding="utf-8"))

# the garak closure's entries for the three packages of GHSA-3fx2-cqw9-xr3c, as tools/model-eval-requirements.txt
# pinned them before #191
LANGGRAPH_LOCK = """\
langchain==1.4.1 \\
    --hash=sha256:1286dd89c7fe2c552ba5b058fae16576e0acc8b0a5c1d060edc24d7d1f9230b7
langgraph==1.2.11 \\
    --hash=sha256:8bab70de7b2d00b5300fb289bcf38d8b241400f3184c1e95e8ce706fb0e8686b
langgraph-sdk==0.4.4 \\
    --hash=sha256:39afe416c91742925e6f8a93715f566d499b36e1b636b804a4ffe3190e4f4e64
"""


def recorded(url: str, body: dict | None = None) -> dict:
    """The recorded answer to a request; any other request is a test failure."""
    key = f"GET {url}" if body is None else f"POST {url} " + json.dumps(body, sort_keys=True)
    if key not in RESPONSES:
        raise AssertionError(f"unrecorded request: {key}")
    return RESPONSES[key]


def facts(tmp_path: Path, lock: str, *packages: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(lock, encoding="utf-8")
    code = advisory_facts.main(["--lockfile", str(lockfile), *packages], fetch=recorded)
    return code, " ".join(capsys.readouterr().out.split())


def test_the_advisories_on_the_pinned_version_and_their_first_fix(tmp_path, capsys):
    code, out = facts(tmp_path, LANGGRAPH_LOCK, "langgraph-sdk", "langgraph", capsys=capsys)
    assert code == 0, out
    assert "langgraph-sdk 0.4.4" in out and "langgraph 1.2.11" in out
    assert "GHSA-3fx2-cqw9-xr3c / CVE-2026-118667" in out
    assert "first fixed in 0.4.6" in out and "first fixed in 1.2.14" in out


# the semgrep closure's entries for semgrep and mcp (tools/semgrep-requirements.txt, 2026-10-29)
MCP_LOCK = """\
mcp==1.29.0 \\
    --hash=sha256:f5a075bb611f23d6f4d080c6a1699fa62772eebc562ba9e66b306ddde1c755f7
semgrep==1.179.0 \\
    --hash=sha256:b529c4db63f293918989b84ce4640f12f1b1e4680d9e7fcab5f3554f9113dfc5
"""


def test_a_dependent_that_pins_the_affected_version_refuses_the_fix(tmp_path, capsys):
    """semgrep 1.179.0 requires mcp==1.29.0, so no relock reaches mcp 1.30.0: the case for a dated exception."""
    code, out = facts(tmp_path, MCP_LOCK, "mcp", capsys=capsys)
    assert code == 0, out
    assert "required by semgrep 1.179.0: mcp==1.29.0, refuses 1.30.0" in out


def test_dependents_whose_range_holds_the_fix_accept_it(tmp_path, capsys):
    code, out = facts(tmp_path, LANGGRAPH_LOCK, "langgraph", "langgraph-sdk", capsys=capsys)
    assert code == 0, out
    assert "required by langchain 1.4.1: langgraph<1.3.0,>=1.2.11, accepts 1.2.14" in out
    assert "required by langgraph 1.2.11: langgraph-sdk<0.5.0,>=0.4.2, accepts 0.4.6" in out


def test_what_the_fixs_own_requirements_change(tmp_path, capsys):
    """langgraph 1.2.14 raises its langgraph-sdk floor to 0.4.6; langgraph-sdk 0.4.6 requires what 0.4.4 did."""
    code, out = facts(tmp_path, LANGGRAPH_LOCK, "langgraph", "langgraph-sdk", capsys=capsys)
    assert code == 0, out
    assert ("requirements of 1.2.14 against 1.2.11: - langgraph-sdk<0.5.0,>=0.4.2 + langgraph-sdk<0.5.0,>=0.4.6") in out
    assert "requirements of 0.4.6 against 0.4.4: unchanged" in out


# the garak closure's litellm entry before #189: the cp310-abi3-manylinux_2_28_x86_64 wheel, one of seven
LITELLM_LOCK = """\
litellm==1.101.0 \\
    --hash=sha256:140ee0997324b8fd2405f7f8c26f42c0f364996dc4030187344a90cf27916667
"""


def test_the_fixs_wheel_for_the_pinned_platform_and_its_sha256(tmp_path, capsys):
    """Of 1.101.3's seven wheels, the one with the tags of the wheel 1.101.0 was pinned by; a single universal wheel too."""
    code, out = facts(tmp_path, LITELLM_LOCK, "litellm", capsys=capsys)
    assert code == 0, out
    assert ("wheel of 1.101.3 for the pinned platform: litellm-1.101.3-cp310-abi3-manylinux_2_28_x86_64.whl, "
            "sha256 f6d4781771a209b74162d3f44ac7f894974ed61184702cdc5903442916869cf2") in out
    code, out = facts(tmp_path, LANGGRAPH_LOCK, "langgraph-sdk", capsys=capsys)
    assert ("wheel of 0.4.6 for the pinned platform: langgraph_sdk-0.4.6-py3-none-any.whl, "
            "sha256 57122b02bda41d37a97a5e09eb018aa8c9b3dc85c433880073779bd9324b7eea") in out


def test_a_package_without_advisories_says_so(tmp_path, capsys):
    code, out = facts(tmp_path, LANGGRAPH_LOCK, "langchain", capsys=capsys)
    assert code == 0, out
    assert "langchain 1.4.1" in out and "osv.dev lists no advisory on it" in out


def test_a_package_the_lockfile_does_not_pin_is_a_usage_error(tmp_path, capsys):
    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(LANGGRAPH_LOCK, encoding="utf-8")
    code = advisory_facts.main(["--lockfile", str(lockfile), "langgraph", "not-a-package"], fetch=recorded)
    captured = capsys.readouterr()
    assert code == 2, captured.out + captured.err
    assert "not-a-package is not pinned in" in captured.err and captured.out == ""


def test_a_relock_the_dependents_allow_gets_a_draft_header_note_and_one_they_refuse_names_them(tmp_path, capsys):
    """The line to start the lockfile header's hand-applied note from; or, when a dependent refuses the fix, who blocks it."""
    code, out = facts(tmp_path, LITELLM_LOCK, "litellm", capsys=capsys)
    assert code == 0, out
    assert ("draft: # - <date>: litellm 1.101.0 -> 1.101.3 (GHSA-7hp6-4w63-5g45 / CVE-2026-114612), the SHA-256 of its "
            "cp310-abi3-manylinux_2_28_x86_64 wheel") in out
    code, out = facts(tmp_path, MCP_LOCK, "mcp", capsys=capsys)
    assert "a relock cannot reach 1.30.0: semgrep 1.179.0 refuses it" in out and "draft:" not in out


# the garak closure's nltk and transformers entries before #189: transformers asks for nltk<=3.8.1 only in extras
NLTK_LOCK = """\
nltk==3.10.3 \\
    --hash=sha256:ff9598a8e20518ee0d557745890cc4435b9578489e2dcbc69c4f81fa060caf7c
transformers==5.17.0 \\
    --hash=sha256:78ec1ce21579b38dfb83950a0658cd119f87212a2fcfdff478096ce9d6c03801
"""


def test_a_requirement_inside_an_extra_the_closure_does_not_install_is_no_dependent(tmp_path, capsys):
    code, out = facts(tmp_path, NLTK_LOCK, "nltk", capsys=capsys)
    assert code == 0, out
    assert "required by transformers" not in out
    assert "draft: # - <date>: nltk 3.10.3 -> 3.10.4" in out


def test_an_advisory_that_names_only_its_last_affected_version_is_cleared_by_a_later_fix(tmp_path, capsys):
    """osv.dev records GHSA-8mgp-746c-j5xp with last_affected 3.10.3 and no fix; GHSA-j456-xh4h-cpf2's 3.10.4 is later,
    so it clears both (osv.dev lists nothing on 3.10.4)."""
    code, out = facts(tmp_path, NLTK_LOCK, "nltk", capsys=capsys)
    assert code == 0, out
    assert "GHSA-8mgp-746c-j5xp / CVE-2026-81726 / PYSEC-2026-3740" in out
    assert "affected up to 3.10.3, no fixed release named" in out and "first fixed in 3.10.4" in out
    assert "wheel of 3.10.4 for the pinned platform: nltk-3.10.4-py3-none-any.whl" in out


def test_the_fix_is_the_one_that_fixes_every_advisory_read_across_every_interval(tmp_path, capsys):
    """Made-up advisories on mcp 1.29.0: the pinned version in a range's second interval; an interval ending at 1.29.0,
    which does not hold it; and a lower fix, 1.29.5, beside the 1.30.0 the others need."""
    osv = {"vulns": [
        {"id": "SYN-1", "summary": "second interval", "affected": [{"package": {"name": "mcp", "ecosystem": "PyPI"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.2.0"}, {"introduced": "1.8.0"}, {"fixed": "1.30.0"}]}]}]},
        {"id": "SYN-2", "summary": "ends at the pin", "affected": [{"package": {"name": "mcp", "ecosystem": "PyPI"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.29.0"}, {"introduced": "1.29.0"}, {"fixed": "1.30.0"}]}]}]},
        {"id": "SYN-3", "summary": "a lower fix", "affected": [{"package": {"name": "mcp", "ecosystem": "PyPI"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.29.5"}]}]}]},
    ]}

    def made_up(url: str, body: dict | None = None) -> dict:
        return osv if body is not None and body["package"]["name"] == "mcp" else recorded(url, body)

    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(MCP_LOCK, encoding="utf-8")
    assert advisory_facts.main(["--lockfile", str(lockfile), "mcp"], fetch=made_up) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "SYN-1: second interval; first fixed in 1.30.0" in out
    assert "SYN-2: ends at the pin; first fixed in 1.30.0" in out
    assert "SYN-3: a lower fix; first fixed in 1.29.5" in out
    assert "required by semgrep 1.179.0: mcp==1.29.0, refuses 1.30.0" in out


def test_without_a_release_that_clears_every_advisory_it_says_so(tmp_path, capsys):
    """A made-up pair on mcp 1.29.0: one fixed in 1.30.0, one still affecting 1.31.0 with no fix named."""
    osv = {"vulns": [
        {"id": "SYN-A", "summary": "fixed", "affected": [{"package": {"name": "mcp", "ecosystem": "PyPI"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.30.0"}]}]}]},
        {"id": "SYN-B", "summary": "later", "affected": [{"package": {"name": "mcp", "ecosystem": "PyPI"}, "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.31.0"}]}]}]},
    ]}

    def made_up(url: str, body: dict | None = None) -> dict:
        return osv if body is not None and body["package"]["name"] == "mcp" else recorded(url, body)

    lockfile = tmp_path / "requirements.txt"
    lockfile.write_text(MCP_LOCK, encoding="utf-8")
    assert advisory_facts.main(["--lockfile", str(lockfile), "mcp"], fetch=made_up) == 0
    out = " ".join(capsys.readouterr().out.split())
    assert "SYN-B: later; affected up to 1.31.0, no fixed release named" in out
    assert "no release named clears every advisory" in out
    assert "draft:" not in out and "refuses" not in out and "wheel of" not in out


@pytest.mark.parametrize("url", ["https://example.com/pypi/mcp/1.29.0/json", "http://pypi.org/pypi/mcp/1.29.0/json",
                                 "https://pypi.org.example.com/pypi/x/1/json", "file:///etc/passwd"])
def test_the_network_adapter_reads_only_osv_dev_and_pypi_over_https(url):
    """tools/semgrep-triage.yaml accepts this file's urlopen because these two prefixes are the only URLs it opens."""
    with pytest.raises(ValueError, match="only osv.dev and PyPI"):
        advisory_facts.fetch_json(url)
