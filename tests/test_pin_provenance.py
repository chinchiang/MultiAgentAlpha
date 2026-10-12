"""Tools review items 8-10: the trivy-db record names the artifact that was downloaded, ASVS references are
validated down to the requirement, and the calibration corpora are pinned to a commit."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mara.groundtruth import load, validate_ref
from mara.scoring.idcheck import check_finding_refs
from mara.tools import trivy_db as tdb
from tests.test_bias_and_scoring import _finding
from tests.test_trivy_db import _fake_trivy, _now_iso

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fetch_calib_corpora as corpora  # noqa: E402
import trivy_db as trivy_db_script  # noqa: E402

DIGEST = "sha256:" + "ab" * 32


# ------------------------------------------------------------------ 8. trivy-db provenance

@pytest.fixture
def fake_trivy(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    _fake_trivy(tools, _now_iso(2))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    return tools, tmp_path / "cache"


def _download(cache: Path, *args: str) -> int:
    return trivy_db_script.main(["--cache-dir", str(cache), "download", "--repository", "example.invalid/aquasec/trivy-db:2", *args])


def test_download_fetches_the_digest_the_registry_named_and_records_it(fake_trivy, monkeypatch):
    tools, cache = fake_trivy
    monkeypatch.setattr(trivy_db_script, "head_manifest",
                        lambda ref: {"manifest_digest": DIGEST, "layer_digest": "sha256:" + "cd" * 32, "created": "2026-10-12T00:00:00Z"})
    assert _download(cache) == 0
    argv = (tools / "argv.txt").read_text()
    assert f"--db-repository example.invalid/aquasec/trivy-db@{DIGEST}" in argv and "trivy-db:2" not in argv, \
        "by digest: a tag can move between the registry query and the download"
    rec = json.loads(tdb.record_path(cache).read_text())
    assert rec["repository"] == "example.invalid/aquasec/trivy-db:2" and rec["downloaded_ref"].endswith(f"@{DIGEST}")
    assert rec["manifest_digest"] == DIGEST and rec["provenance"] == "digest"
    ok, lines = tdb.check(cache, 48)
    assert ok and not any("provenance unverified" in line for line in lines)


def test_unknown_provenance_is_refused_unless_explicitly_allowed(fake_trivy, monkeypatch, capsys):
    tools, cache = fake_trivy
    monkeypatch.setattr(trivy_db_script, "head_manifest",
                        lambda ref: {"manifest_digest": "unknown", "layer_digest": "unknown", "created": "unknown", "error": "unreachable"})
    assert _download(cache) == 1
    assert not (tools / "argv.txt").exists(), "trivy is not run when the record could not say what it fetched"
    assert not tdb.record_path(cache).exists() and "did not name the manifest digest" in capsys.readouterr().out
    assert _download(cache, "--allow-unknown-provenance") == 0
    rec = json.loads(tdb.record_path(cache).read_text())
    assert rec["provenance"] == "unverified" and rec["downloaded_ref"] == "example.invalid/aquasec/trivy-db:2"
    ok, lines = tdb.check(cache, 48)
    assert ok and any("provenance unverified" in line for line in lines), "status says so; the content check still applies"


# ------------------------------------------------------------------ 9. ASVS to the requirement

def test_asvs_requirements_are_pinned_from_the_release_csv():
    asvs = load("asvs_5_0")
    reqs = [(c, s, r) for c, ch in asvs["chapters"].items() for s, rs in ch["requirements"].items() for r in rs]
    assert len(reqs) == 345 and len(set(reqs)) == 345
    assert all(set(ch["requirements"]) == set(ch["sections"]) for ch in asvs["chapters"].values())
    assert "5cf9b032440be53ce345ab3c130fda46ba1ce7a2" in asvs["_requirements_source"]


@pytest.mark.parametrize("ref, ok", [("ASVS 5.0 V6.2.1", True), ("ASVS 5.0 V15.2.3", True), ("ASVS 5.0 V17.3.2", True),
                                      ("ASVS 5.0 V1.2", True), ("ASVS 5.0 V1", True),
                                      ("ASVS 5.0 V1.2.99", False), ("ASVS 5.0 V6.2.13", False), ("ASVS 5.0 V18.1.1", False),
                                      ("ASVS 5.0 V1.9.1", False)])
def test_asvs_refs_are_validated_down_to_the_requirement(ref, ok):
    assert validate_ref(ref)[0] is ok, validate_ref(ref)


def test_a_made_up_requirement_is_stripped_from_a_finding():
    ref = check_finding_refs(_finding(refs=["ASVS 5.0 V1.2.5", "ASVS 5.0 V1.2.99"]))
    assert ref.finding.standard_refs == ["ASVS 5.0 V1.2.5"] and ref.stripped == ["ASVS 5.0 V1.2.99"]


# ------------------------------------------------------------------ 10. calibration corpora pinned

def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "app.js").write_text("v1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "release")
    pinned = _git(repo, "rev-parse", "HEAD")
    (repo / "app.js").write_text("v2\n")
    _git(repo, "commit", "-q", "-am", "later push")
    _git(repo, "config", "uploadpack.allowAnySHA1InWant", "true")  # as GitHub serves any reachable commit
    return repo, pinned


def test_a_corpus_is_checked_out_at_its_pinned_commit_not_the_branch_tip(upstream, tmp_path):
    repo, pinned = upstream
    c = corpora.Corpus("demo", repo.as_uri(), "v1", pinned)
    dest = tmp_path / "corpora" / "demo"
    assert corpora.fetch(c, dest) == pinned and (dest / "app.js").read_text() == "v1\n"
    assert corpora.fetch(c, dest) == pinned, "an existing checkout at the pin is reused"


def test_a_checkout_at_another_commit_is_refused(upstream, tmp_path):
    repo, pinned = upstream
    dest = tmp_path / "corpora" / "demo"
    subprocess.run(["git", "clone", "-q", repo.as_uri(), str(dest)], check=True, capture_output=True)
    with pytest.raises(corpora.FetchError, match="not the pinned demo v1"):
        corpora.fetch(corpora.Corpus("demo", repo.as_uri(), "v1", pinned), dest)


def test_an_unknown_commit_leaves_nothing_behind(upstream, tmp_path):
    repo, _ = upstream
    dest = tmp_path / "corpora" / "demo"
    with pytest.raises(corpora.FetchError):
        corpora.fetch(corpora.Corpus("demo", repo.as_uri(), "v9", "0" * 40), dest)
    assert not dest.exists()
    with pytest.raises(corpora.FetchError, match="40-character"):
        corpora.fetch(corpora.Corpus("demo", repo.as_uri(), "v1", "main"), tmp_path / "x")


def test_the_shipped_corpora_are_pinned_to_full_commit_ids():
    assert {c.name for c in corpora.CORPORA} == {"juice-shop", "WebGoat"}
    assert all(corpora.COMMIT_RE.match(c.commit) and c.tag for c in corpora.CORPORA)
    assert "fetch_calib_corpora.py" in (ROOT / "scripts" / "fetch_calib_corpora.sh").read_text()
