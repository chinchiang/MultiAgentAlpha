"""Appendix E prompt 7: the tool installer must refuse a wrong SHA-256, refuse a publisher checksum
that disagrees, refuse to skip signatures silently, and the runner must only execute what the
installer put under .mara-tools/bin. No network: every URL is file://."""

import hashlib
import io
import json
import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from install_tools import InstallError, install, load_lock, python_for_pip  # noqa: E402

from mara.tools import runner  # noqa: E402


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _fake_tool(text: str) -> bytes:
    return f"#!/bin/sh\n{text}\n".encode()


@pytest.fixture
def assets(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    bin_bytes = _fake_tool("echo fake-binary")
    (src / "tool-a").write_bytes(bin_bytes)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = _fake_tool("echo fake-archived")
        info = tarfile.TarInfo("tool-b-x86_64/tool-b")
        info.size = len(data)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(data))
    (src / "tool-b.tar.gz").write_bytes(buf.getvalue())
    (src / "checksums.txt").write_text(f"{_sha(bin_bytes)}  tool-a\n{_sha(buf.getvalue())}  tool-b.tar.gz\n")
    return src


def _lock(src: Path, **override) -> dict:
    lock = {
        "schema": 1, "install_dir": ".mara-tools",
        "tools": {
            "tool-a": {"version": "1.0", "kind": "binary", "url": f"file://{src / 'tool-a'}", "sha256": _sha((src / "tool-a").read_bytes()),
                       "publisher_checksums_url": f"file://{src / 'checksums.txt'}", "verify": {"method": "checksums-file"}},
            "tool-b": {"version": "2.0", "kind": "archive", "extract": "tool-b", "url": f"file://{src / 'tool-b.tar.gz'}",
                       "sha256": _sha((src / "tool-b.tar.gz").read_bytes()),
                       "verify": {"method": "cosign-keyless", "bundle_url": f"file://{src / 'tool-a'}", "oidc_issuer": "x", "certificate_identity_regexp": "y"}},
        },
    }
    for k, v in override.items():
        lock["tools"][k].update(v)
    return lock


def test_installs_and_writes_manifest(assets, tmp_path):
    dest = tmp_path / "mt"
    manifest = install(_lock(assets), install_dir=dest, no_signature_check=True)
    assert (dest / "bin" / "tool-a").is_file() and os.access(dest / "bin" / "tool-a", os.X_OK)
    assert (dest / "bin" / "tool-b").read_bytes() == _fake_tool("echo fake-archived")
    assert manifest["tools"]["tool-a"]["signature_verified"] is False
    assert "SKIPPED" in manifest["tools"]["tool-b"]["verified_by"]
    assert json.loads((dest / "manifest.json").read_text())["tools"]["tool-b"]["version"] == "2.0"


def test_wrong_sha256_aborts_and_installs_nothing(assets, tmp_path):
    dest = tmp_path / "mt"
    bad = _lock(assets, **{"tool-a": {"sha256": "0" * 64}})
    with pytest.raises(InstallError, match="SHA-256 mismatch"):
        install(bad, install_dir=dest, only=["tool-a"], no_signature_check=True)
    assert not (dest / "bin" / "tool-a").exists()


def test_publisher_checksum_disagreement_aborts(assets, tmp_path):
    (assets / "checksums.txt").write_text(f"{'1' * 64}  tool-a\n")
    with pytest.raises(InstallError, match="publisher checksum"):
        install(_lock(assets), install_dir=tmp_path / "mt", only=["tool-a"], no_signature_check=True)
    assert not (tmp_path / "mt" / "bin" / "tool-a").exists()


def test_signature_method_without_verifier_aborts_unless_explicitly_skipped(assets, tmp_path):
    with pytest.raises(InstallError, match="needs 'cosign'"):
        install(_lock(assets), install_dir=tmp_path / "mt", only=["tool-b"])
    assert not (tmp_path / "mt" / "bin" / "tool-b").exists()


def test_lock_validation_rejects_malformed_sha(tmp_path, assets):
    bad = _lock(assets, **{"tool-a": {"sha256": "nope"}})
    p = tmp_path / "bad.lock"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(InstallError, match="malformed sha256"):
        load_lock(p)


def test_shipped_lock_is_well_formed():
    lock = load_lock(ROOT / "tools" / "versions.lock")
    assert set(lock["tools"]) >= {"cosign", "slsa-verifier", "gitleaks", "osv-scanner", "zizmor", "trivy", "semgrep"}
    for name, t in lock["tools"].items():
        if t["kind"] != "pip":
            assert t["url"].startswith("https://github.com/"), name
            assert t["verify"]["method"] in {"cosign-keyless", "slsa-provenance", "github-attestation", "checksums-file"}, name
    req = (ROOT / lock["tools"]["semgrep"]["requirements"]).read_text()
    assert f"semgrep=={lock['tools']['semgrep']['version']}" in req and req.count("--hash=sha256:") >= 60
    boot = (ROOT / "tools" / "bootstrap-requirements.txt").read_text()
    assert boot.lower().count("pyyaml==") == 1 and "--hash=sha256:" in boot


def test_runner_only_executes_pinned_tools(tmp_path, monkeypatch):
    mt = tmp_path / "mt"
    (mt / "bin").mkdir(parents=True)
    sarif = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "zizmor"}}, "results": [
        {"ruleId": "zizmor/dangerous-triggers", "level": "error", "message": {"text": "x"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/deploy.yml"}, "region": {"startLine": 2}}}]}]}]})
    fake = mt / "bin" / "zizmor"
    fake.write_text("#!/bin/sh\ncat <<'EOF'\n" + sarif + "\nEOF\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    (mt / "manifest.json").write_text(json.dumps({"tools": {"zizmor": {"version": "9.9.9"}}}))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(mt))
    target = tmp_path / "target"
    target.mkdir()
    runs = {r.tool: r for r in runner.run_all(target, tmp_path / "out", enabled=["zizmor", "gitleaks"])}
    assert runs["zizmor"].ran and runs["zizmor"].results[0].rule_id == "zizmor/dangerous-triggers" and "9.9.9" in runs["zizmor"].note
    assert not runs["gitleaks"].ran and "install_tools.py" in runs["gitleaks"].note
    # PATH is never consulted
    monkeypatch.setenv("PATH", str(mt / "bin") + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "empty"))
    assert runner.tool_path("zizmor") is None


def test_verifier_verifies_its_own_release_with_the_downloaded_artifact(tmp_path):
    """cosign is not installed when its own bundle is checked (the CI failure on PR #6): the
    freshly downloaded artifact must act as the verifier, and later tools must use bin/cosign."""
    src = tmp_path / "src"
    src.mkdir()
    log = tmp_path / "calls.log"
    fake_cosign = f"#!/bin/sh\necho \"$0 $@\" >> {log}\nexit 0\n".encode()
    (src / "cosign-linux-amd64").write_bytes(fake_cosign)
    (src / "bundle.json").write_text("{}")
    other = _fake_tool("echo other")
    (src / "other").write_bytes(other)
    lock = {"schema": 1, "tools": {
        "cosign": {"role": "verifier", "version": "9", "kind": "binary", "url": f"file://{src / 'cosign-linux-amd64'}", "sha256": _sha(fake_cosign),
                   "verify": {"method": "cosign-keyless", "bundle_url": f"file://{src / 'bundle.json'}", "oidc_issuer": "i", "certificate_identity_regexp": "r"}},
        "other": {"version": "1", "kind": "binary", "url": f"file://{src / 'other'}", "sha256": _sha(other),
                  "verify": {"method": "cosign-keyless", "bundle_url": f"file://{src / 'bundle.json'}", "oidc_issuer": "i", "certificate_identity_regexp": "r"}},
    }}
    dest = tmp_path / "mt"
    manifest = install(lock, install_dir=dest)
    assert manifest["tools"]["cosign"]["signature_verified"] and manifest["tools"]["other"]["signature_verified"]
    calls = log.read_text().splitlines()
    assert len(calls) == 2
    assert calls[0].startswith(str(dest / "cache" / "cosign-linux-amd64")), "self-verification must use the downloaded artifact"
    assert calls[1].startswith(str(dest / "bin" / "cosign")), "later tools must use the installed verifier"
    assert "verify-blob" in calls[1] and "--certificate-identity-regexp r" in calls[1]


def test_failed_signature_verification_aborts(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    bad_cosign = b"#!/bin/sh\necho nope >&2\nexit 1\n"
    (src / "cosign-linux-amd64").write_bytes(bad_cosign)
    (src / "bundle.json").write_text("{}")
    lock = {"schema": 1, "tools": {"cosign": {"role": "verifier", "version": "9", "kind": "binary", "url": f"file://{src / 'cosign-linux-amd64'}",
                                              "sha256": _sha(bad_cosign), "verify": {"method": "cosign-keyless", "bundle_url": f"file://{src / 'bundle.json'}",
                                                                                     "oidc_issuer": "i", "certificate_identity_regexp": "r"}}}}
    with pytest.raises(InstallError, match="cosign keyless verification FAILED"):
        install(lock, install_dir=tmp_path / "mt")
    assert not (tmp_path / "mt" / "bin" / "cosign").exists()


def test_pip_lock_requires_the_locked_interpreter():
    """CI runners default to another CPython; wheels are ABI-specific so the hash lock only holds for
    the interpreter it was generated with (the second CI failure on PR #6)."""
    here = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert python_for_pip({"platform": {"python": here}}) == Path(sys.executable)
    with pytest.raises(InstallError, match="CPython 9.9"):
        python_for_pip({"platform": {"python": "9.9"}})
