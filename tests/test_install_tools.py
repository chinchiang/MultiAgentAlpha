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

from install_tools import InstallError, install, load_lock  # noqa: E402

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
