"""Appendix E prompt 7: the tool installer must refuse a wrong SHA-256, refuse a publisher checksum
that disagrees, refuse to skip signatures silently, and the runner must only execute what the
installer put under .mara-tools/bin. No network: every URL is file://."""

import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from install_tools import InstallError, git_paths_digest, install, load_lock, python_for_pip  # noqa: E402

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
    assert set(lock["tools"]) >= {"cosign", "slsa-verifier", "gitleaks", "osv-scanner", "zizmor", "trivy", "semgrep", "csp-evaluator"}
    for name, t in lock["tools"].items():
        if t["kind"] == "git":
            assert t["url"].startswith("https://github.com/") and t["url"].endswith(".git"), name
            assert t["verify"]["method"] in {"git-commit-gpg", "git-commit"} and len(t["commit"]) == 40 and len(t["sha256"]) == 64, name
            assert t["paths"] and all(p.endswith("/security") for p in t["paths"]), "only security rulesets are pinned"
        elif t["kind"] == "npm":
            # the tarball and the registry metadata must both pin the exact immutable version
            assert re.match(r"^https://registry\.npmjs\.org/[\w.-]+/-/[\w.-]+\.tgz$", t["url"]), name
            assert f"-{t['version']}.tgz" in t["url"], name
            assert re.match(r"^https://registry\.npmjs\.org/[\w.-]+/[\w.-]+$", t["publisher_checksums_url"]), name
            assert t["publisher_checksums_url"].rstrip("/").endswith(f"/{t['version']}"), name
            assert t["verify"]["method"] == "npm-integrity", name
        elif t["kind"] != "pip":
            assert t["url"].startswith("https://github.com/"), name
            assert t["verify"]["method"] in {"cosign-keyless", "slsa-provenance", "github-attestation", "checksums-file"}, name
    rules = lock["tools"]["semgrep-rules"]
    assert rules["verify"]["gpg_key_url"] == "https://github.com/web-flow.gpg" and rules["verify"]["gpg_fingerprint"] == "968479A1AFF927E37D1A566BB5690EEEBB952194"
    req = (ROOT / lock["tools"]["semgrep"]["requirements"]).read_text()
    assert f"semgrep=={lock['tools']['semgrep']['version']}" in req and req.count("--hash=sha256:") >= 60
    boot = (ROOT / "tools" / "bootstrap-requirements.txt").read_text()
    assert boot.lower().count("pyyaml==") == 1 and "--hash=sha256:" in boot



def test_every_pinned_url_names_a_release_or_a_commit_not_a_branch():
    # A branch URL (slsa-verifier's SHA256SUM.md at main, until 2026-09-27) changes under the pin: the
    # next release's section comes first and the cross-check fails, or the file is rewritten. npm
    # tarballs and their registry metadata are immutable once published for a given version.
    lock = load_lock(ROOT / "tools" / "versions.lock")
    release = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/releases/download/v?(?P<tag>[\w.-]+)/[^/]+$")
    raw_at_commit = re.compile(r"^https://raw\.githubusercontent\.com/[\w.-]+/[\w.-]+/[0-9a-f]{40}/[^?#]+$")
    npm_tarball = re.compile(r"^https://registry\.npmjs\.org/[\w.-]+/-/[\w.-]+\.tgz$")
    npm_doc = re.compile(r"^https://registry\.npmjs\.org/[\w.-]+/[\w.-]+$")
    checked = 0
    for name, t in lock["tools"].items():
        fields = {k: v for k, v in {**t, **t.get("verify", {})}.items() if k.endswith("_url")}
        if t["kind"] not in {"git", "pip"}:
            fields["url"] = t["url"]
        for field, url in fields.items():
            if field == "gpg_key_url":
                continue  # GitHub's web-flow key: pinned by gpg_key_id, not by URL
            ok = bool((m := release.match(url)) and m["tag"] == str(t["version"])) or bool(raw_at_commit.match(url))
            if t["kind"] == "npm" and field == "url":
                ok = ok or bool(npm_tarball.match(url) and f"-{t['version']}.tgz" in url)
            if t["kind"] == "npm" and field == "publisher_checksums_url":
                ok = ok or bool(npm_doc.match(url) and url.rstrip("/").endswith(f"/{t['version']}"))
            assert ok, f"{name}.{field}: {url}"
            checked += 1
    assert checked >= 15


# ----------------------------------------------------------------------------- npm kind (csp-evaluator)


def _npm_package(version: str = "1.2.3", *, complete: bool = True) -> bytes:
    buf = io.BytesIO()
    files = [("package/package.json", json.dumps({"name": "fake-evaluator", "version": version}).encode()),
             ("package/dist/evaluator.js", b'"use strict";\nmodule.exports = {};\n'),
             ("package/dist/parser.js", b'"use strict";\nmodule.exports = {};\n')]
    if not complete:
        files = [f for f in files if f[0] != "package/dist/evaluator.js"]
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for fname, data in files:
            info = tarfile.TarInfo(fname)
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _npm_lock(src: Path, tarball: Path, **override) -> dict:
    # registry-shaped file:// URLs — <...>/<name>/-/<name>-<version>.tgz and <...>/<name>/<version> —
    # the same shapes the https URLs in the shipped lock have
    reg = src / "registry.npmjs.org" / "fake-evaluator"
    spec = {"version": "1.2.3", "kind": "npm",
            "url": f"file:///{(reg / '-' / tarball.name).as_posix()}",
            "sha256": _sha(tarball.read_bytes()),
            "publisher_checksums_url": f"file:///{(reg / '1.2.3').as_posix()}",
            "verify": {"method": "npm-integrity"}}
    spec.update(override)
    return {"schema": 1, "tools": {"fake-evaluator": spec}}


def _registry_doc(reg: Path, name: str, version: str, tarball: Path) -> None:
    import base64

    integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball.read_bytes()).digest()).decode()
    reg.mkdir(parents=True, exist_ok=True)
    (reg / version).write_text(json.dumps({"name": name, "version": version, "dist": {"integrity": integrity}}), encoding="utf-8")


def test_npm_kind_installs_package_driver_and_shims(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    reg = src / "registry.npmjs.org" / "fake-evaluator"
    tarball = reg / "-" / "fake-evaluator-1.2.3.tgz"
    tarball.parent.mkdir(parents=True, exist_ok=True)
    tarball.write_bytes(_npm_package())
    _registry_doc(reg, "fake-evaluator", "1.2.3", tarball)
    dest = tmp_path / "mt"
    manifest = install(_npm_lock(src, tarball), install_dir=dest)
    entry = manifest["tools"]["fake-evaluator"]
    assert entry["kind"] == "npm" and entry["signature_verified"] is False
    assert (dest / "fake-evaluator" / "dist" / "evaluator.js").is_file()
    assert (dest / "fake-evaluator" / "mara_driver.js").is_file(), "the repository's driver is installed next to the package"
    assert (dest / "fake-evaluator" / "mara_driver.js").read_bytes() == (ROOT / "src" / "mara" / "tools" / "csp_driver.js").read_bytes()
    assert (dest / "bin" / "fake-evaluator").is_file() and "mara_driver.js" in (dest / "bin" / "fake-evaluator").read_text()
    assert (dest / "bin" / "fake-evaluator.cmd").is_file() and "mara_driver.js" in (dest / "bin" / "fake-evaluator.cmd").read_text()
    assert "npm-integrity" in entry["verified_by"]


def test_npm_kind_refuses_registry_integrity_mismatch(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    reg = src / "registry.npmjs.org" / "fake-evaluator"
    tarball = reg / "-" / "fake-evaluator-1.2.3.tgz"
    tarball.parent.mkdir(parents=True, exist_ok=True)
    tarball.write_bytes(_npm_package())
    _registry_doc(reg, "fake-evaluator", "1.2.3", tarball)
    # the same SHA-256 as pinned, but the registry metadata names a different digest
    doc = json.loads((reg / "1.2.3").read_text())
    doc["dist"]["integrity"] = "sha512-" + "A" * 88
    (reg / "1.2.3").write_text(json.dumps(doc))
    with pytest.raises(InstallError, match="dist.integrity mismatch"):
        install(_npm_lock(src, tarball), install_dir=tmp_path / "mt")
    assert not (tmp_path / "mt" / "fake-evaluator").exists()


def test_npm_kind_refuses_metadata_for_another_version(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    reg = src / "registry.npmjs.org" / "fake-evaluator"
    tarball = reg / "-" / "fake-evaluator-1.2.3.tgz"
    tarball.parent.mkdir(parents=True, exist_ok=True)
    tarball.write_bytes(_npm_package())
    # the metadata URL is pinned at 1.2.3 but the registry serves a document for 9.9.9
    _registry_doc(reg, "fake-evaluator", "9.9.9", tarball)
    (reg / "1.2.3").write_text((reg / "9.9.9").read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.raises(InstallError, match="not fake-evaluator@1.2.3|does not match"):
        install(_npm_lock(src, tarball), install_dir=tmp_path / "mt")


def test_npm_kind_refuses_an_incomplete_package(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    reg = src / "registry.npmjs.org" / "fake-evaluator"
    tarball = reg / "-" / "fake-evaluator-1.2.3.tgz"
    tarball.parent.mkdir(parents=True, exist_ok=True)
    tarball.write_bytes(_npm_package(complete=False))
    _registry_doc(reg, "fake-evaluator", "1.2.3", tarball)
    with pytest.raises(InstallError, match="tarball has no dist/evaluator.js"):
        install(_npm_lock(src, tarball), install_dir=tmp_path / "mt")
    assert not (tmp_path / "mt" / "fake-evaluator").exists()


def test_lock_validation_rejects_bad_npm_entries(tmp_path):
    tarball = tmp_path / "x.tgz"
    tarball.write_bytes(b"x")
    base = {"version": "1.0", "kind": "npm", "url": f"file:///{tarball.as_posix()}", "sha256": _sha(b"x"),
            "publisher_checksums_url": "https://registry.npmjs.org/pkg/1.0", "verify": {"method": "npm-integrity"}}
    for bad in ({"url": "https://example.com/pkg/-/pkg-1.0.tgz"},
                {"url": "https://registry.npmjs.org/pkg/-/pkg-9.9.9.tgz"},
                {"sha256": "nope"},
                {"publisher_checksums_url": "https://example.com/doc.json"}):
        p = tmp_path / "bad.lock"
        p.write_text(yaml.safe_dump({"schema": 1, "tools": {"pkg": {**base, **bad}}}))
        with pytest.raises(InstallError):
            load_lock(p)

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
    fake_cosign = f"#!/bin/sh\necho \"$0 $@\" >> '{log.as_posix()}'\nexit 0\n".encode()
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
    assert calls[0].replace("\\", "/").startswith((dest / "cache" / "cosign-linux-amd64").as_posix()), "self-verification must use the downloaded artifact"
    assert calls[1].replace("\\", "/").startswith((dest / "bin" / "cosign").as_posix()), "later tools must use the installed verifier"
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


# ----------------------------------------------------------------------------- git kind (semgrep-rules)


def _git(repo: Path, *args: str) -> str:
    import subprocess

    return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def rules_repo(tmp_path):
    repo = tmp_path / "rules"
    (repo / "python" / "x" / "security").mkdir(parents=True)
    (repo / "python" / "x" / "security" / "r1.yaml").write_text("rules: []\n")
    (repo / "python" / "x" / "security" / "r1.py").write_text("# test target\n")
    (repo / "python" / "x" / "other" / "audit").mkdir(parents=True)
    (repo / "python" / "x" / "other" / "audit" / "r2.yaml").write_text("rules: []\n")
    _git(repo, "init", "-q", "-b", "release")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "rules")
    return repo


def _git_lock(repo: Path, **override) -> dict:
    spec = {"version": "release@test", "kind": "git", "url": f"file://{repo}", "commit": _git(repo, "rev-parse", "HEAD"),
            "paths": ["python/x/security"], "sha256": git_paths_digest(repo, ["python/x/security"]), "verify": {"method": "git-commit"}}
    spec.update(override)
    return {"schema": 1, "tools": {"semgrep-rules": spec}}


def test_git_kind_checks_out_the_pinned_commit_and_digest(rules_repo, tmp_path):
    dest = tmp_path / "mt"
    manifest = install(_git_lock(rules_repo), install_dir=dest)
    entry = manifest["tools"]["semgrep-rules"]
    assert (dest / "semgrep-rules" / "python" / "x" / "security" / "r1.yaml").is_file()
    assert _git(dest / "semgrep-rules", "rev-parse", "HEAD") == entry["commit"] and entry["paths"] == ["python/x/security"]
    assert entry["sha256"] == git_paths_digest(rules_repo, ["python/x/security"]) and entry["signature_verified"] is False
    # the digest covers only the pinned paths and every file under them, in a path-ordered, content-bound way
    assert git_paths_digest(rules_repo, ["python/x/security"]) != git_paths_digest(rules_repo, ["python/x/other"])
    (rules_repo / "python" / "x" / "security" / "r1.py").write_text("# changed\n")
    assert git_paths_digest(rules_repo, ["python/x/security"]) != entry["sha256"]


def test_git_kind_aborts_on_digest_or_commit_mismatch(rules_repo, tmp_path):
    with pytest.raises(InstallError, match="digest over"):
        install(_git_lock(rules_repo, sha256="0" * 64), install_dir=tmp_path / "a")
    assert not (tmp_path / "a" / "semgrep-rules").exists()
    with pytest.raises(InstallError, match="git fetch failed|not the pinned"):
        install(_git_lock(rules_repo, commit="1" * 40), install_dir=tmp_path / "b")
    assert not (tmp_path / "b" / "semgrep-rules").exists()
    # a signature method needs the key: without network there is no key, and skipping must be explicit
    with pytest.raises(InstallError, match="could not download|GPG"):
        install(_git_lock(rules_repo, verify={"method": "git-commit-gpg", "gpg_key_url": "file:///nonexistent/key.asc", "gpg_fingerprint": "968479A1AFF927E37D1A566BB5690EEEBB952194"}),
                install_dir=tmp_path / "c")
    m = install(_git_lock(rules_repo, verify={"method": "git-commit-gpg", "gpg_key_url": "file:///nonexistent/key.asc", "gpg_fingerprint": "968479A1AFF927E37D1A566BB5690EEEBB952194"}),
                install_dir=tmp_path / "c", no_signature_check=True)
    assert "SKIPPED" in m["tools"]["semgrep-rules"]["verified_by"]


def test_lock_validation_rejects_bad_git_entries(rules_repo, tmp_path):
    for bad in ({"commit": "abc"}, {"sha256": "nope"}, {"paths": []}, {"paths": ["../etc"]}):
        p = tmp_path / "bad.lock"
        p.write_text(yaml.safe_dump(_git_lock(rules_repo, **bad)))
        with pytest.raises(InstallError):
            load_lock(p)


def test_moving_into_place_outlasts_a_briefly_held_handle(tmp_path, monkeypatch):
    """On Windows a fresh checkout is opened by the virus scanner or the indexer for a moment, and the
    rename into place failed with WinError 5 (seen in this suite: test_git_kind_* flaked)."""
    import install_tools

    src, dest = tmp_path / "x.installing", tmp_path / "x"
    src.mkdir()
    real, calls = Path.replace, []

    def held(self, target):
        calls.append(target)
        if len(calls) < 3:
            raise PermissionError(5, "Access is denied")
        return real(self, target)

    monkeypatch.setattr(Path, "replace", held)
    monkeypatch.setattr(install_tools.time, "sleep", lambda s: None)
    install_tools.move_into_place(src, dest)
    assert dest.is_dir() and not src.exists() and len(calls) == 3


def test_a_handle_that_stays_held_still_fails(tmp_path, monkeypatch):
    import install_tools

    src = tmp_path / "x.installing"
    src.mkdir()
    monkeypatch.setattr(Path, "replace", lambda self, target: (_ for _ in ()).throw(PermissionError(5, "Access is denied")))
    monkeypatch.setattr(install_tools.time, "sleep", lambda s: None)
    with pytest.raises(PermissionError):
        install_tools.move_into_place(src, tmp_path / "x")
