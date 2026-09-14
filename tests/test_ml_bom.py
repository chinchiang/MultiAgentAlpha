"""G-7: the self-hosted weights are listed in a CycloneDX 1.6 ML-BOM (safetensors-only hashes,
licence, source, signature); policy P7 enforces it once required; governance G-7 reads the same BOM."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from mara import mlbom  # noqa: E402
from mara.config import MaraConfig, load_config  # noqa: E402
from mara.pipeline import Pipeline  # noqa: E402
from mara.policy import p7_ml_bom  # noqa: E402
from mara.report.markdown_out import render_markdown  # noqa: E402

SCRIPT = ROOT / "scripts" / "ml_bom.py"


def _weights(tmp_path: Path) -> Path:
    d = tmp_path / "weights"
    d.mkdir()
    (d / "model-00001-of-00002.safetensors").write_bytes(b"\x00" * 4096)
    (d / "model-00002-of-00002.safetensors").write_bytes(b"\x01" * 2048)
    (d / "config.json").write_text('{"architectures": ["ExampleForCausalLM"]}\n', encoding="utf-8")
    return d


def _entry(files, **kw) -> mlbom.ModelEntry:
    base = dict(model_id="example/model-7b", family="deepseek", name="example-model", version="7b",
                source={"kind": "huggingface", "url": "https://huggingface.co/example/model-7b", "revision": "abc"},
                license={"id": "Apache-2.0"}, serving="vllm", architecture={"family": "Example", "name": "ExampleForCausalLM"},
                signature={"method": "cosign-keyless", "identity": "p@example.internal", "issuer": "https://issuer.example"}, files=files)
    base.update(kw)
    return mlbom.ModelEntry(**base)


def test_hash_dir_requires_safetensors_and_refuses_pickle(tmp_path):
    d = _weights(tmp_path)
    files = mlbom.hash_dir(d)
    assert [f.path for f in files] == ["config.json", "model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"]
    assert all(mlbom.SHA256_RE.match(f.sha256) for f in files) and files[1].size == 4096
    digest = mlbom.manifest_digest(files)
    assert mlbom.SHA256_RE.match(digest) and digest == mlbom.manifest_digest(list(reversed(files)))
    (d / "pytorch_model.bin").write_bytes(b"\x80\x04")
    with pytest.raises(mlbom.PickleWeightsError):
        mlbom.hash_dir(d)
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.md").write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        mlbom.hash_dir(empty)


def test_manifest_round_trip_builds_a_schema_valid_complete_bom(tmp_path):
    d = _weights(tmp_path)
    manifest = tmp_path / "models.yaml"
    e = _entry([])
    manifest.write_text(yaml.safe_dump({"models": [{
        "model_id": e.model_id, "family": e.family, "name": e.name, "version": e.version, "source": e.source,
        "license": e.license, "format": "safetensors", "serving": e.serving, "architecture": e.architecture,
        "signature": e.signature, "files": []}]}), encoding="utf-8")
    with pytest.raises(ValueError):  # pending entries are refused by default
        mlbom.build_bom(mlbom.load_manifest(manifest))
    mlbom.write_manifest_files(manifest, e.model_id, mlbom.hash_dir(d))
    entries = mlbom.load_manifest(manifest)
    assert not entries[0].pending and len(entries[0].files) == 3
    bom = mlbom.build_bom(entries, timestamp="2026-09-12T00:00:00Z", serial="urn:uuid:8d7c6b5a-4f3e-4d2c-9b1a-0e9f8d7c6b5a")
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert mlbom.validate_schema(bom) == []
    comp = mlbom.ml_components(bom)["example/model-7b"]
    assert comp["type"] == "machine-learning-model" and mlbom.component_problems(comp) == []
    assert comp["hashes"][0]["content"] == mlbom.manifest_digest(entries[0].files)
    assert {c["name"] for c in comp["components"]} == {"config.json", "model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"}
    assert mlbom.props(comp)["status"] == "complete" and mlbom.props(comp)["format"] == "safetensors"
    assert any(dep["ref"] == "mara" and comp["bom-ref"] in dep["dependsOn"] for dep in bom["dependencies"])
    # rebuilding from the same manifest is identical apart from serial number and timestamp
    again = mlbom.build_bom(mlbom.load_manifest(manifest))
    assert mlbom.bom_equal_ignoring_volatile(bom, again)


def test_component_problems_name_each_missing_piece(tmp_path):
    files = mlbom.hash_dir(_weights(tmp_path))
    ok = mlbom.build_component(_entry(files), allow_pending=False)
    assert mlbom.component_problems(ok) == []
    pending = mlbom.build_component(_entry([]), allow_pending=True)
    assert any("pending" in p for p in mlbom.component_problems(pending)) and any("SHA-256" in p for p in mlbom.component_problems(pending))
    no_lic = mlbom.build_component(_entry(files, license={}), allow_pending=False)
    assert any("licence" in p for p in mlbom.component_problems(no_lic))
    no_src = mlbom.build_component(_entry(files, source={}), allow_pending=False)
    assert any("distribution" in p for p in mlbom.component_problems(no_src))
    unsigned = mlbom.build_component(_entry(files, signature={}), allow_pending=False)
    assert any("signature" in p for p in mlbom.component_problems(unsigned))
    with pytest.raises(ValueError):
        mlbom.build_component(_entry(files, format="pickle"), allow_pending=False)
    with pytest.raises(mlbom.PickleWeightsError):
        mlbom.build_component(_entry(files + [mlbom.FileEntry("model.bin", "0" * 64, 1)]), allow_pending=False)
    tampered = json.loads(json.dumps(ok))
    tampered["components"].append({"type": "file", "name": "extra.bin", "hashes": [{"alg": "SHA-256", "content": "0" * 64}]})
    assert any("pickle-based file listed" in p for p in mlbom.component_problems(tampered))


def test_verify_dir_detects_tampering_and_extra_files(tmp_path):
    d = _weights(tmp_path)
    bom = mlbom.build_bom([_entry(mlbom.hash_dir(d))])
    assert mlbom.verify_dir(bom, "example/model-7b", d) == []
    assert mlbom.verify_dir(bom, "other", d) == ["model_id 'other' has no component in the BOM"]
    (d / "config.json").write_text("{}", encoding="utf-8")
    (d / "extra.safetensors").write_bytes(b"\x02")
    problems = mlbom.verify_dir(bom, "example/model-7b", d)
    assert "hash mismatch: config.json" in problems and "not in BOM: extra.safetensors" in problems
    (d / "model-00002-of-00002.safetensors").unlink()
    assert "missing on disk: model-00002-of-00002.safetensors" in mlbom.verify_dir(bom, "example/model-7b", d)


def test_cli_round_trip_and_cosign_commands(tmp_path, monkeypatch):
    d = _weights(tmp_path)
    manifest = tmp_path / "models.yaml"
    manifest.write_text(yaml.safe_dump({"models": [{"model_id": "example/model-7b", "family": "deepseek", "name": "example-model", "version": "7b",
                                                    "source": {"kind": "huggingface", "url": "https://huggingface.co/example/model-7b"},
                                                    "license": {"id": "Apache-2.0"}, "serving": "vllm",
                                                    "signature": {"method": "cosign-keyless"}, "files": []}]}), encoding="utf-8")
    run = lambda *a: subprocess.run([sys.executable, str(SCRIPT), *a], capture_output=True, text=True)  # noqa: E731
    r = run("build", "--manifest", str(manifest), "--out", str(tmp_path / "bom.json"))
    assert r.returncode == 2 and "pending" in r.stderr
    r = run("hash-dir", str(d), "--model-id", "example/model-7b", "--write-manifest", str(manifest))
    assert r.returncode == 0 and r.stdout.count("\n") == 3
    r = run("build", "--manifest", str(manifest), "--out", str(tmp_path / "bom.json"))
    assert r.returncode == 0
    r = run("validate", "--bom", str(tmp_path / "bom.json"), "--manifest", str(manifest))
    assert r.returncode == 0 and "schema: valid" in r.stdout and "complete" in r.stdout
    r = run("verify", "--bom", str(tmp_path / "bom.json"), "--model-id", "example/model-7b", "--weights", str(d))
    assert r.returncode == 0 and "match" in r.stdout
    (d / "config.json").write_text("{}", encoding="utf-8")
    r = run("verify", "--bom", str(tmp_path / "bom.json"), "--model-id", "example/model-7b", "--weights", str(d))
    assert r.returncode == 1 and "MISMATCH hash mismatch: config.json" in r.stdout
    # drift: manifest changed after the BOM was built
    raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    raw["models"][0]["version"] = "8b"
    manifest.write_text(yaml.safe_dump(raw), encoding="utf-8")
    r = run("validate", "--bom", str(tmp_path / "bom.json"), "--manifest", str(manifest))
    assert r.returncode == 1 and "drift" in r.stdout
    # cosign: only the locked binary under MARA_TOOLS_DIR, never PATH
    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    fake = tools / "bin" / "cosign"
    fake.write_text("#!/bin/sh\necho \"$@\" > \"$(dirname \"$0\")/args.txt\"\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    cmd = mlbom.cosign_verify_blob_cmd(tmp_path / "bom.json", tmp_path / "b.sigstore.json", "p@example.internal", "https://issuer.example")
    assert cmd[0] == str(fake) and cmd[1] == "verify-blob" and "--certificate-identity" in cmd and cmd[-1].endswith("bom.json")
    with pytest.raises(ValueError):
        mlbom.cosign_verify_blob_cmd(tmp_path / "bom.json", tmp_path / "b", "", "")
    env = {**os.environ, "MARA_TOOLS_DIR": str(tools)}
    r = subprocess.run([sys.executable, str(SCRIPT), "verify-signature", "--bom", str(tmp_path / "bom.json"), "--bundle", str(tmp_path / "b.sigstore.json"),
                        "--certificate-identity", "p@example.internal", "--certificate-oidc-issuer", "https://issuer.example"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0 and "verified" in r.stdout and "verify-blob" in (tools / "bin" / "args.txt").read_text(encoding="utf-8")
    assert "sign-blob" in run("sign-command", "--bom", str(tmp_path / "bom.json")).stdout


def _cfg_with(tmp_path: Path, bom_path: Path, model_id: str, **ml_bom) -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "examples" / "ml-bom-required.yaml").read_text(encoding="utf-8"))
    raw["models"][1]["model"] = model_id
    raw["ml_bom"] = {**raw["ml_bom"], "path": str(bom_path), **ml_bom}
    return MaraConfig.model_validate(raw)


def test_policy_p7_three_states(tmp_path):
    d = _weights(tmp_path)
    complete = tmp_path / "complete.cdx.json"
    complete.write_text(json.dumps(mlbom.build_bom([_entry(mlbom.hash_dir(d))])), encoding="utf-8")
    pending = tmp_path / "pending.cdx.json"
    pending.write_text(json.dumps(mlbom.build_bom([_entry([])], allow_pending=True)), encoding="utf-8")
    r = p7_ml_bom(_cfg_with(tmp_path, complete, "example/model-7b", required=True))
    assert r.passed and "1/1" in r.reason
    with pytest.raises(ValueError, match="pending"):  # required + pending refuses the whole config at load
        _cfg_with(tmp_path, pending, "example/model-7b", required=True)
    r = p7_ml_bom(_cfg_with(tmp_path, pending, "example/model-7b", required=False))
    assert r.passed and "not required" in r.reason and "0/1" in r.reason
    with pytest.raises(ValueError, match="no machine-learning-model component"):
        _cfg_with(tmp_path, complete, "someone/else", required=True)
    with pytest.raises(ValueError, match="bundle"):
        _cfg_with(tmp_path, complete, "example/model-7b", required=True, require_signature=True, bundle=str(tmp_path / "missing.json"))
    bundle = tmp_path / "b.sigstore.json"
    bundle.write_text("{}", encoding="utf-8")
    r = p7_ml_bom(_cfg_with(tmp_path, complete, "example/model-7b", required=True, require_signature=True, bundle=str(bundle)))
    assert r.passed and "signature bundle" in r.reason
    # the repository configs
    assert [x.passed for x in __import__("mara.policy", fromlist=["evaluate_policies"]).evaluate_policies(load_config(ROOT / "config" / "mara.yaml"))].count(False) == 0
    assert load_config(ROOT / "config" / "examples" / "ml-bom-required.yaml").ml_bom.required


def test_repository_bom_is_pending_but_valid_and_governance_g7_says_why(tmp_path):
    import governance_check as gc

    bom = mlbom.load_bom(ROOT / "sbom" / "ml-bom.cdx.json")
    assert mlbom.validate_schema(bom) == []
    assert mlbom.bom_equal_ignoring_volatile(bom, mlbom.build_bom(mlbom.load_manifest(ROOT / "sbom" / "models.yaml"), allow_pending=True))
    comps = mlbom.ml_components(bom)
    assert set(comps) == {"deepseek-v3.2", "nvidia/nemotron-3-super"}
    assert all("hashes" not in c and mlbom.props(c)["status"] == "pending" for c in comps.values())
    r = gc.check_g7(ROOT, ROOT / "config" / "mara.yaml")
    assert r.status == gc.FAIL and "deepseek-v3.2" in r.evidence and "nvidia/nemotron-3-super" in r.evidence and "hash-dir" in r.evidence
    # a repository whose config points at a complete, signed BOM passes
    root = tmp_path / "repo"
    (root / "sbom").mkdir(parents=True)
    (root / "config").mkdir()
    d = _weights(tmp_path)
    (root / "sbom" / "ml-bom.cdx.json").write_text(json.dumps(mlbom.build_bom([_entry(mlbom.hash_dir(d))])), encoding="utf-8")
    (root / "sbom" / "ml-bom.cdx.json.sigstore.json").write_text("{}", encoding="utf-8")
    raw = yaml.safe_load((ROOT / "config" / "examples" / "ml-bom-required.yaml").read_text(encoding="utf-8"))
    raw["ml_bom"].update({"path": "sbom/ml-bom.cdx.json", "require_signature": True, "bundle": "sbom/ml-bom.cdx.json.sigstore.json"})
    (root / "config" / "mara.yaml").write_text(yaml.safe_dump(raw), encoding="utf-8")
    r = gc.check_g7(root, root / "config" / "mara.yaml")
    assert r.status == gc.PASS and "example/model-7b" in r.evidence and "P7" in r.evidence
    (root / "sbom" / "ml-bom.cdx.json.sigstore.json").unlink()
    assert gc.check_g7(root, root / "config" / "mara.yaml").status == gc.FAIL


def test_pipeline_records_ml_bom_status_in_the_report(tmp_path):
    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    assert mlbom.status_for_config(cfg) == {}  # mock providers are not self-hosted weights
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path)
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    assert report.bias_audit["ml_bom"] == {} and "## Model provenance" in render_markdown(report)
    live = load_config(ROOT / "config" / "mara.yaml")
    st = mlbom.status_for_config(live, ROOT)
    assert {s.status for s in st.values()} == {"pending"} and set(st) == {"deepseek-reviewer", "nemotron-reviewer"}


# ---------------------------------------------------------------- registry hashes (Hugging Face, no download)

SHA_A, SHA_B = "a" * 64, "b" * 64
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _fake_hf(tree_pages: list[list[dict]], blobs: dict[str, bytes], calls: list[str]):
    """A fetch() standing in for huggingface.co: revision lookup, a paginated tree, and small blobs."""
    def fetch(url: str) -> tuple[bytes, dict]:
        calls.append(url)
        if "/api/models/org/model/revision/" in url:
            return json.dumps({"sha": COMMIT, "siblings": []}).encode(), {}
        if "/api/models/org/model/tree/" in url:
            page = int(url.rsplit("page=", 1)[1]) if "page=" in url else 0
            headers = {"link": f'<https://huggingface.co/api/models/org/model/tree/{COMMIT}?recursive=true&page={page + 1}>; rel="next"'} \
                if page + 1 < len(tree_pages) else {}
            return json.dumps(tree_pages[page]).encode(), headers
        if f"/org/model/resolve/{COMMIT}/" in url:
            return blobs[url.rsplit("/", 1)[1]], {}
        raise AssertionError(f"unexpected url {url}")
    return fetch


def test_registry_files_uses_lfs_oids_hashes_small_git_files_and_pins_the_commit():
    pages = [[{"type": "file", "path": "model-00001-of-00002.safetensors", "size": 5, "lfs": {"oid": SHA_A, "size": 5000}},
              {"type": "directory", "path": "figures"}],
             [{"type": "file", "path": "model-00002-of-00002.safetensors", "size": 5, "lfs": {"oid": SHA_B, "size": 6000}},
              {"type": "file", "path": "config.json", "size": 12, "oid": "1234567890abcdef1234"}]]
    calls: list[str] = []
    commit, files = mlbom.registry_files("org/model", "main", fetch=_fake_hf(pages, {"config.json": b'{"a": 1}\n'}, calls))
    assert commit == COMMIT
    assert [(f.path, f.sha256, f.size) for f in files] == [
        ("config.json", hashlib.sha256(b'{"a": 1}\n').hexdigest(), 9),
        ("model-00001-of-00002.safetensors", SHA_A, 5000),
        ("model-00002-of-00002.safetensors", SHA_B, 6000)]
    assert sum("/tree/" in c for c in calls) == 2 and sum("/resolve/" in c for c in calls) == 1, "weights are never fetched, only listed"
    assert f"/tree/{COMMIT}?" in calls[1], "the tree is read at the resolved commit, not at the moving branch"


def test_registry_files_refuses_pickle_trees_bad_oids_and_oversized_git_files():
    calls: list[str] = []
    pages = [[{"type": "file", "path": "pytorch_model.bin", "size": 1, "lfs": {"oid": SHA_A, "size": 1}},
              {"type": "file", "path": "model.safetensors", "size": 1, "lfs": {"oid": SHA_B, "size": 1}}]]
    with pytest.raises(mlbom.PickleWeightsError, match="pytorch_model.bin"):
        mlbom.registry_files("org/model", "main", fetch=_fake_hf(pages, {}, calls))
    pages = [[{"type": "file", "path": "model.safetensors", "size": 1, "lfs": {"oid": "notahash", "size": 1}}]]
    with pytest.raises(ValueError, match="not a SHA-256"):
        mlbom.registry_files("org/model", "main", fetch=_fake_hf(pages, {}, calls))
    pages = [[{"type": "file", "path": "model.safetensors", "size": 1, "lfs": {"oid": SHA_A, "size": 1}},
              {"type": "file", "path": "huge.json", "size": mlbom.NON_LFS_MAX_BYTES + 1}]]
    with pytest.raises(ValueError, match="exceeds the"):
        mlbom.registry_files("org/model", "main", fetch=_fake_hf(pages, {}, calls))
    pages = [[{"type": "file", "path": "README.md", "size": 3}]]
    with pytest.raises(ValueError, match="no .safetensors"):
        mlbom.registry_files("org/model", "main", fetch=_fake_hf(pages, {"README.md": b"hi\n"}, calls))
    for bad in ("https://hf-mirror.com/org/model", "http://huggingface.co/org/model", "https://huggingface.co/org"):
        with pytest.raises(ValueError):
            mlbom.hf_repo_from_url(bad)
    assert mlbom.hf_repo_from_url("https://huggingface.co/deepseek-ai/DeepSeek-V3.2/tree/main") == "deepseek-ai/DeepSeek-V3.2"


def test_registry_hashes_cli_writes_files_and_revision_and_refuses_non_hf_sources(tmp_path, monkeypatch, capsys):
    sys.path.insert(0, str(ROOT / "scripts"))
    import ml_bom as cli

    manifest = tmp_path / "models.yaml"
    manifest.write_text(yaml.safe_dump({"models": [
        {"model_id": "m-hf", "family": "deepseek", "name": "M", "version": "1", "source": {"kind": "huggingface", "url": "https://huggingface.co/org/model", "revision": ""},
         "license": {"id": "MIT"}, "format": "safetensors", "serving": "vllm", "signature": {"method": "cosign-keyless"}, "files": []},
        {"model_id": "m-ngc", "family": "nemotron", "name": "N", "version": "3", "source": {"kind": "ngc", "url": "https://huggingface.co/nvidia"},
         "license": {"name": "x"}, "format": "safetensors", "serving": "nim", "signature": {"method": "ngc"}, "files": []}]}, sort_keys=False))
    pages = [[{"type": "file", "path": "model.safetensors", "size": 1, "lfs": {"oid": SHA_A, "size": 4096}},
              {"type": "file", "path": "config.json", "size": 2}]]
    monkeypatch.setattr(mlbom, "_http_fetch", _fake_hf(pages, {"config.json": b"{}"}, []))
    ns = argparse.Namespace(model_id="m-hf", revision=None, manifest=manifest, write_manifest=manifest)
    assert cli.cmd_registry_hashes(ns) == 0
    out = capsys.readouterr()
    assert f"{SHA_A}  model.safetensors" in out.out and f"commit {COMMIT}" in out.err
    entries = {e.model_id: e for e in mlbom.load_manifest(manifest)}
    assert entries["m-hf"].source["revision"] == COMMIT and [f.sha256 for f in entries["m-hf"].files] == [hashlib.sha256(b"{}").hexdigest(), SHA_A]
    assert not entries["m-hf"].pending and entries["m-ngc"].pending, "only the requested entry changes"
    # the now-complete entry builds into a complete, schema-valid component
    bom = mlbom.build_bom([entries["m-hf"]])
    (c,) = mlbom.ml_components(bom).values()
    assert mlbom.component_problems(c) == [] and mlbom.validate_schema(bom) == []
    assert cli.cmd_registry_hashes(argparse.Namespace(model_id="m-ngc", revision=None, manifest=manifest, write_manifest=None)) == 2
    assert "not huggingface" in capsys.readouterr().err
