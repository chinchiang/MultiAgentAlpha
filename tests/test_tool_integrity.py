"""Tool integrity (2026-10-12 review, tools batch): a scanner that could not read everything does not report a complete
run, no interpreter is taken from PATH, the ML-BOM signature is checked offline and verified by cosign, a stale
Scorecard JSON is never read, and the semgrep-rules signing key is pinned by its full fingerprint."""

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from mara.config import MaraConfig
from mara.tools import csp_eval, runner
from mara.tools.sarif import scan_complete

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


# ------------------------------------------------------------------ CSP

def test_a_flood_of_dummy_policies_makes_the_csp_scan_incomplete(tmp_path):
    """MAX_POLICIES dummy <meta> tags in a file that sorts first stopped the extraction, and the run still reported
    executionSuccessful: true, so the real CSPs behind them were never evaluated and coverage read complete."""
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "a.html").write_text("".join(f'<meta http-equiv="Content-Security-Policy" content="default-src \'self\' https://x{i}">\n'
                                                   for i in range(csp_eval.MAX_POLICIES + 5)), encoding="utf-8")
    (tmp_path / "zz").mkdir()
    (tmp_path / "zz" / "nginx.conf").write_text('add_header Content-Security-Policy "script-src *";\n', encoding="utf-8")
    policies, truncated = csp_eval.extract_policies(tmp_path)
    assert truncated and len(policies) == csp_eval.MAX_POLICIES and all(p.file == "a/a.html" for p in policies)
    doc = csp_eval.build_sarif(policies, [], version="1", truncated=truncated)
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is False and not scan_complete(doc)


def test_skipped_files_are_reported_and_dot_directories_are_read(tmp_path):
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "server.conf").write_text('add_header Content-Security-Policy "script-src \'self\'";\n', encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "x.conf").write_text('add_header Content-Security-Policy "script-src *";\n', encoding="utf-8")
    (tmp_path / "big.js").write_text("x" * (csp_eval.MAX_FILE_BYTES + 1), encoding="utf-8")
    skipped: list[str] = []
    policies, truncated = csp_eval.extract_policies(tmp_path, skipped)
    assert [p.file for p in policies] == [".well-known/server.conf"], "only the VCS/tool directories are skipped"
    assert not truncated and skipped == ["big.js: over 512 KiB, not read"]
    doc = csp_eval.build_sarif(policies, [], version="1", skipped=skipped)
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert scan_complete(doc) and any(n["descriptor"]["id"] == "CSP_FILE_SKIPPED" and "big.js" in n["message"]["text"] for n in notes)


# ------------------------------------------------------------------ no interpreter from PATH

def test_a_script_tool_on_windows_runs_only_with_the_named_shell(tmp_path, monkeypatch):
    """On WinError 193 the runner used to take `sh` from PATH (or next to the `git` on PATH) and run the tool with it."""
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if len(calls) == 1:
            e = OSError("not a valid Win32 application")
            e.winerror = 193
            raise e
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(runner.sys, "platform", "win32")
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    fake_sh = tmp_path / "evil-sh.exe"
    fake_sh.write_text("x")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("MARA_WINDOWS_SH", raising=False)
    with pytest.raises(OSError):
        runner._run(["tool.sh", "--scan"], tmp_path)
    assert calls == [["tool.sh", "--scan"]], "nothing found on PATH is run"
    calls.clear()
    monkeypatch.setenv("MARA_WINDOWS_SH", str(fake_sh))
    assert runner._run(["tool.sh", "--scan"], tmp_path).returncode == 0
    assert calls[1] == [str(fake_sh), "tool.sh", "--scan"]


# ------------------------------------------------------------------ ML-BOM signature

def _bundle_for(data: bytes) -> dict:
    return {"messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(hashlib.sha256(data).digest()).decode()},
                                 "signature": "sig"}}


def _sig_cfg(bom: Path, bundle: Path) -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["ml_bom"] = {"required": False, "path": str(bom), "require_signature": True, "bundle": str(bundle),
                     "certificate_identity": "https://github.com/o/r/.github/workflows/sign.yml@refs/heads/main",
                     "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"}
    return MaraConfig.model_validate(raw, context={"skip_policies": True})


def test_the_bundle_must_be_made_for_this_bom(tmp_path):
    from mara.mlbom import bundle_digest_matches

    bom = tmp_path / "bom.json"
    bom.write_text('{"components": []}', encoding="utf-8")
    bundle = tmp_path / "bom.sigstore.json"
    bundle.write_text(json.dumps(_bundle_for(bom.read_bytes())), encoding="utf-8")
    assert bundle_digest_matches(bom, bundle)[0]
    bom.write_text('{"components": ["edited after signing"]}', encoding="utf-8")
    ok, why = bundle_digest_matches(bom, bundle)
    assert not ok and "made for another file" in why
    bundle.write_text("not json", encoding="utf-8")
    assert not bundle_digest_matches(bom, bundle)[0]


def test_cosign_verifies_the_signature_and_a_failure_blocks_the_review(tmp_path, monkeypatch):
    """require_signature used to check only that a bundle file existed; cosign was never called."""
    from mara import mlbom

    tools = tmp_path / "tools"
    (tools / "bin").mkdir(parents=True)
    exe = tools / "bin" / ("cosign.exe" if sys.platform == "win32" else "cosign")
    exe.write_text("fake")
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tools))
    bom = tmp_path / "bom.json"
    bom.write_text("{}", encoding="utf-8")
    bundle = tmp_path / "bom.sigstore.json"
    bundle.write_text(json.dumps(_bundle_for(bom.read_bytes())), encoding="utf-8")
    cfg = _sig_cfg(bom, bundle)
    seen = []

    def cosign(rc):
        def run(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, rc, "", "" if rc == 0 else "error: none of the expected identities matched")
        return run

    ok, why = mlbom.verify_signature(cfg, runner=cosign(0))
    assert ok and seen[-1][1:3] == ["verify-blob", "--bundle"] and "--certificate-identity" in seen[-1]
    ok, why = mlbom.verify_signature(cfg, runner=cosign(1))
    assert not ok and "none of the expected identities" in why
    exe.unlink()
    assert not mlbom.verify_signature(cfg, runner=cosign(0))[0], "no cosign is a failure, never a pass"

    # the pipeline: an unverified signature makes the review incomplete
    from mara.pipeline import Pipeline

    asked_in = []  # the workspace the pipeline asks cosign to verify in: its own (Pipeline.workspace)

    def unverified(cfg, root=None, runner=None):  # verify_signature's parameters
        asked_in.append(root)
        return False, "cosign verify-blob exit 1"

    monkeypatch.setattr(mlbom, "verify_signature", unverified)
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / "out")
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    assert asked_in == [pipe.workspace]
    assert "ml_bom_signature_unverified" in report.incomplete_reasons
    assert report.ml_bom_signature.startswith("failed:") and "ml_bom_signature" not in report.bias_audit


# ------------------------------------------------------------------ Scorecard

def test_scorecard_never_reads_an_earlier_runs_json(tmp_path):
    """A crash that wrote nothing left the previous run's scorecard.json to be parsed and gated on."""
    import scorecard_ci as sc

    from tests.test_scorecard_ci import DOC, _fake_scorecard, _policy
    from tests.test_scorecard_ci import _run as run_scorecard

    tools = tmp_path / "tools"
    out = tmp_path / "scorecard.json"
    out.write_text(json.dumps(DOC), encoding="utf-8")  # an earlier, passing run
    _fake_scorecard(tools, sc.locked_version(), None, crash=True)
    r = run_scorecard(tools, "--repo", "github.com/o/r", "--json", str(out), "--policy", str(_policy(tmp_path, "enforce: {}\n")))
    assert r.returncode == 1 and "wrote no" in r.stderr and not out.exists()


# ------------------------------------------------------------------ semgrep-rules signing key

FPR = "968479A1AFF927E37D1A566BB5690EEEBB952194"


def _gpg(monkeypatch, tmp_path, *, key_fprs, validsig_fpr):
    import install_tools as it

    monkeypatch.setattr(it, "download", lambda url, dest, **kw: dest)

    def run(cmd, env=None):
        if "--fingerprint" in cmd:
            return subprocess.CompletedProcess(cmd, 0, "".join(f"fpr:::::::::{f}:\n" for f in key_fprs), "")
        if "verify-commit" in cmd:
            status = (f"[GNUPG:] GOODSIG {FPR[-16:]} GitHub\n"
                      f"[GNUPG:] VALIDSIG {validsig_fpr} 2026-10-01 1 0 4 0 1 10 00 {validsig_fpr}\n")
            return subprocess.CompletedProcess(cmd, 0, "", status)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(it, "run", run)
    spec = {"commit": "a" * 40, "verify": {"method": "git-commit-gpg", "gpg_key_url": "https://github.com/web-flow.gpg", "gpg_fingerprint": FPR}}
    return it, spec


def test_the_signing_key_is_pinned_by_its_full_fingerprint(tmp_path, monkeypatch):
    """Only a 64-bit key-id suffix was compared, and VALIDSIG was accepted whatever key it named."""
    it, spec = _gpg(monkeypatch, tmp_path, key_fprs=[FPR], validsig_fpr=FPR)
    assert FPR in it.verify_commit_gpg("semgrep-rules", spec, tmp_path, tmp_path)
    collided = "0" * 24 + FPR[-16:]  # same 64-bit key id, another key
    it, spec = _gpg(monkeypatch, tmp_path, key_fprs=[collided], validsig_fpr=collided)
    with pytest.raises(it.InstallError, match="is not " + FPR):
        it.verify_commit_gpg("semgrep-rules", spec, tmp_path, tmp_path)
    it, spec = _gpg(monkeypatch, tmp_path, key_fprs=[FPR, collided], validsig_fpr=collided)
    with pytest.raises(it.InstallError, match="not validly signed"):
        it.verify_commit_gpg("semgrep-rules", spec, tmp_path, tmp_path)
    spec["verify"] = {**spec["verify"], "gpg_fingerprint": FPR[-16:]}
    with pytest.raises(it.InstallError, match="40-hex fingerprint"):
        it.verify_commit_gpg("semgrep-rules", spec, tmp_path, tmp_path)
