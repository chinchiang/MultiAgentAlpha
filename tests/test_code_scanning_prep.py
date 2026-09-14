"""scripts/code_scanning_prep.py: triaged (suppressed) and unlocated results are dropped, paths become
repository-relative, every run gets its own Code Scanning category, missing inputs are skipped, GitHub's
limits are enforced, and nothing-to-upload is an error."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "code_scanning_prep.py"
sys.path.insert(0, str(ROOT / "scripts"))

import code_scanning_prep as prep  # noqa: E402


def _res(uri: str | None, suppressed: bool = False) -> dict:
    r = {"ruleId": "r", "level": "warning", "message": {"text": "m"}}
    if uri is not None:
        r["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 3}}}]
    if suppressed:
        r["suppressions"] = [{"kind": "external", "status": "accepted", "justification": "triaged"}]
    return r


def _write(path: Path, *results: dict, name: str = "Semgrep OSS") -> Path:
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": name}}, "results": list(results)}]}), encoding="utf-8")
    return path


def test_relative_uri_strips_workspace_dot_and_file_scheme(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    assert prep.relative_uri("./scripts/x.py", ws) == "scripts/x.py"
    assert prep.relative_uri(f"{ws.resolve().as_posix()}/scripts/x.py", ws) == "scripts/x.py"
    assert prep.relative_uri(f"file://{ws.resolve().as_posix()}/a/b.txt", ws) == "a/b.txt"
    assert prep.relative_uri(".github/workflows/x.yml", ws) == ".github/workflows/x.yml"


def test_suppressed_and_unlocated_results_are_dropped_and_category_set(tmp_path):
    src = _write(tmp_path / "semgrep.sarif", _res("./scripts/a.py"), _res("scripts/b.py", suppressed=True), _res(None))
    out = tmp_path / "out"
    out.mkdir()
    t = prep.prepare_file("semgrep", src, out, tmp_path)
    assert (t["kept"], t["suppressed"], t["unlocated"]) == (1, 1, 1)
    doc = json.loads((out / "semgrep.sarif").read_text())
    run = doc["runs"][0]
    assert run["automationDetails"] == {"id": "mara-l0/semgrep/"}
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "scripts/a.py"
    assert run["tool"]["driver"]["name"] == "Semgrep OSS" and doc["version"] == "2.1.0"


def test_cli_skips_missing_inputs_and_reports_each_tool(tmp_path):
    _write(tmp_path / "osv.sarif", _res("tools/bootstrap-requirements.txt"))
    _write(tmp_path / "zizmor.sarif")
    r = subprocess.run([sys.executable, str(SCRIPT), "--out", str(tmp_path / "cs"), "--workspace", str(tmp_path),
                        f"osv={tmp_path / 'osv.sarif'}", f"gitleaks={tmp_path / 'gitleaks.sarif'}", f"zizmor={tmp_path / 'zizmor.sarif'}"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "gitleaks   skipped" in r.stdout and "category mara-l0/osv/" in r.stdout and "2 file(s) ready" in r.stdout
    assert sorted(p.name for p in (tmp_path / "cs").iterdir()) == ["osv.sarif", "zizmor.sarif"]
    assert json.loads((tmp_path / "cs" / "zizmor.sarif").read_text())["runs"][0]["results"] == []


def test_nothing_to_upload_and_bad_arguments(tmp_path):
    r = subprocess.run([sys.executable, str(SCRIPT), "--out", str(tmp_path / "cs"), f"semgrep={tmp_path / 'none.sarif'}"], capture_output=True, text=True)
    assert r.returncode == 1 and "nothing to upload" in r.stderr
    r = subprocess.run([sys.executable, str(SCRIPT), "--out", str(tmp_path / "cs"), "semgrep.sarif"], capture_output=True, text=True)
    assert r.returncode == 2 and "TOOL=PATH" in r.stderr
    (tmp_path / "bad.sarif").write_text("{}", encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--out", str(tmp_path / "cs"), f"trivy={tmp_path / 'bad.sarif'}"], capture_output=True, text=True)
    assert r.returncode == 2 and "not a SARIF" in r.stderr


def test_over_limit_file_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(prep, "MAX_RESULTS", 2)
    src = _write(tmp_path / "trivy.sarif", _res("a"), _res("b"), _res("c"))
    monkeypatch.setattr(sys, "argv", ["x", "--out", str(tmp_path / "cs"), f"trivy={src}"])
    assert prep.main() == 2
    assert not (tmp_path / "cs" / "trivy.sarif").exists()
