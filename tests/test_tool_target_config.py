"""The reviewed repository cannot switch its own L0 scans off. The target is untrusted: a pull
request that adds `.semgrepignore`, `.trivyignore`, `trivy.yaml`, an `osv-scanner.toml` with
`ignore = true` overrides, a `zizmor.yml` or inline `# zizmor: ignore[...]` comments would
otherwise make the tool report "ran, nothing found", and model silence would clear the gate.
(Verified against the pinned binaries: each of those suppresses results with the old arguments.)"""

import json
import subprocess
from pathlib import Path

import pytest

from mara.tools import runner
from tests import tool_installs

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / ".mara-tools"
EMPTY_SARIF = json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]})


def _argv_after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def test_every_tool_is_handed_neutral_config_instead_of_the_targets(tmp_path, monkeypatch):
    import mara.tools.trivy_db as trivy_db

    seen: dict[str, list[str]] = {}

    def fake_run(cmd, cwd, timeout=600, env=None):
        exe = Path(cmd[0]).name
        seen[exe] = cmd
        for flag in ("--output", "--output-file"):
            if flag in cmd:
                Path(_argv_after(cmd, flag)).write_text(EMPTY_SARIF, encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout=EMPTY_SARIF if exe == "zizmor" else "", stderr="")

    monkeypatch.setenv("MARA_SEMGREP_CONFIG", str(tmp_path / "rules.yml"))
    monkeypatch.setattr(runner, "tool_path", lambda tool: tmp_path / "bin" / tool)
    tool_installs.manifest(tmp_path / "tools", *runner.TOOL_DIMENSIONS)  # each at its locked version
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(runner, "_run", fake_run)
    fake_db = tmp_path / "trivy.db"
    fake_db.write_bytes(b"")
    monkeypatch.setattr(trivy_db, "db_path", lambda cache: fake_db)  # "the offline database is there"
    monkeypatch.setattr(trivy_db, "check", lambda cache, max_age: (True, []))  # "...and matches its record"
    target = tmp_path / "target"
    target.mkdir()
    for name, text in {".semgrepignore": "*\n", ".trivyignore": "CVE-2018-18074\n", "trivy.yaml": "severity: [LOW]\n",
                       "osv-scanner.toml": "[[PackageOverrides]]\nname = \"requests\"\nignore = true\n"}.items():
        (target / name).write_text(text, encoding="utf-8")
    out = tmp_path / "out"
    runner.run_all(target, out, enabled=["semgrep", "osv-scanner", "zizmor", "trivy"])

    assert "--x-ignore-semgrepignore-files" in seen["semgrep"]
    osv_config = Path(_argv_after(seen["osv-scanner"], "--config"))
    assert osv_config.read_text(encoding="utf-8") == "" and out.resolve() in osv_config.parents
    assert {"--no-config", "--no-ignores", "--collect=all"} <= set(seen["zizmor"])
    trivy_ignore, trivy_config = Path(_argv_after(seen["trivy"], "--ignorefile")), Path(_argv_after(seen["trivy"], "--config"))
    assert trivy_ignore.read_text(encoding="utf-8") == "" and trivy_config.read_text(encoding="utf-8") == "{}\n"
    for p in (osv_config, trivy_ignore, trivy_config):
        assert target.resolve() not in p.parents, "the neutral files live in the output directory, never in the target"
    # the target's own files are untouched
    assert (target / ".semgrepignore").read_text(encoding="utf-8") == "*\n"


def test_semgrep_without_pinned_rules_does_not_fall_back_to_the_registry(tmp_path, monkeypatch):
    """Without the pinned semgrep-rules the runner used to scan with p/default from semgrep.dev and label
    the run as the pinned one; now semgrep is not run, which keeps the review incomplete."""
    monkeypatch.delenv("MARA_SEMGREP_CONFIG", raising=False)
    monkeypatch.setattr(runner, "tool_path", lambda tool: tmp_path / "bin" / tool)
    tool_installs.manifest(tmp_path / "tools", *runner.TOOL_DIMENSIONS)  # each at its locked version
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(runner, "_run", lambda *a, **k: pytest.fail("semgrep must not be invoked without its pinned rules"))
    (tmp_path / "target").mkdir()
    [run] = runner.run_all(tmp_path / "target", tmp_path / "out", enabled=["semgrep"])
    assert not run.ran and "no registry fallback" in run.note


@pytest.mark.skipif(not (TOOLS / "bin" / "semgrep").exists(), reason="locked semgrep not installed under .mara-tools (run scripts/install_tools.py)")
def test_real_semgrep_scans_what_the_targets_semgrepignore_hides(tmp_path, monkeypatch):
    monkeypatch.setenv("MARA_TOOLS_DIR", str(TOOLS))
    rule = tmp_path / "rule.yml"
    rule.write_text("rules:\n  - id: probe-os-system\n    pattern: os.system(...)\n    message: os.system\n"
                    "    languages: [python]\n    severity: ERROR\n", encoding="utf-8")
    monkeypatch.setenv("MARA_SEMGREP_CONFIG", str(rule))
    target = tmp_path / "target"
    target.mkdir()
    code = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
    (target / "app.py").write_text(code, encoding="utf-8")
    (target / "hidden.py").write_text(code, encoding="utf-8")
    (target / ".semgrepignore").write_text("hidden.py\n", encoding="utf-8")
    [run] = runner.run_all(target, tmp_path / "out", enabled=["semgrep"])
    assert run.ran, run.note
    assert {r.file for r in run.results} == {"app.py", "hidden.py"}


def _zizmor_with(monkeypatch, tmp_path, returncode, stderr):
    def fake_run(cmd, cwd, timeout=600, env=None):
        return subprocess.CompletedProcess(cmd, returncode, stdout="", stderr=stderr)

    monkeypatch.setattr(runner, "tool_path", lambda tool: tmp_path / "bin" / tool)
    tool_installs.manifest(tmp_path / "tools", "zizmor")  # at its locked version
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))
    monkeypatch.setattr(runner, "_run", fake_run)


NO_INPUTS = "Error: no audit was performed\n\nCaused by:\n    no inputs collected\n"


def test_zizmor_with_nothing_to_audit_is_a_complete_run_only_when_the_target_really_has_no_inputs(tmp_path, monkeypatch):
    """zizmor 1.30.1 exits 3 'no inputs collected' on a target without workflows, actions or dependabot:
    every review of such a repository used to be incomplete (required_tool_incomplete)."""
    _zizmor_with(monkeypatch, tmp_path, 3, NO_INPUTS)
    target = tmp_path / "plain"
    target.mkdir()
    (target / "app.py").write_text("print(1)\n", encoding="utf-8")
    [run] = runner.run_all(target, tmp_path / "out1", enabled=["zizmor"])
    assert run.ran and run.results == [] and "no GitHub Actions inputs" in run.note
    # the target's word is not taken: a workflow present with the same exit code is a failed scan
    (target / ".github" / "workflows").mkdir(parents=True)
    (target / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    [run] = runner.run_all(target, tmp_path / "out2", enabled=["zizmor"])
    assert not run.ran
    # exit 3 for any other reason is a failure as before
    _zizmor_with(monkeypatch, tmp_path, 3, "Error: something else\n")
    plain = tmp_path / "plain2"
    plain.mkdir()
    [run] = runner.run_all(plain, tmp_path / "out3", enabled=["zizmor"])
    assert not run.ran


def test_actions_inputs_are_found_where_zizmor_collects_them(tmp_path):
    for rel in ("tools/x/action.yaml", ".github/dependabot.yml", ".github/workflows/deploy.yaml"):
        t = tmp_path / rel.replace("/", "_")
        (t / rel).parent.mkdir(parents=True)
        (t / rel).write_text("x: 1\n", encoding="utf-8")
        assert runner.has_actions_inputs(t), rel
    t = tmp_path / "none"
    (t / "docs" / "workflows").mkdir(parents=True)
    (t / "docs" / "workflows" / "a.yml").write_text("x: 1\n", encoding="utf-8")  # not under .github
    assert not runner.has_actions_inputs(t)
    outside = tmp_path / "outside" / ".github" / "workflows"
    outside.mkdir(parents=True)
    (outside / "ci.yml").write_text("on: push\n", encoding="utf-8")
    try:
        (t / "linked").symlink_to(tmp_path / "outside", target_is_directory=True)
    except OSError as e:  # Windows without Developer Mode or admin rights (WinError 1314)
        pytest.skip(f"cannot create a symlink here: {e}")
    assert not runner.has_actions_inputs(t), "a symlink out of the target is not followed"
