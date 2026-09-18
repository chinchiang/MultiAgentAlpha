"""Adversarial regressions from the 2026-09-18 review; no live providers or attack traffic."""
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from mara.agents import base, judge
from mara.config import ModelSpec, load_config
from mara.context.repo_map import RepoContext, build_context
from mara.pipeline import Pipeline
from mara.providers.base import Completion, Provider
from mara.report.human_queue_out import build_queue, queue_key
from mara.report.markdown_out import render_markdown
from mara.report.psirt_out import legal_deadlines
from mara.schemas import Finding, JudgeVote, ModelFamily, Provenance
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class Reply(Provider):
    def __init__(self, spec, data=None):
        super().__init__(spec)
        self.data, self.requests = data, []

    def complete(self, **kwargs):
        self.requests.append(kwargs)
        return Completion(data=self.data, raw_text=json.dumps(self.data), refused=self.data is None)


def pipeline(tmp_path):
    return Pipeline(load_config(ROOT / "config/mara.mock.yaml"), out_dir=tmp_path / "out")


def finding():
    return Finding(id="F-1", dimension="vulnerabilities", title="SQL finding", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=1, quote="unsafe()", verified=True)],
                   reachability="reachable", reachability_argument="public", exploit_sketch="input",
                   cvss4_vector=VECTOR, model_confidence=0.9, source_family=ModelFamily.ANTHROPIC, source_model="test")


def vote(fam, pass_id="forward", verdict="true_positive", severity="High"):
    return JudgeVote(finding_id="F-1", verdict=verdict, severity_band=severity, reason="test",
                     judge_family=fam, judge_model="test", presentation_order=0, pass_id=pass_id)


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True).stdout.strip()


def test_context_does_not_read_symlinks_ignored_or_secret_files(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE_MARKER")
    (root / "link.py").symlink_to(outside)
    (root / ".env").write_text("LOCAL_SECRET_MARKER")
    (root / "ignored.py").write_text("IGNORED_MARKER")
    (root / "app.py").write_text('token = "' + 'ghp_' + 'A' * 36 + '"\nprint(1)')
    (root / ".gitignore").write_text("ignored.py\n.env\n")
    git(root, "init", "-q")
    git(root, "add", "app.py", "link.py", ".gitignore")
    ctx = build_context(root)
    assert "OUTSIDE_MARKER" not in ctx.bundle() and "LOCAL_SECRET_MARKER" not in ctx.bundle()
    assert "IGNORED_MARKER" not in ctx.bundle() and 'ghp_' + 'A' * 36 not in ctx.bundle()
    assert ctx.omitted["link.py"] and ctx.redacted == ["app.py"]
    assert not ctx.complete


def test_context_batches_cover_all_sources_and_report_oversize(tmp_path, monkeypatch):
    import mara.context.repo_map as mod
    monkeypatch.setattr(mod, "MAX_TOTAL_CHARS", 80)
    for i in range(5):
        (tmp_path / f"{i}.py").write_text("print('covered')\n")
    (tmp_path / "huge.md").write_text("x" * (mod.MAX_FILE_BYTES + 1))
    ctx = build_context(tmp_path)
    assert len(list(ctx.batches())) > 1
    assert {name for batch in ctx.batches() for name in batch.content} == {f"{i}.py" for i in range(5)}
    assert "huge.md" in ctx.omitted and not ctx.complete


def test_quote_validation_never_falls_back_to_disk(tmp_path):
    (tmp_path / "outside.py").write_text("unsafe()")
    ctx = RepoContext(root=tmp_path, content={"app.py": "unsafe()"})
    assert base.verify_quote(ctx, "app.py", 1, "unsafe()")
    for path, line, quote in [(str(tmp_path / "outside.py"), 1, "unsafe()"), ("../outside.py", 1, "unsafe()"),
                              ("outside.py", 1, "unsafe()"), ("app.py", 999999, "   "), ("app.py", 1, "   ")]:
        assert not base.verify_quote(ctx, path, line, quote)


def test_line_number_overhead_is_bounded_and_redacted_changes_invalidate_revision(tmp_path):
    (tmp_path / "dense.py").write_text("\n" * 100_000)
    (tmp_path / "app.py").write_text('password = "secret-original"\n')
    before = build_context(tmp_path)
    assert before.omitted["dense.py"] == "request_size_limit"
    (tmp_path / "app.py").write_text('password = "secret-changed"\n')
    after = build_context(tmp_path)
    assert before.content_hash == after.content_hash
    assert before.revision != after.revision


def test_prerecorded_secret_scan_cannot_authorize_live_egress(tmp_path, monkeypatch):
    import mara.pipeline as mod
    pipe = pipeline(tmp_path)
    (tmp_path / "app.py").write_text("print(1)")
    for name, provider in list(pipe.providers.items()):
        pipe.providers[name] = Reply(provider.spec.model_copy(update={"provider": "openai_compatible"}))
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(tool="gitleaks", ran=True)])
    monkeypatch.setattr(mod, "run_all", lambda *_a, **_k: [ToolRun(tool="gitleaks", ran=False, note="not installed")])
    report = pipe.run(tmp_path, mode="live", sarif_dir=tmp_path)
    assert "source_egress_blocked_by_secret_preflight" in report.incomplete_reasons
    assert not any(p.requests for p in pipe.providers.values())


def test_psirt_confirmed_event_updates_existing_handoff_without_resetting_it():
    import mara.psirt_ledger as pl
    ledger = {"items": {"key": {"stages": {"internal_handoff": {"sent_at": "2026-09-18T00:00:00Z"}}}}}
    event = {"confirmed_by": "psirt", "event_type": "actively_exploited_vulnerability", "awareness_at": "2026-09-10T00:00:00Z"}
    pl.confirm_event(ledger, "key", event, "PSIRT-1")
    assert ledger["items"]["key"]["deadlines"]["early_warning_by"].startswith("2026-09-11")
    assert pl.already_sent(ledger, "key") == "2026-09-18T00:00:00Z"
    event["remediation_available_at"] = "2026-09-20T00:00:00Z"
    pl.confirm_event(ledger, "key", event, "PSIRT-1-patch")
    assert ledger["items"]["key"]["deadlines"]["final_report_by"].startswith("2026-10-04")
    assert len(ledger["items"]["key"]["event_history"]) == 2
    with pytest.raises(ValueError):
        legal_deadlines({"event_type": "severe_incident", "awareness_at": "2026-09-10T00:00:00Z"})


def test_ticket_body_treats_model_text_as_literal():
    import human_queue_issues as hq
    item = {"key": "v2-" + "a" * 24, "finding_id": "F-1", "reasons": [], "dimension": "xss", "cwe": "CWE-79", "file": "app.py", "line": 1,
            "tier": "C", "cvss4_score": 9, "cvss4_severity": "Critical", "ssvc_decision": "Act", "weighted_score": 0,
            "votes_tp": 0, "votes_fp": 0, "votes_human": 1, "finder_families": ["anthropic"], "reachability": "unknown",
            "reachability_argument": "ok", "exploit_sketch": "x", "quote": "`\n# forged\n<img src=x onerror=alert(1)>"}
    body = hq.ticket_body(item, "target")
    assert "\n# forged" not in body and "<img" not in body and "&#96;" in body


@pytest.mark.parametrize("bad", ["CVSS:4.0/invalid", "CVSS:4.0/AV:Q", VECTOR + "/AV:N", "CVSS:4.0/AV:N"])
def test_invalid_cvss_is_rejected_at_model_boundary(bad):
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding().model_dump(), "cvss4_vector": bad})


def test_duplicate_judge_reply_is_not_counted(tmp_path):
    pipe = pipeline(tmp_path)
    row = {"finding_id": "F-1", "verdict": "false_positive", "severity_band": "None", "reason": "test"}
    provider = Reply(pipe.cfg.models[0], {"items": [row] * 100})
    votes, errors = judge.run_judge(provider, [{"finding_id": "F-1"}], "forward")
    assert not votes and errors


def test_quorum_requires_two_independent_families_and_both_passes(tmp_path):
    pipe, f = pipeline(tmp_path), finding()
    finders = {f.id: {ModelFamily.ANTHROPIC}}
    one = [vote(ModelFamily.DEEPSEEK)]
    c = pipe.score([f], finders, {}, {}, one, [])[0]
    assert not c.accepted and c.needs_human and c.independent_judges == 0
    full = [vote(fam, pass_id) for fam in (ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON) for pass_id in ("forward", "reverse")]
    accepted = pipe.score([f], finders, {}, {}, full, [])[0]
    assert accepted.accepted and accepted.independent_judges == 2
    repeated = pipe.score([f], finders, {}, {}, full + [full[0]] * 100, [])[0]
    assert not repeated.accepted and repeated.needs_human
    unknown = pipe.score([f.model_copy(update={"cvss4_vector": "CVSS:4.0/invalid"})], finders, {}, {}, full, [])[0]
    assert unknown.cvss4_score is None and not unknown.accepted


def test_all_refusals_and_tool_only_findings_block_with_no_score(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    pipe.providers = {n: Reply(p.spec) for n, p in pipe.providers.items()}
    (tmp_path / "app.py").write_text("unsafe()")
    tool = ToolResult("semgrep", "sql", "error", "SQL injection", "app.py", 1, "CWE-89")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun("semgrep", True, [tool])])
    report = pipe.run(tmp_path, mode="mock")
    assert not report.gate_passed and report.overall_score is None and report.review_status == "incomplete"
    assert len(report.tool_results) == 1 and report.tool_results[0]["rule_id"] == "sql"
    assert report.bias_audit["reviewer_refusals"] == 33


def test_one_verified_quote_cannot_launder_an_invalid_primary_location(tmp_path):
    pipe, f = pipeline(tmp_path), finding()
    bad = Provenance(file="../outside.py", line=999, quote="fabricated", verified=False)
    f = f.model_copy(update={"provenance": [bad, *f.provenance]})
    votes = [vote(family, pass_id) for family in (ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON) for pass_id in ("forward", "reverse")]
    c = pipe.score([f], {f.id: {ModelFamily.ANTHROPIC}}, {}, {}, votes, [])[0]
    assert not c.accepted and c.needs_human and c.tier.value == "D"
    assert "unverified_provenance" in c.human_reasons


def test_live_secret_preflight_stops_all_provider_requests(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    pipe.providers = {n: Reply(p.spec.model_copy(update={"provider": "anthropic"})) for n, p in pipe.providers.items()}
    (tmp_path / "app.py").write_text("unsafe()")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun("gitleaks", False)])
    report = pipe.run(tmp_path, mode="live")
    assert not report.gate_passed and not any(p.requests for p in pipe.providers.values())
    assert "source_egress_blocked_by_secret_preflight" in report.incomplete_reasons


def test_mock_cannot_be_labelled_live(tmp_path):
    with pytest.raises(ValueError, match="provider mode"):
        pipeline(tmp_path).run(tmp_path, mode="live")


def test_nonempty_model_bom_does_not_crash_completed_report(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    pipe.ml_bom_status = {"selfhosted": SimpleNamespace(model_id="example", status="pending", component_name="x", component_version="1", digest="")}
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [])
    report = pipe.run(tmp_path, mode="mock")
    assert report.bias_audit["ml_bom"]["selfhosted"]["status"] == "pending"
    assert any("ML-BOM" in line for line in pipe.log)


def test_human_queue_uses_effective_decision_without_recalculating_threshold(tmp_path):
    pipe, f = pipeline(tmp_path), finding()
    pipe.human_alpha_threshold = 1.0
    votes = [vote(fam, pass_id, verdict) for fam, verdict in [(ModelFamily.DEEPSEEK, "true_positive"),
             (ModelFamily.NEMOTRON, "false_positive")] for pass_id in ("forward", "reverse")]
    result = pipe.score([f], {f.id: {ModelFamily.ANTHROPIC}}, {}, {}, votes, [])[0]
    queued = build_queue([f], {f.id: result}, {}, {}, votes, pipe.cfg)
    assert result.needs_human and len(queued) == 1 and "agreement_below_threshold" in queued[0].reasons


def test_removed_label_does_not_lend_its_actor_to_remaining_verdict(monkeypatch):
    import human_queue_issues as hq
    events = [{"id": 1, "event": "labeled", "label": {"name": "decision:true-positive"}, "actor": {"login": "mallory"}, "created_at": "2026-09-01T00:00:00Z"},
              {"id": 2, "event": "labeled", "label": {"name": "decision:false-positive"}, "actor": {"login": "alice"}, "created_at": "2026-09-02T00:00:00Z"},
              {"id": 3, "event": "unlabeled", "label": {"name": "decision:false-positive"}, "actor": {"login": "alice"}}]
    monkeypatch.setattr(hq, "gh", lambda *_: json.dumps([events]))
    assert hq.decision_actor("o/r", 1) == "mallory"
    events.pop()
    assert hq.decision_event("o/r", 1, "decision:true-positive") is None


def test_queue_identity_separates_targets_and_revisions():
    keys = {queue_key("app.py", 1, "CWE-89", target_id=t, revision=r, context_hash="ctx")
            for t in ("repo-a", "repo-b") for r in ("rev1", "rev2")}
    assert len(keys) == 4


def test_calibration_counts_zero_finding_called_families():
    import calibrate
    rep = {"findings": [], "bias_audit": {"reviewer_calls[anthropic]": 11, "reviewer_refusals[anthropic]": 11}}
    runs = [("s9", rep, [{"file": "a.py", "line": 1, "cwe": "CWE-89"}])]
    stats, families = calibrate.family_metrics(runs)
    assert families == ["anthropic"] and stats["anthropic"]["CWE-89"]["fn"] == 1
    assert calibrate.audit_rates(runs, families)["anthropic"]["refusal_rate"] == 1


def test_cra_clocks_use_confirmed_event_anchors():
    event = {"confirmed_by": "PSIRT", "event_type": "actively_exploited_vulnerability", "awareness_at": "2026-09-01T00:00:00Z"}
    assert legal_deadlines(None) == {}
    deadlines = legal_deadlines(event)
    assert deadlines["early_warning_by"].startswith("2026-09-02") and "final_report_by" not in deadlines
    event["remediation_available_at"] = "2026-09-20T00:00:00Z"
    assert legal_deadlines(event)["final_report_by"].startswith("2026-10-04")
    event.update(event_type="severe_incident", notification_at="2026-01-31T00:00:00Z")
    assert legal_deadlines(event)["final_report_by"].startswith("2026-02-28")


def test_https_required_except_loopback():
    spec = dict(name="test", family="other", provider="openai_compatible", model="test", data_residency="on_prem")
    with pytest.raises(ValidationError, match="HTTPS"):
        ModelSpec(**spec, base_url="http://model.internal/v1")
    assert ModelSpec(**spec, base_url="https://model.internal/v1")
    assert ModelSpec(**spec, base_url="http://127.0.0.1:8000/v1")


def test_untrusted_markdown_is_literal_even_when_rejected(mock_report):
    report = mock_report[1].model_copy(deep=True)
    report.findings[0].title = "bad\n# Gate approved\n[click](https://evil.invalid)"
    text = render_markdown(report)
    assert "\n# Gate approved" not in text and "[click](https://evil.invalid)" not in text


def test_site_strips_active_content_and_hashes_only_expected_scripts():
    import build_html as site
    body, toc = site.safe_body('# Safe\n<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n[x](javascript:alert)\nhttps://example.org/a')
    assert '<script' not in body and '<img' not in body and 'href="javascript:' not in body
    assert 'href="https://example.org/a"' in body and 'href="#s0"' in toc
    generated = site.OUT.read_text()
    assert site.csp_hash(site.JS) in generated and site.csp_hash(site.CSS) in generated
    assert "unsafe-inline" not in generated.split("</head>")[0] and '<html lang="zh-Hant">' in generated


def test_git_range_includes_all_pr_commits_when_main_advances(tmp_path):
    from gitleaks_ci import scan_range
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "config", "user.name", "Test")
    git(tmp_path, "config", "user.email", "test@example.invalid")
    def commit(name):
        (tmp_path / name).write_text(name)
        git(tmp_path, "add", name)
        git(tmp_path, "commit", "-qm", name)
        return git(tmp_path, "rev-parse", "HEAD")
    common = commit("a")
    git(tmp_path, "checkout", "-qb", "pr")
    first, head = commit("c"), commit("d")
    git(tmp_path, "checkout", "-q", "main")
    base_sha = commit("b")
    opts, _ = scan_range(base_sha, head, "pull_request", tmp_path)
    assert opts == f"{common}..{head}" and first in git(tmp_path, "rev-list", opts)
    opts, _ = scan_range("0" * 40, head, "push", tmp_path)
    assert first in git(tmp_path, "rev-list", opts)


def test_semgrep_error_with_sarif_cannot_pass(tmp_path, monkeypatch):
    import semgrep_ci
    report = tmp_path / "semgrep.sarif"
    triage = tmp_path / "triage.yaml"
    triage.write_text("accepted: []")
    monkeypatch.setattr(semgrep_ci, "check_pins", lambda: (Path("/fake/semgrep"), []))
    monkeypatch.setattr(semgrep_ci, "locked", lambda: ("1", "abc", []))
    monkeypatch.setattr(sys, "argv", ["semgrep_ci", "--triage", str(triage), "--report", str(report), "--target", str(tmp_path)])
    def fake_run(argv, **kwargs):
        if "--version" in argv:
            return SimpleNamespace(stdout="1", stderr="", returncode=0)
        report.write_text(json.dumps({"runs": [{"invocations": [{"executionSuccessful": False}], "results": []}]}))
        return SimpleNamespace(stdout="", stderr="error", returncode=2)
    monkeypatch.setattr(semgrep_ci.subprocess, "run", fake_run)
    assert semgrep_ci.main() != 0


def test_osv_partial_scan_with_only_suppressions_cannot_pass(tmp_path, monkeypatch):
    import osv_ci
    report, lock = tmp_path / "osv.sarif", tmp_path / "requirements.txt"
    lock.write_text("example==1")
    monkeypatch.setattr(osv_ci, "tool_path", lambda _: Path("/fake/osv"))
    monkeypatch.setattr(osv_ci, "locked_version", lambda: "1")
    monkeypatch.setattr(osv_ci, "installed_version", lambda _: "1")
    monkeypatch.setattr(sys, "argv", ["osv_ci", "--lockfile", str(lock), "--report", str(report)])
    def fake_run(argv, **kwargs):
        if "--version" in argv:
            return SimpleNamespace(stdout="1", stderr="", returncode=0)
        report.write_text(json.dumps({"runs": [{"results": [{"ruleId": "CVE-test", "suppressions": [{"status": "accepted"}]}]}]}))
        return SimpleNamespace(stdout="", stderr="partial error", returncode=130)
    monkeypatch.setattr(osv_ci.subprocess, "run", fake_run)
    assert osv_ci.main() != 0


def test_live_calibration_rejects_a_forged_mock_mode_label(tmp_path, monkeypatch):
    import calibrate
    monkeypatch.setattr(sys, "argv", ["calibrate", "--mode", "live", "--out-dir", str(tmp_path)])
    monkeypatch.setattr(calibrate, "load_runs", lambda *_: [("s1", {"provider_mode": "live", "provider_manifest": [
        {"type": "mock", "family": "anthropic", "model": "mock"}], "config_hash": "hash", "revision": "rev"}, [])])
    with pytest.raises(SystemExit, match="provenance"):
        calibrate.main()


def test_cross_target_and_legacy_decisions_never_apply():
    import calibrate
    decision = {"decision": "true_positive", "target": "/a/s9", "target_id": "target-a", "revision": "rev",
                "file": "app.py", "line": 1, "cwe": "CWE-89", "adjudicator_trained": True, "decision_event_id": 1, "context_hash": "ctx"}
    report = {"target": "/b/s9", "target_id": "target-b", "revision": "rev", "coverage": {"content_hash": "ctx"}}
    assert calibrate.apply_decisions("s9", report, [], [decision]) == ([], 0)
    assert calibrate.apply_decisions("s9", {"target": "/a/s9"}, [], [decision]) == ([], 0)


def test_sarif_upload_job_has_no_repository_code_and_osv_scopes_are_separate():
    import yaml
    data = yaml.safe_load((ROOT / ".github/workflows/mara-review.yml").read_text())
    upload = data["jobs"]["code-scanning"]
    assert upload["permissions"]["security-events"] == "write"
    assert all("run" not in step and "checkout@" not in step.get("uses", "") for step in upload["steps"])
    runs = [s.get("run", "") for s in data["jobs"]["deterministic-tools"]["steps"]]
    model_scan = [s for s in runs if "osv_ci.py" in s and "osv-model-eval.toml" in s]
    assert len(model_scan) == 1 and model_scan[0].count("--lockfile") == 1
    assert "IgnoredVulns" not in (ROOT / "tools/osv-scanner.toml").read_text()
