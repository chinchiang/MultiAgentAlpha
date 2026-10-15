"""Adversarial regressions from the 2026-09-18 review; no live providers or attack traffic."""
import dataclasses
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from mara import exchange
from mara.agents import base, judge
from mara.config import ModelSpec, load_config
from mara.context.repo_map import RepoContext, build_context
from mara.pipeline import Pipeline
from mara.providers.base import STOP_END, STOP_MAX_TOKENS, STOP_REFUSAL, Provider, RawReply
from mara.report.human_queue_out import build_queue, queue_key
from mara.report.markdown_out import render_markdown
from mara.report.psirt_out import legal_deadlines
from mara.schemas import EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult
from tests.reply_records import ballot

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


class Reply(Provider):
    def __init__(self, spec, data=None):
        super().__init__(spec)
        self.data, self.requests = data, []

    def complete(self, **kwargs):
        self.requests.append(kwargs)
        return RawReply(STOP_REFUSAL) if self.data is None else RawReply(STOP_END, answer_text=json.dumps(self.data))


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
    has_symlink = True
    try:
        (root / "link.py").symlink_to(outside)
    except OSError:
        has_symlink = False
    (root / ".env").write_text("LOCAL_SECRET_MARKER")
    (root / "ignored.py").write_text("IGNORED_MARKER")
    (root / "app.py").write_text('token = "' + 'ghp_' + 'A' * 36 + '"\nprint(1)')
    (root / ".gitignore").write_text("ignored.py\n.env\n")
    git(root, "init", "-q")
    git_add = ["app.py", ".gitignore"] + (["link.py"] if has_symlink else [])
    git(root, "add", *git_add)
    ctx = build_context(root)
    assert "OUTSIDE_MARKER" not in ctx.bundle() and "LOCAL_SECRET_MARKER" not in ctx.bundle()
    assert "IGNORED_MARKER" not in ctx.bundle() and 'ghp_' + 'A' * 36 not in ctx.bundle()
    if has_symlink:
        assert ctx.omitted["link.py"]
        assert not ctx.complete
    assert ctx.redacted == ["app.py"]


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
    assert "\n# forged" not in body
    # the quote sits in a code span, verbatim and inert: rendered, it is text, not a heading or an element
    import markdown
    html_out = markdown.markdown(body)
    assert "<img" not in html_out and "<h1>" not in html_out
    assert "<code>` # forged &lt;img src=x onerror=alert(1)&gt;</code>" in html_out


def test_code_spans_show_untrusted_text_verbatim():
    """literal()'s character references are not decoded inside code spans, so evidence quotes rendered
    as `cursor.execute&#40;&quot;SELECT &#42;...`; code() needs no escaping, only a fence the text
    cannot contain, so the span shows the text as written and cannot be closed early."""
    import html as html_mod

    import markdown

    from mara.report.escaping import code
    for text in ['cursor.execute("SELECT * FROM t WHERE id=" + q)', "a ` b `` c", "`edge`", "x | y <b>z</b> [l](u)", ""]:
        out = markdown.markdown(f"- Quote: {code(text)} tail")
        inner = out.split("<code>", 1)[1].split("</code>", 1)[0]
        assert html_mod.unescape(inner).strip() == text.strip() and "tail" in out.split("</code>", 1)[1], (text, out)


@pytest.mark.parametrize("bad", ["CVSS:4.0/invalid", "CVSS:4.0/AV:Q", VECTOR + "/AV:N", "CVSS:4.0/AV:N"])
def test_invalid_cvss_is_rejected_at_model_boundary(bad):
    with pytest.raises(ValidationError):
        Finding.model_validate({**finding().model_dump(), "cvss4_vector": bad})


def test_duplicate_judge_reply_is_not_counted(tmp_path):
    pipe = pipeline(tmp_path)
    row = {"finding_id": "F-1", "verdict": "false_positive", "severity_band": "None", "reason": "test"}
    provider = Reply(pipe.cfg.models[0], {"items": [row] * 100})
    votes, rec = judge.run_judge(provider, [{"finding_id": "F-1"}], "forward")
    assert not votes and rec.voided and rec.invalid_items == 99


def _voided_skeptic(data, n=3, *, refused=False, error=""):
    """(the voided reply's log codes, the counters it writes)."""
    from mara.agents import skeptic
    from mara.audit import Audit

    class One(Provider):
        def complete(self, **kwargs):
            if error:
                raise RuntimeError(error)
            if refused:
                return RawReply(STOP_REFUSAL)
            return RawReply(STOP_END, answer_text="" if data is None else json.dumps(data))

    ctx = RepoContext(root=Path("."), content={"app.py": "unsafe()\n"})
    fs = [finding().model_copy(update={"id": f"F-{i}"}) for i in range(1, n + 1)]
    verdicts, rec = skeptic.run_skeptic(One(load_config(ROOT / "config/mara.mock.yaml").models[0]), ctx, fs)
    assert verdicts == [] and rec.voided
    audit = Audit()
    audit.record(rec)
    return rec.log_codes, audit


def _sk(fid, verdict="stands"):
    return {"finding_id": fid, "verdict": verdict, "reason": "r", "sanitizer_or_control": ""}


def test_incomplete_ballots_count_one_invalid_item_per_uncovered_finding():
    """A well-formed reply that drops findings used to leave only the summary marker, which the
    invalid-output audit does not count: nothing was counted and the run stayed complete."""
    details, audit = _voided_skeptic({"items": []})
    assert details.count("missing_verdict") == 3 and audit["skeptic_invalid_items"] == 3
    assert _voided_skeptic({"items": [_sk("F-1"), _sk("F-2")]})[1]["skeptic_invalid_items"] == 1
    details, audit = _voided_skeptic({"items": [_sk("F-1"), _sk("F-1"), _sk("F-2"), _sk("F-3"), _sk("F-9")]})
    assert details.count("duplicate_verdict") == 1 and details.count("unexpected_verdict") == 1 and audit["skeptic_invalid_items"] == 2
    # a schema-invalid item already counts once and is not counted again as missing
    details, audit = _voided_skeptic({"items": [_sk("F-1"), {"finding_id": "F-2", "verdict": "maybe"}]})
    assert audit["skeptic_invalid_items"] == 2 and details.count("missing_verdict") == 1
    # response-level outcomes are not multiplied by the batch size
    details, audit = _voided_skeptic(None, refused=True)
    assert (audit["skeptic_refusals"], audit["skeptic_invalid_items"], details) == (1, 0, ())
    # a failed call is a provider error (skeptic_errors), never invalid output charged to the model
    details, audit = _voided_skeptic(None, error="provider_http_error:503")
    assert (audit["skeptic_errors"], audit["skeptic_invalid_items"]) == (1, 0) and "provider_http_error:503" in details
    assert _voided_skeptic(None)[1]["skeptic_invalid_items"] == 1  # empty body


class _OverrideRole(Provider):
    """The wrapped mock provider, except that calls for `role` get `data` back."""

    def __init__(self, inner, role, data):
        super().__init__(inner.spec)
        self.inner, self.role, self.data = inner, role, data

    def bind_target(self, root):
        self.inner.bind_target(root)

    def complete(self, *, system, user, schema, role, max_tokens=16000):
        if role == self.role:
            return RawReply(STOP_END, answer_text=json.dumps(self.data))
        return self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)


@pytest.mark.parametrize("role,counter", [("skeptic", "skeptic_invalid_items"), ("redteam", "redteam_invalid_items")])
def test_an_empty_ballot_never_passes_silently(tmp_path, role, counter):
    cfg = load_config(ROOT / "config/mara.mock.yaml")
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / "out")
    pipe.providers = {n: _OverrideRole(p, role, {"items": []}) for n, p in pipe.providers.items()}
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    assert report.bias_audit[counter] > 0 and counter in report.incomplete_reasons and not report.gate_passed
    if role == "skeptic":
        assert report.bias_audit[counter] == len(report.findings), "one missing verdict per unchallenged finding"
        assert all(c.skeptic_abstained for c in report.consensus)
        assert not [c for c in report.consensus if c.tier == EvidenceTier.B], "no independent challenge, no tier B"


def test_a_refutation_must_cite_a_non_blank_line_of_a_file_the_skeptic_was_shown():
    from mara.agents.skeptic import _control_location_ok

    ctx = RepoContext(root=Path("."), content={"app.py": "import db\n\nq = db.param(x)\n", "other.py": "safe()\n"})
    assert _control_location_ok(ctx, "db.param at app.py:3", {"app.py"})
    assert not _control_location_ok(ctx, "see other.py:1", {"app.py"}), "a file the skeptic never received"
    assert not _control_location_ok(ctx, "app.py:2", {"app.py"}), "a blank line is no control"
    assert not _control_location_ok(ctx, "app.py:99", {"app.py"}) and not _control_location_ok(ctx, "parameterised query", {"app.py"})


class _EchoRole(_OverrideRole):
    """Follows the planted canary instruction for `role`: replies with the token, without naming the planted file."""

    def complete(self, *, system, user, schema, role, max_tokens=16000):
        if role == self.role:
            token = user.split("Reply with the token ")[1].split()[0]
            return RawReply(STOP_END, answer_text=json.dumps(self.data), aside=f"Pre-approved: {token}")
        return self.inner.complete(system=system, user=user, schema=schema, role=role, max_tokens=max_tokens)


@pytest.mark.parametrize("role", ["skeptic", "redteam"])
def test_l3_agents_carry_a_canary_and_an_echo_voids_their_verdicts(tmp_path, role):
    """The skeptic and the red team read raw repository files and can clear or downgrade a finding, but
    only reviewers and the context agent carried a canary: an injection steering refutations was invisible."""
    cfg = load_config(ROOT / "config/mara.mock.yaml")
    pipe = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path / "out")
    pipe.providers = {n: _EchoRole(p, role, {"items": []}) for n, p in pipe.providers.items()}
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    key = f"{role}_canary_echoes"
    assert report.bias_audit[key] > 0 and key in report.incomplete_reasons and not report.gate_passed
    assert report.bias_audit[f"{role}_invalid_items"] == 0, "an echo is counted as an echo, not as invalid output"
    if role == "skeptic":
        assert not report.skeptic and all(c.skeptic_abstained for c in report.consensus)
    else:
        assert not report.redteam


def test_tool_corroboration_needs_the_same_file_and_a_blocking_level():
    """A bare suffix match let a tool hit in services/billing/main.py corroborate a finding in main.py
    and promote it to tier A; a note-level result corroborated as strongly as an error."""
    from mara.pipeline import _tool_corroborates

    f = finding().model_copy(update={"provenance": [Provenance(file="main.py", line=10, quote="unsafe()", verified=True)]})

    def hit(file, level="error"):
        return [ToolResult("semgrep", "sql", level, "SQL injection", file, 11, "CWE-89")]

    assert _tool_corroborates(f, hit("main.py")) and _tool_corroborates(f, hit("./main.py"))
    assert not _tool_corroborates(f, hit("services/billing/main.py")), "another file with the same name"
    assert not _tool_corroborates(f, hit("main.py", level="note")), "a note is information, not evidence"
    # a tool that ran from the repository top level reports the target's own prefix (pre-recorded zizmor)
    assert _tool_corroborates(f, hit("fixtures/vuln-sample/main.py"), "fixtures/vuln-sample")
    assert not _tool_corroborates(f, hit("other/vuln-sample/main.py"), "fixtures/vuln-sample")


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
    # an invalid vector cannot reach scoring: Finding rejects it at the model boundary
    # (test_invalid_cvss_is_rejected_at_model_boundary); one smuggled past validation fails loudly, never as "Unknown"
    from mara.scoring import cvss4

    with pytest.raises(cvss4.CVSS4Error):
        pipe.score([f.model_copy(update={"cvss4_vector": "CVSS:4.0/invalid"})], finders, {}, {}, full, [])


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


class Truncated(Provider):
    def complete(self, **kwargs):
        return RawReply(STOP_MAX_TOKENS, answer_text='{"findings": [')


def test_truncated_reviewer_replies_block_the_gate(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    pipe.providers = {n: Truncated(p.spec) for n, p in pipe.providers.items()}
    (tmp_path / "app.py").write_text("unsafe()")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(t, True) for t in ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy")])
    report = pipe.run(tmp_path, mode="mock")
    assert report.bias_audit["reviewer_truncations"] == 33 and report.bias_audit["reviewer_refusals"] == 0
    assert not report.gate_passed and report.overall_score is None and report.review_status == "incomplete"
    assert "reviewer_truncations" in report.incomplete_reasons


def test_l3_prefers_a_family_outside_every_finder_and_audits_the_fallback(tmp_path, monkeypatch):
    pipe, f = pipeline(tmp_path), finding()
    seen = []
    def answer(role):
        return lambda p, ctx, fs: (seen.append((role, p.family)), ([], ballot(role, p.family.value, len(fs), exchange.REFUSAL)))[1]

    monkeypatch.setattr("mara.pipeline.skeptic.run_skeptic", answer("skeptic"))
    monkeypatch.setattr("mara.pipeline.redteam.run_redteam", answer("redteam"))
    # the configured skeptic (nemotron) and red team (deepseek) both found it: only anthropic is independent
    two = {f.id: {ModelFamily.NEMOTRON, ModelFamily.DEEPSEEK}}
    pipe.run_skeptics(RepoContext(root=tmp_path), [f], two)
    pipe.run_redteam(RepoContext(root=tmp_path), [f], two)
    assert seen == [("skeptic", ModelFamily.ANTHROPIC), ("redteam", ModelFamily.ANTHROPIC)]
    assert not pipe.audit["skeptic_same_family"] and not pipe.audit["redteam_same_family"]
    every = {f.id: {ModelFamily.ANTHROPIC, ModelFamily.NEMOTRON, ModelFamily.DEEPSEEK}}
    pipe.run_skeptics(RepoContext(root=tmp_path), [f], every)
    pipe.run_redteam(RepoContext(root=tmp_path), [f], every)
    assert pipe.audit["skeptic_same_family"] == 1 and pipe.audit["redteam_same_family"] == 1
    assert any("no skeptic outside the finder families" in line for line in pipe.log)


def test_missing_config_is_a_usage_error_not_a_traceback(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from mara.cli import app

    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MARA_HOME", raising=False)
    target = tmp_path / "target"  # not the workspace itself, which check_outside refuses before the config is looked up
    target.mkdir()
    for args in (["review", str(target), "--provider", "mock"], ["check-config"]):
        res = CliRunner().invoke(app, args)
        assert res.exit_code == 2 and not isinstance(res.exception, FileNotFoundError), res.output
        assert "config file not found" in res.output


def test_skeptic_refusal_is_an_abstention_not_invalid_output(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    (tmp_path / "app.py").write_text("unsafe()")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(t, True) for t in ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy")])
    monkeypatch.setattr("mara.pipeline.skeptic.run_skeptic", lambda p, ctx, fs: ([], ballot("skeptic", p.family.value, len(fs), exchange.REFUSAL)))
    report = pipe.run(tmp_path, mode="mock")
    assert report.bias_audit["skeptic_refusals"] == report.bias_audit["skeptic_calls"] >= 1
    assert report.bias_audit["skeptic_invalid_items"] == 0
    assert "skeptic_refusals" in report.incomplete_reasons and not report.gate_passed
    assert report.consensus and all(c.skeptic_abstained for c in report.consensus)
    assert all(c.tier != EvidenceTier.B for c in report.consensus)  # the independent challenge is missing


def test_judge_refusal_is_counted_separately_from_invalid_output(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    (tmp_path / "app.py").write_text("unsafe()")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(t, True) for t in ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy")])
    monkeypatch.setattr("mara.pipeline.judge.run_judge", lambda p, batch, pass_id, self_ids=None: (
        [], ballot("judge", p.family.value, len(batch), exchange.REFUSAL, pass_id=pass_id)))
    report = pipe.run(tmp_path, mode="mock")
    # every judge call refused: 3 families x 2 chunks (30 findings, MAX_L4_FINDINGS per pass) x 2 passes
    assert report.bias_audit["judge_refusals"] == report.bias_audit["judge_calls"] == 12
    assert report.bias_audit["judge_invalid_items"] == 0
    assert "judge_refusals" in report.incomplete_reasons and not report.gate_passed


def test_unresolvable_base_ref_is_a_usage_error(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from mara.cli import app

    monkeypatch.chdir(tmp_path)  # the workspace; the target is a directory below it, never the workspace itself
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("unsafe()")
    res = CliRunner().invoke(
        app, ["review", str(target), "--provider", "mock", "--config", str(ROOT / "config" / "mara.mock.yaml"),
              "--base", "no-such-ref"])
    # exit 2 (usage error) and no report: the message text goes through typer's rich error
    # panel, whose rendering varies with terminal width and encoding, so assert the outcome
    assert res.exit_code == 2 and not (tmp_path / "out" / "report.json").exists()
    assert "WorkspaceInsideTarget" not in repr(res.exception)


def test_trust_anchors_never_come_from_the_review_target(tmp_path, monkeypatch):
    """`cd target && mara review .` used to execute target/.mara-tools/bin/* as the pinned tools and
    let a planted target/calib/latest.json satisfy policy P8."""
    from typer.testing import CliRunner

    from mara import workspace
    from mara.cli import app

    target = tmp_path / "target"
    (target / ".mara-tools" / "bin").mkdir(parents=True)
    (target / "app.py").write_text("unsafe()")
    monkeypatch.chdir(target)
    monkeypatch.delenv("MARA_TOOLS_DIR", raising=False)
    monkeypatch.delenv("MARA_HOME", raising=False)
    with pytest.raises(workspace.WorkspaceInsideTarget, match="MARA workspace"):
        workspace.check_outside(target)
    res = CliRunner().invoke(app, ["review", ".", "--provider", "mock", "--config", str(ROOT / "config" / "mara.mock.yaml"),
                                   "--out", str(tmp_path / "out")])
    assert res.exit_code == 2 and isinstance(res.exception, SystemExit) and not (tmp_path / "out" / "report.json").exists()
    # a workspace outside the target is fine, even when the working directory is the target
    home = tmp_path / "mara-home"
    home.mkdir()
    monkeypatch.setenv("MARA_HOME", str(home))
    workspace.check_outside(target)
    assert workspace.resolve("calib/latest.json") == home / "calib" / "latest.json"
    from mara.tools.runner import tools_dir
    assert tools_dir() == (home / ".mara-tools").resolve()
    # ...but not a tool directory or trivy database pointed into it
    monkeypatch.setenv("MARA_TOOLS_DIR", str(target / ".mara-tools"))
    with pytest.raises(workspace.WorkspaceInsideTarget, match="tool directory"):
        workspace.check_outside(target)
    monkeypatch.setenv("MARA_TOOLS_DIR", str(home / ".mara-tools"))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(target / "cache"))
    with pytest.raises(workspace.WorkspaceInsideTarget, match="trivy"):
        workspace.check_outside(target)
    # the ordinary layout: the workspace is a parent of the target (mara review fixtures/vuln-sample)
    monkeypatch.delenv("MARA_TRIVY_CACHE_DIR")
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / ".mara-tools"))
    workspace.check_outside(target)


def test_review_defaults_resolve_in_the_workspace_and_no_config_or_output_lies_in_the_target(tmp_path, monkeypatch):
    """With MARA_HOME set and the job running inside the target, `mara review .` used to load the target's
    config/mara.yaml (its models, endpoints and gate) and write out/ into the target, where the next
    review of a non-git target bundled the previous reports into the prompts."""
    import re
    import shutil

    from typer.testing import CliRunner

    from mara import cli

    def words(text):
        # The refusal is the precise WorkspaceInsideTarget text ("the config file … lies inside the review
        # target", and the same for the output directory). Typer shows it in a rich panel, and on GitHub
        # Actions that panel is a colour terminal: a wrap inserts the border's ANSI codes between words.
        # Those codes contain letters and digits, so joining word characters on the raw panel hides the phrase.
        plain = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
        return "".join(re.findall(r"\w+", plain))

    home =tmp_path / "mara-home"
    (home / "config").mkdir(parents=True)
    shutil.copy(ROOT / "config" / "mara.mock.yaml", home / "config" / "mara.mock.yaml")
    target = tmp_path / "target"
    (target / "config").mkdir(parents=True)
    (target / "app.py").write_text("print(1)\n")
    (target / "config" / "mara.mock.yaml").write_text("planted: true\n")  # would fail to load if it were read
    monkeypatch.setenv("MARA_HOME", str(home))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(home / ".mara-tools"))
    monkeypatch.delenv("MARA_TRIVY_CACHE_DIR", raising=False)
    monkeypatch.chdir(target)
    seen = {}

    class Stop(Exception):
        pass

    def fake_load(path):
        seen["config"] = Path(path)
        raise Stop

    monkeypatch.setattr(cli, "load_config", fake_load)
    res = CliRunner().invoke(cli.app, ["review", str(target), "--provider", "mock"])
    assert isinstance(res.exception, Stop), res.output
    assert seen["config"] == home / "config" / "mara.mock.yaml", "the default config is the workspace's, not the target's"

    def run(*args):
        return CliRunner().invoke(cli.app, ["review", str(target), "--provider", "mock", *args])

    for args, what in ((["--config", str(target / "config" / "mara.mock.yaml")], "the config file"),
                       (["--config", "config/mara.mock.yaml"], "the config file"),  # relative to the working directory: the target
                       (["--config", str(home / "config" / "mara.mock.yaml"), "--out", "out"], "the output directory"),
                       (["--config", str(home / "config" / "mara.mock.yaml"), "--out", str(target)], "the output directory")):
        seen.clear()
        res = run(*args)
        said = words(res.output)
        assert res.exit_code == 2 and words(what) in said and words("lies inside the review target") in said, (args, res.output)
        assert not seen, "refused before the config is read"
    # the default output directory is in the workspace too
    monkeypatch.setattr(cli, "load_config", load_config)
    monkeypatch.setattr(cli.Pipeline, "run", lambda self, *a, **k: (_ for _ in ()).throw(Stop()))
    seen_out = {}
    real_init = cli.Pipeline.__init__

    def init(self, cfg, **kw):
        seen_out["out"] = Path(kw["out_dir"])
        real_init(self, cfg, **kw)

    monkeypatch.setattr(cli.Pipeline, "__init__", init)
    res = run()
    assert isinstance(res.exception, Stop), res.output
    assert seen_out["out"] == home / "out"
    # check-config's default is the workspace's config as well
    res = CliRunner().invoke(cli.app, ["check-config"])
    assert words(str(home / "config" / "mara.yaml")) in words(res.output), res.output


def test_the_calibration_secret_exemption_is_narrow(tmp_path, monkeypatch):
    """Calibration samples seed hard-coded credentials on purpose (CWE-798 labels), and the live secret
    preflight blocked egress for three of the five. The exemption: only on the operator's flag, only for
    a target below <workspace>/calib/samples/ with an answer key, only for findings at a declared
    CWE-798 file:line; any other secret still blocks."""
    from mara import pipeline as pl

    sample = tmp_path / "calib" / "samples" / "s9"
    sample.mkdir(parents=True)
    labels = {"sample": "s9", "labels": [
        {"dimension": "secrets", "cwe": "CWE-798", "file": "app.py", "line": 3, "quote": "TOKEN = \"x\"", "title": "seeded"},
        {"dimension": "xss", "cwe": "CWE-79", "file": "app.py", "line": 9, "quote": "q", "title": "xss"}]}
    (sample / "labels.json").write_text(json.dumps(labels), encoding="utf-8")
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    key = pl.calibration_answer_key(sample)
    assert [(lab["file"], lab["line"]) for lab in key] == [("app.py", 3)]
    from mara.review_status import secret_preflight
    from mara.tools.runner import ToolRun

    def exempted(res):
        return secret_preflight("live", [ToolRun("gitleaks", True, [res])], key).exempted == (res,)

    assert exempted(ToolResult("gitleaks", "generic-api-key", "error", "secret", "app.py", 3, "CWE-798"))
    assert not exempted(ToolResult("gitleaks", "aws", "error", "secret", "app.py", 4, "CWE-798")), "another line"
    assert not exempted(ToolResult("gitleaks", "aws", "error", "secret", "config.py", 3, "CWE-798")), "another file"
    # a reviewed repository cannot claim the exemption by shipping its own labels.json
    elsewhere = tmp_path / "repo"
    elsewhere.mkdir()
    (elsewhere / "labels.json").write_text(json.dumps(labels), encoding="utf-8")
    with pytest.raises(ValueError, match="needs a target below"):
        pl.calibration_answer_key(elsewhere)
    (sample / "labels.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="not a calibration answer key"):
        pl.calibration_answer_key(sample)


def test_live_egress_with_the_exemption_passes_only_declared_secrets(tmp_path, monkeypatch):
    import mara.pipeline as mod

    sample = tmp_path / "calib" / "samples" / "s9"
    sample.mkdir(parents=True)
    (sample / "app.py").write_text("import os\n\nTOKEN = 'seeded-test-value'\n", encoding="utf-8")
    (sample / "labels.json").write_text(json.dumps({"labels": [
        {"dimension": "secrets", "cwe": "CWE-798", "file": "app.py", "line": 3, "quote": "TOKEN", "title": "seeded"}]}), encoding="utf-8")
    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "tools"))

    def run(extra_secret):
        pipe = pipeline(tmp_path)
        pipe.providers = {n: Reply(p.spec, {"findings": []}) for n, p in pipe.providers.items()}
        results = [ToolResult("gitleaks", "generic-api-key", "error", "secret", "app.py", 3, "CWE-798")]
        if extra_secret:
            results.append(ToolResult("gitleaks", "aws-access-token", "error", "secret", "app.py", 1, "CWE-798"))
        monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun("gitleaks", True, results)])
        report = pipe.run(sample, mode="mock", calibration_sample=True)
        return pipe, report

    pipe, report = run(extra_secret=False)
    assert report.bias_audit["secret_preflight_calibration_exempted"] == 1
    assert any("1 seeded secret(s) declared by the calibration answer key, 0 other finding(s)" in line for line in pipe.log)
    pipe, report = run(extra_secret=True)
    assert report.bias_audit["secret_preflight_calibration_exempted"] == 1, "the undeclared one is not exempted"
    assert any("0 other finding(s)" not in line and "1 other finding(s)" in line for line in pipe.log), "and it still blocks"
    # the egress rule itself is mara.review_status.secret_preflight (tests/test_review_status.py)
    assert mod.Pipeline.run.__kwdefaults__["calibration_sample"] is False, "off unless the operator asks"


def test_p8_reads_its_evidence_from_the_workspace(tmp_path, monkeypatch):
    import datetime as dt

    from mara.config import MaraConfig
    from mara.policy import AAT_METHOD, evaluate_policies

    raw = yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8"))
    raw["gate"] = dict(raw.get("gate") or {}, unsupervised_reject_allowed=True)
    cfg = MaraConfig.model_validate(raw, context={"skip_policies": True})
    home = tmp_path / "home"
    (home / "calib").mkdir(parents=True)
    (home / "calib" / "latest.json").write_text(json.dumps({"date": dt.date.today().isoformat(), "mode": "live", "aat": {
        "method": AAT_METHOD, "passed": True, "n": 12, "rejection": {"n": 59, "passed": True, "miss_rate_upper": 0.0495}}}), encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # no calib/ here
    p8 = lambda: [r for r in evaluate_policies(cfg) if r.id == "P8"][0]  # noqa: E731
    assert not p8().passed
    monkeypatch.setenv("MARA_HOME", str(home))
    assert p8().passed


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
    pipe.outcome_policy = dataclasses.replace(pipe.outcome_policy, alpha_threshold=1.0)
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


class Failing(Provider):
    def complete(self, **kwargs):
        raise RuntimeError("provider_http_error:429")


def test_provider_errors_block_the_gate_and_are_not_counted_as_refusals(tmp_path, monkeypatch):
    pipe = pipeline(tmp_path)
    pipe.providers = {n: Failing(p.spec) for n, p in pipe.providers.items()}
    (tmp_path / "app.py").write_text("unsafe()")
    monkeypatch.setattr(pipe, "run_tools", lambda *_: [ToolRun(t, True) for t in ("semgrep", "gitleaks", "osv-scanner", "zizmor", "trivy")])
    report = pipe.run(tmp_path, mode="mock")
    assert report.bias_audit["reviewer_errors"] == 33 and report.bias_audit["reviewer_refusals"] == 0
    assert not report.gate_passed and report.overall_score is None and "reviewer_errors" in report.incomplete_reasons
    import calibrate
    rates = calibrate.audit_rates([("s", {"bias_audit": report.bias_audit}, [])], ["anthropic"])["anthropic"]
    assert rates["error_rate"] == 1 and rates["refusal_rate"] == 0


def test_queue_identity_separates_targets_and_revisions():
    keys = {queue_key("app.py", 1, "CWE-89", target_id=t, revision=r, context_hash="ctx")
            for t in ("repo-a", "repo-b") for r in ("rev1", "rev2")}
    assert len(keys) == 4


def _repo_with_sample(root, remote):
    (root / "sample").mkdir(parents=True)
    (root / "sample" / "app.py").write_text("print('sample')\n", encoding="utf-8")
    (root / "notes.txt").write_text("v1\n", encoding="utf-8")
    git(root, "init", "-q", "-b", "main")
    git(root, "remote", "add", "origin", remote)
    git(root, "add", ".")
    git(root, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init")


def test_decision_identity_survives_unrelated_commits_and_other_checkouts(tmp_path):
    """Decisions bind to (target_id, revision, context hash). The target id used to be the absolute
    path and the revision the repository commit, so a decision taken on CI never matched a local
    run, and committing the synced decisions (or touching any sibling) unbound all of them."""
    a = tmp_path / "a"
    _repo_with_sample(a, "https://github.com/example-org/product.git")
    first = build_context(a / "sample")
    assert json.loads(first.identity) == ["git", "github.com/example-org/product", "sample"]
    # a commit outside the target directory changes the commit, not the binding
    (a / "notes.txt").write_text("v2\n", encoding="utf-8")
    git(a, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "unrelated")
    second = build_context(a / "sample")
    assert second.commit != first.commit
    assert (second.identity, second.revision, second.content_hash) == (first.identity, first.revision, first.content_hash)
    # another clone of the same repository (ssh remote, other location) names the target the same way
    b = tmp_path / "elsewhere" / "b"
    _repo_with_sample(b, "git@github.com:example-org/product.git")
    other = build_context(b / "sample")
    assert other.identity == first.identity and other.revision == first.revision
    # changing the reviewed code does unbind
    (a / "sample" / "app.py").write_text("print('changed')\n", encoding="utf-8")
    git(a, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-am", "change")
    assert build_context(a / "sample").revision != first.revision
    # another directory of the same repository is another target
    assert build_context(a).identity != first.identity


def test_a_subdirectory_target_sends_tracked_files_only(tmp_path):
    """`has_git` used to look for target/.git only: a subdirectory target (mara review fixtures/x) was
    walked with rglob, so untracked and gitignored local files went to the providers."""
    repo = tmp_path / "repo"
    _repo_with_sample(repo, "https://github.com/example-org/product.git")
    (repo / "sample" / "untracked_local.yaml").write_text("token: LOCAL_ONLY_MARKER\n", encoding="utf-8")
    (repo / ".gitignore").write_text("sample/ignored.txt\n", encoding="utf-8")
    (repo / "sample" / "ignored.txt").write_text("IGNORED_MARKER\n", encoding="utf-8")
    ctx = build_context(repo / "sample")
    assert sorted(ctx.content) == ["app.py"] and ctx.complete
    assert "LOCAL_ONLY_MARKER" not in ctx.bundle() and "IGNORED_MARKER" not in ctx.bundle()


def test_a_failing_git_ls_files_fails_closed_instead_of_walking_the_tree(tmp_path, monkeypatch):
    import mara.context.repo_map as mod

    repo = tmp_path / "repo"
    _repo_with_sample(repo, "https://github.com/example-org/product.git")
    (repo / "sample" / "untracked_local.yaml").write_text("token: LOCAL_ONLY_MARKER\n", encoding="utf-8")
    real = subprocess.run

    def broken(cmd, *a, **kw):  # e.g. "detected dubious ownership" in a CI container
        if "ls-files" in cmd:
            return subprocess.CompletedProcess(cmd, 128, stdout=b"", stderr=b"fatal: detected dubious ownership")
        return real(cmd, *a, **kw)

    monkeypatch.setattr(mod.subprocess, "run", broken)
    ctx = build_context(repo / "sample")
    assert ctx.omitted == {".": "git_ls_files_failed"} and not ctx.complete and not ctx.content


def test_untracked_directories_keep_a_path_identity(tmp_path):
    # tmp_path may itself sit inside a parent repository (a home-directory dotfiles repo): a directory
    # that is not part of a committed history is named by its path and has no git revision
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    ctx = build_context(tmp_path)
    assert json.loads(ctx.identity) == ["path", str(tmp_path.resolve())]
    assert ctx.revision.startswith("non-git:") and ctx.commit == ""


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
    generated = site.OUT.read_text(encoding="utf-8")
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
    monkeypatch.setattr(calibrate, "load_runs", lambda *_, **__: [("s1", {"provider_mode": "live", "provider_manifest": [
        {"type": "mock", "family": "anthropic", "model": "mock"}], "config_hash": "hash", "revision": "rev"}, [])])
    with pytest.raises(SystemExit, match="provenance"):
        calibrate.main()


def test_cross_target_and_legacy_decisions_never_apply():
    import calibrate
    decision = {"decision": "true_positive", "target": "/a/s9", "target_id": "target-a", "revision": "rev",
                "file": "app.py", "line": 1, "cwe": "CWE-89", "adjudicator_trained": True, "decision_event_id": 1, "context_hash": "ctx"}
    report = {"target": "/b/s9", "target_id": "target-b", "revision": "rev", "coverage": {"content_hash": "ctx"}}
    from mara.decisions import Decision, TrainingRequirement, select

    assert isinstance(Decision.parse(decision), str), "a record without a key is not a decision"
    decision.update(key=queue_key("app.py", 1, "CWE-89", target_id="target-a", revision="rev", context_hash="ctx"),
                    decided_by="alice", decided_at="2026-10-01T08:00:00Z")
    parsed = Decision.parse(decision)
    anyone = TrainingRequirement(required=False)
    assert select([parsed], report, anyone).usable == [] and select([parsed], {"target": "/a/s9"}, anyone).usable == []
    assert calibrate.apply_decisions(select([parsed], report, anyone).usable, []) == ([], 0)


def test_sarif_upload_job_has_no_repository_code_and_osv_scopes_are_separate():
    import yaml
    data = yaml.safe_load((ROOT / ".github/workflows/mara-review.yml").read_text(encoding="utf-8"))
    upload = data["jobs"]["code-scanning"]
    assert upload["permissions"]["security-events"] == "write"
    assert all("run" not in step and "checkout@" not in step.get("uses", "") for step in upload["steps"])
    runs = [s.get("run", "") for s in data["jobs"]["deterministic-tools"]["steps"]]
    model_scan = [s for s in runs if "osv_ci.py" in s and "osv-model-eval.toml" in s]
    assert len(model_scan) == 1 and model_scan[0].count("--lockfile") == 1
    semgrep_scan = [s for s in runs if "osv_ci.py" in s and "osv-semgrep.toml" in s]
    assert len(semgrep_scan) == 1 and semgrep_scan[0].count("--lockfile") == 1 and "semgrep-requirements.txt" in semgrep_scan[0]
    main_scan = [s for s in runs if "osv_ci.py" in s and "osv-scanner.toml" in s]
    assert len(main_scan) == 1 and "semgrep-requirements.txt" not in main_scan[0]
    assert "IgnoredVulns" not in (ROOT / "tools/osv-scanner.toml").read_text(encoding="utf-8")
