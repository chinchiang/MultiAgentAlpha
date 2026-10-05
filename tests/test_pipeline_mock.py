"""End-to-end run on the seeded fixture with three mock families."""

import pytest

from mara.report.markdown_out import render_markdown
from mara.report.sarif_out import to_sarif
from mara.schemas import EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance, SkepticVerdict

SEEDED = {  # (dimension, cwe, file) that must be accepted
    ("vulnerabilities", "CWE-89", "app.py"),
    ("xss", "CWE-79", "app.py"),
    ("xss", "CWE-79", "static/index.html"),
    ("authn_authz", "CWE-639", "app.py"),
    ("authn_authz", "CWE-565", "app.py"),
    ("secrets", "CWE-798", "config.py"),
    ("secrets", "CWE-312", "config.py"),
    ("secrets", "CWE-532", "app.py"),
    ("github_actions", "CWE-829", ".github/workflows/deploy.yml"),
    ("github_actions", "CWE-78", ".github/workflows/deploy.yml"),
    ("error_handling", "CWE-209", "app.py"),
    ("supply_chain", "CWE-494", "Dockerfile"),
    ("input_validation", "CWE-1427", "README.md"),
    ("csp", "CWE-1021", "static/index.html"),
    ("dependencies", "CWE-1395", "requirements.txt"),
    ("architecture", "CWE-285", "app.py"),
}


def _accepted(report):
    cons = {c.finding_id: c for c in report.consensus}
    return [f for f in report.findings if cons[f.id].accepted], cons


def test_every_seeded_defect_is_retained_for_human_review(mock_report):
    _, report = mock_report
    accepted, _ = _accepted(report)
    unresolved = {q.finding_id for q in report.human_queue}
    got = {(f.dimension, f.cwe, f.provenance[0].file) for f in report.findings
           if f in accepted or f.id in unresolved}
    missing = SEEDED - got
    assert not missing, f"seeded defects not accepted: {missing}"


def test_fabricated_quote_is_rejected_as_tier_d(mock_report):
    _, report = mock_report
    _, cons = _accepted(report)
    fake = next(f for f in report.findings if f.title == "SQL injection in profile query")
    assert not any(p.verified for p in fake.provenance)
    assert cons[fake.id].tier == EvidenceTier.D
    assert not cons[fake.id].accepted
    assert cons[fake.id].skeptic_refuted


def test_refuted_finding_the_jury_overrode_goes_to_human(mock_report):
    """assessment #37: a skeptic-refuted finding with high jury consensus must not re-enter the
    blocking logic; it is forced to the human queue instead of being accepted."""
    pipe, _ = mock_report
    f = Finding(
        id="F-9001", dimension="vulnerabilities", title="SQL injection in search", cwe="CWE-89",
        provenance=[Provenance(file="app.py", line=32, quote="cursor.execute(q)", verified=True)],
        reachability="reachable", reachability_argument="user input reaches the query",
        exploit_sketch="inject via the search parameter",
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
        model_confidence=0.9, source_family=ModelFamily.MOCK, source_model="mock-a",
        finder_families=[ModelFamily.MOCK],
    )
    votes = [
        JudgeVote(finding_id="F-9001", verdict="true_positive", severity_band="High", reason="reachable",
                  judge_family=fam, judge_model=f"{fam.value}-judge", presentation_order=0, pass_id=pas)
        for fam in (ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK, ModelFamily.NEMOTRON)
        for pas in ("forward", "reverse")
    ]
    sk = SkepticVerdict(finding_id="F-9001", verdict="refuted", reason="query is parameterised",
                        sanitizer_or_control="app.py:41 prepared statements",
                        source_family=ModelFamily.MOCK, source_model="mock-skeptic")
    cons = pipe.score([f], {f.id: {ModelFamily.MOCK}}, {"F-9001": sk}, {}, votes, [])[0]
    assert cons.skeptic_refuted
    assert cons.tier != EvidenceTier.D  # the jury did override the refutation
    assert cons.needs_human and not cons.accepted
    assert "skeptic_refuted_jury_overrode" in cons.human_reasons


def test_tool_corroboration_yields_tier_a(mock_report):
    _, report = mock_report
    _, cons = _accepted(report)
    sqli = next(f for f in report.findings if f.cwe == "CWE-89" and f.provenance[0].line == 32)
    assert cons[sqli.id].tool_corroborated
    assert cons[sqli.id].tier == EvidenceTier.A
    assert cons[sqli.id].cvss4_severity in ("High", "Critical")


def test_tool_corroboration_respects_tool_dimensions():
    # csp-evaluator emits results without CWEs; without the dimension guard such a result would
    # corroborate any finding within +-3 lines, whatever the dimension
    from mara.pipeline import _tool_corroborates
    from mara.tools.sarif import ToolResult

    result = ToolResult(tool="csp-evaluator", rule_id="csp.test", level="error", message="weak CSP",
                        file="static/index.html", line=5, cwe=None, cwes=[])

    def finding(dim, cwe):
        return Finding(id="F-0001", dimension=dim, title="t", cwe=cwe,
                       provenance=[Provenance(file="static/index.html", line=6, quote="abc", verified=True)],
                       reachability_argument="r", exploit_sketch="e",
                       cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                       model_confidence=0.9, source_family=ModelFamily.MOCK, source_model="m",
                       finder_families=[ModelFamily.MOCK])

    assert _tool_corroborates(finding("csp", "CWE-1021"), [result])
    assert not _tool_corroborates(finding("xss", "CWE-79"), [result])


def test_multi_family_agreement_without_tool_yields_tier_b(mock_report):
    _, report = mock_report
    _, cons = _accepted(report)
    curl = next(f for f in report.findings if f.cwe == "CWE-494")
    assert not cons[curl.id].tool_corroborated
    assert cons[curl.id].tier == EvidenceTier.B


def test_gate_blocks_on_high_tier_high_severity(mock_report):
    _, report = mock_report
    assert report.gate_passed is False
    assert report.overall_score is None and report.review_status == "incomplete"


def test_bias_audit_captures_refusal_and_position_flip(mock_report):
    pipe, report = mock_report
    audit = report.bias_audit
    assert audit["reviewer_refusals"] == 1  # nemotron mock refuses error_handling
    assert audit["position_flips"] >= 1  # deepseek mock flips 'open redirect' on the reverse pass
    assert audit["standard_refs_stripped"] == 2  # ASVS V18.1 and A11:2025 do not exist (ASVS 5.0 ends at V17)
    assert audit["findings_with_unverified_quotes"] >= 1  # fake quote plus masked secret quotations
    assert isinstance(audit["global_krippendorff_alpha"], float)


def test_unstable_finding_is_not_accepted(mock_report):
    _, report = mock_report
    _, cons = _accepted(report)
    redirect = next(f for f in report.findings if f.cwe == "CWE-601")
    assert not cons[redirect.id].accepted
    assert not cons[redirect.id].position_consistent


def test_reports_render(mock_report):
    _, report = mock_report
    sarif = to_sarif(report)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "MARA"
    assert all(r["level"] in ("error", "warning", "note", "none") for r in sarif["runs"][0]["results"])
    assert all(0 <= r["rank"] <= 100 for r in sarif["runs"][0]["results"])
    md = render_markdown(report)
    assert "## Accepted findings" in md and "## Bias and integrity audit" in md


def test_tool_corroboration_matches_git_root_relative_paths(mock_report):
    """zizmor run from the repo root reports fixtures/vuln-sample/.github/workflows/deploy.yml while the
    finding says .github/workflows/deploy.yml; both must corroborate, and a leading dot must survive."""
    from mara.pipeline import _norm_path

    assert _norm_path("./.github/workflows/deploy.yml") == ".github/workflows/deploy.yml"
    _, report = mock_report
    _, cons = _accepted(report)
    gha = [f for f in report.findings if f.dimension == "github_actions" and f.provenance[0].line in (12, 15, 16)]
    assert gha and all(cons[f.id].tool_corroborated and cons[f.id].tier == EvidenceTier.A for f in gha)


def test_context_view_is_built_pinned_to_the_bundle(mock_report):
    """The L1 context agent runs once, its facts are quote-verified and recorded (assessment #19)."""
    pipe, report = mock_report
    audit = report.bias_audit
    assert audit["context_calls"] == 1 and audit["context_refusals"] == 0 and audit["canary_echoes"] == 0
    assert audit["context_view_items"] >= 3  # container, external systems, data store at minimum
    assert (pipe.out_dir / "context.json").exists()
    assert "context_view_incomplete" not in report.incomplete_reasons
    assert "context" in pipe.providers["mock-a"].calls  # the configured context role produced the view


def test_incremental_review_limits_the_bundle_to_changed_files_and_import_neighbours(tmp_path):
    import subprocess

    from mara.context.repo_map import build_context, restrict_to_increment

    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)

    git("init")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "test")
    (repo / "lib.py").write_text("def helper():\n    return 1\n")
    (repo / "app.py").write_text("import lib\n\nunsafe()\n")
    (repo / "notes.md").write_text("documentation only\n")
    git("add", "-A")
    git("commit", "-m", "init")
    (repo / "app.py").write_text("import lib\n\nvery_unsafe()\n")
    git("add", "-A")
    git("commit", "-m", "touch app only")

    ctx = build_context(repo)
    before = ctx.content_hash
    changed, related = restrict_to_increment(ctx, "HEAD~1")
    assert changed == ["app.py"] and related == ["lib.py"]  # the import neighbour stays in the bundle
    assert ctx.excluded.get("notes.md") == "out_of_increment" and "notes.md" not in ctx.content
    assert ctx.content_hash != before and ctx.changed == changed and ctx.related == related
    assert not ctx.omitted

    # an unresolvable base ref is a usage error, never an empty 'nothing changed'
    with pytest.raises(ValueError):
        restrict_to_increment(build_context(repo), "no-such-ref")


def _git_repo(repo, files):
    import subprocess

    repo.mkdir()

    def git(*args):
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@example.com", "-c", "user.name=t", *args], check=True, capture_output=True)

    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    git("init", "-q")
    git("add", "-A")
    git("commit", "-q", "-m", "init")
    return git


def test_incremental_review_finds_importers_of_a_changed_submodule(tmp_path):
    """`from app import models` and `from . import models` import the module app.models, but only `app`
    was recorded, so changing app/models.py left both callers out of the increment."""
    from mara.context.repo_map import build_context, restrict_to_increment

    repo = tmp_path / "repo"
    git = _git_repo(repo, {
        "app/__init__.py": "", "app/models.py": "class Order:\n    pass\n",
        "app/views.py": "from app import models\n\nmodels.Order()\n",
        "app/admin.py": "from . import models as m\n",
        "app/api.py": "from app import (\n    helpers,\n    models,\n)\n",
        "app/helpers.py": "def h():\n    return 1\n",
        "app/unrelated.py": "from app import helpers\n",
    })
    (repo / "app" / "models.py").write_text("class Order:\n    owner = None\n")
    git("commit", "-q", "-am", "change models")
    ctx = build_context(repo)
    changed, related = restrict_to_increment(ctx, "HEAD~1")
    assert changed == ["app/models.py"]
    assert {"app/views.py", "app/admin.py", "app/api.py"} <= set(related)
    assert ctx.excluded.get("app/unrelated.py") == "out_of_increment"


def test_a_deleted_file_does_not_make_every_incremental_review_incomplete(tmp_path):
    from mara.context.repo_map import build_context, restrict_to_increment

    repo = tmp_path / "repo"
    git = _git_repo(repo, {"app.py": "import legacy\n", "legacy.py": "def old():\n    pass\n"})
    (repo / "app.py").write_text("print('no legacy')\n")
    git("rm", "-q", "legacy.py")
    git("commit", "-q", "-am", "drop legacy")
    ctx = build_context(repo)
    changed, _ = restrict_to_increment(ctx, "HEAD~1")
    assert changed == ["app.py"] and ctx.deleted == ["legacy.py"]
    assert not ctx.omitted and ctx.complete and ctx.coverage()["deleted"] == ["legacy.py"]
