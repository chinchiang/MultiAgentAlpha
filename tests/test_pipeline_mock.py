"""End-to-end run on the seeded fixture with three mock families."""

from mara.report.markdown_out import render_markdown
from mara.report.sarif_out import to_sarif
from mara.schemas import EvidenceTier

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


def test_tool_corroboration_yields_tier_a(mock_report):
    _, report = mock_report
    _, cons = _accepted(report)
    sqli = next(f for f in report.findings if f.cwe == "CWE-89" and f.provenance[0].line == 32)
    assert cons[sqli.id].tool_corroborated
    assert cons[sqli.id].tier == EvidenceTier.A
    assert cons[sqli.id].cvss4_severity in ("High", "Critical")


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
    assert audit["standard_refs_stripped"] == 2  # ASVS V17.1 and A11:2025 do not exist
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
