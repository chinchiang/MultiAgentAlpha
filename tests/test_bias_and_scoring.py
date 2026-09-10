import pytest

from mara.bias.blinding import blind_finding, blinded_batches
from mara.config import MaraConfig
from mara.schemas import EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance
from mara.scoring.consensus import krippendorff_alpha_nominal, weighted_consensus
from mara.scoring.idcheck import check_finding_refs
from mara.scoring.tiers import assign_tier, ssvc_decision


def _finding(i=1, fam=ModelFamily.ANTHROPIC, refs=None):
    return Finding(
        id=f"F-{i:04d}", dimension="xss", title="Reflected XSS " + "x" * 100, cwe="CWE-79",
        standard_refs=refs or ["OWASP A05:2025"],
        provenance=[Provenance(file="app.py", line=26, quote="return render_template_string(", verified=True)],
        reachability="reachable", reachability_argument="public route " * 45, exploit_sketch="craft q", 
        cvss4_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", model_confidence=0.99,
        source_family=fam, source_model="m",
    )


def test_blinding_strips_identity_and_scores_and_clips_length():
    view = blind_finding(_finding(), None)
    assert "source_family" not in view and "model_confidence" not in view and "cvss" not in str(view).lower()
    assert len(view["claim"]) <= 120 and len(view["reachability_argument"]) <= 300 < 45 * 13


def test_reverse_pass_is_exact_mirror_and_seeded_order_is_deterministic():
    fs = [_finding(i) for i in range(1, 8)]
    f1, r1 = blinded_batches(fs, {}, "seed")
    f2, _ = blinded_batches(fs, {}, "seed")
    assert [x["finding_id"] for x in r1] == list(reversed([x["finding_id"] for x in f1]))
    assert [x["finding_id"] for x in f1] == [x["finding_id"] for x in f2]
    assert [x["finding_id"] for x in f1] != [f.id for f in fs]  # emission order does not leak


def test_config_rejects_single_family_panel():
    bad = {
        "models": [{"name": "a", "family": "anthropic", "provider": "mock", "model": "x", "data_residency": "on_prem"},
                   {"name": "b", "family": "anthropic", "provider": "mock", "model": "y", "data_residency": "on_prem"}],
        "roles": {"reviewers": ["a", "b"], "skeptic": "a", "redteam": "b", "judges": ["a", "b"]},
    }
    with pytest.raises(ValueError, match="family"):
        MaraConfig.model_validate(bad)


def test_config_refuses_source_code_to_vendor_api_without_zdr():
    bad = {
        "models": [{"name": "a", "family": "anthropic", "provider": "anthropic", "model": "claude-opus-5", "data_residency": "vendor_api_30d"},
                   {"name": "d", "family": "deepseek", "provider": "openai_compatible", "model": "x", "base_url": "http://x", "data_residency": "on_prem"}],
        "roles": {"reviewers": ["a", "d"], "skeptic": "d", "redteam": "d", "judges": ["a", "d"]},
    }
    with pytest.raises(ValueError, match="data_residency"):
        MaraConfig.model_validate(bad)


def test_idcheck_strips_nonexistent_refs():
    f, reasons = check_finding_refs(_finding(refs=["ASVS 5.0 V1", "ASVS 5.0 V17", "OWASP A01:2025", "NIST 800-53 AC-3"]))
    assert f.standard_refs == ["ASVS 5.0 V1", "OWASP A01:2025"]
    assert len(reasons) == 2


def _vote(fam, verdict, pass_id, self_family=False):
    return JudgeVote(finding_id="F-0001", verdict=verdict, severity_band="High", reason="r", judge_family=fam,
                     judge_model="m", presentation_order=0, pass_id=pass_id, self_family=self_family)


def test_weighted_consensus_penalises_position_flip_and_self_votes():
    stable = [_vote(ModelFamily.DEEPSEEK, "true_positive", "forward"), _vote(ModelFamily.DEEPSEEK, "true_positive", "reverse")]
    flip = [_vote(ModelFamily.NEMOTRON, "true_positive", "forward"), _vote(ModelFamily.NEMOTRON, "false_positive", "reverse")]
    s1, *_, consistent1 = weighted_consensus(stable, {})
    s2, *_, consistent2 = weighted_consensus(stable + flip, {})
    assert s1 == 1.0 and consistent1
    assert s2 == 0.75 and not consistent2
    selfv = [_vote(ModelFamily.ANTHROPIC, "true_positive", "forward", True), _vote(ModelFamily.ANTHROPIC, "true_positive", "reverse", True)]
    other = [_vote(ModelFamily.DEEPSEEK, "false_positive", "forward"), _vote(ModelFamily.DEEPSEEK, "false_positive", "reverse")]
    s3, *_ = weighted_consensus(selfv + other, {}, self_judge_discount=0.5)
    assert s3 == pytest.approx(1 / 3, abs=1e-3)  # self vote worth half of an independent one


def test_krippendorff_alpha_known_values():
    assert krippendorff_alpha_nominal({"a": ["x", "x"], "b": ["y", "y"], "c": ["x", "x"]}) == 1.0
    assert krippendorff_alpha_nominal({"a": ["x", "y"], "b": ["y", "x"]}) < 0
    assert krippendorff_alpha_nominal({"a": ["x"]}) is None


def test_tier_rules():
    common = dict(reachability="reachable", consensus_score=0.9, accept_threshold=0.6, skeptic_refuted=False)
    assert assign_tier(provenance_verified=False, tool_corroborated=True, families_agreeing=[ModelFamily.ANTHROPIC], **common) == EvidenceTier.D
    assert assign_tier(provenance_verified=True, tool_corroborated=True, families_agreeing=[ModelFamily.ANTHROPIC, ModelFamily.TOOL], **common) == EvidenceTier.A
    assert assign_tier(provenance_verified=True, tool_corroborated=False, families_agreeing=[ModelFamily.ANTHROPIC, ModelFamily.DEEPSEEK], **common) == EvidenceTier.B
    assert assign_tier(provenance_verified=True, tool_corroborated=False, families_agreeing=[ModelFamily.ANTHROPIC], **common) == EvidenceTier.C
    assert assign_tier(provenance_verified=True, tool_corroborated=False, families_agreeing=[], reachability="reachable", consensus_score=0.2, accept_threshold=0.6, skeptic_refuted=True) == EvidenceTier.D


def test_ssvc_decisions():
    assert ssvc_decision(severity="Critical", exploitable="yes", tier=EvidenceTier.A) == "Act"
    assert ssvc_decision(severity="High", exploitable="conditional", tier=EvidenceTier.B) == "Attend"
    assert ssvc_decision(severity="High", exploitable="no", tier=EvidenceTier.B) == "Track*"
    assert ssvc_decision(severity="Critical", exploitable="yes", tier=EvidenceTier.D) == "Track"
