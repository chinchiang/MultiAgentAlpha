import pytest

from mara.bias.blinding import blind_finding, blinded_batches
from mara.config import MaraConfig
from mara.schemas import EvidenceTier, Finding, JudgeVote, ModelFamily, Provenance
from mara.scoring.consensus import krippendorff_alpha_nominal, weighted_consensus
from mara.scoring.idcheck import check_finding_refs
from mara.scoring.tiers import assign_tier, ssvc_decision
from tests import scored_rows


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
                   {"name": "d", "family": "deepseek", "provider": "openai_compatible", "model": "x", "base_url": "https://x", "data_residency": "on_prem"}],
        "roles": {"reviewers": ["a", "d"], "skeptic": "d", "redteam": "d", "judges": ["a", "d"]},
    }
    with pytest.raises(ValueError, match="data_residency"):
        MaraConfig.model_validate(bad)


def test_idcheck_strips_nonexistent_refs():
    ref = check_finding_refs(_finding(refs=["ASVS 5.0 V1", "ASVS 5.0 V18", "OWASP A01:2025", "NIST 800-53 AC-3"]))
    assert ref.finding.standard_refs == ["ASVS 5.0 V1", "OWASP A01:2025"]
    assert ref.stripped == ["ASVS 5.0 V18", "NIST 800-53 AC-3"]
    assert not ref.unknown_cwe


def _scoring(findings, votes):
    """Jury scoring of `findings`, found by anthropic, on `votes` and no other ballot, on the mock panel."""
    return scored_rows.score(scored_rows.found_by(findings, ModelFamily.ANTHROPIC), votes)


def _both_passes(fid, fam, verdict, reverse=None):
    return [JudgeVote(finding_id=fid, verdict=v, severity_band="High", reason="r", judge_family=fam, judge_model="m",
                      presentation_order=0, pass_id=pass_id) for pass_id, v in (("forward", verdict), ("reverse", reverse or verdict))]


def test_agreement_proxy_is_undefined_for_a_single_rater_family():
    # one family voting consistently is not "perfect agreement": quorum still gates the finding
    def proxy(votes):
        return _scoring([_finding()], votes).rows[0].agreement_proxy

    assert proxy(_both_passes("F-0001", ModelFamily.DEEPSEEK, "true_positive")) is None
    assert proxy(_both_passes("F-0001", ModelFamily.DEEPSEEK, "true_positive", reverse="false_positive")) is None
    two = _both_passes("F-0001", ModelFamily.DEEPSEEK, "true_positive") + _both_passes("F-0001", ModelFamily.NEMOTRON, "true_positive")
    assert proxy(two) == 1.0


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
    assert krippendorff_alpha_nominal({"a": ["x", "y"], "b": ["y", "x"]}) == -0.5
    # no variation at all: alpha is undefined (0/0), not perfect agreement
    assert krippendorff_alpha_nominal({"a": ["x", "x"], "b": ["x", "x"]}) is None


def test_corpus_alpha_counts_each_family_once_not_once_per_pass():
    """Two self-consistent families that always disagree: alpha is -0.5. Fed both passes of each family
    as separate raters it read -0.17, a family's agreement with itself counted as inter-family agreement."""
    fs = [_finding(1), _finding(2)]
    votes = [v for f in fs for v in _both_passes(f.id, ModelFamily.DEEPSEEK, "true_positive") + _both_passes(f.id, ModelFamily.NEMOTRON, "false_positive")]
    assert _scoring(fs, votes).global_alpha == -0.5
    # and each pair of families' agreement, which calibration reads back from the audit (judge_agreement[a~b])
    assert _scoring(fs, votes).family_agreement == {"deepseek~nemotron": 0.0}
    assert krippendorff_alpha_nominal({f.id: [x.verdict for x in votes if x.finding_id == f.id] for f in fs}) == -0.1667
    # a family whose two passes disagree has no single label for that finding: nemotron's split passes on F-0001 leave
    # deepseek's label alone there (alpha 0.0); kept as nemotron's forward label alpha would read -0.25, as its
    # reverse one 0.4444
    fs = [_finding(1), _finding(2), _finding(3)]
    split = (_both_passes("F-0001", ModelFamily.DEEPSEEK, "true_positive")
             + _both_passes("F-0001", ModelFamily.NEMOTRON, "false_positive", reverse="true_positive")
             + _both_passes("F-0002", ModelFamily.DEEPSEEK, "true_positive") + _both_passes("F-0002", ModelFamily.NEMOTRON, "false_positive")
             + _both_passes("F-0003", ModelFamily.DEEPSEEK, "false_positive") + _both_passes("F-0003", ModelFamily.NEMOTRON, "false_positive"))
    assert _scoring(fs, split).global_alpha == 0.0


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
