"""Consensus rows as jury scoring writes them (mara.scoring.jury), one per named state: each is scored from a finding, the
votes the ballot round would collect on it and, for tier A, a tool result, so a test that reads a row's fields gets a
state scoring produces (the hand-written rows these replace claimed so and were not). The finder is anthropic, so the
mock jury's other two families judge it; the rejected states need FOUR_JUDGES, since the mock jury, three judge families
that also review, can reject no finding (docs/adr/0005-jury-outcome.md)."""

from __future__ import annotations

from pathlib import Path

from mara.ballot_round import Ballots
from mara.config import MaraConfig, load_config
from mara.schemas import ConsensusResult, Finding, JudgeVote, ModelFamily, Provenance, SkepticVerdict
from mara.scoring import jury
from mara.scoring.outcome import OutcomePolicy
from mara.tools.sarif import ToolResult

ROOT = Path(__file__).resolve().parents[1]
MOCK = load_config(ROOT / "config" / "mara.mock.yaml")

VECTORS = {"Medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",  # CVSS 6.9
           "High": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",  # CVSS 8.7
           "Critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}  # CVSS 9.3

FINDER = ModelFamily.ANTHROPIC

# each state: the judges' verdicts by family (both passes alike), and what else sets it apart
STATES: dict[str, dict] = {
    # two independent families confirm it: tier B, accepted
    "accepted": {"verdicts": {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "true_positive"}},
    # both call it a false positive: no family agrees, tier D, dropped
    "dropped": {"verdicts": {ModelFamily.DEEPSEEK: "false_positive", ModelFamily.NEMOTRON: "false_positive"}},
    # the skeptic refuted it and the jury did not carry it: tier D, dropped
    "refuted": {"verdicts": {ModelFamily.DEEPSEEK: "false_positive", ModelFamily.NEMOTRON: "false_positive"}, "refuted": True},
    # confirmed, but its quote was not found in the file: tier D, needs a human
    "unverified": {"verdicts": {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "true_positive"}, "verified": False},
    # confirmed, but its reachability went unargued: tier C, which needs a human at or above the tier C floor
    "tier_c": {"verdicts": {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "true_positive"}, "reachability": "unknown"},
    # both send it to a human
    "all_needs_human": {"verdicts": {ModelFamily.DEEPSEEK: "needs_human", ModelFamily.NEMOTRON: "needs_human"}},
    # the two split: agreement 0.25, below the alpha threshold, so a human decides
    "split": {"verdicts": {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "false_positive"}},
    # a tool corroborates it and one of three independent families confirms it: tier A, agreement 0.5, not accepted -
    # rejected, or under rejection review while policy P8 does not allow unsupervised rejection
    "rejected": {"verdicts": {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "false_positive",
                              ModelFamily.MISTRAL: "false_positive"}, "tool": True, "four_judges": True},
}


def four_judges(cfg: MaraConfig = MOCK) -> MaraConfig:
    """`cfg` with a fourth judge family (mistral) that does not review, the smallest change to the mock panel that lets
    the jury reject a finding."""
    raw = cfg.model_dump(mode="json")
    raw["models"].append({"name": "mock-m", "family": "mistral", "provider": "mock", "model": "mock-mistral",
                          "data_residency": "on_prem"})
    raw["roles"]["judges"].append("mock-m")
    return MaraConfig.model_validate(raw, context={"skip_policies": True})


FOUR_JUDGES = four_judges()


def policy(cfg: MaraConfig = MOCK, *, exclude_tier_c: bool = False) -> OutcomePolicy:
    """The outcome policy `cfg` gives with the human queue not tightened (or with tier C excluded, as tightening does)."""
    return OutcomePolicy.from_config(cfg, alpha_threshold=cfg.gate.human_threshold_alpha, exclude_tier_c=exclude_tier_c)


def finding(fid: str = "F-1", *, severity: str = "High", reachability: str = "reachable", verified: bool = True) -> Finding:
    return Finding(id=fid, dimension="vulnerabilities", title=f"SQL injection {fid}", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=1, quote="unsafe()", verified=verified)], reachability=reachability,
                   reachability_argument="r", exploit_sketch="e", cvss4_vector=VECTORS[severity], model_confidence=0.9,
                   source_family=FINDER, source_model="m", finder_families=[FINDER])


def votes(fid: str, verdicts: dict[ModelFamily, str]) -> list[JudgeVote]:
    """Each family's verdict on `fid` in both passes."""
    return [JudgeVote(finding_id=fid, verdict=verdict, severity_band="High", reason="r", judge_family=fam, judge_model="m",
                      presentation_order=0, pass_id=pass_id) for fam, verdict in verdicts.items() for pass_id in ("forward", "reverse")]


def row(state: str, fid: str = "F-1", *, outcome_policy: OutcomePolicy | None = None, severity: str = "High") -> ConsensusResult:
    """The consensus row jury scoring writes for a finding `fid` in `state` (one of STATES), at `severity`, under
    `outcome_policy` (the mock config's, or the four-judge panel's for the rejected states, by default)."""
    s = STATES[state]
    cfg = FOUR_JUDGES if s.get("four_judges") else MOCK
    f = finding(fid, severity=severity, reachability=s.get("reachability", "reachable"), verified=s.get("verified", True))
    skeptic = {fid: SkepticVerdict(finding_id=fid, verdict="refuted", reason="r", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON,
                                   source_model="m")} if s.get("refuted") else {}
    tools = [ToolResult("semgrep", "sql", "error", "SQL injection", "app.py", 1, "CWE-89")] if s.get("tool") else []
    ballots = Ballots(skeptic=skeptic, unchallenged=frozenset(), redteam={}, votes=votes(fid, s["verdicts"]))
    (r,) = jury.score([f], {fid: {FINDER}}, ballots, tools, jury=jury.Jury.from_config(cfg),
                      policy=outcome_policy or policy(cfg)).rows
    return r


def tool_corroborated(f: Finding, tool_results: list[ToolResult], tool_path_prefix: str = "") -> bool:
    """Whether jury scoring counts `tool_results` as corroborating `f`, unvoted, on the mock jury."""
    (r,) = jury.score([f], {f.id: {f.source_family}}, Ballots(skeptic={}, unchallenged=frozenset(), redteam={}, votes=[]), tool_results,
                      jury=jury.Jury.from_config(MOCK), policy=policy(), tool_path_prefix=tool_path_prefix).rows
    return r.tool_corroborated
