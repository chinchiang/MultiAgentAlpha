"""Consensus rows as jury scoring writes them (mara.scoring.jury), one per named state: each is scored from a finding, the
votes the ballot round would collect on it and, for tier A, a tool result, so a test that reads a row's fields gets a
state scoring produces (the hand-written rows these replace claimed so and were not). The finder is anthropic, so the
mock panel's other two judge families vote on it; the rejected states need FOUR_JUDGE_PANEL, since the mock panel, whose three
judge families also review, can reject no finding (docs/adr/0005-jury-outcome.md)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mara.ballot_round import Ballots
from mara.config import MaraConfig, load_config
from mara.schemas import ConsensusResult, Finding, JudgeVote, ModelFamily, Provenance, RedTeamNote, SkepticVerdict
from mara.scoring import jury
from mara.scoring.outcome import OutcomePolicy
from mara.tools.sarif import ToolResult

ROOT = Path(__file__).resolve().parents[1]
MOCK = load_config(ROOT / "config" / "mara.mock.yaml")

VECTORS = {"Medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",  # CVSS 6.9
           "High": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",  # CVSS 8.7
           "Critical": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}  # CVSS 9.3

FINDER = ModelFamily.ANTHROPIC


@dataclass(frozen=True)
class State:
    """What sets one named state apart: the judges' verdicts by family (both passes alike) and the rest of its evidence."""

    verdicts: dict[ModelFamily, str]
    refuted: bool = False  # the skeptic refuted it
    verified: bool = True  # its quote was found in the file
    reachability: str = "reachable"
    tool: bool = False  # a tool result corroborates it
    four_judge_panel: bool = False  # scored on FOUR_JUDGE_PANEL


CONFIRMED = {ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "true_positive"}
REFUTED = {ModelFamily.DEEPSEEK: "false_positive", ModelFamily.NEMOTRON: "false_positive"}
STATES: dict[str, State] = {
    # two independent families confirm it: tier B, accepted
    "accepted": State(CONFIRMED),
    # both call it a false positive: no family agrees, tier D, dropped
    "dropped": State(REFUTED),
    # the skeptic refuted it and the jury did not carry it: tier D, dropped
    "refuted": State(REFUTED, refuted=True),
    # confirmed, but its quote was not found in the file: tier D, needs a human
    "unverified": State(CONFIRMED, verified=False),
    # confirmed, but its reachability went unargued: tier C, which needs a human at or above the tier C floor
    "tier_c": State(CONFIRMED, reachability="unknown"),
    # both send it to a human
    "all_needs_human": State({ModelFamily.DEEPSEEK: "needs_human", ModelFamily.NEMOTRON: "needs_human"}),
    # the two split: agreement 0.25, below the alpha threshold, so a human decides
    "split": State({ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "false_positive"}),
    # a tool corroborates it and one of three independent families confirms it: tier A, agreement 0.5, not accepted -
    # rejected, or under rejection review while policy P8 does not allow unsupervised rejection
    "rejected": State({ModelFamily.DEEPSEEK: "true_positive", ModelFamily.NEMOTRON: "false_positive", ModelFamily.MISTRAL: "false_positive"},
                      tool=True, four_judge_panel=True),
}


def four_judge_panel(cfg: MaraConfig = MOCK) -> MaraConfig:
    """`cfg` with a fourth judge family (mistral) that does not review, the smallest change to the mock panel that lets
    the jury reject a finding."""
    raw = cfg.model_dump(mode="json")
    raw["models"].append({"name": "mock-m", "family": "mistral", "provider": "mock", "model": "mock-mistral",
                          "data_residency": "on_prem"})
    raw["roles"]["judges"].append("mock-m")
    return MaraConfig.model_validate(raw, context={"skip_policies": True})


FOUR_JUDGE_PANEL = four_judge_panel()


def policy(cfg: MaraConfig = MOCK, *, exclude_tier_c: bool = False) -> OutcomePolicy:
    """The outcome policy `cfg` gives with the human queue not tightened (or with tier C excluded, as tightening does)."""
    return OutcomePolicy.from_config(cfg, alpha_threshold=cfg.gate.human_threshold_alpha, exclude_tier_c=exclude_tier_c)


def score(findings: list[Finding], finders: dict[str, set[ModelFamily]], votes: list[JudgeVote], *, cfg: MaraConfig = MOCK,
          outcome_policy: OutcomePolicy | None = None, skeptic: dict[str, SkepticVerdict] | None = None,
          redteam: dict[str, RedTeamNote] | None = None, tool_results: list[ToolResult] | None = None,
          tool_path_prefix: str = "") -> jury.JuryScoring:
    """Jury scoring of `findings` on `votes` (and the skeptic's verdicts, the red team's notes and tool results, when
    given) by `cfg`'s jury, under `outcome_policy` (the one `cfg` gives untightened by default)."""
    ballots = Ballots(skeptic=skeptic or {}, unchallenged=frozenset(), redteam=redteam or {}, votes=votes)
    return jury.score(findings, finders, ballots, tool_results or [], jury=jury.Jury.from_config(cfg),
                      policy=outcome_policy or policy(cfg), tool_path_prefix=tool_path_prefix)


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
    skeptic = {fid: SkepticVerdict(finding_id=fid, verdict="refuted", reason="r", sanitizer_or_control="", source_family=ModelFamily.NEMOTRON,
                                   source_model="m")} if s.refuted else None
    tools = [ToolResult("semgrep", "sql", "error", "SQL injection", "app.py", 1, "CWE-89")] if s.tool else None
    (r,) = score([finding(fid, severity=severity, reachability=s.reachability, verified=s.verified)], {fid: {FINDER}}, votes(fid, s.verdicts),
                 cfg=FOUR_JUDGE_PANEL if s.four_judge_panel else MOCK, outcome_policy=outcome_policy, skeptic=skeptic, tool_results=tools).rows
    return r


def tool_corroborated(f: Finding, tool_results: list[ToolResult], tool_path_prefix: str = "") -> bool:
    """Whether jury scoring counts `tool_results` as corroborating `f`, unvoted, on the mock panel."""
    (r,) = score([f], {f.id: {f.source_family}}, [], tool_results=tool_results, tool_path_prefix=tool_path_prefix).rows
    return r.tool_corroborated
