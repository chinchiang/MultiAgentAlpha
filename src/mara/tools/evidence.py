"""Tool evidence (GLOSSARY.md: tool evidence, required tool, tool alert, corroboration): what the deterministic tools
reported on one review's target, and the rules that read it - which tools ran, whether the review's required tools
did, which results are alerts and which finding an alert corroborates. Pure: the pipeline runs the tools, and decides
from the gitleaks runs whether source may leave the host (mara.review_status.secret_preflight,
docs/adr/0007-review-status-and-gate.md)."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from ..identity import NEAR_LINES, norm_cwe, norm_path
from ..schemas import Finding
from .runner import TOOL_DIMENSIONS, ToolRun
from .sarif import ToolResult

ALERT_LEVELS = ("error", "warning")


def is_alert(level: str | None) -> bool:
    """A result at level error or warning is a tool alert; a note is information, and so is a report's result without
    a level."""
    return level in ALERT_LEVELS


def scans(tool: str, dimension: str) -> bool:
    """Whether `tool` scans for findings in `dimension` (TOOL_DIMENSIONS)."""
    return dimension in TOOL_DIMENSIONS.get(tool, [])


def required_tools(dimensions: Iterable[str]) -> frozenset[str]:
    """The tools that scan at least one of `dimensions`."""
    wanted = set(dimensions)
    return frozenset(t for t in TOOL_DIMENSIONS if any(scans(t, d) for d in wanted))


@dataclass(frozen=True)
class ToolEvidence:
    """Every tool run of one review, the live secret preflight's gitleaks in place of a pre-recorded one; the results
    and the tools that ran are read from the runs."""

    runs: list[ToolRun]

    @property
    def results(self) -> list[ToolResult]:
        """Every run's results, those of a scan that did not complete (`scanner_incomplete`) included."""
        return [r for run in self.runs for r in run.results]

    @property
    def ran(self) -> frozenset[str]:
        """The tools whose run completed."""
        return frozenset(run.tool for run in self.runs if run.ran)

    def ran_for(self, dimension: str) -> bool:
        """Whether a tool that scans `dimension` ran; without one the dimension has no tier A."""
        return any(scans(t, dimension) for t in self.ran)

    def complete_for(self, dimensions: Iterable[str]) -> bool:
        """Whether every required tool of a review of `dimensions` ran and no run failed: stricter than a required tool
        (GLOSSARY.md), since a failed run of a tool no dimension needs counts too (a follow-up of the tool evidence rework)."""
        return required_tools(dimensions) <= self.ran and all(r.ran for r in self.runs)

    def runs_of(self, tool: str) -> list[ToolRun]:
        """The runs of `tool`, in order."""
        return [r for r in self.runs if r.tool == tool]


def corroborates(f: Finding, tool_results: list[ToolResult], prefix: str = "") -> bool:
    """A tool result corroborates a finding (tier A) only on the same file, within +-3 lines, with a
    matching CWE (or none), from a tool that scans the finding's dimension, at level error or
    warning - the levels that also block as unresolved tool findings; a note is information.

    Same file means the exact path. Tools that ran from the repository top level report paths
    below it (pre-recorded zizmor: fixtures/vuln-sample/.github/workflows/deploy.yml), so a path
    that is exactly `prefix/<finding path>` also matches, prefix being the target's own path below
    the top level. A bare suffix match did not: `main.py` matched `services/billing/main.py`, and a
    tool hit in another file promoted a single-family finding to tier A."""
    for t in tool_results:
        # a tool only corroborates findings in the dimensions it scans for (TOOL_DIMENSIONS):
        # csp-evaluator emits results without CWEs, and without this guard any such result would
        # corroborate any finding that happens to sit within +-3 lines
        if not scans(t.tool, f.dimension) or not is_alert(t.level):
            continue
        tf = norm_path(t.file)
        for p in f.provenance:
            pf = norm_path(p.file)
            same_file = tf == pf or (bool(prefix) and tf == f"{prefix}/{pf}")
            if same_file and abs(t.line - p.line) <= NEAR_LINES:
                cwes = {norm_cwe(c) for c in (t.cwes or ([t.cwe] if t.cwe else []))}
                if not cwes or norm_cwe(f.cwe) in cwes:
                    return True
    return False
