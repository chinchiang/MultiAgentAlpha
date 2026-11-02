"""The records of one finding (GLOSSARY.md: Bias audit; docs/adr/0005-jury-outcome.md): a report holds them in lists, the
consensus rows, the skeptic's verdicts, the red team's notes, the judges' votes and the human queue, each row naming its
finding by `finding_id`. The review writes one consensus row per finding (`JuryScoring`), the skeptic, the red team and the
judges do not rule on every finding, and a report is read back by what is in it, so a reader asks the report for a finding's
row and treats a finding that has none as one that has none: `ReviewReport.consensus_by_id()` and its siblings hold no key
for it, and each reader decides what that means (the page lists the finding without a ruling; the Markdown and SARIF reports,
the PSIRT selection, the dimension scores and the human queue leave it out).

The cases of the last group describe how the readers treated a finding without a row before they shared the lookups (marked
"characterization"): they passed on their first run and hold the refactor to it."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mara.config import MaraConfig
from mara.human_queue import build_queue
from mara.report.markdown_out import render_markdown
from mara.report.psirt_out import select_psirt_findings
from mara.report.sarif_out import to_sarif
from mara.scoring.dimension_score import score_dimension
from mara.scoring.jury import JuryScoring
from mara.web import views

ROOT = Path(__file__).resolve().parents[1]
LOOKUPS = [("consensus_by_id", "consensus"), ("skeptic_by_id", "skeptic"), ("redteam_by_id", "redteam"), ("queue_by_id", "human_queue")]


def _psirt_cfg() -> MaraConfig:
    raw = yaml.safe_load((ROOT / "config" / "mara.mock.yaml").read_text(encoding="utf-8"))
    raw["psirt"] = {"enabled": True, "webhook_url": "https://psirt.example.internal/intake", "product": "IPC-7000", "shipped": True}
    return MaraConfig.model_validate(raw)


@pytest.fixture(scope="module")
def case(mock_report):
    """A copy of the mock review's report with rows accepted as the PSIRT tests accept them, the ids of five findings, and
    the report without a consensus row for two of them (one accepted, one in the human queue), without a skeptic verdict for
    a third, a red-team note for a fourth and any vote for a fifth."""
    cfg = _psirt_cfg()
    report = mock_report[1].model_copy(deep=True)
    count = 0
    for c in report.consensus:
        if c.tier.value == "A" and c.cvss4_severity == "Critical" and count < 3:
            c.accepted, c.needs_human, c.human_reasons = True, False, []
            count += 1
        elif c.tier.value == "B":
            c.accepted, c.needs_human, c.human_reasons = True, False, []
    x = next(f.id for f, _, _ in select_psirt_findings(report, cfg))
    sk, rt = {v.finding_id: v for v in report.skeptic}, {n.finding_id: n for n in report.redteam}
    queue = build_queue(report.findings, {c.finding_id: c for c in report.consensus}, sk, rt, list(report.votes), cfg)
    q = queue[0].finding_id
    y = next(v.finding_id for v in report.skeptic if v.finding_id not in (x, q))
    z = next(n.finding_id for n in report.redteam if n.finding_id not in (x, q, y))
    w = next(v.finding_id for v in report.votes if v.finding_id not in (x, q, y, z))
    degraded = report.model_copy(update={
        "consensus": [c for c in report.consensus if c.finding_id not in (x, q)], "skeptic": [v for v in report.skeptic if v.finding_id != y],
        "redteam": [n for n in report.redteam if n.finding_id != z], "votes": [v for v in report.votes if v.finding_id != w]})
    return {"cfg": cfg, "report": report, "degraded": degraded, "x": x, "q": q, "y": y, "z": z, "w": w}


@pytest.mark.parametrize(("lookup", "field"), LOOKUPS)
def test_a_lookup_of_a_report_holds_each_row_under_its_finding_and_no_key_for_a_finding_without_one(case, lookup, field):
    report, degraded = case["report"], case["degraded"]
    found = getattr(report, lookup)()
    rows = getattr(report, field)
    assert list(found) == [r.finding_id for r in rows]
    assert all(found[r.finding_id] is r for r in rows), "the rows themselves, not copies"
    reduced = getattr(degraded, lookup)()
    assert set(reduced) == {r.finding_id for r in getattr(degraded, field)}, "no key for a finding without a row"
    assert (set(reduced) < set(found)) == (len(getattr(degraded, field)) < len(rows))


def test_the_votes_of_a_report_are_grouped_under_their_finding_in_the_order_they_were_cast(case):
    report, degraded = case["report"], case["degraded"]
    grouped = report.votes_by_id()
    assert set(grouped) == {v.finding_id for v in report.votes}
    for finding_id, votes in grouped.items():
        assert votes == [v for v in report.votes if v.finding_id == finding_id]
        assert all(a is b for a, b in zip(votes, [v for v in report.votes if v.finding_id == finding_id], strict=True))
    assert case["w"] in grouped and case["w"] not in degraded.votes_by_id()


def test_a_lookup_follows_the_lists_of_the_report_as_they_are_now(case):
    """`assemble` sets the report's human queue after it has built the report: a lookup is not remembered."""
    report = case["report"].model_copy(deep=True)
    assert report.queue_by_id() or not report.human_queue
    report.human_queue = []
    report.consensus = report.consensus[:1]
    assert report.queue_by_id() == {} and list(report.consensus_by_id()) == [report.consensus[0].finding_id]


def test_the_consensus_rows_of_a_scoring_are_found_by_finding_and_are_the_rows_the_decisions_are_recorded_on(case):
    rows = case["report"].consensus
    scoring = JuryScoring(rows=rows, position_flips=0, global_alpha=None, family_agreement={})
    found = scoring.rows_by_id()
    assert list(found) == [c.finding_id for c in rows] and all(found[c.finding_id] is c for c in rows)


def _page_row(report, finding_id):
    return next(f for f in views.report_view({}, report, None)["findings"] if f["id"] == finding_id)


def test_the_page_shows_no_severity_for_a_finding_without_a_consensus_row(case):
    """The string "None" is a CVSS severity a ruled finding can have; a finding nobody ruled on has no severity at all."""
    row = _page_row(case["degraded"], case["x"])
    assert row["severity"] is None and row["consensus"] is None
    assert _page_row(case["degraded"], case["q"])["severity"] is None
    others = {f["id"]: f["severity"] for f in views.report_view({}, case["degraded"], None)["findings"]}
    full = {f["id"]: f["severity"] for f in views.report_view({}, case["report"], None)["findings"]}
    assert {k: v for k, v in others.items() if k not in (case["x"], case["q"])} == {k: v for k, v in full.items() if k not in (case["x"], case["q"])}


# characterization: the readers as they were before they shared the lookups. These pass on their first run.


def test_characterization_a_cvss_severity_of_none_is_still_the_string_none(case):
    report = case["report"].model_copy(deep=True)
    report.consensus = [c.model_copy(update={"cvss4_severity": "None"}) if c.finding_id == case["x"] else c for c in report.consensus]
    row = _page_row(report, case["x"])
    assert row["severity"] == "None" and row["consensus"] is not None


def test_characterization_the_page_lists_a_finding_without_rows_and_shows_what_it_has_of_them(case):
    degraded = case["degraded"]
    shown = views.report_view({}, degraded, None)["findings"]
    assert sorted(f["id"] for f in shown) == sorted(f["id"] for f in views.report_view({}, case["report"], None)["findings"])
    assert _page_row(degraded, case["y"])["skeptic"] is None and _page_row(degraded, case["z"])["redteam"] is None
    assert _page_row(degraded, case["w"])["votes"] == [] and _page_row(case["report"], case["w"])["votes"]
    assert _page_row(degraded, case["y"])["consensus"] is not None, "only what is missing is missing"


def test_characterization_the_markdown_report_leaves_out_a_finding_without_a_consensus_row(case):
    full, degraded = render_markdown(case["report"]), render_markdown(case["degraded"])
    headings = lambda text: {line for line in text.splitlines() if line.startswith("### ")}  # noqa: E731
    assert any(h.startswith(f"### {case['x']} ") for h in headings(full))
    assert not any(h.startswith(f"### {case['x']} ") for h in headings(degraded))
    assert {h for h in headings(full) if not h.startswith(f"### {case['x']} ") and not h.startswith(f"### {case['q']} ")} == {
        h for h in headings(degraded) if not h.startswith(f"### {case['q']} ")}


def test_characterization_the_sarif_report_emits_nothing_for_a_finding_without_a_consensus_row(case):
    full, degraded = to_sarif(case["report"])["runs"][0]["results"], to_sarif(case["degraded"])["runs"][0]["results"]
    title = next(f.title for f in case["report"].findings if f.id == case["x"])
    assert any(title in r["message"]["text"] for r in full) and not any(title in r["message"]["text"] for r in degraded)
    assert len(full) - len(degraded) >= 1


def test_characterization_the_psirt_selection_skips_a_finding_without_a_consensus_row(case):
    picked = [f.id for f, _, _ in select_psirt_findings(case["report"], case["cfg"])]
    assert case["x"] in picked
    assert [f.id for f, _, _ in select_psirt_findings(case["degraded"], case["cfg"])] == [i for i in picked if i != case["x"]]


def test_characterization_the_dimension_scores_and_the_human_queue_skip_a_finding_without_a_consensus_row(case):
    report, degraded = case["report"], case["degraded"]
    cons = {c.finding_id: c for c in report.consensus}
    cons_without = {c.finding_id: c for c in degraded.consensus}
    finding = next(f for f in report.findings if f.id == case["x"])
    with_row = score_dimension(finding.dimension, report.findings, cons, True)
    without = score_dimension(finding.dimension, report.findings, cons_without, True)
    assert with_row.accepted_findings - without.accepted_findings == 1
    sk, rt = {v.finding_id: v for v in report.skeptic}, {n.finding_id: n for n in report.redteam}
    full_queue = [i.finding_id for i in build_queue(report.findings, cons, sk, rt, list(report.votes), case["cfg"])]
    queue = [i.finding_id for i in build_queue(report.findings, cons_without, sk, rt, list(report.votes), case["cfg"])]
    assert case["q"] in full_queue and queue == [i for i in full_queue if i != case["q"]]
