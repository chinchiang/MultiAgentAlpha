"""The workbench's budget carries the jury's global alpha the way `mara.audit.alpha` reads it: a number, or None.

`Audit.set_alpha` writes the string "n/a" when the jury had no alpha, and `audit.alpha` reads a report back as a number
or None (a string, a boolean or a missing key is None). `views.budget` used to send the audit's value as it stands, so
the page received "n/a", or whatever an old or hand-written report held, where it expects a number or nothing."""

from __future__ import annotations

import pytest

from mara.schemas import ReviewReport
from mara.web.views import budget


def _report(audit: dict) -> ReviewReport:
    return ReviewReport.model_construct(bias_audit=audit, provider_manifest=[], tool_results=[], human_queue=[],
                                        human_queue_tightening=None)


@pytest.mark.parametrize("held, shown", [
    ({"global_krippendorff_alpha": 0.4872}, 0.4872),
    ({"global_krippendorff_alpha": 0}, 0.0),
    ({"global_krippendorff_alpha": -0.1667}, -0.1667),
    ({"global_krippendorff_alpha": "n/a"}, None),
    ({"global_krippendorff_alpha": True}, None),
    ({"global_krippendorff_alpha": "0.5"}, None),
    ({}, None),
])
def test_the_budget_carries_the_alpha_a_report_holds_as_a_number_or_none(held, shown):
    assert budget({}, _report(held), None)["global_krippendorff_alpha"] == shown


def test_the_budget_of_a_run_without_a_report_has_no_alpha():
    assert budget({}, None, None)["global_krippendorff_alpha"] is None


def test_a_number_stays_a_number():
    sent = budget({}, _report({"global_krippendorff_alpha": 1}), None)["global_krippendorff_alpha"]
    assert sent == 1.0 and isinstance(sent, float)
