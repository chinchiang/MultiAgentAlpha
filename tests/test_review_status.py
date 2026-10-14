"""mara.review_status: the review status, the gate and the secret preflight (docs/adr/0007-review-status-and-gate.md)."""

from mara.review_status import secret_preflight
from mara.tools.runner import ToolRun
from mara.tools.sarif import ToolResult

SECRET = ToolResult("gitleaks", "generic-api-key", "error", "secret", "app.py", 3, "CWE-798")


def test_a_mock_review_never_blocks_egress():
    """Nothing leaves the host in a mock review, so even a missing scan or a found secret does not block."""
    assert not secret_preflight("mock", [], None).blocked
    assert not secret_preflight("mock", [ToolRun("gitleaks", True, [SECRET])], None).blocked


def test_a_live_review_blocks_egress_unless_gitleaks_ran_and_found_nothing():
    assert secret_preflight("live", [], None).blocked, "no secret scan at all"
    assert secret_preflight("live", [ToolRun("gitleaks", False)], None).blocked, "the scan did not run"
    assert secret_preflight("live", [ToolRun("gitleaks", True), ToolRun("gitleaks", False)], None).blocked, "one run failed"
    assert secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], None).blocked, "a secret was found"
    assert not secret_preflight("live", [ToolRun("gitleaks", True)], None).blocked


def test_a_seeded_secret_the_calibration_answer_key_declares_is_exempted_and_nothing_else():
    key = [{"file": "./app.py", "line": 3, "cwe": "CWE-798"}]
    other = ToolResult("gitleaks", "aws-access-token", "error", "secret", "app.py", 1, "CWE-798")
    seeded = secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], key)
    assert not seeded.blocked and seeded.exempted == (SECRET,) and seeded.unexplained == ()
    both = secret_preflight("live", [ToolRun("gitleaks", True, [SECRET, other])], key)
    assert both.blocked and both.exempted == (SECRET,) and both.unexplained == (other,)
    assert secret_preflight("live", [ToolRun("gitleaks", True, [SECRET])], None).unexplained == (SECRET,), "no key, no exemption"
