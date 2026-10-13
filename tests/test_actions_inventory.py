"""Appendix E prompt 5: the read-only Actions inventory must detect the seeded pwn request and
report the hardened self-review workflow correctly, without network or zizmor."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from actions_inventory import SEVERITY_ORDER, classify_ref, find_workflows, inventory_workflow, render  # noqa: E402


def test_classify_ref():
    assert classify_ref("actions/checkout", "11bd71901bbe5b1630ceea73d27597364c9af683") == "sha"
    assert classify_ref("actions/checkout", "v4") == "tag"
    assert classify_ref("actions/checkout", "4.2.2") == "tag"
    assert classify_ref("some-org/deploy-action", "main") == "branch"
    assert classify_ref("./.github/actions/local", "") == "local"
    assert classify_ref("docker://alpine:3.20", "") == "docker"


def test_seeded_fixture_is_critical_pwn_request():
    inv = inventory_workflow(ROOT / "fixtures/vuln-sample/.github/workflows/deploy.yml", ROOT)
    assert inv.parse_error is None, "the seeded workflow must be valid YAML so zizmor and GitHub can parse it"
    assert inv.pull_request_target
    assert inv.head_checkout_lines == [12]
    assert inv.top_permissions == "write-all"
    assert [(u.line, u.kind) for u in inv.uses] == [(10, "tag"), (16, "branch")]
    assert [(i.line, i.expression, i.untrusted) for i in inv.run_interpolations] == [(15, "github.event.pull_request.title", True)]
    assert inv.severity == "Critical"
    texts = " ".join(t for _, t in inv.findings)
    assert "pwn request" in texts and "攻擊者可控" in texts


def test_hardened_workflow_has_no_critical_or_high():
    inv = inventory_workflow(ROOT / ".github/workflows/mara-review.yml", ROOT)
    assert inv.parse_error is None
    assert set(inv.triggers) == {"pull_request", "push", "schedule", "workflow_dispatch"}
    assert not inv.pull_request_target, "a comment mentioning pull_request_target must not count as a trigger"
    assert not inv.head_checkout_lines
    assert inv.top_permissions == "{}"
    assert set(inv.job_permissions) == {"deterministic-tools", "code-scanning", "tests-and-mock-review", "tests-py312", "human-queue"}
    assert "write" not in inv.job_permissions["deterministic-tools"] and "write" not in inv.job_permissions["tests-and-mock-review"]
    assert inv.job_permissions["tests-py312"] == "{contents: read}"
    assert inv.job_permissions["code-scanning"] == "{contents: read, security-events: write}"   # upload-sarif only; runs no repo scan
    assert inv.job_permissions["human-queue"] == "{contents: read, issues: write}"   # G-11 tickets
    assert not any("contents: write" in p or "id-token" in p for p in inv.job_permissions.values())
    assert inv.uses and all(u.kind == "sha" for u in inv.uses)
    assert not inv.run_interpolations
    assert SEVERITY_ORDER.index(inv.severity) >= SEVERITY_ORDER.index("Medium")


def test_find_workflows_skips_the_tool_checkouts_under_mara_tools(tmp_path):
    real = tmp_path / ".github" / "workflows"
    real.mkdir(parents=True)
    (real / "b.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    vendored = tmp_path / ".mara-tools" / "semgrep-rules" / ".github" / "workflows"
    vendored.mkdir(parents=True)
    (vendored / "a.yml").write_text("on: push\njobs: {}\n", encoding="utf-8")
    assert [p.relative_to(tmp_path).as_posix() for p in find_workflows(tmp_path)] == [".github/workflows/b.yml"]


CHECKOUT_HEAD = ("jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                 "      - uses: actions/checkout@0000000000000000000000000000000000000000\n"
                 "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")


@pytest.mark.parametrize("on", [
    "on: {pull_request_target: {types: [opened]}}\n",     # flow mapping: the line patterns saw no trigger at all
    "on: {push: {branches: [main]}, pull_request_target: {}}\n",
    "on: [push, pull_request_target]\n",
    "on: pull_request_target\n",
    "on:\n    pull_request_target:    # four-space indent and a trailing comment\n      types: [opened]\n",
    "'on':\n  - push\n  - pull_request_target\n",
    "\"on\": {pull_request_target: null}\n",
])
def test_pull_request_target_is_read_from_the_parsed_triggers(tmp_path, on):
    wf = tmp_path / ".github" / "workflows" / "x.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("name: x\n" + on + CHECKOUT_HEAD, encoding="utf-8")
    inv = inventory_workflow(wf, tmp_path)
    assert inv.parse_error is None
    assert "pull_request_target" in inv.triggers and inv.pull_request_target, inv.triggers
    assert inv.severity == "Critical" and any("pwn request" in t for _, t in inv.findings)
    # and governance G-6 sees it
    from governance_check import FAIL, check_g6

    r = check_g6(tmp_path)
    assert r.status == FAIL and "使用 pull_request_target" in r.evidence


SHA = "0123456789abcdef0123456789abcdef01234567"


def _wf(tmp_path, body: str):
    wf = tmp_path / ".github" / "workflows" / "x.yml"
    wf.parent.mkdir(parents=True, exist_ok=True)
    wf.write_text(body, encoding="utf-8")
    return inventory_workflow(wf, tmp_path)


def test_a_quoted_sha_pin_is_a_sha_pin(tmp_path):
    """The quote stayed in the reference, so a correctly pinned `uses: "owner/action@<sha>"` read as a tag and G-6 failed."""
    from governance_check import check_g6

    inv = _wf(tmp_path, "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"
                        f"      - uses: \"actions/checkout@{SHA}\" # v4\n        with:\n          persist-credentials: false\n"
                        "      - uses: 'actions/setup-python@v5'\n")
    assert [(u.raw, u.kind) for u in inv.uses] == [(f"actions/checkout@{SHA}", "sha"), ("actions/setup-python@v5", "tag")]
    evidence = check_g6(tmp_path).evidence
    assert "`actions/setup-python@v5`" in evidence and f"`actions/checkout@{SHA}`" not in evidence, "only the tag is a problem"


def test_a_flow_style_head_checkout_is_a_pwn_request(tmp_path):
    """`- {uses: ..., with: {ref: <PR head>}}` was invisible to the line patterns: neither the action nor the checkout."""
    inv = _wf(tmp_path, "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                        "      - {uses: actions/checkout@v4, with: {ref: \"${{ github.event.pull_request.head.sha }}\"}}\n")
    assert [(u.raw, u.kind, u.line) for u in inv.uses] == [("actions/checkout@v4", "tag", 7)]
    assert inv.head_checkout_lines == [7] and inv.severity == "Critical"
    assert any(sev == "Critical" and "pwn request" in t for sev, t in inv.findings)


def test_github_script_interpolation_is_checked_like_run(tmp_path):
    """actions/github-script evaluates its `script:` as JavaScript; ${{ github.event.pull_request.title }} in it is the
    same injection as in a shell `run:`, and only `run:` bodies used to be scanned."""
    inv = _wf(tmp_path, "on: pull_request\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                        f"      - uses: actions/github-script@{SHA}\n        with:\n          script: |\n"
                        "            const t = '${{ github.event.pull_request.title }}';\n"
                        "            core.info(`${{ github.ref }}`);\n")
    assert [(i.line, i.where, i.untrusted) for i in inv.run_interpolations] == [(10, "script", True), (11, "script", False)]
    assert inv.severity == "Critical" and any("`script:`" in t and "pull_request.title" in t for sev, t in inv.findings if sev == "Critical")


def test_parsed_triggers_ignore_what_github_ignores(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "x.yml"
    wf.parent.mkdir(parents=True)
    # the event name inside a filter, a step name or a comment is not a trigger
    wf.write_text("name: pull_request_target\non: {push: {branches: [pull_request_target]}}  # not pull_request_target\n"
                  "jobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n"
                  "      - name: pull_request_target\n        run: \"echo pull_request_target:\"\n", encoding="utf-8")
    inv = inventory_workflow(wf, tmp_path)
    assert inv.parse_error is None
    assert inv.triggers == ["push"] and not inv.pull_request_target


def test_invalid_yaml_is_flagged_but_still_inventoried(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "bad.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("on:\n  pull_request_target:\njobs:\n  a:\n    steps:\n      - run: echo \"x: ${{ github.event.pull_request.title }}\"\n", encoding="utf-8")
    inv = inventory_workflow(wf, tmp_path)
    assert inv.parse_error and "line 6" in inv.parse_error
    assert inv.pull_request_target and inv.run_interpolations[0].untrusted
    assert any(sev == "Medium" and "合法 YAML" in txt for sev, txt in inv.findings)


def test_block_scalar_run_and_cache_key(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "x.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: x\non:\n  pull_request:\n  issue_comment:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/cache@v4\n        with:\n          key: build-${{ github.head_ref }}\n"
        "      - run: |\n          echo start\n          echo \"${{ github.event.comment.body }}\"\n          echo ${{ github.ref }}\n"
        "      - run: echo done\n",
        encoding="utf-8",
    )
    inv = inventory_workflow(wf, tmp_path)
    assert inv.parse_error is None
    assert [(i.line, i.untrusted) for i in inv.run_interpolations] == [(14, True), (15, False)]
    assert inv.cache_keys == [(11, "build-${{ github.head_ref }}", True)]
    assert inv.severity == "Critical"
    assert any("cache" in t for _, t in inv.findings)


def test_render_puts_critical_first_and_lists_every_workflow():
    invs = [inventory_workflow(p, ROOT) for p in find_workflows(ROOT)]
    assert len(invs) >= 3
    md = render(invs, {}, root=ROOT, offline=True, date="2026-01-01", zizmor_present=False)
    rows = [ln for ln in md.splitlines() if ln.startswith("| **")]
    assert len(rows) == len(invs)
    assert rows[0].startswith("| **Critical**")
    for inv in invs:
        assert f"`{inv.path}`" in md
    assert "未執行：zizmor 不在 PATH" in md


def test_jobs_without_timeout_are_flagged(tmp_path):
    wf = tmp_path / ".github" / "workflows" / "x.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(
        "name: x\non:\n  push:\njobs:\n  timed:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n    steps:\n      - run: echo ok\n"
        "  untimed:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n",
        encoding="utf-8",
    )
    inv = inventory_workflow(wf, tmp_path)
    assert inv.parse_error is None
    assert inv.jobs_without_timeout == ["untimed"]
    assert any("timeout-minutes" in t for _, t in inv.findings)


def test_real_workflows_set_timeout_on_every_job_and_the_fixture_does_not():
    for p in find_workflows(ROOT):
        inv = inventory_workflow(p, ROOT)
        if inv.path.startswith(".github/workflows/"):
            assert not inv.jobs_without_timeout, f"{inv.path}: jobs without timeout-minutes: {inv.jobs_without_timeout}"
        elif "fixtures/vuln-sample" in inv.path:
            # seeded material stays untouched: the detection must keep flagging it
            assert inv.jobs_without_timeout, f"{inv.path}: expected the missing-timeout finding on the seeded workflow"
