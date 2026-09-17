"""Appendix E prompt 5: the read-only Actions inventory must detect the seeded pwn request and
report the hardened self-review workflow correctly, without network or zizmor."""

import sys
from pathlib import Path

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
    assert inv.triggers == ["pull_request", "push"]
    assert not inv.pull_request_target, "a comment mentioning pull_request_target must not count as a trigger"
    assert not inv.head_checkout_lines
    assert inv.top_permissions == "{}"
    assert set(inv.job_permissions) == {"deterministic-tools", "code-scanning", "tests-and-mock-review", "human-queue"}
    assert "write" not in inv.job_permissions["deterministic-tools"] and "write" not in inv.job_permissions["tests-and-mock-review"]
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
