"""Scanner exceptions: the osv and trivy lists agree, and an entry close to its expiry is announced early."""

from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ignore_expiry as ie  # noqa: E402

D = dt.date


def test_closure_exceptions_are_the_same_in_osv_and_trivy():
    # Every closure config (the isolated model-evaluation closure, and the semgrep tool closure whose
    # pyjwt is pinned upstream) must appear in tools/trivyignore.yaml with the same ids and expiries, or
    # one scanner fails while the other passes.
    trivy: dict[str, object] = {}
    for vid, until in ie.trivy_entries(ROOT / "tools" / "trivyignore.yaml"):
        assert vid not in trivy, f"{vid} listed twice in trivyignore.yaml"
        trivy[vid] = until
    osv_ids: set[str] = set()
    for name in ("osv-model-eval.toml", "osv-semgrep.toml"):
        for vid, until in ie.osv_entries(ROOT / "tools" / name):
            assert until is not None, f"{name}: {vid} has no expiry"
            assert vid not in osv_ids, f"{vid} listed in two osv configs"
            osv_ids.add(vid)
            assert trivy.get(vid) == until, f"{vid}: osv expiry {until} but trivy expiry {trivy.get(vid)}"
    assert set(trivy) == osv_ids, f"trivyignore ids with no osv entry: {sorted(set(trivy) - osv_ids)}"


def test_every_exception_has_an_expiry_and_the_main_osv_list_stays_empty():
    assert ie.osv_entries(ROOT / "tools" / "osv-scanner.toml") == []
    for vid, until in ie.trivy_entries(ROOT / "tools" / "trivyignore.yaml"):
        assert until is not None, vid


def test_expiring_warns_within_the_window_and_after_expiry():
    entries = [("CVE-A", D(2026, 12, 17)), ("CVE-B", D(2027, 6, 1)), ("CVE-C", None)]
    assert ie.expiring(entries, D(2026, 9, 27)) == ["CVE-C: exception has no readable expiry date"]
    msgs = ie.expiring(entries, D(2026, 11, 17))
    assert len(msgs) == 2 and msgs[0].startswith("CVE-A: exception expires on 2026-12-17 (30 days)")
    assert ie.expiring(entries, D(2026, 11, 16)) == ["CVE-C: exception has no readable expiry date"]
    assert ie.expiring(entries, D(2026, 12, 18))[0] == "CVE-A: exception expired on 2026-12-17"


def test_parsers_read_both_formats(tmp_path):
    toml = tmp_path / "osv.toml"
    toml.write_text('[[IgnoredVulns]]\nid = "GHSA-1"\nignoreUntil = 2026-10-01\nreason = "r"\n', encoding="utf-8")
    yml = tmp_path / "trivy.yaml"
    yml.write_text(
        "vulnerabilities:\n  - id: CVE-1\n    expired_at: 2026-10-01\nmisconfigurations:\n  - id: DS-0001\n    expired_at: '2026-11-01'\n",
        encoding="utf-8",
    )
    assert ie.osv_entries(toml) == [("GHSA-1", D(2026, 10, 1))]
    assert ie.trivy_entries(yml) == [("CVE-1", D(2026, 10, 1)), ("DS-0001", D(2026, 11, 1))]


def test_warn_prints_github_annotations(capsys):
    n = ie.warn(Path("tools/x.toml"), [("CVE-A", D(2026, 10, 1))], today=D(2026, 9, 27))
    assert n == 1
    assert capsys.readouterr().out.startswith("::warning file=tools/x.toml::CVE-A: exception expires on 2026-10-01 (4 days)")
