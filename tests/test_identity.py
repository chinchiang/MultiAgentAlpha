"""mara.identity: one path, place and key rule for every module that matches or keys findings (architecture review
candidate 2)."""

import sys
from pathlib import Path

import pytest

from mara.agents import base
from mara.context.repo_map import RepoContext
from mara.identity import norm_path, same_place
from mara.schemas import Provenance

ROOT = Path(__file__).resolve().parents[1]


def test_one_path_form():
    assert norm_path("./././app.py") == norm_path(".\\app.py") == norm_path("app.py") == "app.py"
    assert norm_path(".github/workflows/ci.yml") == ".github/workflows/ci.yml", "lstrip('./') ate this dot"
    assert norm_path("../app.py") == "../app.py" and norm_path(".env") == ".env"
    assert same_place("./app.py", 10, "cwe-89", "app.py", 13, "CWE-89")
    assert not same_place("app.py", 10, "CWE-89", "app.py", 14, "CWE-89")
    assert not same_place(".env", 1, "CWE-798", "env", 1, "CWE-798")


def test_a_provenance_citing_dot_slash_is_the_same_file_and_verifies():
    """verify_quote looked `./app.py` up as given: the finding was unverified (tier D) and dedupe refused to merge it
    with the verified `app.py` one, although it said ./app.py and app.py are one file."""
    p = Provenance(file="./src\\app.py", line=1, quote="query = build(user)")
    assert p.file == "src/app.py"
    ctx = RepoContext(root=Path("."), content={"src/app.py": "query = build(user)\n"})
    assert base.verify_quote(ctx, p.file, p.line, p.quote)


def test_calibration_matches_findings_to_labels_by_the_same_rule():
    sys.path.insert(0, str(ROOT / "scripts"))
    import calibrate

    def f(file, line, cwe):
        return {"provenance": [{"file": file, "line": line}], "cwe": cwe}

    assert calibrate._match(f("./app.py", 12, "cwe-89"), {"file": "app.py", "line": 10, "cwe": "CWE-89"})
    assert not calibrate._match(f(".env", 1, "CWE-798"), {"file": "env", "line": 1, "cwe": "CWE-798"}), "lstrip merged them"
    assert not calibrate._match(f("../app.py", 1, "CWE-89"), {"file": "app.py", "line": 1, "cwe": "CWE-89"})


@pytest.mark.parametrize("ref", ["OWASP A01:2025\n", "CWE-89\n", "ASVS 5.0 V6.2\n", "OWASP API1:2023\n", "OWASP LLM01:2025\n", " CWE-89"])
def test_a_reference_with_a_trailing_newline_or_space_is_not_a_reference(ref):
    """`$` also matches before a trailing newline, so a newline-bearing id passed validation and went unescaped into
    the Markdown, SARIF and PSIRT outputs."""
    from mara.groundtruth import validate_ref

    assert not validate_ref(ref)[0] and validate_ref(ref.strip())[0]


@pytest.fixture(scope="module")
def mock_report(tmp_path_factory):
    from mara.config import load_config
    from mara.pipeline import Pipeline

    pipe = Pipeline(load_config(ROOT / "config" / "mara.mock.yaml"), mock_fixtures=str(ROOT / "fixtures" / "mock-responses"),
                    out_dir=tmp_path_factory.mktemp("out"))
    return pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")


def test_an_alert_keeps_its_fingerprint_when_an_earlier_twin_changes_state(mock_report):
    """The occurrence index was counted over the emitted (accepted or queued) findings only: two findings sharing
    dimension, CWE, file and quote swapped fingerprints - and code scanning moved a dismissal to the other one - when
    the earlier one was accepted in one run and rejected in the next."""
    from mara.report.sarif_out import to_sarif

    report = mock_report.model_copy(deep=True)
    base_f = report.findings[0]
    twin = base_f.model_copy(update={"id": "F-9999", "provenance": [base_f.provenance[0].model_copy(update={"line": base_f.provenance[0].line + 40})]})
    report.findings.append(twin)
    cons = {c.finding_id: c for c in report.consensus}
    report.consensus.append(cons[base_f.id].model_copy(update={"finding_id": twin.id}))
    report.human_queue = []

    def fingerprints(first_accepted: bool) -> dict[str, str]:
        for c in report.consensus:
            if c.finding_id == base_f.id:
                c.accepted = first_accepted
            if c.finding_id == twin.id:
                c.accepted = True
        return {r["properties"]["findingId"]: r["partialFingerprints"]["maraContent/v1"]
                for run in to_sarif(report)["runs"] for r in run["results"]}

    both, only_twin = fingerprints(True), fingerprints(False)
    assert base_f.id in both and base_f.id not in only_twin and twin.id in only_twin
    assert both[twin.id] == only_twin[twin.id], "the twin's alert keeps its identity when its earlier twin is rejected"
    assert both[twin.id] != both[base_f.id]
