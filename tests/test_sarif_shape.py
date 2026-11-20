"""A file that is JSON but not shaped as SARIF (#344): mara.tools.sarif checks the parts its readers read into or take
as text or a number, so each reader takes such a file as a report it cannot read, and a review takes it as a tool's scan
that did not complete."""

import json
import re
import shutil
from pathlib import Path

import pytest

from mara.tools.sarif import error_notifications, read_sarif, scan_complete
from mara.tools.semgrep_rules import normalize_sarif, timeouts
from tests.test_semgrep_ci import _tool_dir_with_a_fake_semgrep, needs_tools

ROOT = Path(__file__).resolve().parents[1]


def _invocation(**parts) -> dict:
    """A document with one run whose one invocation holds `parts`."""
    return {"runs": [{"invocations": [parts]}]}


def _notification(**parts) -> dict:
    """A document whose one notification is an error with `parts`."""
    return _invocation(toolExecutionNotifications=[{"level": "error", **parts}])


def _driver(**parts) -> dict:
    """A document whose one run's driver holds `parts`."""
    return {"runs": [{"tool": {"driver": parts}}]}


def _rule(**parts) -> dict:
    """A document whose one rule, with the id `r`, holds `parts`, and whose one result names it."""
    return {"runs": [{"tool": {"driver": {"rules": [{"id": "r", **parts}]}}, "results": [{"ruleId": "r"}]}]}


def _result(**parts) -> dict:
    """A document whose one run has one result with `parts`."""
    return {"runs": [{"results": [{"ruleId": "r", **parts}]}]}


def _located(**location) -> dict:
    """A document whose one result's physical location holds `location`."""
    return _result(locations=[{"physicalLocation": location}])


# each part shape_problem checks (what the readers read into or take as text or a number), one at a time with a type
# SARIF does not give it: an object where an array goes and a string where a number goes included, which can be iterated
# or compared without raising
NOT_SHAPED = {
    "document is a list": [1],
    "document is a string": "text",
    "runs is a number": {"runs": 5},
    "runs is an object": {"runs": {"a": 1}},
    "runs is null": {"runs": None},
    "a run is a number": {"runs": [1]},
    "invocations is a number": {"runs": [{"invocations": 5}]},
    "invocations is a string": {"runs": [{"invocations": ""}]},
    "an invocation is a number": {"runs": [{"invocations": [1]}]},
    "the notifications are a number": _invocation(toolExecutionNotifications=5),
    "the notifications are an object": _invocation(toolExecutionNotifications={}),
    "a notification is a number": _invocation(toolConfigurationNotifications=[1]),
    "a notification's message is a string": _notification(message="text"),
    "a notification's message text is a number": _notification(message={"text": 5}),
    "a notification's locations are a number": _notification(message={"text": "m"}, locations=5),
    "a notification's location is a number": _notification(message={"text": "m"}, locations=[1]),
    "a notification's physical location is a string": _notification(message={"text": "m"}, locations=[{"physicalLocation": "x"}]),
    "a notification's artifact location is a string": _notification(message={"text": "m"},
                                                                     locations=[{"physicalLocation": {"artifactLocation": "x"}}]),
    "a notification's uri is a number": _notification(message={"text": "m"},
                                                       locations=[{"physicalLocation": {"artifactLocation": {"uri": 5}}}]),
    "a notification's descriptor is a string": _notification(descriptor="Timeout"),  # read by semgrep_rules.timeouts
    "a notification's descriptor is an array": _notification(descriptor=["Timeout"]),
    "a tool is a string": {"runs": [{"tool": "x"}]},
    "a driver is a string": {"runs": [{"tool": {"driver": "x"}}]},
    "a driver's name is a number": _driver(name=5),
    "a rule's name is a number": _driver(rules=[{"id": "r", "name": 5}]),  # read by normalize_sarif, for semgrep
    "the rules are a number": _driver(rules=5),
    "the rules are an object": _driver(rules={}),
    "a rule is a number": _driver(rules=[1]),
    "a rule's id is a list": _driver(rules=[{"id": [1]}]),
    "a rule's properties are a string": _rule(properties="x"),
    "a rule's tags are a number": _rule(properties={"tags": 5}),
    "a rule's tags are a string": _rule(properties={"tags": "CWE-89"}),
    "a rule's default configuration is a string": _rule(defaultConfiguration="x"),
    "a rule's default level is a number": _rule(defaultConfiguration={"level": 5}),
    "the results are a number": {"runs": [{"results": 5}]},
    "the results are an object": {"runs": [{"results": {}}]},
    "a result is a number": {"runs": [{"results": [1]}]},
    "a result's rule id is a number": {"runs": [{"results": [{"ruleId": 5}]}]},
    "a result's rule is a string": _result(rule="x"),  # read by normalize_sarif
    "a result's rule's id is a number": _result(rule={"id": 5}),
    "a result's level is a number": _result(level=5),
    "a result's suppressions are a number": _result(suppressions=5),
    "a result's suppression is a number": _result(suppressions=[1]),
    "a result's locations are a number": _result(locations=5),
    "a result's location is a number": _result(locations=[1]),
    "a result's physical location is a string": _result(locations=[{"physicalLocation": "x"}]),
    "a result's artifact location is a string": _located(artifactLocation="x"),
    "a result's uri is a number": _located(artifactLocation={"uri": 5}),
    "a result's region is a string": _located(region="x"),
    "a result's start line is a string": _located(region={"startLine": "x"}),
    "a result's start line is true": _located(region={"startLine": True}),  # Python takes a JSON true for an int
    "a result's message is a string": _result(message="text"),
    "a result's message text is a number": _result(message={"text": 5}),
}


def _write(tmp_path: Path, doc: object) -> Path:
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@pytest.mark.parametrize("doc", NOT_SHAPED.values(), ids=NOT_SHAPED.keys())
def test_a_document_not_shaped_as_sarif_has_no_error_notifications(tmp_path, doc):
    assert error_notifications(_write(tmp_path, doc)) == []


@pytest.mark.parametrize("doc", NOT_SHAPED.values(), ids=NOT_SHAPED.keys())
def test_a_document_not_shaped_as_sarif_is_a_scan_that_did_not_complete(doc):
    """A scan whose report cannot be read did not complete."""
    assert scan_complete(doc) is False


@pytest.mark.parametrize("doc", NOT_SHAPED.values(), ids=NOT_SHAPED.keys())
def test_reading_the_results_of_a_document_not_shaped_as_sarif_names_the_file_and_the_part(tmp_path, doc):
    """Not a partial list of results: the caller is told the file cannot be read, which file, and the part that is not
    shaped as SARIF."""
    path = _write(tmp_path, doc)
    with pytest.raises(ValueError, match=f"^{re.escape(str(path))}: not shaped as SARIF \\(.+\\)$"):
        read_sarif(path)


@pytest.mark.parametrize("doc", NOT_SHAPED.values(), ids=NOT_SHAPED.keys())
def test_normalizing_a_document_not_shaped_as_sarif_leaves_the_file_as_it_is(tmp_path, doc):
    """semgrep's SARIF is normalized before it is read (semgrep_ci.py, run_all): one not shaped as SARIF is left byte for
    byte for the readers to refuse, and is returned as it was read."""
    path = _write(tmp_path, doc)
    before = path.read_bytes()
    assert normalize_sarif(path) == doc
    assert path.read_bytes() == before


@pytest.mark.parametrize("doc", NOT_SHAPED.values(), ids=NOT_SHAPED.keys())
def test_a_document_not_shaped_as_sarif_has_no_timeouts(tmp_path, doc):
    """semgrep_ci.py prints the timeouts of semgrep's SARIF (semgrep_rules.timeouts): one not shaped as SARIF has none."""
    assert timeouts(_write(tmp_path, doc)) == []


@pytest.mark.parametrize("doc, part", [
    ({"runs": [{"invocations": [1]}]}, "runs[0].invocations[0] is a number, not an object"),
    (_located(region={"startLine": "x"}), "runs[0].results[0].locations[0].physicalLocation.region.startLine is a string, not an integer"),
    ({"runs": None}, "runs is null, not an array"),
], ids=["an invocation", "a start line", "runs"])
def test_the_part_not_shaped_as_sarif_is_named_by_where_it_is(tmp_path, doc, part):
    with pytest.raises(ValueError, match=re.escape(f"({part})")):
        read_sarif(_write(tmp_path, doc))


@pytest.mark.parametrize("path", sorted((ROOT / "fixtures").rglob("*.sarif")), ids=lambda p: p.name)
def test_every_sarif_a_tool_wrote_for_the_fixtures_is_shaped_as_sarif(path):
    """What the tools write is read as before: the check is no stricter than what they write."""
    read_sarif(path)
    assert scan_complete(json.loads(path.read_text(encoding="utf-8"))) is True


def test_a_sarif_shaped_document_still_gives_each_error_notification_and_where(tmp_path):
    doc = _notification(message={"text": "could not parse"},
                        locations=[{"physicalLocation": {"artifactLocation": {"uri": "a.py"}}}])
    assert error_notifications(_write(tmp_path, doc)) == ["could not parse (a.py)"]


def test_a_sarif_shaped_document_is_complete_unless_it_records_a_failure():
    assert scan_complete(_invocation(executionSuccessful=True, toolExecutionNotifications=[{"level": "warning"}])) is True
    assert scan_complete(_invocation(executionSuccessful=False)) is False


def test_the_results_of_a_sarif_shaped_document_are_read_as_before(tmp_path):
    doc = {"runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": [
        {"id": "r", "properties": {"tags": ["CWE-89: SQL injection"]}, "defaultConfiguration": {"level": "error"}}]}},
        "results": [{"ruleId": "r", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}]},
                    {"ruleId": "r", "suppressions": [{"status": "accepted"}]}]}]}
    (result,) = read_sarif(_write(tmp_path, doc))
    assert (result.tool, result.rule_id, result.level, result.message, result.file, result.line, result.cwes) == (
        "semgrep", "r", "error", "m", "a.py", 3, ["CWE-89"])


def test_only_a_result_s_first_location_is_checked_for_it_is_the_one_read(tmp_path):
    """read_sarif reads a result's first location only: a later one of another type leaves the file as readable as
    before."""
    doc = _result(locations=[{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 3}}}, 1])
    (result,) = read_sarif(_write(tmp_path, doc))
    assert (result.file, result.line) == ("a.py", 3) and scan_complete(doc) is True


# a null that every reader of the part takes for its absence (`or`), so a file holding one was read before and still is
NULL_READ_AS_ABSENT = {
    "an invocation's notifications are null": (_invocation(toolExecutionNotifications=None), [], True),
    "a notification's message is null": (_notification(message=None, locations=[]), [""], False),
    "a notification's locations are null": (_notification(message={"text": "m"}, locations=None), ["m"], False),
    "a notification's descriptor is null": (_notification(message={"text": "m"}, descriptor=None), ["m"], False),
}


@pytest.mark.parametrize("doc, notes, complete", NULL_READ_AS_ABSENT.values(), ids=NULL_READ_AS_ABSENT.keys())
def test_a_null_the_notification_readers_take_for_absent_is_still_read(tmp_path, doc, notes, complete):
    assert error_notifications(_write(tmp_path, doc)) == notes
    assert scan_complete(doc) is complete


@pytest.mark.parametrize("doc", [doc for doc, _notes, _complete in NULL_READ_AS_ABSENT.values()], ids=NULL_READ_AS_ABSENT.keys())
def test_normalizing_a_null_the_readers_take_for_absent_leaves_it_as_it_is(tmp_path, doc):
    """semgrep's SARIF is normalized before it is read (semgrep_ci.py, run_all): a null it holds where the readers take
    one for absent does not stop it, and the document it returns still holds the null."""
    assert normalize_sarif(_write(tmp_path, doc)) == doc


def test_a_result_whose_locations_are_null_is_still_read_as_having_none(tmp_path):
    (result,) = read_sarif(_write(tmp_path, _result(locations=None)))
    assert (result.file, result.line) == ("", 1)


@pytest.mark.parametrize("doc", [{"runs": [1]}, {"runs": [{"invocations": [1]}]}], ids=["a run", "an invocation"])
def test_a_review_whose_prerecorded_sarif_is_not_shaped_as_sarif_completes_without_that_tool(root, tmp_path, mock_report, doc):
    """`mara review --sarif-dir`: the file is tool evidence of a tool's scan that did not complete, the note says why
    whichever part is not shaped (an invocation, which only the notification readers read, too), the other tools' runs
    are as in a review of the recorded SARIF, and the review is incomplete for it."""
    from mara.config import load_config
    from mara.pipeline import Pipeline
    from mara.workspace import Workspace

    sarif_dir = tmp_path / "sarif"
    shutil.copytree(root / "fixtures" / "vuln-sample-sarif", sarif_dir)
    (sarif_dir / "semgrep.sarif").write_text(json.dumps(doc), encoding="utf-8")
    pipe = Pipeline(load_config(root / "config" / "mara.mock.yaml", Workspace(root)), mock_fixtures=str(root / "fixtures" / "mock-responses"),
                    out_dir=tmp_path / "out")
    report = pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=sarif_dir, provider_mode="mock")
    health = {t["tool"]: t for t in report.tool_health}
    assert health["semgrep"]["ran"] is False and f"{sarif_dir / 'semgrep.sarif'}: not shaped as SARIF" in health["semgrep"]["note"]
    _, recorded = mock_report
    assert [t for t in report.tool_health if t["tool"] != "semgrep"] == [t for t in recorded.tool_health if t["tool"] != "semgrep"]
    assert "required_tool_incomplete" in report.incomplete_reasons


def test_a_tool_whose_sarif_is_not_shaped_as_sarif_is_a_scan_that_did_not_complete(tmp_path):
    """run_all: the stand-in osv-scanner (test_osv_ci.py) writes such a file and exits 0. Its scan did not complete, the
    note says why, and the tools after it still get their runs (gitleaks, which this tool directory does not hold)."""
    from mara.tools.runner import run_all
    from tests import tool_installs
    from tests.test_osv_ci import _tools

    tools = _tools(tmp_path, json.dumps({"runs": [1]}), exit_code=0)
    target = tmp_path / "t"
    target.mkdir()
    osv, gitleaks = run_all(target, tmp_path / "out", enabled=["osv-scanner", "gitleaks"], workspace=tool_installs.workspace(tools))
    assert (osv.tool, osv.ran, osv.results) == ("osv-scanner", False, [])
    assert f"{tmp_path / 'out' / 'osv-scanner.sarif'}: not shaped as SARIF" in osv.note
    assert gitleaks.tool == "gitleaks"


@needs_tools
def test_semgrep_writing_a_file_not_shaped_as_sarif_is_a_scan_that_did_not_complete(tmp_path):
    """run_all normalizes semgrep's SARIF before it reads it: the stand-in semgrep of test_semgrep_ci.py writes such a
    file, and the scan did not complete, with the note saying why, as for any other tool."""
    from mara.tools.runner import run_all
    from tests import tool_installs

    tools = _tool_dir_with_a_fake_semgrep(tmp_path, 0, {"runs": [1]})
    target = tmp_path / "t"
    target.mkdir()
    (semgrep,) = run_all(target, tmp_path / "out", enabled=["semgrep"], workspace=tool_installs.workspace(tools))
    assert (semgrep.tool, semgrep.ran, semgrep.results) == ("semgrep", False, [])
    assert f"{tmp_path / 'out' / 'semgrep.sarif'}: not shaped as SARIF" in semgrep.note
