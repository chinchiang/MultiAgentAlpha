"""Which launch the workbench admits (mara.web.admission, docs/adr/0006-local-web-workbench.md): one review runs at a
time, and never while an environment job replaces the tools or the trivy database it uses, nor such a job while a review
runs; one environment job runs at a time. Each row is a launch, the kinds running, and the refusal the page is told."""

import pytest

from mara.web import admission

RUN = "a review is already running; wait for it or cancel it"
TOOLS_BEING_REPLACED = "an environment job is replacing the tools or the trivy database; wait for it"
JOB = "an environment job is already running"
RUN_USES_THE_TOOLS = "a review is running with the installed tools; wait for it or cancel it"
KINDS = ["run", "install_tools", "trivy_db_download", "trivy_db_status", "check_config"]


@pytest.mark.parametrize("kind", KINDS)
def test_nothing_running_admits_every_launch(kind):
    assert admission.refusal(kind, set()) is None


@pytest.mark.parametrize("kind, running, refused", [
    ("run", {"run"}, RUN),
    ("run", {"run", "trivy_db_status"}, RUN),
    ("run", {"install_tools"}, TOOLS_BEING_REPLACED),
    ("run", {"trivy_db_download"}, TOOLS_BEING_REPLACED),
    ("install_tools", {"check_config"}, JOB),
    ("trivy_db_download", {"trivy_db_status"}, JOB),
    ("trivy_db_status", {"install_tools"}, JOB),
    ("check_config", {"trivy_db_download"}, JOB),
    ("install_tools", {"run"}, RUN_USES_THE_TOOLS),
    ("trivy_db_download", {"run"}, RUN_USES_THE_TOOLS),
])
def test_a_launch_is_refused_while_a_kind_it_excludes_runs(kind, running, refused):
    assert admission.refusal(kind, running) == refused


@pytest.mark.parametrize("kind, running", [
    ("run", {"trivy_db_status"}),
    ("run", {"check_config"}),
    ("trivy_db_status", {"run"}),
    ("check_config", {"run"}),
])
def test_a_job_replacing_no_tools_and_a_run_are_admitted_beside_each_other(kind, running):
    assert admission.refusal(kind, running) is None


def test_where_two_refusals_apply_a_job_replacing_the_tools_is_told_of_the_job_first():
    """A run and a job replacing no tools run beside each other: the job's own refusal comes first."""
    assert admission.refusal("install_tools", {"run", "trivy_db_status"}) == JOB
