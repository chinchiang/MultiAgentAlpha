"""Which launch the workbench admits (GLOSSARY.md: workbench, run; docs/adr/0006-local-web-workbench.md): one review runs
at a time, and never while an environment job replaces the tools or the trivy database it uses, nor such a job while a
review runs; one environment job runs at a time.

Pure: `refusal()` reads only the kind launched and the kinds running it is given.
"""

from __future__ import annotations

from collections.abc import Collection

CHANGES_TOOLS = frozenset({"install_tools", "trivy_db_download"})  # never while a review executes the tools or reads the database


def refusal(kind: str, running: Collection[str]) -> str | None:
    """Why a launch of `kind` ("run", or a job's kind) is refused while `running` runs; None when it is admitted."""
    if kind == "run" and "run" in running:
        return "a review is already running; wait for it or cancel it"
    if kind == "run" and CHANGES_TOOLS & set(running):
        return "an environment job is replacing the tools or the trivy database; wait for it"
    if kind != "run" and set(running) - {"run"}:
        return "an environment job is already running"
    if kind in CHANGES_TOOLS and "run" in running:
        return "a review is running with the installed tools; wait for it or cancel it"
    return None
