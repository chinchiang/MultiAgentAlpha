"""The review invocation (GLOSSARY.md: Review invocation, Usage error, Provider mode): what one call of `mara review`
takes and what it leaves, for the command line, the pipeline and the workbench alike
(docs/adr/0006-local-web-workbench.md, docs/adr/0007-review-status-and-gate.md).

A config's models classify as mock, live or mixed by their providers, and a review runs only in the provider mode its
models have: a mixed config runs in neither. Once its reports are written, a review exits EXIT_PSIRT when an internal
PSIRT hand-off failed, which outranks EXIT_GATE for an enforced blocked gate, and 0 otherwise; EXIT_GATE is also a
usage error's code, so whether a review finished is its progress record's to say (GLOSSARY.md: Progress record).
check_paths reads the file system and load reads the config file; the rest is pure.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

import yaml

from .config import load_config

if TYPE_CHECKING:
    from .config import MaraConfig


class InvocationError(ValueError):
    """A review invocation's usage error: `param` is the option (or TARGET) at fault, as the command line names it;
    `kind` is the workbench's code for it."""

    def __init__(self, message: str, *, param: str, kind: str) -> None:
        super().__init__(message)
        self.param = param
        self.kind = kind


class ProviderMode(StrEnum):
    """`mara review --provider`: any other value is a usage error on --provider, before the config is read."""

    live = "live"
    mock = "mock"


def config_provider_mode(kinds: Iterable[str]) -> Literal["mock", "live", "mixed"]:
    """mock when every provider kind is mock, live when none is, mixed otherwise."""
    kinds = set(kinds)
    return "mock" if kinds == {"mock"} else "live" if "mock" not in kinds else "mixed"


def check_provider_mode(kinds: Iterable[str], provider_mode: str) -> None:
    """Nothing when `provider_mode` is live or mock and the provider kinds classify as it; InvocationError
    provider_mismatch on --provider otherwise."""
    if provider_mode not in tuple(ProviderMode):
        # only Pipeline.run can be given one: "mixed" would otherwise pass for a mixed config
        raise InvocationError(f"--provider {provider_mode!r}: a review's provider mode is live or mock",
                              param="--provider", kind="provider_mismatch")
    kinds = set(kinds)
    if config_provider_mode(kinds) != provider_mode:
        needs = "needs only mock models" if provider_mode == "mock" else "needs no mock model"
        raise InvocationError(f"the models' providers are {sorted(kinds)}; --provider {provider_mode} {needs}",
                              param="--provider", kind="provider_mismatch")


def default_config(provider_mode: str, root: Path) -> Path:
    """The workspace `root`'s config for a review without --config: config/mara.mock.yaml for mock, config/mara.yaml
    otherwise, whether or not the file exists."""
    return root / "config" / ("mara.mock.yaml" if provider_mode == "mock" else "mara.yaml")


def check_paths(target: Path, config: Path | None, out: Path, inputs: dict[str, Path], *, provider_mode: str, root: Path) -> Path:
    """The config file, `config` or else the workspace `root`'s default for `provider_mode`, when it, the output
    directory and `inputs` (each path by its option) lie outside `target` and it exists; reads no config.
    InvocationError inside_target on TARGET, else config_not_found on --config."""
    from .workspace import WorkspaceInsideTarget, check_outside

    config = config if config is not None else default_config(provider_mode, root)
    try:
        check_outside(target, {f"the config file {config}": config, f"the output directory {out}": out,
                               **{f"{flag} {p}": p for flag, p in inputs.items()}})
    except WorkspaceInsideTarget as e:
        raise InvocationError(str(e), param="TARGET", kind="inside_target") from e
    if not config.is_file():
        raise InvocationError(f"config file not found: {config} (run from the MARA workspace, set MARA_HOME or pass --config)",
                              param="--config", kind="config_not_found")
    return config


def load(config: Path, provider_mode: str) -> MaraConfig:
    """The config file `config`, validated (structure and policies), whose models' providers classify as
    `provider_mode`. InvocationError config_invalid on --config for a file load_config refuses, else
    check_provider_mode's provider_mismatch."""
    try:
        cfg = load_config(config)
    except (OSError, ValueError, yaml.YAMLError) as e:  # unreadable, or refused: pydantic's ValidationError is a ValueError
        raise InvocationError(" ".join(str(e).split()), param="--config", kind="config_invalid") from e
    check_provider_mode((m.provider for m in cfg.models), provider_mode)
    return cfg


# the files a review writes into its output directory: human_queue.* when the human queue is enabled,
# psirt-notifications.json when PSIRT is, context.json when the context role returned a view (roles.context set and
# source egress not blocked), progress.json when --progress-file names it there
REVIEW_ARTIFACTS = ("report.md", "report.json", "report.sarif", "pipeline.log", "context.json", "human_queue.md",
                    "human_queue.json", "psirt-notifications.json", "progress.json")

EXIT_GATE = 2  # a blocked gate that is enforced; also a usage error, which only the progress record tells apart
EXIT_PSIRT = 3  # an internal PSIRT hand-off that did not arrive


def exit_code(psirt_failed: bool, gate_enforced: bool) -> int:
    """The exit code of a review whose reports were all written: EXIT_PSIRT outranks EXIT_GATE, else 0."""
    return EXIT_PSIRT if psirt_failed else EXIT_GATE if gate_enforced else 0


def outcome(code: int, report: dict[str, Any]) -> tuple[bool, bool]:
    """(gate enforced, PSIRT hand-off failed) of a finished review, from its exit code and its report.json: the report's
    gate_enforced when it records one (the exit code cannot say, since EXIT_PSIRT outranks EXIT_GATE), else
    code == EXIT_GATE."""
    recorded = report.get("gate_enforced")
    return (recorded if isinstance(recorded, bool) else code == EXIT_GATE), code == EXIT_PSIRT


@dataclass(frozen=True)
class ReviewInvocation:
    """One call of `mara review`: a field per option, named as the command names its parameters."""

    target: Path
    config: Path
    provider: str
    out: Path
    sarif_dir: Path | None = None
    mock_fixtures: Path | None = None
    fail_on_gate: bool = False
    notify_psirt: bool = False
    psirt_event: Path | None = None
    psirt_resend: bool = False
    base: str | None = None
    calibration_sample: bool = False
    progress_file: Path | None = None


def argv(inv: ReviewInvocation) -> list[str]:
    """`mara review`'s arguments for `inv`, from "review" on: every option that is set, and none that is not."""
    args = ["review", str(inv.target), "--provider", inv.provider, "--config", str(inv.config), "--out", str(inv.out)]
    paths = (("--sarif-dir", inv.sarif_dir), ("--mock-fixtures", inv.mock_fixtures), ("--psirt-event", inv.psirt_event),
             ("--progress-file", inv.progress_file))
    for flag, p in paths:
        if p is not None:
            args += [flag, str(p)]
    if inv.base is not None:
        args.append(f"--base={inv.base}")  # one argument: the ref can never be read as an option
    flags = (("--fail-on-gate", inv.fail_on_gate), ("--notify-psirt", inv.notify_psirt), ("--psirt-resend", inv.psirt_resend),
             ("--calibration-sample", inv.calibration_sample))
    args += [flag for flag, on in flags if on]
    return args
