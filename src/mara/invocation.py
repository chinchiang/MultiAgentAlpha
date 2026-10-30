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
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

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


def check_provider_mode(kinds: Iterable[str], provider_mode: ProviderMode) -> None:
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


def default_config(provider_mode: ProviderMode, root: Path) -> Path:
    """The workspace `root`'s config for a review without --config: config/mara.mock.yaml for mock, config/mara.yaml
    otherwise, whether or not the file exists."""
    return root / "config" / ("mara.mock.yaml" if provider_mode == "mock" else "mara.yaml")


def check_paths(inv: ReviewInvocation, root: Path) -> Path:
    """The config file of `inv`, its config or else the workspace `root`'s default for its provider mode, when it, the
    output directory and the path options that are set lie outside the target and it exists; reads no config.
    InvocationError inside_target on TARGET, else config_not_found on --config."""
    from .workspace import WorkspaceInsideTarget, check_outside

    config = inv.config if inv.config is not None else default_config(inv.provider, root)
    try:
        check_outside(inv.target, {f"the config file {config}": config, f"the output directory {inv.out}": inv.out,
                                   **{f"{flag} {p}": p for flag, p in path_options(inv).items()}})
    except WorkspaceInsideTarget as e:
        raise InvocationError(str(e), param="TARGET", kind="inside_target") from e
    if not config.is_file():
        raise InvocationError(f"config file not found: {config} (run from the MARA workspace, set MARA_HOME or pass --config)",
                              param="--config", kind="config_not_found")
    return config


def load(config: Path, provider_mode: ProviderMode) -> MaraConfig:
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


class FinishedReview(NamedTuple):
    """What a finished review's exit code and report.json say about it beside its reports."""

    gate_enforced: bool
    psirt_failed: bool


def outcome(code: int, report: dict[str, Any]) -> FinishedReview:
    """Whether a finished review's gate was enforced and its PSIRT hand-off failed, from its exit code and its
    report.json: the report's gate_enforced when it records one (the exit code cannot say, since EXIT_PSIRT outranks
    EXIT_GATE), else code == EXIT_GATE."""
    recorded = report.get("gate_enforced")
    return FinishedReview(gate_enforced=recorded if isinstance(recorded, bool) else code == EXIT_GATE, psirt_failed=code == EXIT_PSIRT)


@dataclass(frozen=True)
class ReviewInvocation:
    """One call of `mara review`: a field per option, named as the command names its parameters, the option's flag
    being the name with dashes (`option`); no config is the provider mode's default (check_paths)."""

    target: Path
    config: Path | None
    provider: ProviderMode
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


# the options naming a file or directory other than the config and the output directory: evidence inputs, which the
# reviewed repository must not supply, and the progress file, an output that would be bundled into the next review
PATH_OPTIONS = ("sarif_dir", "mock_fixtures", "psirt_event", "progress_file")


def option(field: str) -> str:
    """The flag of ReviewInvocation's `field`: "sarif_dir" is --sarif-dir."""
    return "--" + field.replace("_", "-")


def path_options(inv: ReviewInvocation) -> dict[str, Path]:
    """The path options of `inv` that are set, each by its flag, in PATH_OPTIONS' order."""
    paths = {option(f): getattr(inv, f) for f in PATH_OPTIONS}
    return {flag: p for flag, p in paths.items() if p is not None}


def review_args(inv: ReviewInvocation) -> list[str]:
    """`mara review`'s arguments for `inv`, from "review" on: every option that is set, and none that is not."""
    args = ["review", str(inv.target), "--provider", inv.provider]
    if inv.config is not None:
        args += ["--config", str(inv.config)]
    args += ["--out", str(inv.out)]
    for flag, p in path_options(inv).items():
        args += [flag, str(p)]
    if inv.base is not None:
        args.append(f"--base={inv.base}")  # one argument: the ref can never be read as an option
    flags = (("--fail-on-gate", inv.fail_on_gate), ("--notify-psirt", inv.notify_psirt), ("--psirt-resend", inv.psirt_resend),
             ("--calibration-sample", inv.calibration_sample))
    args += [flag for flag, on in flags if on]
    return args
