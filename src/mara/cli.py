from __future__ import annotations

import json
import os
from pathlib import Path
from typing import cast

import typer
from rich.console import Console
from rich.table import Table
from typer.core import TyperGroup

from .config import MaraConfig
from .invocation import InvocationError, ProviderMode, check_paths, default_config, exit_code, load
from .pipeline import Pipeline
from .progress import Progress
from .report.markdown_out import enforcement_wording, write_markdown
from .report.sarif_out import write_sarif
from .schemas import DIMENSION_LABELS, ReviewReport

app = typer.Typer(add_completion=False,
                  help="MARA - Multi-Agent Review Architecture. `mara` alone starts the local web workbench, as `mara serve` does.")
console = Console()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Without a command, start the workbench as `mara serve` with no options does."""
    if ctx.invoked_subcommand is None:
        # serve's own command parses an empty argument list, so its options' defaults are the ones used (ctx.invoke on
        # the command would parse sys.argv; on the bare function it would pass Typer's OptionInfo objects as the values)
        serve_cmd = cast(TyperGroup, ctx.command).commands["serve"]
        with serve_cmd.make_context("serve", [], parent=ctx) as sub:
            serve_cmd.invoke(sub)


@app.command()
def review(
    target: Path = typer.Argument(..., help="Repository or directory to review"),
    config: Path | None = typer.Option(None, "--config", "-c", show_default=False,
                                       help="default: <workspace>/config/mara.yaml (config/mara.mock.yaml with --provider mock)"),
    provider: ProviderMode = typer.Option(ProviderMode.live, "--provider"),
    out: Path | None = typer.Option(None, "--out", "-o", show_default=False, help="default: <workspace>/out"),
    sarif_dir: Path | None = typer.Option(None, "--sarif-dir", help="Ingest pre-recorded L0 SARIF instead of running tools"),
    mock_fixtures: Path | None = typer.Option(None, "--mock-fixtures"),
    fail_on_gate: bool = typer.Option(False, "--fail-on-gate", help="Exit 2 when the gate blocks (implied by rollout.phase: blocking)"),
    notify_psirt: bool = typer.Option(False, "--notify-psirt", help="POST internal PSIRT hand-off payloads to the configured PSIRT webhook"),
    psirt_event: Path | None = typer.Option(None, "--psirt-event", help="PSIRT-confirmed incident event JSON for legal clock anchors"),
    psirt_resend: bool = typer.Option(False, "--psirt-resend", help="With --notify-psirt: send even findings the ledger says were already delivered"),
    base: str | None = typer.Option(None, "--base",
                                    help="Incremental review: files changed since this git ref, plus import neighbours, manifests and workflows"),
    calibration_sample: bool = typer.Option(False, "--calibration-sample",
                                            help="The target is a labelled sample under <workspace>/calib/samples/: the secrets its "
                                                 "answer key declares (CWE-798) do not block live egress; any other secret still does"),
    progress_file: Path | None = typer.Option(None, "--progress-file",
                                              help="Write the review's live progress (stages, log lines) to this JSON file; `mara serve` reads it"),
):
    """Run the six-layer review and write out/report.sarif, out/report.md, out/report.json."""
    from .workspace import resolve, root

    # The defaults are MARA's own files, so they resolve against the workspace (MARA_HOME, else the working
    # directory) like every other trust anchor: with MARA_HOME set and the job running inside the target,
    # a relative default would let the reviewed repository supply the config (models, endpoints, gate).
    cfg_path = config if config is not None else default_config(provider.value, root())
    out = out if out is not None else resolve("out")
    try:
        # before the config is even read; the pipeline repeats the workspace, tool and trivy checks
        # pre-recorded SARIF is tool evidence, mock fixtures are the models' answers and a PSIRT event
        # starts legal clocks: from inside the target, the reviewed repository would supply its own verdict
        # the progress file is an output: inside the target it would be bundled into the next review
        inputs = {"--sarif-dir": sarif_dir, "--mock-fixtures": mock_fixtures, "--psirt-event": psirt_event, "--progress-file": progress_file}
        check_paths(target, cfg_path, out, {flag: p for flag, p in inputs.items() if p is not None})
    except InvocationError as e:
        raise typer.BadParameter(str(e), param_hint=e.param) from e
    progress = Progress(progress_file)  # a no-op without --progress-file
    try:
        report, cfg, psirt_failed = _review(target, cfg_path, provider.value, out, sarif_dir, mock_fixtures, fail_on_gate, notify_psirt,
                                            psirt_event, psirt_resend, base, calibration_sample, progress)
    except BaseException as e:
        # the reports were not all written: the workbench must not read a usage error's exit 2 as a blocked gate
        progress.finish(ok=False, error=type(e).__name__)
        raise
    progress.finish(ok=True)
    # an internal hand-off that did not arrive is an operational failure (EU CRA Article 14 clocks may depend on it):
    # never a green run, and its 3 outranks an enforced gate's 2. The reports are written either way.
    # G-10: whether a blocked gate is enforced (the blocking phase, or --fail-on-gate) was decided by mara.review_status
    # and recorded in report.json; the gate's message says which, and the exit code the command ends with
    code = exit_code(psirt_failed, bool(report.gate_enforced))
    if psirt_failed:
        why = ": the PSIRT hand-off failed" + (", which outranks the gate" if report.gate_enforced else "")
    else:
        why = "" if report.gate_enforced else ", G-10"
    if not report.gate_passed:
        console.print(f"rollout phase [bold]{cfg.rollout.phase}[/bold]: the gate blocked: "
                      f"{enforcement_wording(bool(report.gate_enforced))} (exit {code}{why})")
    if psirt_failed:
        console.print("[bold red]PSIRT hand-off failed for at least one finding; see the ledger and retry with --notify-psirt[/bold red]")
    if code:
        raise typer.Exit(code=code)


def _review(target: Path, cfg_path: Path, provider: str, out: Path, sarif_dir: Path | None, mock_fixtures: Path | None,
            fail_on_gate: bool, notify_psirt: bool, psirt_event: Path | None, psirt_resend: bool, base: str | None,
            calibration_sample: bool, progress: Progress) -> tuple[ReviewReport, MaraConfig, bool]:
    """Load the config, run the review and write every report; returns (report, config, PSIRT send failed)."""
    from .workspace import WorkspaceInsideTarget, resolve

    try:
        cfg = load(cfg_path, provider)
    except InvocationError as e:
        raise typer.BadParameter(str(e), param_hint=e.param) from e
    pipe = Pipeline(cfg, mock_fixtures=str(mock_fixtures) if mock_fixtures else None, out_dir=out, progress=progress)
    event = None
    if psirt_event:
        # read before the review, and handed to it: the notifications are built once, and the report's psirt holds these
        try:
            event = json.loads(psirt_event.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise typer.BadParameter(f"{psirt_event}: not a readable JSON event ({type(e).__name__})", param_hint="--psirt-event") from e
    try:
        report = pipe.run(target, sarif_dir=sarif_dir, provider_mode=provider, base_ref=base, calibration_sample=calibration_sample,
                          psirt_event=event, fail_on_gate=fail_on_gate)
    except WorkspaceInsideTarget as e:
        raise typer.BadParameter(str(e), param_hint="TARGET") from e
    except ValueError as e:
        # a broken base ref or an ineligible calibration target is a usage error, not an empty review
        if base is not None or calibration_sample:
            raise typer.BadParameter(str(e), param_hint="--base" if base is not None else "--calibration-sample") from e
        raise
    out.mkdir(parents=True, exist_ok=True)
    write_sarif(report, out / "report.sarif")
    write_markdown(report, out / "report.md")
    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "pipeline.log").write_text("\n".join(pipe.log) + "\n", encoding="utf-8")
    if cfg.human_queue.enabled:
        from .report.human_queue_out import write_human_queue

        write_human_queue(report, out)
    psirt_failed = False
    if cfg.psirt.enabled:
        from .report.psirt_out import send_psirt, write_psirt

        write_psirt(report.psirt, out / "psirt-notifications.json")
        if notify_psirt and report.psirt:
            for s in send_psirt(report.psirt, cfg, ledger_path=resolve(cfg.psirt.ledger_file), resend=psirt_resend):
                if s.get("skipped"):
                    console.print(f"PSIRT {s['finding_id']} [{s['dedupe_key']}]: skipped, {s['reason']} (ledger {cfg.psirt.ledger_file})")
                else:
                    psirt_failed |= not s["ok"]
                    status = f"HTTP {s['status_code']}" if s["status_code"] is not None else s.get("error", "no response")
                    console.print(f"PSIRT {s['finding_id']} [{s['dedupe_key']}]: {status} {'ok' if s['ok'] else 'FAILED'}")

    overall = f"{report.overall_score}/100" if report.overall_score is not None else "unavailable (review incomplete)"
    t = Table(title=f"MARA · {target} · overall {overall} · gate {'PASSED' if report.gate_passed else 'BLOCKED'}")
    for col in ("Dimension", "Score", "Accepted", "Rejected", "Awaiting decision", "Tool"):
        t.add_column(col)
    for d in report.dimensions:
        t.add_row(DIMENSION_LABELS[d.dimension], str(d.score), str(d.accepted_findings), str(d.rejected_findings),
                  str(d.human_queue), "yes" if d.tool_ran else "no")
    console.print(t)
    if report.gate_reasons:
        console.print(f"gate reasons: {', '.join(report.gate_reasons)}")
    console.print(f"[bold]wrote[/bold] {out/'report.sarif'}, {out/'report.md'}, {out/'report.json'}"
                  + (f", {out/'human_queue.md'} ({len(report.human_queue)} item(s))" if cfg.human_queue.enabled else "")
                  + (f", {out/'psirt-notifications.json'} ({len(report.psirt)} PSIRT payload(s))" if cfg.psirt.enabled else ""))
    return report, cfg, psirt_failed


@app.command()
def export_summary(
    report: Path = typer.Argument(..., exists=True, dir_okay=False, help="report.json written by mara review"),
    out: Path | None = typer.Option(None, "--out", "-o", show_default=False, help="default: <workspace>/out/score-summary.json"),
    label: str | None = typer.Option(None, "--label", help="Target name for the receiving team, chosen by the operator (one line, 1-80 chars)"),
    allow_mock: bool = typer.Option(False, "--allow-mock", help="Export a mock-mode report (tests and demonstrations only)"),
):
    """Write the score summary of a review report: dimension scores and overall score, no finding detail (CN-3).
    The target and revision cross only as pseudonyms keyed by MARA_SUMMARY_KEY, which stays in the country."""
    from .report.summary_out import SummaryRefused, build_summary, check_destination, load_report, write_summary
    from .workspace import resolve

    out = out if out is not None else resolve("out/score-summary.json")
    try:
        source = report.read_bytes()
    except OSError as e:
        raise typer.BadParameter(f"cannot read {report} ({type(e).__name__})", param_hint="REPORT") from e
    try:
        parsed = load_report(source)
        check_destination(out, report, parsed)
        summary = build_summary(parsed, source, key=os.environ.get("MARA_SUMMARY_KEY", ""), label=label, allow_mock=allow_mock)
    except SummaryRefused as e:
        raise typer.BadParameter(str(e), param_hint=e.param_hint) from e
    write_summary(summary, out)
    console.print(f"[bold]wrote[/bold] {out}")


@app.command()
def cvss(vector: str):
    """Score a CVSS 4.0 vector with the FIRST-equivalent calculator."""
    from .scoring import cvss4

    try:
        s = cvss4.score(vector)
    except cvss4.CVSS4Error as e:
        raise typer.BadParameter(str(e), param_hint="VECTOR") from e
    # JSON goes to stdout as is: the rich console would colour it and wrap long strings, which breaks a parser
    typer.echo(json.dumps({"vector": vector, "score": s, "severity": cvss4.severity(s), "nomenclature": cvss4.nomenclature(vector)}))


@app.command()
def check_config(
    config: Path | None = typer.Argument(None, show_default=False, help="default: <workspace>/config/mara.yaml"),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Evaluate every configuration policy (P1-P8) and exit non-zero if any fails."""
    import yaml

    from .config import MaraConfig
    from .policy import evaluate_policies
    from .workspace import resolve

    config = config if config is not None else resolve("config/mara.yaml")
    if not config.is_file():
        raise typer.BadParameter(f"config file not found: {config} (run from the MARA workspace, set MARA_HOME or pass the path)",
                                 param_hint="CONFIG")
    raw = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    # Full structural validation (fields, cross-field checks, unknown keys) so check-config can
    # never report "policies pass" for a file load_config would refuse; policies are rendered
    # separately afterwards instead of failing the whole validation.
    try:
        cfg = MaraConfig.model_validate(raw, context={"skip_policies": True})
    except Exception as e:  # structural error: nothing to evaluate
        console.print(f"[red]invalid config structure:[/red] {e}")
        raise typer.Exit(code=1) from e
    results = evaluate_policies(cfg)
    if as_json:
        typer.echo(json.dumps([r.__dict__ for r in results], ensure_ascii=False, indent=1))
    else:
        t = Table(title=f"MARA policy check · {config}")
        for col in ("Policy", "Status", "Reason"):
            t.add_column(col)
        for r in results:
            t.add_row(f"{r.id} {r.name}", "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]", r.reason)
        console.print(t)
    failed = [r for r in results if not r.passed]
    summary = f"{len(results) - len(failed)}/{len(results)} policies pass; families {sorted({m.family.value for m in cfg.models})}"
    if as_json:
        typer.echo(summary, err=True)  # stdout stays one JSON document
    else:
        console.print(summary)
    if failed:
        raise typer.Exit(code=1)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Loopback address to listen on: 127.0.0.1, localhost or ::1"),
    port: int = typer.Option(8765, "--port", min=0, max=65535, help="TCP port; 0 picks a free one"),
    out: Path | None = typer.Option(None, "--out", "-o", show_default=False,
                                    help="Where runs and jobs are kept (runs/<id>/, jobs/<id>/); default: <workspace>/out"),
    no_browser: bool = typer.Option(False, "--no-browser", help="Print the URL without opening a browser"),
):
    """Start the local web workbench: launch reviews, follow their stages, read findings, roles and models, check the tools.
    Loopback only; the printed URL carries this server's session token (docs/adr/0006-local-web-workbench.md)."""
    from .web.server import LOOPBACK_HOSTS
    from .web.server import serve as run_server
    from .workspace import resolve, root

    if host not in LOOPBACK_HOSTS:
        # finding detail must stay where the review ran (CN-3); reach a remote workbench through an SSH tunnel instead
        raise typer.BadParameter(f"{host}: the workbench listens on a loopback address only ({', '.join(LOOPBACK_HOSTS)}); "
                                 "use an SSH tunnel (ssh -L 8765:127.0.0.1:8765 host) to open it from another machine",
                                 param_hint="--host")
    try:
        run_server(host=host, port=port, workspace=root(), out_dir=out if out is not None else resolve("out"), open_browser=not no_browser,
                   echo=console.print)
    except OSError as e:
        console.print(f"[red]cannot listen on {host}:{port}:[/red] {e}")
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    app()
