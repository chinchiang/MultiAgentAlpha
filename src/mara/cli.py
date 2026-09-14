from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import load_config
from .pipeline import Pipeline
from .report.markdown_out import write_markdown
from .report.sarif_out import write_sarif
from .schemas import DIMENSION_LABELS

app = typer.Typer(add_completion=False, help="MARA - Multi-Agent Review Architecture")
console = Console()


@app.command()
def review(
    target: Path = typer.Argument(..., help="Repository or directory to review"),
    config: Path = typer.Option(Path("config/mara.yaml"), "--config", "-c"),
    provider: str = typer.Option("live", "--provider", help="live | mock"),
    out: Path = typer.Option(Path("out"), "--out", "-o"),
    sarif_dir: Path | None = typer.Option(None, "--sarif-dir", help="Ingest pre-recorded L0 SARIF instead of running tools"),
    mock_fixtures: Path | None = typer.Option(None, "--mock-fixtures"),
    fail_on_gate: bool = typer.Option(False, "--fail-on-gate", help="Exit 2 when the gate blocks (implied by rollout.phase: blocking)"),
    notify_psirt: bool = typer.Option(False, "--notify-psirt", help="POST the CRA Article 14 payloads to the configured PSIRT webhook"),
    psirt_resend: bool = typer.Option(False, "--psirt-resend", help="With --notify-psirt: send even findings the ledger says were already delivered"),
):
    """Run the six-layer review and write out/report.sarif, out/report.md, out/report.json."""
    cfg_path = config
    if provider == "mock" and config == Path("config/mara.yaml") and Path("config/mara.mock.yaml").exists():
        cfg_path = Path("config/mara.mock.yaml")
    cfg = load_config(cfg_path)
    if provider == "mock" and any(m.provider != "mock" for m in cfg.models):
        raise typer.BadParameter("--provider mock requires a config whose models all use provider: mock")
    pipe = Pipeline(cfg, mock_fixtures=str(mock_fixtures) if mock_fixtures else None, out_dir=out)
    report = pipe.run(target, sarif_dir=sarif_dir, mode=provider)
    out.mkdir(parents=True, exist_ok=True)
    write_sarif(report, out / "report.sarif")
    write_markdown(report, out / "report.md")
    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "pipeline.log").write_text("\n".join(pipe.log) + "\n", encoding="utf-8")
    if cfg.human_queue.enabled:
        from .report.human_queue_out import write_human_queue

        write_human_queue(report, out)
    if cfg.psirt.enabled:
        from .report.psirt_out import send_psirt, write_psirt

        write_psirt(report.psirt, out / "psirt-notifications.json")
        if notify_psirt and report.psirt:
            for s in send_psirt(report.psirt, cfg, ledger_path=Path(cfg.psirt.ledger_file), resend=psirt_resend):
                if s.get("skipped"):
                    console.print(f"PSIRT {s['finding_id']} [{s['dedupe_key']}]: skipped, {s['reason']} (ledger {cfg.psirt.ledger_file})")
                else:
                    console.print(f"PSIRT {s['finding_id']} [{s['dedupe_key']}]: HTTP {s['status_code']} {'ok' if s['ok'] else 'FAILED'}")

    t = Table(title=f"MARA · {target} · overall {report.overall_score}/100 · gate {'PASSED' if report.gate_passed else 'BLOCKED'}")
    for col in ("Dimension", "Score", "Accepted", "Rejected", "Human", "Tool"):
        t.add_column(col)
    for d in report.dimensions:
        t.add_row(DIMENSION_LABELS[d.dimension], str(d.score), str(d.accepted_findings), str(d.rejected_findings),
                  str(d.human_queue), "yes" if d.tool_ran else "no")
    console.print(t)
    console.print(f"[bold]wrote[/bold] {out/'report.sarif'}, {out/'report.md'}, {out/'report.json'}"
                  + (f", {out/'human_queue.md'} ({len(report.human_queue)} item(s))" if cfg.human_queue.enabled else "")
                  + (f", {out/'psirt-notifications.json'} ({len(report.psirt)} PSIRT payload(s))" if cfg.psirt.enabled else ""))
    phase = cfg.rollout.phase
    if not report.gate_passed and phase != "blocking":
        console.print(f"rollout phase [bold]{phase}[/bold]: the gate would have blocked; result recorded, merge not enforced (G-10)")
    if not report.gate_passed and (fail_on_gate or phase == "blocking"):
        raise typer.Exit(code=2)


@app.command()
def cvss(vector: str):
    """Score a CVSS 4.0 vector with the FIRST-equivalent calculator."""
    from .scoring import cvss4

    s = cvss4.score(vector)
    console.print(json.dumps({"vector": vector, "score": s, "severity": cvss4.severity(s), "nomenclature": cvss4.nomenclature(vector)}))


@app.command()
def check_config(
    config: Path = typer.Argument(Path("config/mara.yaml")),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
):
    """Evaluate every configuration policy (P1-P7) and exit non-zero if any fails."""
    import yaml

    from .config import GateConfig, MaraConfig, MlBomConfig, ModelEvalConfig, ModelSpec, PsirtConfig, RolesConfig, RolloutConfig
    from .policy import evaluate_policies

    raw = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    try:
        models = [ModelSpec.model_validate(m) for m in raw.get("models", [])]
        roles = RolesConfig.model_validate(raw.get("roles", {}))
        gate = GateConfig.model_validate(raw.get("gate", {}) or {})
        psirt = PsirtConfig.model_validate(raw.get("psirt", {}) or {})
        ml_bom = MlBomConfig.model_validate(raw.get("ml_bom", {}) or {})
        rollout = RolloutConfig.model_validate(raw.get("rollout", {}) or {})
        model_eval = ModelEvalConfig.model_validate(raw.get("model_eval", {}) or {})
    except Exception as e:  # structural error: nothing to evaluate
        console.print(f"[red]invalid config structure:[/red] {e}")
        raise typer.Exit(code=1) from e
    extra = {k: v for k, v in raw.items() if k not in ("models", "roles", "gate", "psirt", "ml_bom", "rollout", "model_eval")}
    cfg = MaraConfig.model_construct(models=models, roles=roles, gate=gate, psirt=psirt, ml_bom=ml_bom, rollout=rollout,
                                     model_eval=model_eval, **extra)
    names = {m.name for m in models}
    unknown = [n for n in [roles.skeptic, roles.redteam, *roles.reviewers, *roles.judges] if n not in names]
    if unknown:
        console.print(f"[red]roles reference unknown models:[/red] {sorted(set(unknown))}")
        raise typer.Exit(code=1)
    results = evaluate_policies(cfg)
    if as_json:
        console.print(json.dumps([r.__dict__ for r in results], ensure_ascii=False, indent=1))
    else:
        t = Table(title=f"MARA policy check · {config}")
        for col in ("Policy", "Status", "Reason"):
            t.add_column(col)
        for r in results:
            t.add_row(f"{r.id} {r.name}", "[green]PASS[/green]" if r.passed else "[red]FAIL[/red]", r.reason)
        console.print(t)
    failed = [r for r in results if not r.passed]
    console.print(f"{len(results) - len(failed)}/{len(results)} policies pass; families {sorted({m.family.value for m in models})}")
    if failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
