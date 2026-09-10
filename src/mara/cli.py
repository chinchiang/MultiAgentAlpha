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
    fail_on_gate: bool = typer.Option(False, "--fail-on-gate", help="Exit 2 when the gate blocks"),
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

    t = Table(title=f"MARA · {target} · overall {report.overall_score}/100 · gate {'PASSED' if report.gate_passed else 'BLOCKED'}")
    for col in ("Dimension", "Score", "Accepted", "Rejected", "Human", "Tool"):
        t.add_column(col)
    for d in report.dimensions:
        t.add_row(DIMENSION_LABELS[d.dimension], str(d.score), str(d.accepted_findings), str(d.rejected_findings),
                  str(d.human_queue), "yes" if d.tool_ran else "no")
    console.print(t)
    console.print(f"[bold]wrote[/bold] {out/'report.sarif'}, {out/'report.md'}, {out/'report.json'}")
    if fail_on_gate and not report.gate_passed:
        raise typer.Exit(code=2)


@app.command()
def cvss(vector: str):
    """Score a CVSS 4.0 vector with the FIRST-equivalent calculator."""
    from .scoring import cvss4

    s = cvss4.score(vector)
    console.print(json.dumps({"vector": vector, "score": s, "severity": cvss4.severity(s), "nomenclature": cvss4.nomenclature(vector)}))


@app.command()
def check_config(config: Path = typer.Argument(Path("config/mara.yaml"))):
    """Validate family-diversity and data-residency rules."""
    cfg = load_config(config)
    console.print(f"ok: {len(cfg.models)} models, families {sorted({m.family.value for m in cfg.models})}")


if __name__ == "__main__":
    app()
