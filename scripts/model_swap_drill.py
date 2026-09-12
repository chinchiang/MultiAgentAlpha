"""G-4: cold-standby configurations and model-swap drills.

  python3 scripts/model_swap_drill.py check [--config config/mara.yaml]
      per production family: standby config present and loadable, last live drill; exit 1 when G-4 fails.
  python3 scripts/model_swap_drill.py rehearse --standby config/examples/standby-for-deepseek.yaml
      load the standby config through the policies, confirm it swaps exactly one family, then run the
      pipeline on the seeded fixture with every model switched to the mock provider to prove the
      process (roles, dimensions, gate) is unchanged; appends a `rehearsal` entry. Does NOT satisfy G-4.
  python3 scripts/model_swap_drill.py record --replaced deepseek --standby-config config/examples/standby-for-deepseek.yaml \\
      --started 2026-10-01T09:00 --completed 2026-10-03T15:00 --outcome pass --performed-by <login> --evidence CHG-123
      a live drill on the real endpoints; appends a `live` entry (the one G-4 counts).
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara import govdocs  # noqa: E402
from mara.config import MaraConfig, load_config  # noqa: E402

DRILLS = ROOT / "ops" / "model-swap-drills.yaml"


def cmd_check(a: argparse.Namespace) -> int:
    cfg = load_config(a.config)
    ok = True
    for st in govdocs.drill_status(cfg, ROOT, a.today, a.drills):
        cfg_line = f"standby {st.standby_config} → {st.standby_family}" if st.config_ok else f"standby: {st.config_problem}"
        drill_line = (f"live drill {st.drill.date} {st.drill.duration_hours:g} h {st.drill.outcome}" if st.drill_ok and st.drill else st.drill_problem)
        print(f"{st.family}: {'OK' if st.ok else 'MISSING'} — {cfg_line}; {drill_line}")
        ok &= st.ok
    print("G-4: " + ("PASS" if ok else "FAIL (every production family needs a loadable standby config and a passed live drill within a week)"))
    return 0 if ok else 1


def _mockify(cfg_path: Path) -> Path:
    """Copy of a standby config with every model on the mock provider (same names, families, roles)."""
    import yaml

    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    for m in raw["models"]:
        m["provider"] = "mock"
        m["model"] = f"mock-{m['family']}"
        for k in ("base_url", "api_key_env", "data_residency"):
            m.pop(k, None)
    tmp = Path(tempfile.mkdtemp(prefix="mara-rehearsal-")) / "standby.mock.yaml"
    tmp.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return tmp


def cmd_rehearse(a: argparse.Namespace) -> int:
    from mara.pipeline import Pipeline

    prod = load_config(a.config)
    prod_fams = govdocs.production_families(prod)
    replaced = str(a.replaced or (govdocs.read_front_matter(a.standby)[0].get("standby_for") if a.standby.suffix == ".md" else "") or "")
    if not replaced:
        import yaml

        replaced = str((yaml.safe_load(a.standby.read_text(encoding="utf-8")) or {}).get("standby_for", ""))
    if replaced not in prod_fams:
        print(f"ERROR: standby_for={replaced!r} is not a production family {prod_fams}", file=sys.stderr)
        return 2
    sb_fam, problem = govdocs._standby_family_of(prod_fams, a.standby, replaced)
    if problem:
        print(f"ERROR: {a.standby}: {problem}", file=sys.stderr)
        return 2
    print(f"standby config loads through P1-P7; replaces {replaced} with {sb_fam}")
    mock_cfg = MaraConfig.model_validate(__import__("yaml").safe_load(_mockify(a.standby).read_text(encoding="utf-8")))
    started = dt.datetime.now(dt.UTC)
    pipe = Pipeline(mock_cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=Path(tempfile.mkdtemp(prefix="mara-rehearsal-out-")))
    report = pipe.run(ROOT / "fixtures" / "vuln-sample", sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", mode="mock")
    same_dims = [d.dimension for d in report.dimensions] == list(prod.dimensions)
    print(f"mock review on the standby panel: {len(report.findings)} findings, gate {'passed' if report.gate_passed else 'blocked'}, "
          f"families {report.families_used}, dimensions unchanged: {same_dims}")
    outcome = "pass" if same_dims and report.findings else "fail"
    hours = round((dt.datetime.now(dt.UTC) - started).total_seconds() / 3600, 3)
    drill = govdocs.Drill(a.today, "rehearsal", replaced, sb_fam, str(a.standby.relative_to(ROOT)) if a.standby.is_relative_to(ROOT) else str(a.standby),
                          max(hours, 0.001), outcome, a.performed_by or "rehearsal", "mock review of fixtures/vuln-sample")
    govdocs.append_drill(a.drills, drill)
    print(f"rehearsal recorded in {a.drills} ({outcome}); a live drill on the real endpoints is still needed for G-4")
    return 0 if outcome == "pass" else 1


def cmd_record(a: argparse.Namespace) -> int:
    started, completed = dt.datetime.fromisoformat(a.started), dt.datetime.fromisoformat(a.completed)
    if completed <= started:
        print("ERROR: completed must be after started", file=sys.stderr)
        return 2
    hours = round((completed - started).total_seconds() / 3600, 2)
    prod = load_config(a.config)
    sb_fam, problem = govdocs._standby_family_of(govdocs.production_families(prod), a.standby_config, a.replaced)
    if problem:
        print(f"ERROR: {a.standby_config}: {problem}", file=sys.stderr)
        return 2
    rel = str(a.standby_config.relative_to(ROOT)) if a.standby_config.is_relative_to(ROOT) else str(a.standby_config)
    drill = govdocs.Drill(completed.date(), "live", a.replaced, sb_fam, rel, hours, a.outcome, a.performed_by, a.evidence)
    govdocs.append_drill(a.drills, drill)
    verdict = "counts for G-4" if a.outcome == "pass" and hours <= govdocs.DRILL_MAX_HOURS else f"does not satisfy G-4 (needs pass within {govdocs.DRILL_MAX_HOURS} h)"
    print(f"live drill recorded: {a.replaced}→{sb_fam} {hours} h {a.outcome}; {verdict}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "mara.yaml")
    ap.add_argument("--drills", type=Path, default=DRILLS)
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today())
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    s = sub.add_parser("rehearse")
    s.add_argument("--standby", type=Path, required=True)
    s.add_argument("--replaced", help="production family replaced (default: standby_for in the config)")
    s.add_argument("--performed-by", default="")
    s = sub.add_parser("record")
    s.add_argument("--replaced", required=True)
    s.add_argument("--standby-config", type=Path, required=True)
    s.add_argument("--started", required=True, help="ISO datetime the swap decision was taken")
    s.add_argument("--completed", required=True, help="ISO datetime the pipeline reviewed a real PR on the standby")
    s.add_argument("--outcome", required=True, choices=["pass", "fail"])
    s.add_argument("--performed-by", required=True)
    s.add_argument("--evidence", required=True)
    a = ap.parse_args()
    try:
        return {"check": cmd_check, "rehearse": cmd_rehearse, "record": cmd_record}[a.cmd](a)
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
