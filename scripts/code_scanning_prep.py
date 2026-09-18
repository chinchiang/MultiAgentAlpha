"""Prepare the L0 SARIF files for one upload to GitHub Code Scanning.

  python3 scripts/code_scanning_prep.py --out code-scanning [--workspace .] semgrep=semgrep.sarif osv=osv.sarif ...

Each `tool=path` names one SARIF produced by the L0 job for the real repository (never the fixture
scans and never the mock review report, which describe seeded material). For every run in a file:
  - results with an accepted suppression are dropped: they are triaged findings whose
    reason lives in the repository (tools/semgrep-triage.yaml, tools/osv-scanner.toml) and must not
    reappear as alerts, whatever GitHub does with the suppressions property;
  - results without a physical location are dropped (Code Scanning needs a file to attach an alert to);
  - `artifactLocation.uri` is made repository-relative (`./` prefix, `file://` scheme and the workspace
    path removed);
  - `runs[].automationDetails.id` is set to `mara-l0/<tool>/`, the category Code Scanning uses to keep
    the five analyses apart and to close an earlier alert when a later upload no longer reports it.
A missing input file is skipped with a note (gitleaks writes no report on a clean scan). A file with
more than 25 000 results or larger than 10 MB is refused (GitHub's limits) -> exit 2. If nothing at
all was written -> exit 1 (there is nothing to upload; the L0 job died before producing SARIF).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MAX_RESULTS = 25_000
MAX_BYTES = 10 * 1024 * 1024


def relative_uri(uri: str, workspace: Path) -> str:
    u = uri
    if u.startswith("file://"):
        u = u[len("file://"):]
    ws = workspace.resolve().as_posix().rstrip("/") + "/"
    if u.startswith(ws):
        u = u[len(ws):]
    while u.startswith("./"):
        u = u[2:]
    return u


def prepare_run(run: dict, tool: str, workspace: Path) -> dict:
    """Returns counters; mutates the run."""
    kept, suppressed, unlocated = [], 0, 0
    for r in run.get("results", []):
        if any(s.get("status") == "accepted" for s in r.get("suppressions", [])):
            suppressed += 1
            continue
        locs = r.get("locations") or []
        phys = locs[0].get("physicalLocation", {}) if locs else {}
        uri = phys.get("artifactLocation", {}).get("uri")
        if not uri:
            unlocated += 1
            continue
        for loc in locs:
            al = loc.get("physicalLocation", {}).get("artifactLocation", {})
            if al.get("uri"):
                al["uri"] = relative_uri(al["uri"], workspace)
        kept.append(r)
    run["results"] = kept
    run["automationDetails"] = {"id": f"mara-l0/{tool}/"}
    driver = run.setdefault("tool", {}).setdefault("driver", {})
    driver.setdefault("name", tool)
    return {"kept": len(kept), "suppressed": suppressed, "unlocated": unlocated}


def prepare_file(tool: str, src: Path, out_dir: Path, workspace: Path) -> dict:
    doc = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise ValueError(f"{src}: not a SARIF document (no runs[])")
    doc.setdefault("version", "2.1.0")
    doc.setdefault("$schema", "https://json.schemastore.org/sarif-2.1.0.json")
    totals = {"kept": 0, "suppressed": 0, "unlocated": 0}
    for run in doc["runs"]:
        c = prepare_run(run, tool, workspace)
        for k in totals:
            totals[k] += c[k]
    text = json.dumps(doc, indent=1, sort_keys=True) + "\n"
    out = out_dir / f"{tool}.sarif"
    out.write_text(text, encoding="utf-8")
    totals["bytes"] = len(text.encode("utf-8"))
    totals["path"] = str(out)
    return totals


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=Path("code-scanning"))
    ap.add_argument("--workspace", type=Path, default=Path("."))
    ap.add_argument("inputs", nargs="+", metavar="TOOL=PATH")
    a = ap.parse_args()

    a.out.mkdir(parents=True, exist_ok=True)
    written, problems = 0, 0
    for item in a.inputs:
        if "=" not in item:
            print(f"ERROR: expected TOOL=PATH, got {item!r}", file=sys.stderr)
            return 2
        tool, path = item.split("=", 1)
        tool = tool.strip().lower()
        src = Path(path)
        if not tool or "/" in tool or "\\" in tool:
            print(f"ERROR: bad tool name {tool!r}", file=sys.stderr)
            return 2
        if not src.is_file():
            why = " (a clean gitleaks scan writes no report)" if tool == "gitleaks" else ""
            print(f"{tool:<10} skipped: {src} does not exist{why}")
            continue
        try:
            t = prepare_file(tool, src, a.out, a.workspace)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        flag = ""
        if t["kept"] > MAX_RESULTS or t["bytes"] > MAX_BYTES:
            flag = "  REFUSED (over GitHub's 25 000 results / 10 MB limit)"
            problems += 1
            Path(t["path"]).unlink()
        else:
            written += 1
        print(f"{tool:<10} results {t['kept']:>5}  dropped: {t['suppressed']} suppressed, {t['unlocated']} without location  "
              f"{t['bytes']:>8} bytes  category mara-l0/{tool}/{flag}")
    if problems:
        return 2
    if not written:
        print("ERROR: no SARIF prepared; nothing to upload", file=sys.stderr)
        return 1
    print(f"{written} file(s) ready under {a.out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
