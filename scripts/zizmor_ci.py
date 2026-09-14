"""Audit GitHub workflows with the zizmor pinned in tools/versions.lock and keep the SARIF (replaces zizmor-action).

  python3 scripts/zizmor_ci.py --target .github/workflows [--report zizmor.sarif] [--persona regular|auditor|pedantic] [--offline]

The binary comes only from MARA_TOOLS_DIR/bin (scripts/install_tools.py: SHA-256 and GitHub attestation
verified), never from PATH, and its manifest version must equal the lock. zizmor is run with
`--format sarif`, which exits 0 even when it has findings (measured on the seeded fixture with 1.30.1),
so the verdict is taken from the SARIF itself: any result -> exit 2 (the job fails), zizmor crashed or
wrote no SARIF -> exit 1, clean -> exit 0. Without --offline zizmor also runs its online audits
(impostor commits, ref confusion, known-vulnerable actions) and needs GH_TOKEN in the environment; CI
passes the workflow token, local runs behind a proxy use --offline.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools.runner import installed_version, tool_path, tools_dir  # noqa: E402

PERSONAS = ("regular", "auditor", "pedantic")


def locked_version(lock: Path = ROOT / "tools" / "versions.lock") -> str:
    import yaml

    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    return str(d.get("tools", d).get("zizmor", {}).get("version", ""))


def summarize(doc: dict) -> list[dict]:
    rows = []
    for run in doc.get("runs", []):
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            rows.append({"rule": r.get("ruleId", "?"), "level": r.get("level", "?"),
                         "uri": loc.get("artifactLocation", {}).get("uri", "?"),
                         "line": loc.get("region", {}).get("startLine", "?"),
                         "text": " ".join(str(r.get("message", {}).get("text", "")).split())})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=Path, default=Path(".github/workflows"))
    ap.add_argument("--report", type=Path, default=Path("zizmor.sarif"))
    ap.add_argument("--persona", default="regular", choices=PERSONAS)
    ap.add_argument("--offline", action="store_true", help="skip zizmor's online audits (no GitHub API calls)")
    a = ap.parse_args()

    exe = tool_path("zizmor")
    if exe is None:
        print(f"ERROR: zizmor is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)", file=sys.stderr)
        return 2
    want, have = locked_version(), installed_version("zizmor")
    if not want or have != want:
        print(f"ERROR: installed zizmor {have!r} does not match tools/versions.lock {want!r}; re-run scripts/install_tools.py", file=sys.stderr)
        return 2
    if not a.target.exists():
        print(f"ERROR: target {a.target} does not exist", file=sys.stderr)
        return 2
    print(f"zizmor {have} from {exe} (lock {want}); persona {a.persona}; {'offline' if a.offline else 'online audits enabled'}")

    argv = [str(exe), "--no-progress", "--format", "sarif", "--persona", a.persona]
    if a.offline:
        argv.append("--offline")
    argv.append(str(a.target))
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    for line in r.stderr.strip().splitlines()[-8:]:
        print("  " + line)
    if r.returncode != 0 or not r.stdout.strip():
        print(f"ERROR: zizmor exited {r.returncode} without a SARIF document (crash, not a clean audit)", file=sys.stderr)
        return 1
    try:
        doc = json.loads(r.stdout)
    except ValueError as e:
        print(f"ERROR: zizmor output is not JSON: {e}", file=sys.stderr)
        return 1
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(r.stdout, encoding="utf-8")
    rows = summarize(doc)
    if rows:
        print(f"FINDINGS: {len(rows)} (any finding fails the job; fix the workflow, do not suppress)")
        for row in rows:
            print(f"  {row['rule']}  {row['level']}  {row['uri']}:{row['line']}  {row['text'][:120]}")
        return 2
    print(f"clean: zizmor reported no findings on {a.target} ({a.report} written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
