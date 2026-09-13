"""Known-vulnerability and misconfiguration scan with the trivy pinned in tools/versions.lock and the offline
database recorded by scripts/trivy_db.py, for CI (L0 job) and local use.

  python3 scripts/trivy_ci.py --target fixtures/vuln-sample --report fixture-trivy.sarif --expect-package requests
      scan the seeded fixture and require the named package to be reported vulnerable (requests==2.19.0).
  python3 scripts/trivy_ci.py --target . --report trivy.sarif --ignorefile tools/trivyignore.yaml --skip-dirs fixtures,calib/samples
      scan the repository (the hash-locked closures under tools/ are matched through --file-patterns); any
      vulnerability or misconfiguration not ignored in the ignore file (statement + expired_at) exits 2.

trivy comes only from MARA_TOOLS_DIR/bin (version must equal the lock) and runs `fs` with
--skip-db-update --skip-java-db-update --skip-check-update --offline-scan against the database under
MARA_TRIVY_CACHE_DIR: scripts/trivy_db.py status must pass first (fresh, matching its record), and the
scan never opens a network connection. Exit 0 ok, 2 findings (or expected package missing) or unusable
database, 1 trivy crashed or wrote no SARIF.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from trivy_db import PinError, load_config, pinned_trivy  # noqa: E402

from mara.tools import trivy_db as tdb  # noqa: E402

# result.message.text: "Package: requests Installed Version: 2.19.0 Vulnerability CVE-2018-18074 Severity: HIGH ..."
# misconfig:            "Artifact: Dockerfile Type: dockerfile Vulnerability DS-0001 Severity: MEDIUM Message: ..."
PKG_RE = re.compile(r"Package:\s+(?P<name>\S+)\s+Installed Version:\s+(?P<version>\S+)")
ART_RE = re.compile(r"Artifact:\s+(?P<name>\S+)\s+Type:\s+(?P<type>\S+)")
SEV_RE = re.compile(r"Severity:\s+(?P<sev>[A-Z]+)")
REPO_FILE_PATTERNS = [r"pip:.*-requirements\.txt"]


def summarize(doc: dict) -> list[dict]:
    rows = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            text = res.get("message", {}).get("text", "")
            pkg = PKG_RE.search(text)
            art = ART_RE.search(text)
            sev = SEV_RE.search(text)
            rows.append({"id": res.get("ruleId", "?"), "uri": loc.get("artifactLocation", {}).get("uri", "?"),
                         "line": loc.get("region", {}).get("startLine"),
                         "package": (pkg.group("name"), pkg.group("version")) if pkg else None,
                         "artifact": (art.group("name"), art.group("type")) if art else None,
                         "severity": sev.group("sev") if sev else "?"})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=Path, required=True)
    ap.add_argument("--report", type=Path, default=Path("trivy.sarif"))
    ap.add_argument("--ignorefile", type=Path, help="trivy YAML ignore file (vulnerabilities/misconfigurations with statement and expired_at)")
    ap.add_argument("--skip-dirs", default="", help="comma-separated directories to skip, relative to the target")
    ap.add_argument("--scanners", default="vuln,misconfig")
    ap.add_argument("--expect-package", help="require this package to be reported vulnerable (fixture check)")
    ap.add_argument("--max-age-hours", type=float)
    a = ap.parse_args()

    try:
        exe = pinned_trivy()
    except PinError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    cache = tdb.cache_dir()
    ok, lines = tdb.check(cache, a.max_age_hours if a.max_age_hours is not None else load_config()["max_age_hours"])
    for line in lines:
        print(("  db: " if ok else "ERROR: ") + line)
    if not ok:
        return 2
    ver = subprocess.run([str(exe), "--version"], capture_output=True, text=True).stdout.strip().splitlines()
    print(f"trivy {ver[0] if ver else '?'} from {exe}; offline database under {cache}")

    report = a.report.resolve()
    report.unlink(missing_ok=True)
    argv = tdb.scan_args(str(exe), cache, report, a.scanners)
    if a.ignorefile:
        if not a.ignorefile.is_file():
            print(f"ERROR: ignore file {a.ignorefile} not found", file=sys.stderr)
            return 2
        argv += ["--ignorefile", str(a.ignorefile.resolve())]
    skip = [d for d in a.skip_dirs.split(",") if d.strip()]
    if skip:
        argv += ["--skip-dirs", ",".join(skip)]
    if not a.expect_package:
        for p in REPO_FILE_PATTERNS:
            argv += ["--file-patterns", p]
    argv.append(str(a.target))
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    for line in (r.stderr + r.stdout).strip().splitlines()[-6:]:
        print("  " + line)
    if r.returncode != 0:
        print(f"ERROR: trivy exited {r.returncode} (crash, not a clean scan)", file=sys.stderr)
        return 1
    if not report.is_file() or not report.read_text(encoding="utf-8").strip():
        print("ERROR: trivy wrote no SARIF", file=sys.stderr)
        return 1
    rows = summarize(json.loads(report.read_text(encoding="utf-8")))
    for x in rows:
        what = f"{x['package'][0]}@{x['package'][1]}" if x["package"] else (f"{x['artifact'][0]} ({x['artifact'][1]})" if x["artifact"] else "?")
        print(f"  FINDING {x['id']}  {x['severity']}  {what}  ({x['uri']}:{x['line']})")

    if a.expect_package:
        hit = [x for x in rows if x["package"] and x["package"][0].lower() == a.expect_package.lower()]
        if not hit:
            print(f"ERROR: expected {a.expect_package} to be reported vulnerable; it was not (scanner, database or fixture changed)", file=sys.stderr)
            return 2
        print(f"expected package {a.expect_package} reported vulnerable in {len(hit)} advisory(ies)")
        return 0
    if rows:
        print(f"FINDINGS: {len(rows)} not ignored by {a.ignorefile or '(no ignore file)'}; relock the dependency or add an entry with a statement and expired_at")
        return 2
    print("no findings (after the ignore file)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
