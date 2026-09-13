"""Known-vulnerability scan with the osv-scanner pinned in tools/versions.lock, for CI (L0 job) and local use.

  python3 scripts/osv_ci.py --lockfile tools/semgrep-requirements.txt [--lockfile ...] --config tools/osv-scanner.toml --report osv.sarif
      scan the hash-locked dependency closures this repository installs; any vulnerability not ignored
      in the osv-scanner config (id + reason + ignoreUntil) exits 2.
  python3 scripts/osv_ci.py --target fixtures/vuln-sample --report fixture-osv.sarif --expect-package requests
      scan the seeded fixture and require that the named package is reported vulnerable (the fixture pins
      requests==2.19.0): exit 2 when it is not, i.e. when the scanner or its database stopped seeing it.

osv-scanner comes only from MARA_TOOLS_DIR/bin and its manifest version must equal the lock. It runs
`scan source` with --no-resolve (only what the manifests declare is checked; hash-locked closures are
complete already, and no transitive resolution request goes to deps.dev) and sends package names and
versions, never source code, to api.osv.dev.
Exit 0 ok, 2 vulnerabilities (or expected package missing), 1 osv-scanner crashed or found no packages.
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

from mara.tools.runner import installed_version, tool_path, tools_dir  # noqa: E402

# osv-scanner exit codes (cmd/osv-scanner): 1 vulnerabilities found, 127 no package sources found, 128 general error,
# 129 scanning finished with errors on some paths, 130 vulnerabilities found and errors on some paths
EXIT_VULNS = {1, 130}
EXIT_NO_PACKAGES = 127
ROW_RE = re.compile(r"^\|\s*(?P<source>[^|]+?)\s*\|\s*(?P<name>[^|]+?)\s*\|\s*(?P<version>[^|]+?)\s*\|\s*$", re.M)


def locked_version(lock: Path = ROOT / "tools" / "versions.lock") -> str:
    import yaml

    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    return str(d.get("tools", d).get("osv-scanner", {}).get("version", ""))


def packages_in(result: dict) -> list[tuple[str, str]]:
    """(package, version) pairs from the 'Affected Packages' table osv-scanner writes into each result message."""
    text = result.get("message", {}).get("text", "") or result.get("message", {}).get("markdown", "")
    out = []
    for m in ROW_RE.finditer(text):
        name, version = m.group("name"), m.group("version")
        if name.lower() in ("package name", "---") or set(name) <= {"-"}:
            continue
        out.append((name, version))
    return out


def summarize(doc: dict) -> list[dict]:
    rows = []
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            rows.append({"id": res.get("ruleId", "?"), "uri": loc.get("artifactLocation", {}).get("uri", "?"),
                         "packages": packages_in(res), "suppressed": bool(res.get("suppressions"))})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=Path, help="directory to scan recursively")
    ap.add_argument("--lockfile", type=Path, action="append", default=[], help="manifest/lockfile to scan (repeatable)")
    ap.add_argument("--config", type=Path, help="osv-scanner.toml with IgnoredVulns (id, reason, ignoreUntil)")
    ap.add_argument("--report", type=Path, default=Path("osv.sarif"))
    ap.add_argument("--expect-package", help="require this package to be reported vulnerable (fixture check)")
    a = ap.parse_args()
    if bool(a.target) == bool(a.lockfile):
        print("ERROR: give exactly one of --target or --lockfile", file=sys.stderr)
        return 2

    exe = tool_path("osv-scanner")
    if exe is None:
        print(f"ERROR: osv-scanner is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)", file=sys.stderr)
        return 2
    want, have = locked_version(), installed_version("osv-scanner")
    if not want or have != want:
        print(f"ERROR: installed osv-scanner {have!r} does not match tools/versions.lock {want!r}; re-run scripts/install_tools.py", file=sys.stderr)
        return 2
    ver = subprocess.run([str(exe), "--version"], capture_output=True, text=True)
    print(f"osv-scanner {(ver.stdout or ver.stderr).strip().splitlines()[0]} from {exe} (lock {want})")

    report = a.report.resolve()
    report.unlink(missing_ok=True)
    argv = [str(exe), "scan", "source", "--format", "sarif", "--output-file", str(report), "--no-resolve", "--verbosity", "warn"]
    if a.config:
        if not a.config.is_file():
            print(f"ERROR: config {a.config} not found", file=sys.stderr)
            return 2
        argv += ["--config", str(a.config.resolve())]
    for lf in a.lockfile:
        if not lf.is_file():
            print(f"ERROR: lockfile {lf} not found", file=sys.stderr)
            return 2
        argv += ["--lockfile", str(lf)]
    if a.target:
        argv += ["-r", str(a.target)]
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    for line in (r.stderr + r.stdout).strip().splitlines()[-8:]:
        print("  " + line)
    if r.returncode == EXIT_NO_PACKAGES:
        print("ERROR: osv-scanner found no package sources to scan (exit 127)", file=sys.stderr)
        return 1
    if r.returncode not in EXIT_VULNS and r.returncode != 0:
        print(f"ERROR: osv-scanner exited {r.returncode} (crash or scan errors, not a clean result)", file=sys.stderr)
        return 1
    if not report.is_file() or not report.read_text(encoding="utf-8").strip():
        print(f"ERROR: osv-scanner exited {r.returncode} but wrote no SARIF", file=sys.stderr)
        return 1
    rows = summarize(json.loads(report.read_text(encoding="utf-8")))
    live = [x for x in rows if not x["suppressed"]]
    for x in rows:
        pk = ", ".join(f"{n}@{v}" for n, v in x["packages"]) or "?"
        print(f"  {'ignored ' if x['suppressed'] else 'VULN    '}{x['id']}  {pk}  ({x['uri']})")

    if a.expect_package:
        hit = [x for x in rows if any(n.lower() == a.expect_package.lower() for n, _ in x["packages"])]
        if not hit:
            print(f"ERROR: expected {a.expect_package} to be reported vulnerable; it was not (scanner, database or fixture changed)", file=sys.stderr)
            return 2
        print(f"expected package {a.expect_package} reported vulnerable in {len(hit)} advisory(ies)")
        return 0
    if live:
        print(f"VULNERABILITIES: {len(live)} un-ignored advisory(ies); bump the dependency (relock) or add an IgnoredVulns entry with a reason and ignoreUntil")
        return 2
    print(f"no un-ignored known vulnerabilities ({len(rows) - len(live)} ignored)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
