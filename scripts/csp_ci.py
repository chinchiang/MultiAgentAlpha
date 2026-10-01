"""CSP review with the csp-evaluator pinned in tools/versions.lock, for CI (L0 job) and local use.

  python3 scripts/csp_ci.py --target . --report csp-evaluator.sarif --triage tools/csp-triage.yaml
      scan the repository; every finding must be covered by a triage entry (rule + path glob +
      reason, same contract as semgrep_ci.py), otherwise exit 2. Covered findings stay in the
      SARIF with a `suppressions` entry carrying the reason.
  python3 scripts/csp_ci.py --target fixtures/vuln-sample --report fixture-csp.sarif --expect fixtures/vuln-sample-sarif/csp-evaluator.sarif
      scan the seeded fixture and require exactly the pre-recorded (rule, file, line) set: exit 2
      on drift. Regenerate the recording by copying --report over the --expect file after
      reviewing the diff.

The npm package and driver come only from MARA_TO_DIR (scripts/install_tools.py: SHA-256 and
registry dist.integrity verified), never from PATH; node >= 18 is the only interpreter used.
Exit 0 clean, 2 untriaged findings or drift (job fails), 1 the scanner crashed (job fails).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools.csp_eval import node_exe, run_csp_eval  # noqa: E402
from mara.tools.runner import installed_version, tool_path, tools_dir  # noqa: E402
from mara.tools.sarif import scan_complete  # noqa: E402
from mara.tools.semgrep_rules import result_keys  # noqa: E402


def locked_version(lock: Path = ROOT / "tools" / "versions.lock") -> str:
    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    return str(d.get("tools", d).get("csp-evaluator", {}).get("version", ""))


def check_pins() -> str | tuple[str, str]:
    """(version, node executable) or an error string when the package, lock version or node is off."""
    want, have = locked_version(), installed_version("csp-evaluator")
    if tool_path("csp-evaluator") is None:
        return f"csp-evaluator is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)"
    if not want or have != want:
        return f"installed csp-evaluator {have!r} does not match tools/versions.lock {want!r}; re-run scripts/install_tools.py"
    node = node_exe()
    if not node:
        return "node interpreter not found on PATH (node >= 18 required to drive the pinned csp-evaluator)"
    try:
        vout = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout.strip()
        major = int(re.match(r"v?(\d+)", vout).group(1))  # type: ignore[union-attr]
    except (subprocess.SubprocessError, AttributeError, ValueError):
        return f"node at {node} did not report a usable version"
    if major < 18:
        return f"node {vout} is too old; csp-evaluator needs node >= 18"
    return have, node


def load_triage(path: Path) -> list[dict]:
    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = d.get("accepted") or []
    for i, e in enumerate(entries):
        if not e.get("rule") or not e.get("paths") or not str(e.get("reason", "")).strip():
            raise SystemExit(f"ERROR: {path} entry {i + 1} needs rule, paths and a non-empty reason")
    return entries


def match_triage(rule_id: str, uri: str, entries: list[dict]) -> dict | None:
    for e in entries:
        if e["rule"] == rule_id and any(fnmatch.fnmatchcase(uri, str(g)) for g in e["paths"]):
            return e
    return None


def apply_triage(doc: dict, entries: list[dict]) -> tuple[list[str], list[str], list[dict]]:
    """Tag covered results with a SARIF suppression. Returns (accepted lines, untriaged lines, stale entries)."""
    accepted, untriaged, used = [], [], set()
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", "?")
            rid = res.get("ruleId", "")
            e = match_triage(rid, uri, entries)
            if e is None:
                untriaged.append(f"{rid}  {uri}:{line}")
                continue
            used.add(id(e))
            res["suppressions"] = [{"kind": "external", "status": "accepted", "justification": " ".join(str(e["reason"]).split())}]
            accepted.append(f"{rid}  {uri}:{line}")
    return accepted, untriaged, [e for e in entries if id(e) not in used]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", type=Path, default=Path("."))
    ap.add_argument("--report", type=Path, default=Path("csp-evaluator.sarif"))
    ap.add_argument("--triage", type=Path, help="YAML of accepted findings; anything not covered fails")
    ap.add_argument("--expect", type=Path, help="pre-recorded SARIF whose (rule, file, line) set must match exactly")
    a = ap.parse_args()
    if bool(a.triage) == bool(a.expect):
        print("ERROR: give exactly one of --triage or --expect", file=sys.stderr)
        return 2

    pins = check_pins()
    if isinstance(pins, str):
        print(f"ERROR: {pins}", file=sys.stderr)
        return 2
    have, node = pins
    print(f"csp-evaluator {have} from {tools_dir() / 'csp-evaluator'} (lock {locked_version()}); node {node}")

    target, report = a.target.resolve(), a.report.resolve()
    report.unlink(missing_ok=True)
    print(f"+ node {tools_dir() / 'csp-evaluator' / 'mara_driver.js'} scan of {target} (CSPs extracted from the source tree, graded by the pinned package)")
    r = run_csp_eval(target, report, version=have, node=node)
    if r.returncode != 0:
        print(f"ERROR: csp-evaluator exited {r.returncode}: {r.stderr.strip()}", file=sys.stderr)
        return 1
    doc = json.loads(report.read_text(encoding="utf-8"))
    if not scan_complete(doc):
        print("ERROR: csp-evaluator SARIF reports an incomplete scan", file=sys.stderr)
        return 1
    props = (doc["runs"][0].get("invocations") or [{}])[0].get("properties", {})
    if props.get("truncated"):
        print(f"ERROR: policy extraction hit the cap after {props.get('policies')} policies; results are incomplete", file=sys.stderr)
        return 1
    for n in (doc["runs"][0].get("invocations") or [{}])[0].get("toolExecutionNotifications", []):
        print("  note " + " ".join(str(n.get("message", {}).get("text", "")).split())[:200])
    keys = result_keys(doc)
    print(f"{props.get('policies', '?')} policy(ies) evaluated, {len(keys)} finding(s)")

    if a.expect:
        recorded = result_keys(json.loads(a.expect.read_text(encoding="utf-8")))
        missing, extra = sorted(set(recorded) - set(keys)), sorted(set(keys) - set(recorded))
        for k in recorded:
            print(f"  recorded  {k[0]}  {k[1]}:{k[2]}")
        if missing or extra:
            for k in missing:
                print(f"  MISSING   {k[0]}  {k[1]}:{k[2]}")
            for k in extra:
                print(f"  EXTRA     {k[0]}  {k[1]}:{k[2]}")
            print(f"DRIFT: live csp-evaluator output differs from {a.expect}; review and copy {a.report} over it to re-record")
            return 2
        if len(keys) < 3:
            print("ERROR: fewer than 3 findings on the seeded fixture; the seeded CSP did not trip the evaluator", file=sys.stderr)
            return 2
        print(f"matches the recording {a.expect}")
        return 0

    entries = load_triage(a.triage)
    accepted, untriaged, stale = apply_triage(doc, entries)
    report.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for h in accepted:
        print(f"  accepted   {h}")
    for e in stale:
        print(f"  STALE triage entry matches nothing: {e['rule']} {e['paths']}")
    if untriaged:
        print(f"UNTRIAGED: {len(untriaged)} finding(s) not covered by {a.triage} (fix the CSP, or add an entry with a reason)")
        for h in untriaged:
            print("  " + h)
        return 2
    print(f"clean: {len(accepted)} accepted finding(s), 0 untriaged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
