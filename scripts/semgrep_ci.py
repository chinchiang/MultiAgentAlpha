"""semgrep scan with the CLI and rules pinned in tools/versions.lock, for CI (L0 job) and local use.

  python3 scripts/semgrep_ci.py --target . --report semgrep.sarif --triage tools/semgrep-triage.yaml
      scan the repository (minus the triage file's `exclude` directories: the seeded fixtures); every
      finding must be covered by a triage entry (rule + path glob + reason), otherwise exit 2. Covered
      findings stay in the SARIF with a `suppressions` entry carrying the reason.
  python3 scripts/semgrep_ci.py --target fixtures/vuln-sample --report fixture-semgrep.sarif --expect fixtures/vuln-sample-sarif/semgrep.sarif
      scan the seeded fixture and require exactly the pre-recorded (rule, file, line) set: exit 2 on drift.
      Regenerate the recording by copying --report over the --expect file after reviewing the diff.

semgrep comes only from MARA_TOOLS_DIR/bin (version must equal the lock); the rules only from
MARA_TOOLS_DIR/semgrep-rules (checkout commit must equal the lock's `semgrep-rules.commit`), restricted
to the `paths` the lock names. --metrics=off, --disable-version-check, never --config auto: nothing is
sent to semgrep.dev. Rule ids are normalised to the registry form (mara.tools.semgrep_rules).
Exit 0 clean, 2 untriaged findings or drift (job fails), 1 semgrep crashed (job fails).
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools.runner import installed_manifest_entry, installed_version, tool_path, tools_dir  # noqa: E402
from mara.tools.sarif import scan_complete  # noqa: E402
from mara.tools.semgrep_rules import RULES_DIR_NAME, normalize_sarif, result_keys, rules_dir, scan_args, scan_env  # noqa: E402


def locked(lock: Path = ROOT / "tools" / "versions.lock") -> tuple[str, str, list[str]]:
    """(semgrep version, rules commit, rule paths) from the lock."""
    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    tools = d.get("tools", d)
    rules = tools.get(RULES_DIR_NAME, {})
    return str(tools.get("semgrep", {}).get("version", "")), str(rules.get("commit", "")), [str(p) for p in rules.get("paths", [])]


def check_pins() -> tuple[Path, list[str]] | str:
    """The semgrep binary and rules checkout, or an error string when either is missing or off-lock."""
    want_ver, want_commit, paths = locked()
    exe = tool_path("semgrep")
    if exe is None:
        return f"semgrep is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)"
    have = installed_version("semgrep")
    if not want_ver or have != want_ver:
        return f"installed semgrep {have!r} does not match tools/versions.lock {want_ver!r}; re-run scripts/install_tools.py"
    rdir = rules_dir()
    entry = installed_manifest_entry(RULES_DIR_NAME) or {}
    if not rdir.is_dir() or not entry:
        return f"{RULES_DIR_NAME} is not installed under {tools_dir()}; run scripts/install_tools.py --only {RULES_DIR_NAME}"
    head = subprocess.run(["git", "-C", str(rdir), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if not want_commit or head != want_commit or entry.get("commit") != want_commit:
        return f"{RULES_DIR_NAME} checkout {head[:12]} / manifest {str(entry.get('commit'))[:12]} does not match the lock {want_commit[:12]}; re-run scripts/install_tools.py"
    configs = [str(rdir / p) for p in paths]
    missing = [c for c in configs if not Path(c).is_dir()]
    if missing:
        return f"pinned rule paths missing from the checkout: {missing}"
    return exe, configs


def load_triage(path: Path) -> tuple[list[dict], list[str]]:
    """(accepted entries, directories to pass as --exclude)."""
    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = d.get("accepted") or []
    for i, e in enumerate(entries):
        if not e.get("rule") or not e.get("paths") or not str(e.get("reason", "")).strip():
            raise SystemExit(f"ERROR: {path} entry {i + 1} needs rule, paths and a non-empty reason")
    return entries, [str(x) for x in (d.get("exclude") or [])]


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
    ap.add_argument("--report", type=Path, default=Path("semgrep.sarif"))
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
    exe, configs = pins
    want_ver, want_commit, _ = locked()
    ver = subprocess.run([str(exe), "--disable-version-check", "--version"], capture_output=True, text=True, env=scan_env()).stdout.strip()
    print(f"semgrep {ver} from {exe} (lock {want_ver}); rules {RULES_DIR_NAME}@{want_commit[:12]}, {len(configs)} pinned rulesets")

    entries, excludes = load_triage(a.triage) if a.triage else ([], [])
    target, report = a.target.resolve(), a.report.resolve()
    report.unlink(missing_ok=True)
    argv = scan_args(str(exe), configs, report)
    for x in excludes:
        argv += ["--exclude", x]
    argv.append(".")
    print("+ (cd " + str(target) + " && " + " ".join(x if not x.startswith(str(rules_dir())) else x.replace(str(tools_dir()), "$MARA_TOOLS_DIR") for x in argv) + ")")
    r = subprocess.run(argv, cwd=target, capture_output=True, text=True, env=scan_env())
    for line in (r.stderr or r.stdout).strip().splitlines()[-4:]:
        print("  " + line)
    if not report.is_file() or not report.read_text(encoding="utf-8").strip():
        print(f"ERROR: semgrep exited {r.returncode} and produced no SARIF", file=sys.stderr)
        return 1
    # scan_args does not use --error: findings are exit 0; every nonzero code is failure.
    if r.returncode != 0:
        print(f"ERROR: semgrep exited {r.returncode}; partial results cannot pass", file=sys.stderr)
        return 1
    doc = normalize_sarif(report)
    if not scan_complete(doc):
        print("ERROR: semgrep SARIF reports an incomplete scan", file=sys.stderr)
        return 1
    keys = result_keys(doc)
    print(f"{len(keys)} finding(s)")

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
            print(f"DRIFT: live semgrep output differs from {a.expect}; review and copy {a.report} over it to re-record")
            return 2
        if len(keys) < 3:
            print("ERROR: fewer than 3 findings on the seeded fixture; the rules did not load", file=sys.stderr)
            return 2
        print(f"matches the recording {a.expect}")
        return 0

    accepted, untriaged, stale = apply_triage(doc, entries)
    report.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    for h in accepted:
        print(f"  accepted   {h}")
    for e in stale:
        print(f"  STALE triage entry matches nothing: {e['rule']} {e['paths']}")
    if untriaged:
        print(f"UNTRIAGED: {len(untriaged)} finding(s) not covered by {a.triage} (fix the code, or add an entry with a reason)")
        for h in untriaged:
            print("  " + h)
        return 2
    print(f"clean: {len(accepted)} accepted finding(s), 0 untriaged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
