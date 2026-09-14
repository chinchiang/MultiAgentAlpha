"""OpenSSF Scorecard with the CLI pinned in tools/versions.lock: JSON result, SARIF for Code Scanning, policy gate.

  GITHUB_AUTH_TOKEN=... python3 scripts/scorecard_ci.py --repo github.com/<owner>/<repo> --commit <sha> \\
      --json scorecard.json --sarif scorecard.sarif --policy tools/scorecard-policy.yaml

The binary comes only from MARA_TOOLS_DIR/bin (scripts/install_tools.py: SHA-256 and SLSA provenance
verified), never from PATH, and its manifest version must equal the lock. The scorecard CLI has no SARIF
output (its --format is default/json/probe/intoto), so this script converts the JSON: one rule per
check, no result for a check that scored 10, `note` for a check Scorecard could not evaluate (-1),
`warning` below 10, `error` when the policy enforces a minimum the score misses. A result's location is
the first `path:line` a check's details name, else README.md:1 (Code Scanning needs a file). The token
is read only from GITHUB_AUTH_TOKEN (the workflow token is enough for a public repository; checks that
need admin scope such as Branch-Protection come back as -1 and are reported as such, never guessed).
Exit 0 policy met, 2 an enforced check scored below its minimum or could not be evaluated, 1 scorecard
crashed or wrote no JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mara.tools.runner import installed_version, tool_path, tools_dir  # noqa: E402

TOKEN_ENV = "GITHUB_AUTH_TOKEN"
PATH_LINE_RE = re.compile(r"(?<![\w/.-])((?:[\w.-]+/)*[\w.-]+\.[A-Za-z0-9]+):(\d+)\b")
KNOWN_CHECKS = {
    "Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices", "Code-Review", "Contributors",
    "Dangerous-Workflow", "Dependency-Update-Tool", "Fuzzing", "License", "Maintained", "Packaging",
    "Pinned-Dependencies", "SAST", "Security-Policy", "Signed-Releases", "Token-Permissions", "Vulnerabilities",
}


def locked_version(lock: Path = ROOT / "tools" / "versions.lock") -> str:
    import yaml

    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    return str(d.get("tools", d).get("scorecard", {}).get("version", ""))


def load_policy(path: Path) -> dict[str, int]:
    import yaml

    d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    enforce = d.get("enforce") or {}
    if not isinstance(enforce, dict):
        raise ValueError(f"{path}: 'enforce' must be a mapping of check name -> minimum score")
    out = {}
    for name, minimum in enforce.items():
        if name not in KNOWN_CHECKS:
            raise ValueError(f"{path}: unknown Scorecard check {name!r}")
        if not isinstance(minimum, int) or not 0 <= minimum <= 10:
            raise ValueError(f"{path}: minimum for {name} must be an integer 0..10")
        out[str(name)] = minimum
    return out


def first_location(details: list[str], root: Path | None) -> tuple[str, int]:
    for line in details or []:
        for m in PATH_LINE_RE.finditer(str(line)):
            path, ln = m.group(1), int(m.group(2))
            if root is None or (root / path).is_file():
                return path, max(ln, 1)
    return "README.md", 1


def evaluate(doc: dict, policy: dict[str, int]) -> tuple[list[dict], list[str]]:
    """Rows per check and the policy failures."""
    rows, failures = [], []
    seen = set()
    for c in doc.get("checks", []):
        name = str(c.get("name", "?"))
        seen.add(name)
        score = c.get("score", -1)
        score = int(score) if isinstance(score, (int, float)) else -1
        minimum = policy.get(name)
        if minimum is None:
            status = "ok" if score == 10 else ("n/a" if score < 0 else "below 10 (not enforced)")
        elif score < 0:
            status = f"FAIL: could not be evaluated, policy needs >= {minimum}"
            failures.append(f"{name}: not evaluated (-1); policy requires >= {minimum}")
        elif score < minimum:
            status = f"FAIL: {score} < {minimum}"
            failures.append(f"{name}: {score} < {minimum}: {c.get('reason', '')}")
        else:
            status = f"ok (>= {minimum})"
        rows.append({"name": name, "score": score, "minimum": minimum, "status": status,
                     "reason": str(c.get("reason", "")), "details": list(c.get("details") or []),
                     "doc": (c.get("documentation") or {}).get("url", ""), "short": (c.get("documentation") or {}).get("short", "")})
    for name in policy:
        if name not in seen:
            failures.append(f"{name}: enforced by policy but absent from Scorecard's output")
    return rows, failures


def to_sarif(doc: dict, rows: list[dict], root: Path | None) -> dict:
    version = str((doc.get("scorecard") or {}).get("version", ""))
    rules, results = [], []
    for row in rows:
        rule_id = f"scorecard/{row['name']}"
        rules.append({"id": rule_id, "name": row["name"], "helpUri": row["doc"] or "https://github.com/ossf/scorecard/blob/main/docs/checks.md",
                      "shortDescription": {"text": row["short"] or row["name"]},
                      "properties": {"score": row["score"]}})
        if row["score"] == 10:
            continue
        if row["score"] < 0:
            level = "note"
        elif row["minimum"] is not None and row["score"] < row["minimum"]:
            level = "error"
        else:
            level = "warning"
        path, line = first_location(row["details"], root)
        detail_lines = [str(d) for d in row["details"][:20]]
        text = f"{row['name']}: score {row['score']}/10. {row['reason']}"
        if row["minimum"] is not None:
            text += f" Policy minimum: {row['minimum']}."
        if detail_lines:
            text += " Details: " + " | ".join(detail_lines)
        if path == "README.md" and not any(PATH_LINE_RE.search(str(d)) for d in row["details"]):
            text += " (No file named by the check; attached to README.md:1.)"
        results.append({"ruleId": rule_id, "level": level, "message": {"text": text},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}],
                        "partialFingerprints": {"scorecardCheck": row["name"]},
                        "properties": {"score": row["score"], "minimum": row["minimum"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "OpenSSF Scorecard", "version": version,
                                          "informationUri": "https://github.com/ossf/scorecard", "rules": rules}},
                      "automationDetails": {"id": "scorecard/"},
                      "results": results,
                      "properties": {"score": doc.get("score"), "repo": doc.get("repo"), "date": doc.get("date")}}]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True, help="github.com/<owner>/<repo>")
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--json", type=Path, default=Path("scorecard.json"))
    ap.add_argument("--sarif", type=Path, default=Path("scorecard.sarif"))
    ap.add_argument("--policy", type=Path, default=ROOT / "tools" / "scorecard-policy.yaml")
    ap.add_argument("--checks", default="", help="comma-separated subset of checks (default: all)")
    ap.add_argument("--source", type=Path, default=Path("."), help="checkout used to resolve detail paths for SARIF locations")
    a = ap.parse_args()

    exe = tool_path("scorecard")
    if exe is None:
        print(f"ERROR: scorecard is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py --only slsa-verifier scorecard (PATH is never used)", file=sys.stderr)
        return 2
    want, have = locked_version(), installed_version("scorecard")
    if not want or have != want:
        print(f"ERROR: installed scorecard {have!r} does not match tools/versions.lock {want!r}; re-run scripts/install_tools.py", file=sys.stderr)
        return 2
    if not os.environ.get(TOKEN_ENV):
        print(f"ERROR: {TOKEN_ENV} is not set; scorecard --repo needs a GitHub token (the workflow token is enough for a public repository)", file=sys.stderr)
        return 2
    try:
        policy = load_policy(a.policy)
    except (OSError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not re.fullmatch(r"github\.com/[\w.-]+/[\w.-]+", a.repo):
        print(f"ERROR: --repo must look like github.com/<owner>/<repo>, got {a.repo!r}", file=sys.stderr)
        return 2
    print(f"scorecard {have} from {exe} (lock {want}); policy enforces {policy or 'nothing'}")

    argv = [str(exe), f"--repo={a.repo}", f"--commit={a.commit}", "--format=json", "--show-details", f"--output={a.json}"]
    if a.checks:
        argv.append(f"--checks={a.checks}")
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    for line in (r.stdout + r.stderr).strip().splitlines()[-8:]:
        print("  " + line)
    if not a.json.is_file():
        print(f"ERROR: scorecard exited {r.returncode} and wrote no {a.json}", file=sys.stderr)
        return 1
    try:
        doc = json.loads(a.json.read_text(encoding="utf-8"))
    except ValueError as e:
        print(f"ERROR: {a.json} is not JSON: {e}", file=sys.stderr)
        return 1
    if r.returncode != 0:
        print(f"note: scorecard exited {r.returncode}; its JSON is used, checks it could not run are -1")
    rows, failures = evaluate(doc, policy)
    root = a.source if (a.source / "README.md").is_file() else None
    sarif = to_sarif(doc, rows, root)
    a.sarif.parent.mkdir(parents=True, exist_ok=True)
    a.sarif.write_text(json.dumps(sarif, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    print(f"aggregate score {doc.get('score')} for {(doc.get('repo') or {}).get('name')} @ {(doc.get('repo') or {}).get('commit')}")
    for row in rows:
        mn = "" if row["minimum"] is None else f" (policy >= {row['minimum']})"
        print(f"  {row['name']:<24} {row['score']:>3}{mn:<16} {row['status']}  {row['reason'][:80]}")
    print(f"SARIF: {len(sarif['runs'][0]['results'])} result(s) in {a.sarif} (category scorecard)")
    if failures:
        print(f"POLICY: {len(failures)} enforced check(s) not met:")
        for f in failures:
            print("  " + f)
        return 2
    print("policy met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
