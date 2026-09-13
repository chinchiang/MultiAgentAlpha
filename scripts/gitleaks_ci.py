"""Secret scan of a change's commits with the gitleaks pinned in tools/versions.lock (replaces gitleaks-action).

  python3 scripts/gitleaks_ci.py --base <sha> --head <sha> --event pull_request|push [--report gitleaks.sarif] [--source .]

The binary comes only from MARA_TOOLS_DIR/bin (scripts/install_tools.py: SHA-256 and publisher
checksum verified), never from PATH, and its manifest version must equal the lock. Range rules:
  pull_request  --no-merges --first-parent <base>..<head>   (the PR's own commits)
  push          <base>..<head>                              (every commit the push brought in)
  no usable base (empty, all zeros, or not an ancestor of head: new branch, force push)
                -> the head commit alone (<head>^..<head>), or a working-tree scan when head has no parent.
gitleaks reads .gitleaks.toml and .gitleaksignore from the source root itself. Findings are redacted.
Exit 0 clean, 2 leaks found (job fails), 1 gitleaks crashed (job fails).
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

ZERO_SHA = re.compile(r"^0{7,40}$")


def locked_version(lock: Path = ROOT / "tools" / "versions.lock") -> str:
    import yaml

    d = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    return str(d.get("tools", d).get("gitleaks", {}).get("version", ""))


def git(args: list[str], cwd: Path) -> tuple[int, str]:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return r.returncode, (r.stdout or r.stderr).strip()


def scan_range(base: str, head: str, event: str, source: Path) -> tuple[str | None, str]:
    """(log-opts for gitleaks git, reason). None means: scan the working tree instead."""
    head = head or "HEAD"
    rc, head_sha = git(["rev-parse", "--verify", f"{head}^{{commit}}"], source)
    if rc != 0:
        raise SystemExit(f"ERROR: head {head!r} is not a commit in {source}: {head_sha}")
    usable = bool(base) and not ZERO_SHA.match(base)
    if usable:
        rc, _ = git(["rev-parse", "--verify", f"{base}^{{commit}}"], source)
        usable = rc == 0 and git(["merge-base", "--is-ancestor", base, head_sha], source)[0] == 0
    if usable:
        if event == "pull_request":
            return f"--no-merges --first-parent {base}..{head_sha}", f"pull_request: the PR's own commits {base[:7]}..{head_sha[:7]}"
        return f"{base}..{head_sha}", f"{event}: every commit in {base[:7]}..{head_sha[:7]}"
    rc, _ = git(["rev-parse", "--verify", f"{head_sha}^"], source)
    why = "no base given" if not base else ("base is all zeros (new branch)" if ZERO_SHA.match(base) else f"base {base[:7]} is not an ancestor of head")
    if rc == 0:
        return f"{head_sha}^..{head_sha}", f"{why}: falling back to the head commit {head_sha[:7]} alone"
    return None, f"{why} and head has no parent: scanning the working tree"


def summarize(report: Path) -> list[str]:
    try:
        d = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for run in d.get("runs", []):
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "?")
            line = loc.get("region", {}).get("startLine", "?")
            commit = str(r.get("partialFingerprints", {}).get("commitSha", ""))[:7]
            out.append(f"{r.get('ruleId', '?')}  {uri}:{line}" + (f"  commit {commit}" if commit else ""))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--event", default="push", choices=["pull_request", "push", "workflow_dispatch", "schedule"])
    ap.add_argument("--report", type=Path, default=Path("gitleaks.sarif"))
    ap.add_argument("--source", type=Path, default=Path("."))
    a = ap.parse_args()

    exe = tool_path("gitleaks")
    if exe is None:
        print(f"ERROR: gitleaks is not installed under {tools_dir() / 'bin'}; run scripts/install_tools.py (PATH is never used)", file=sys.stderr)
        return 2
    want, have = locked_version(), installed_version("gitleaks")
    if not want or have != want:
        print(f"ERROR: installed gitleaks {have!r} does not match tools/versions.lock {want!r}; re-run scripts/install_tools.py", file=sys.stderr)
        return 2
    ver = subprocess.run([str(exe), "version"], capture_output=True, text=True)
    print(f"gitleaks {ver.stdout.strip() or ver.stderr.strip()} from {exe} (lock {want})")

    source = a.source.resolve()
    log_opts, reason = scan_range(a.base, a.head, a.event, source)
    print(f"range: {reason}")
    report = a.report.resolve()
    if log_opts is None:
        argv = [str(exe), "dir", "--no-banner", "--redact", "--exit-code=2", "--report-format=sarif", f"--report-path={report}", str(source)]
    else:
        argv = [str(exe), "git", "--no-banner", "--redact", "--exit-code=2", "--report-format=sarif", f"--report-path={report}",
                f"--log-opts={log_opts}", str(source)]
    print("+ " + " ".join(argv))
    r = subprocess.run(argv, capture_output=True, text=True)
    tail = (r.stdout + r.stderr).strip().splitlines()[-6:]
    for line in tail:
        print("  " + line)
    if r.returncode == 2:
        hits = summarize(report)
        print(f"LEAKS: {len(hits)} finding(s) (secrets redacted; .gitleaksignore fingerprints are commit:file:rule:line)")
        for h in hits:
            print("  " + h)
        return 2
    if r.returncode != 0:
        print(f"ERROR: gitleaks exited {r.returncode} (crash, not a clean scan)", file=sys.stderr)
        return 1
    print("no leaks found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
