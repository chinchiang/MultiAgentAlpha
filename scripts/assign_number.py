"""Replace the GSMD placeholder number with the registry-allocated one.

    python scripts/assign_number.py GSMD-RPT-2026-0908-01            # apply
    python scripts/assign_number.py GSMD-RPT-2026-0908-01 --dry-run  # show what would change

Steps: rewrite every occurrence of the placeholder in tracked text files, rename the two
report files, update the cover note, then rebuild the report and the HTML edition.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLACEHOLDER = "GSMD-RPT-2026-0908-TBD"
NUMBER_RE = re.compile(r"^GSMD-(RPT|PNL|CTI|PLAN|BRF)-\d{4}-\d{4}-\d{2}$")
TEXT_EXT = {".md", ".py", ".txt", ".yml", ".yaml", ".toml", ".html"}
SKIP = {".git", "__pycache__", ".pytest_cache", ".ruff_cache", "out", "build", "dist"}


def tracked_text_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    files = []
    for rel in out.splitlines():
        p = ROOT / rel
        if any(part in SKIP for part in p.parts) or p.suffix.lower() not in TEXT_EXT:
            continue
        if p.name.startswith(PLACEHOLDER):
            continue  # the generated report files are rebuilt, not edited
        files.append(p)
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("number")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--allocated-on", default=None, help="YYYY-MM-DD shown on the cover; default today")
    args = ap.parse_args()
    number = args.number.strip()
    if not NUMBER_RE.match(number):
        print(f"not a GSMD number: {number!r} (expected e.g. GSMD-RPT-2026-0908-01)", file=sys.stderr)
        return 2
    import datetime as dt

    allocated_on = args.allocated_on or dt.date.today().isoformat()
    changed = []
    for p in tracked_text_files():
        text = p.read_text(encoding="utf-8")
        new = text.replace(PLACEHOLDER, number)
        if p == ROOT / "docs" / "parts" / "00_cover.md":
            new = new.replace("（登錄簿配號待補）", f"（登錄簿配號 {allocated_on}）")
        if new != text:
            changed.append(p)
            if not args.dry_run:
                p.write_text(new, encoding="utf-8")
    for rel in changed:
        print(f"{'would edit' if args.dry_run else 'edited'}: {rel.relative_to(ROOT)}")
    for old in sorted((ROOT / "docs").glob(f"{PLACEHOLDER}_*")):
        new_path = old.with_name(old.name.replace(PLACEHOLDER, number))
        print(f"{'would rename' if args.dry_run else 'renamed'}: {old.name} -> {new_path.name}")
        if not args.dry_run:
            subprocess.run(["git", "mv", "-f", str(old), str(new_path)], cwd=ROOT, check=True)
    if args.dry_run:
        return 0
    for script in ("build_report.py", "build_html.py", "count_words.py", "check_citations.py"):
        subprocess.run([sys.executable, str(ROOT / "scripts" / script)], cwd=ROOT, check=True)
    leftovers = subprocess.run(["git", "grep", "-l", PLACEHOLDER], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if leftovers:
        print("placeholder still present in:", leftovers, file=sys.stderr)
        return 1
    print(f"done: {number}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
