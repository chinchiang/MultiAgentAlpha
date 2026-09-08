"""Every 【級別｜Xn】 marker in the body must reference a key that exists as a row in 附錄A.

Keys look like A85, B17, C7.14. Markers may list several keys separated by 、 or ,.
Also flags Part I (executive summary) if it contains CVE ids, version numbers or protocol names
(skill verification item 7).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTS = ROOT / "docs" / "parts"
KEY = re.compile(r"\b([ABC]\d+(?:\.\d+)?)\b")
MARK = re.compile(r"【[^】]*?｜([^】]+)】")
BARE = re.compile(r"【([ABC]\d+(?:\.\d+)?(?:[、,，]\s*[ABC]\d+(?:\.\d+)?)*)】")


def main() -> int:
    sources = (PARTS / "A_sources.md").read_text(encoding="utf-8")
    known = {m.group(1) for m in re.finditer(r"^\| ([ABC]\d+(?:\.\d+)?) \|", sources, re.M)}
    missing: dict[str, set[str]] = {}
    used: set[str] = set()
    for p in sorted(PARTS.glob("*.md")):
        if p.name in ("A_sources.md", "ORDER.txt"):
            continue
        text = p.read_text(encoding="utf-8")
        refs = []
        for m in MARK.finditer(text):
            refs += KEY.findall(m.group(1))
        for m in BARE.finditer(text):
            refs += KEY.findall(m.group(1))
        for r in refs:
            used.add(r)
            if r not in known:
                missing.setdefault(p.name, set()).add(r)
    exec_lines = [ln for ln in (PARTS / "01_executive.md").read_text(encoding="utf-8").splitlines() if not ln.startswith("#")]
    exec_text = "\n".join(exec_lines)
    exec_problems = re.findall(r"CVE-\d{4}-\d+|\bv?\d+\.\d+(?:\.\d+)?\b|\b(?:HTTP|TLS|OAuth|SAML|TCP|SSH)\b", exec_text)
    print(f"附錄A 條目: {len(known)}；正文引用的不同編號: {len(used)}；未被引用的條目: {len(known - used)}")
    ok = True
    if missing:
        ok = False
        for f, keys in missing.items():
            print(f"MISSING in {f}: {sorted(keys)}")
    if exec_problems:
        ok = False
        print("第一部含 CVE/版本號/協定名:", exec_problems)
    print("citations", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
