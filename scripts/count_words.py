"""字數統計：正體中文計字（CJK 統一表意文字），不含附錄A 引用清單。

Also reports the count including appendices and the count of evidence markers, so the
delivery message can state the skill's verification items 2 and 3 with actual numbers.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTS = ROOT / "docs" / "parts"
CJK = re.compile(r"[一-鿿㐀-䶿]")
MARK = re.compile(r"【(已證實|廠商主張|第三方評論|尚未證實)[^】]*】")


def count(text: str) -> int:
    return len(CJK.findall(text))


def main() -> int:
    order = [line.strip() for line in (PARTS / "ORDER.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    body = appendix = 0
    markers = {"已證實": 0, "廠商主張": 0, "第三方評論": 0, "尚未證實": 0}
    per_part = []
    for name in order:
        text = (PARTS / name).read_text(encoding="utf-8")
        n = count(text)
        per_part.append((name, n))
        if name == "A_sources.md":
            continue
        if name[0].isalpha() and name[0].isupper():
            appendix += n
        else:
            body += n
        for m in MARK.finditer(text):
            markers[m.group(1)] += 1
    for name, n in per_part:
        print(f"{name:28s} {n:7,d}")
    print(f"{'正文（第一到十部）':28s} {body:7,d}")
    print(f"{'附錄B到E（不含附錄A）':28s} {appendix:7,d}")
    print(f"{'合計（不含附錄A）':28s} {body + appendix:7,d}")
    print("證據標記:", markers, "合計", sum(markers.values()))
    threshold = 20000
    ok = body + appendix >= threshold
    print("字數門檻", threshold, "→", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
