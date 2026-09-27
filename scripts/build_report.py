"""Concatenate docs/parts/*.md in docs/parts/ORDER.txt order into the single report file."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTS = ROOT / "docs" / "parts"
OUT = ROOT / "docs" / "GSMD-RPT-2026-0908-01_多模型多代理資安審查.md"


def build(parts: Path = PARTS, out: Path = OUT) -> Path:
    order = [line.strip() for line in (parts / "ORDER.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    listed = set(order)
    if len(listed) != len(order):
        raise SystemExit(f"{parts / 'ORDER.txt'} lists a part twice")
    unlisted = sorted(p.name for p in parts.glob("*.md") if p.name not in listed)
    if unlisted:
        raise SystemExit(f"parts missing from {parts / 'ORDER.txt'} would be left out of the report: {unlisted}")
    chunks = []
    for name in order:
        text = (parts / name).read_text(encoding="utf-8").rstrip() + "\n"
        chunks.append(text)
    out.write_text("\n".join(chunks), encoding="utf-8")
    return out


if __name__ == "__main__":
    p = build()
    print(f"wrote {p} ({p.stat().st_size:,} bytes)")
