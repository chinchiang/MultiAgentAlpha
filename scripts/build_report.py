"""Concatenate docs/parts/*.md in docs/parts/ORDER.txt order into the single report file."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARTS = ROOT / "docs" / "parts"
OUT = ROOT / "docs" / "GSMD-RPT-2026-0908-TBD_多模型多代理資安審查.md"


def build() -> Path:
    order = [line.strip() for line in (PARTS / "ORDER.txt").read_text(encoding="utf-8").splitlines() if line.strip()]
    chunks = []
    for name in order:
        text = (PARTS / name).read_text(encoding="utf-8").rstrip() + "\n"
        chunks.append(text)
    OUT.write_text("\n".join(chunks), encoding="utf-8")
    return OUT


if __name__ == "__main__":
    p = build()
    print(f"wrote {p} ({p.stat().st_size:,} bytes)")
