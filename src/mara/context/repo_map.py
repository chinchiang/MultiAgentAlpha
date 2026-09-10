"""L1 context builder. Produces facts, not judgements, and strips authorship signals
(commit messages, author names, PR descriptions) so no reviewer can be swayed by
who wrote the code (authority/sycophancy bias)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".mypy_cache", ".ruff_cache"}
TEXT_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".json", ".yml", ".yaml", ".toml", ".ini",
            ".cfg", ".env", ".md", ".txt", ".sh", ".go", ".java", ".rb", ".php", ".cs", ".sql", ".xml", ".lock"}
MANIFESTS = {"requirements.txt", "package.json", "package-lock.json", "pyproject.toml", "poetry.lock", "go.mod",
             "go.sum", "pom.xml", "build.gradle", "Gemfile", "Gemfile.lock", "composer.json", "Cargo.toml", "Cargo.lock"}
MAX_FILE_BYTES = 200_000
MAX_TOTAL_CHARS = 400_000


@dataclass
class RepoContext:
    root: Path
    files: list[Path] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[Path] = field(default_factory=list)
    workflows: list[Path] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    content: dict[str, str] = field(default_factory=dict)
    content_hash: str = ""

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root)).replace("\\", "/")

    def bundle(self, paths: list[str] | None = None) -> str:
        """Untrusted-data bundle handed to reviewers: every file is fenced and labelled."""
        parts = []
        for rel, text in self.content.items():
            if paths and rel not in paths:
                continue
            numbered = "\n".join(f"{i + 1:5d}| {line}" for i, line in enumerate(text.splitlines()))
            parts.append(f"<file path=\"{rel}\">\n{numbered}\n</file>")
        return "\n".join(parts)

    def summary(self) -> str:
        langs = ", ".join(f"{k}:{v}" for k, v in sorted(self.languages.items(), key=lambda kv: -kv[1]))
        return (
            f"root={self.root.name} files={len(self.files)} languages=[{langs}] "
            f"manifests={[self.rel(m) for m in self.manifests]} workflows={[self.rel(w) for w in self.workflows]} "
            f"entry_points={self.entry_points}"
        )


_ENTRY_PATTERNS = [
    (re.compile(r"@app\.route\((['\"])([^'\"]+)\1"), "flask:{}"),
    (re.compile(r"@(?:router|app)\.(get|post|put|delete|patch)\((['\"])([^'\"]+)\2"), "fastapi:{}"),
    (re.compile(r"app\.(get|post|put|delete|use)\((['\"])([^'\"]+)\2"), "express:{}"),
]


def build_context(root: str | Path) -> RepoContext:
    import hashlib

    root = Path(root).resolve()
    ctx = RepoContext(root=root)
    total = 0
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        ctx.files.append(p)
        ext = p.suffix.lower()
        ctx.languages[ext or p.name] = ctx.languages.get(ext or p.name, 0) + 1
        if p.name in MANIFESTS:
            ctx.manifests.append(p)
        if ".github/workflows" in str(p).replace("\\", "/") and ext in (".yml", ".yaml"):
            ctx.workflows.append(p)
        if (ext in TEXT_EXT or p.name in MANIFESTS or p.name.startswith(".env")) and p.stat().st_size <= MAX_FILE_BYTES:
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if total + len(text) > MAX_TOTAL_CHARS:
                continue
            total += len(text)
            rel = ctx.rel(p)
            ctx.content[rel] = text
            h.update(rel.encode())
            h.update(text.encode("utf-8", "replace"))
            for pat, fmt in _ENTRY_PATTERNS:
                for m in pat.finditer(text):
                    ctx.entry_points.append(fmt.format(m.group(m.lastindex)))
    ctx.content_hash = h.hexdigest()
    return ctx
