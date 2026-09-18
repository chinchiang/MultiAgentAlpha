"""L1 context builder. Produces facts, not judgements, and strips authorship signals
(commit messages, author names, PR descriptions) so no reviewer can be swayed by
who wrote the code (authority/sycophancy bias)."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field, replace
from html import escape
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".mypy_cache", ".ruff_cache"}
TEXT_EXT = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".html",
    ".htm",
    ".css",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".env",
    ".md",
    ".txt",
    ".sh",
    ".go",
    ".java",
    ".rb",
    ".php",
    ".cs",
    ".sql",
    ".xml",
    ".lock",
}
MANIFESTS = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "pyproject.toml",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "Cargo.toml",
    "Cargo.lock",
}
MAX_FILE_BYTES = 200_000
MAX_TOTAL_CHARS = 400_000
MAX_REPOSITORY_CHARS = 16_000_000


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
    revision: str = ""
    omitted: dict[str, str] = field(default_factory=dict)
    excluded: dict[str, str] = field(default_factory=dict)
    redacted: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return bool(self.content) and not self.omitted

    def coverage(self) -> dict:
        return {
            "included": list(self.content),
            "omitted": self.omitted,
            "excluded": self.excluded,
            "redacted": self.redacted,
            "complete": self.complete,
            "content_hash": self.content_hash,
            "revision": self.revision,
        }

    def batches(self):
        """Bound every reviewer request, retaining a manifest for the entire review."""
        batch, size = {}, 0
        for path, text in self.content.items():
            cost = len(text) + len(text.splitlines()) * 8 + len(path) + 50
            if batch and size + cost > MAX_TOTAL_CHARS:
                yield replace(self, content=batch)
                batch, size = {}, 0
            batch[path] = text
            size += cost
        if batch:
            yield replace(self, content=batch)

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root)).replace("\\", "/")

    def bundle(self, paths: list[str] | None = None) -> str:
        """Untrusted-data bundle handed to reviewers: every file is fenced and labelled."""
        parts = []
        for rel, text in self.content.items():
            if paths and rel not in paths:
                continue
            numbered = "\n".join(f"{i + 1:5d}| {line}" for i, line in enumerate(text.splitlines()))
            parts.append(f'<file path="{escape(rel, quote=True)}">\n{numbered}\n</file>')
        return "\n".join(parts)

    def summary(self) -> str:
        langs = ", ".join(f"{k}:{v}" for k, v in sorted(self.languages.items(), key=lambda kv: -kv[1]))
        return (
            f"root={self.root.name} files={len(self.files)} included={len(self.content)} omitted={len(self.omitted)} languages=[{langs}] "
            f"manifests={[self.rel(m) for m in self.manifests]} workflows={[self.rel(w) for w in self.workflows]} "
            f"entry_points={self.entry_points}"
        )


_ENTRY_PATTERNS = [
    (re.compile(r"@app\.route\((['\"])([^'\"]+)\1"), "flask:{}"),
    (re.compile(r"@(?:router|app)\.(get|post|put|delete|patch)\((['\"])([^'\"]+)\2"), "fastapi:{}"),
    (re.compile(r"app\.(get|post|put|delete|use)\((['\"])([^'\"]+)\2"), "express:{}"),
]


# Defense in depth: filenames are excluded even if tracked. The live gate also requires
# a successful local secret scan before any provider call. Never put raw secret values in audit.
_SECRET_FILE = re.compile(r"(?i)^(?:\.env(?:\..*)?|\.netrc|\.npmrc|\.pypirc|credentials(?:\..*)?|id_(?:rsa|ed25519)|.*\.(?:pem|key|p12|pfx))$")
_SECRET_VALUE = re.compile(
    r"(?i)(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-(?:ant-)?[A-Za-z0-9_-]{16,}|(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"\n]{6,}['\"]|"
    r"-----BEGIN [^\n]*PRIVATE KEY-----[\s\S]*?-----END [^\n]*PRIVATE KEY-----)"
)


def redact_secrets(text: str) -> str:
    # Preserve newlines so citations continue to use the original line numbers.
    return _SECRET_VALUE.sub(lambda m: "[REDACTED]" + "\n" * m.group().count("\n"), text)


def _read_bounded(root: Path, rel: Path) -> str:
    """Open each component without following symlinks, including directory components."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in rel.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(rel.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, "rb") as f:
            import stat

            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise ValueError("not_regular_file")
            data = f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("file_size_limit")
        return data.decode("utf-8")
    finally:
        os.close(fd)


def build_context(root: str | Path) -> RepoContext:
    import hashlib

    root = Path(root).resolve()
    ctx = RepoContext(root=root)
    # git ls-files honors the target subdirectory and excludes untracked/ignored local files.
    tracked = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "-z", "--", "."], capture_output=True, check=False)
    paths = (
        [Path(os.fsdecode(x)) for x in tracked.stdout.split(b"\0") if x]
        if tracked.returncode == 0
        else [p.relative_to(root) for p in root.rglob("*") if not p.is_dir()]
    )

    def priority(p):
        return (2 if p.suffix in {".md", ".txt", ".html"} and p.name not in MANIFESTS else 0, str(p))

    total = 0
    h = hashlib.sha256()
    raw_hash = hashlib.sha256()
    for relpath in sorted(set(paths), key=priority):
        rel = relpath.as_posix()
        if relpath.is_absolute() or ".." in relpath.parts:
            ctx.omitted[rel] = "unsafe_path"
            continue
        p = root / relpath
        if any(part in SKIP_DIRS for part in relpath.parts):
            ctx.excluded[rel] = "generated_directory"
            continue
        ctx.files.append(p)
        ext = p.suffix.lower()
        ctx.languages[ext or p.name] = ctx.languages.get(ext or p.name, 0) + 1
        if p.name in MANIFESTS:
            ctx.manifests.append(p)
        if rel.startswith(".github/workflows/") and ext in (".yml", ".yaml"):
            ctx.workflows.append(p)
        if _SECRET_FILE.match(p.name):
            ctx.excluded[rel] = "secret_file"
            continue
        if ext not in TEXT_EXT and p.name not in MANIFESTS and p.name != "Dockerfile":
            ctx.excluded[rel] = "unsupported_format"
            continue
        try:
            text = _read_bounded(root, relpath)
        except (OSError, ValueError, UnicodeError):
            ctx.omitted[rel] = "unreadable_unsafe_or_oversize"
            continue
        sanitized = redact_secrets(text)
        raw_hash.update(json.dumps([rel, text], ensure_ascii=False).encode())
        if sanitized != text:
            ctx.redacted.append(rel)
        if len(sanitized) + len(sanitized.splitlines()) * 8 + len(rel) + 50 > MAX_TOTAL_CHARS:
            ctx.omitted[rel] = "request_size_limit"
            continue
        if total + len(sanitized) > MAX_REPOSITORY_CHARS:
            ctx.omitted[rel] = "repository_size_limit"
            continue
        total += len(sanitized)
        ctx.content[rel] = sanitized
        h.update(json.dumps([rel, sanitized], ensure_ascii=False).encode())
        for pat, fmt in _ENTRY_PATTERNS:
            for m in pat.finditer(sanitized):
                ctx.entry_points.append(fmt.format(m.group(m.lastindex)))
    ctx.content_hash = h.hexdigest()
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True, text=True, check=False)
    commit = head.stdout.strip() if head.returncode == 0 else "non-git"
    raw_hash.update(json.dumps(ctx.omitted, sort_keys=True).encode())
    ctx.revision = f"{commit}:{raw_hash.hexdigest()}"
    return ctx
