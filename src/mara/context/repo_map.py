"""L1 context builder. Produces facts, not judgements, and strips authorship signals
(commit messages, author names, PR descriptions) so no reviewer can be swayed by
who wrote the code (authority/sycophancy bias)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections import defaultdict
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
    changed: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)

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
            "changed": self.changed,
            "related": self.related,
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
    if hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in getattr(os, "supports_dir_fd", set()):
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in rel.parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            leaf = os.open(rel.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=fd)
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
    else:
        # Cross-platform fallback for Windows and systems lacking O_DIRECTORY / dir_fd
        cur = root
        for part in rel.parts:
            cur = cur / part
            if cur.is_symlink():
                raise ValueError("symlink_refused")
        resolved = cur.resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            raise ValueError("outside_root") from None
        if not cur.is_file():
            raise ValueError("not_regular_file")
        if cur.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file_size_limit")
        with cur.open("rb") as f:
            data = f.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("file_size_limit")
        return data.decode("utf-8")


def _content_hash(content: dict[str, str]) -> str:
    """Stable hash over the bundled (rel path, sanitized text) pairs, in bundle order."""
    h = hashlib.sha256()
    for rel, sanitized in content.items():
        h.update(json.dumps([rel, sanitized], ensure_ascii=False).encode())
    return h.hexdigest()


def git_changed_files(root: str | Path, base: str) -> list[str]:
    """Files changed between `base` and HEAD (three-dot: since the merge base), relative
    to the review target directory (assessment #14).

    `git diff` runs from the repository toplevel so its paths are unambiguously
    repo-root-relative; the review target's prefix is then stripped and paths outside the
    target are dropped. An unresolvable base ref is a usage error, never an empty
    'nothing changed'.
    """
    root = Path(root).resolve()
    top = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=False)
    prefix = subprocess.run(["git", "-C", str(root), "rev-parse", "--show-prefix"], capture_output=True, text=True, check=False)
    diff = subprocess.run(["git", "-C", str(top.stdout.strip() if top.returncode == 0 else root), "diff", "--name-only", "-z", f"{base}...HEAD"],
                          capture_output=True, check=False)
    if top.returncode != 0 or prefix.returncode != 0 or diff.returncode != 0:
        raise ValueError(f"cannot resolve base ref {base!r} for incremental review")
    pre = prefix.stdout.strip().replace("\\", "/")
    out = []
    for raw in diff.stdout.split(b"\0"):
        p = os.fsdecode(raw).replace("\\", "/")
        if not p:
            continue
        if pre:
            if not p.startswith(pre):
                continue
            p = p[len(pre):]
        if p:
            out.append(p)
    return out


_PY_IMPORT = re.compile(r"^[ \t]*(?:from[ \t]+([.\w]+)[ \t]+import\b|import[ \t]+([\w.]+(?:[ \t]*,[ \t]*[\w.]+)*))", re.M)
# JS/TS: only relative specifiers are resolvable inside the bundle; bare specifiers are node_modules
_JS_IMPORT = re.compile(r"""(?:require\(\s*|from\s+|import\s+)['"](\.{1,2}/[^'"]+)['"]""")
_JS_SUFFIXES = ("", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js", "/index.jsx")


def _py_module_names(rel: str) -> set[str]:
    """Dotted module names a bundle file can be imported as: full package path + bare name."""
    if not rel.endswith(".py"):
        return set()
    parts = rel[:-3].replace("\\", "/").split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return {".".join(parts), parts[-1]}


def _py_import_specs(rel: str, text: str) -> set[str]:
    """Dotted module names imported by a Python file; relative imports are resolved against
    the importer's package."""
    pkg = rel[:-3].replace("\\", "/").split("/")[:-1]
    if pkg and pkg[-1] == "__init__":
        pkg = pkg[:-1]
    out: set[str] = set()
    for m in _PY_IMPORT.finditer(text):
        names = [m.group(1)] if m.group(1) else [s.strip().split(" as ")[0] for s in m.group(2).split(",")]
        for spec in names:
            if not spec:
                continue
            dots = len(spec) - len(spec.lstrip("."))
            if dots:
                if dots - 1 > len(pkg):
                    continue  # imports above the bundle root: no in-bundle target
                base = pkg[: len(pkg) - (dots - 1)]
                rest = [p for p in spec[dots:].split(".") if p]
                out.add(".".join([*base, *rest]) if rest else ".".join(base))
            else:
                out.add(spec)
    return out


def _js_import_specs(rel: str, text: str) -> set[str]:
    out: set[str] = set()
    for m in _JS_IMPORT.finditer(text):
        target = os.path.normpath(os.path.join(os.path.dirname(rel), m.group(1))).replace("\\", "/")
        if not target.startswith(".."):
            out.update(target + suffix for suffix in _JS_SUFFIXES)
    return out


def _import_specs(rel: str, text: str) -> set[str]:
    if rel.endswith(".py"):
        return _py_import_specs(rel, text)
    if rel.endswith((".js", ".ts", ".tsx", ".jsx")):
        return _js_import_specs(rel, text)
    return set()


def import_neighbours(ctx: RepoContext, changed: list[str]) -> list[str]:
    """Bundle files related to the changed set by imports, in both directions (assessment #14):
    files the changed files import, and files that import them. Over-inclusion is safe — a
    wider bundle only adds context; under-inclusion would hide it."""
    specs_of = {rel: _import_specs(rel, text) for rel, text in ctx.content.items()}
    names_of = {rel: _py_module_names(rel) for rel in ctx.content}
    by_name: dict[str, set[str]] = defaultdict(set)
    for rel, names in names_of.items():
        for n in names:
            by_name[n].add(rel)
    related: set[str] = set()
    for c in changed:
        if c not in ctx.content:
            continue
        for spec in specs_of[c]:
            related |= by_name.get(spec, set())
            related |= by_name.get(spec.rsplit(".", 1)[-1], set())
            related |= {p for p in ctx.content if p.startswith(spec)}
        names = names_of[c]
        for other, specs in specs_of.items():
            if other == c or other in related:
                continue
            for spec in specs:
                if spec in names or spec.rsplit(".", 1)[-1] in names or spec == c:
                    related.add(other)
                    break
    related -= set(changed)
    return sorted(related)


def restrict_to_increment(ctx: RepoContext, base: str) -> tuple[list[str], list[str]]:
    """Narrow the bundle to the changed files, their import neighbours and the
    manifests/workflows (assessment #14). Everything else moves to ctx.excluded with the
    reason 'out_of_increment' — visible in coverage, never silently kept; a changed file the
    bundle cannot show (deleted, unreadable) lands in ctx.omitted so the run fails closed.

    Returns (changed, related). The tree-level revision is unchanged; content_hash is
    recomputed for the narrowed bundle.
    """
    changed = git_changed_files(ctx.root, base)
    in_bundle = [rel for rel in changed if rel in ctx.content]
    for rel in changed:
        if rel not in ctx.content and rel not in ctx.excluded and rel not in ctx.omitted:
            ctx.omitted[rel] = "changed_file_not_in_bundle"
    related = [rel for rel in import_neighbours(ctx, in_bundle) if rel not in in_bundle]
    keep = set(in_bundle) | set(related) | {ctx.rel(m) for m in ctx.manifests} | {ctx.rel(w) for w in ctx.workflows}
    for rel in [rel for rel in ctx.content if rel not in keep]:
        ctx.excluded[rel] = "out_of_increment"
        del ctx.content[rel]
    ctx.changed = in_bundle
    ctx.related = related
    ctx.content_hash = _content_hash(ctx.content)
    return in_bundle, related


def build_context(root: str | Path) -> RepoContext:
    root = Path(root).resolve()
    ctx = RepoContext(root=root)
    # git ls-files honors the target subdirectory and excludes untracked/ignored local files.
    # Check if root is actually a git repository root rather than falling through to a parent user repo
    has_git = (root / ".git").exists()
    tracked = (
        subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "-z", "--", "."], capture_output=True, check=False)
        if has_git
        else None
    )
    paths = (
        [Path(os.fsdecode(x)) for x in tracked.stdout.split(b"\0") if x]
        if tracked is not None and tracked.returncode == 0
        else [p.relative_to(root) for p in root.rglob("*") if not p.is_dir()]
    )

    def priority(p):
        return (2 if p.suffix in {".md", ".txt", ".html"} and p.name not in MANIFESTS else 0, str(p))

    total = 0
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
        for pat, fmt in _ENTRY_PATTERNS:
            for m in pat.finditer(sanitized):
                ctx.entry_points.append(fmt.format(m.group(pat.groups)))  # the route is the last group
    ctx.content_hash = _content_hash(ctx.content)
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True, text=True, check=False)
    commit = head.stdout.strip() if head.returncode == 0 else "non-git"
    raw_hash.update(json.dumps(ctx.omitted, sort_keys=True).encode())
    ctx.revision = f"{commit}:{raw_hash.hexdigest()}"
    return ctx
