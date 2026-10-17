"""Whether a Python source file defines a name, read from its syntax tree without importing it, for tests of documents
that point at code (tests/SEAMS.md, the training quiz's rationales). Reads the files it is given and nothing else."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def _names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Assign):
        return [t.id for t in node.targets if isinstance(t, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _self_attributes(cls: ast.ClassDef) -> set[str]:
    """The attributes `__init__` sets on `self`."""
    init = next((n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "__init__"), None)
    targets = [t for n in ast.walk(init) if isinstance(n, ast.Assign) for t in n.targets] if init else []
    targets += [n.target for n in ast.walk(init) if isinstance(n, ast.AnnAssign)] if init else []
    return {t.attr for t in targets if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self"}


def _imported_from(path: Path, node: ast.ImportFrom, name: str) -> tuple[Path, bool] | None:
    """(the source file, whether it is the module `name` itself) that `node` imports `name` from, when that is in this
    repository's src/; None otherwise."""
    if node.level:
        base = path.parent
        for _ in range(node.level - 1):
            base = base.parent
    elif node.module and node.module.split(".")[0] == "mara":
        base = SRC
    else:
        return None
    package = base.joinpath(*node.module.split(".")) if node.module else base
    for candidate, is_module in ((package / f"{name}.py", True), (package / name / "__init__.py", True),
                                 (package.with_suffix(".py"), False), (package / "__init__.py", False)):
        if candidate.is_file():
            return candidate, is_module
    return None


def defines(path: Path, name: str, *, follow_imports: bool = False) -> bool:
    """Whether `path` defines `name`: a function, class or assignment at the top level, or `Class.member`, a member being
    one the class body defines or an attribute its `__init__` sets on `self`. With `follow_imports`, a top-level name the
    file imports from src/ counts as defined where it comes from, and the rest of `name` is looked up there."""
    scope: list[ast.stmt] = ast.parse(path.read_text(encoding="utf-8")).body
    parts = name.split(".")
    cls: ast.ClassDef | None = None
    for i, part in enumerate(parts):
        found = next((node for node in scope if part in _names(node)), None)
        if found is None and cls is not None:
            return part in _self_attributes(cls) and i == len(parts) - 1
        if found is None and follow_imports and i == 0:
            return _defined_where_imported(path, scope, parts)
        if found is None:
            return False
        cls = found if isinstance(found, ast.ClassDef) else None
        scope = cls.body if cls is not None else []
    return True


def _defined_where_imported(path: Path, scope: list[ast.stmt], parts: list[str]) -> bool:
    for node in scope:
        alias = next((a for a in node.names if (a.asname or a.name) == parts[0]), None) if isinstance(node, ast.ImportFrom) else None
        if alias is None:
            continue
        imported = _imported_from(path, node, alias.name)
        if imported is None:  # from outside src/: only the name itself can be checked
            return len(parts) == 1
        source, is_module = imported
        if is_module:  # `from . import ballot_round`: the rest is looked up in the module
            return len(parts) == 1 or defines(source, ".".join(parts[1:]), follow_imports=True)
        return defines(source, ".".join([alias.name, *parts[1:]]), follow_imports=True)
    return False
