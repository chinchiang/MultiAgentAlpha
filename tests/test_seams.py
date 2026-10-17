"""tests/SEAMS.md points at code that is there: every test file and path it names exists, and every dotted name and class
it names is defined in src/mara (tests.source_names.defines, following imports)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from tests.source_names import defines

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SEAMS = ROOT / "tests" / "SEAMS.md"
SOURCES = sorted((SRC / "mara").rglob("*.py"))
DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.\w+)+$")
CLASS = re.compile(r"^[A-Z]\w*$")
TEST_FILE = re.compile(r"^(\w+\.py)(?:::(\w+))?$")
REPO_PATH = re.compile(r"^(?:src|tests)/[\w./-]+\.(?:py|md)$")


def _modules(name: str) -> list[Path]:
    """The source files of every module of src/mara called `name`."""
    return [p for p in SOURCES if (p.stem == name) or (p.name == "__init__.py" and p.parent.name == name)]


def _classes(name: str) -> list[Path]:
    return [p for p in SOURCES if any(isinstance(n, ast.ClassDef) and n.name == name for n in ast.parse(p.read_text(encoding="utf-8")).body)]


def problem(span: str) -> str:
    """Why a code span of SEAMS.md points at nothing, empty when it points at something or is not a pointer: a test file
    (`test_x.py`, `test_x.py::test_y`), a repository path, a dotted name whose first part is `mara`, a module of src/mara
    or a class of it, or a class alone. A call's arguments are dropped; other spans (a bare lowercase name, code with
    spaces) are not pointers."""
    pointer = span.split("(")[0] if span.endswith(")") else span
    if m := TEST_FILE.match(pointer):
        file, test = ROOT / "tests" / m[1], m[2]
        if not file.is_file():
            return f"{span}: no tests/{m[1]}"
        return f"{span}: tests/{m[1]} defines no {test}" if test and not defines(file, test) else ""
    if REPO_PATH.match(pointer):
        return "" if (ROOT / pointer).is_file() else f"{span}: no {pointer}"
    if not (DOTTED.match(pointer) or CLASS.match(pointer)):
        return ""
    head, *rest = pointer.split(".")
    if head == "mara":
        for k in range(len(rest), 0, -1):
            base = SRC.joinpath("mara", *rest[:k])
            module = next((p for p in (base.with_suffix(".py"), base / "__init__.py") if p.is_file()), None)
            if module is not None:
                name = ".".join(rest[k:])
                return "" if not name or defines(module, name, follow_imports=True) else f"{span}: {module.relative_to(ROOT)} defines no {name}"
        return f"{span}: no module of src/mara"
    candidates = [(p, ".".join(rest)) for p in _modules(head)] or [(p, pointer) for p in _classes(head)]
    if not candidates:
        return f"{span}: names no module or class of src/mara"
    if any(not name or defines(p, name, follow_imports=True) for p, name in candidates):
        return ""
    return f"{span}: " + ", ".join(str(p.relative_to(ROOT)) for p, _ in candidates) + f" defines no {candidates[0][1]}"


def test_every_test_file_path_and_name_seams_md_points_at_exists():
    spans = re.findall(r"`([^`\n]+)`", SEAMS.read_text(encoding="utf-8"))
    assert len(spans) > 40, "the code spans are read"
    problems = [p for p in map(problem, spans) if p]
    assert not problems, "\n".join(problems)


def test_a_pointer_at_nothing_is_found_and_one_at_something_is_not():
    for there in ("Pipeline.run_tools(target, sarif_dir)", "Pipeline.providers", "Pipeline.backlog", "mara.pipeline.run_all",
                  "cli.Pipeline.__init__", "ballot_round.run(...)", "exchange.Canary()", "mara.review_status", "OpenAICompatibleProvider",
                  "test_security_regressions.py::test_prerecorded_secret_scan_cannot_authorize_live_egress", "tests/fake_panel.py",
                  "lambda *_: [ToolRun(...)]", "run()"):
        assert problem(there) == "", there
    for gone in ("Pipeline.run_tool", "Pipeline.providers.x", "cli.Pipeline.nothing", "mara.pipeline.gone", "mara.gone.thing",
                 "ballot_round.gone", "pipe.run(target)", "GoneProvider", "test_gone.py", "test_seams.py::test_gone",
                 "tests/gone.py"):
        assert problem(gone), gone
