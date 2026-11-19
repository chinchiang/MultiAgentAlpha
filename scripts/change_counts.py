"""Count what a change does to the mutation lists and the test files: for a human to copy into the CHANGELOG row, the
commit message and the pull request body, and to run again as the change grows. It writes nothing.

  .venv/bin/python scripts/change_counts.py --base origin/main --worktree   # before the commits
  .venv/bin/python scripts/change_counts.py --base origin/main              # the commits up to HEAD
  .venv/bin/python scripts/change_counts.py --base c8ff6ab^1 --head c8ff6ab # a merged pull request

The change (GLOSSARY.md) is the one scripts/change_lines.py reads for scripts/line_width.py and
scripts/control_chars.py, given by the same arguments. Unlike that reading, which gives the lines a change adds, this
one names each file the change changes, adds or deletes (changed_paths) and reads it whole, at the merge base and after
the change (git show, or the working tree with --worktree), what is not UTF-8 replaced on both sides. It prints, sorted
by path, a line for each:
- mutation list (tests/mutations/*.yaml) the change adds, edits or deletes, the list itself and not, as
  `mutate.py --lists-for` does, a list whose mutated file or focused tests the change touches:
  `<list>: <n> added, <n> changed, <n> removed (<n> in all)`, its mutations matched by name (mutation_list), one on
  both sides with any key different being changed (a `caught_by` or an `error` given, and a re-aligned `old`/`new`,
  alike), and `; <key> changed` for each key of the list other than `mutations` (focused, requires-python) the change
  edits, when the list is on both sides. It does not tell those changes apart: a CHANGELOG row that says what they
  were splits the count by hand (#335's merge changes 18, 17 given a `caught_by` and 1 re-aligned, and v0.13.103's row
  says each);
- test file (a file named test_*.py under tests/, as pytest collects under testpaths = ["tests"]):
  `<file>: <n> added, <n> changed, <n> removed`, its test functions matched by name (test_functions);
then `mutations: …` and `tests: …`, the totals. Exit 0 when it printed, 2 when git cannot tell the change
(change_lines.git_error) or a file of it is not YAML or not Python (`ERROR: <path>: …`), and it prints no count.

GLOSSARY.md terms: Mutation list, Change. Not pure: main, changed_paths, _text and _git run git in the repository and
read its files; test_functions, mutation_list, compare and _counted are pure.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import subprocess
import sys
import textwrap
from typing import TypeGuard

import yaml
from change_lines import git_error, git_prefix, parse_args

LISTS = "tests/mutations/"  # a mutation list (GLOSSARY.md) is a .yaml file right under it
TESTS = "tests/"  # pytest's testpaths: a test file is a test_*.py anywhere under it


def test_functions(text: str | None) -> dict[str, str]:
    """The test functions of a test file's text, as pytest collects them by its default python_functions and
    python_classes, which this repository keeps: each function whose name starts with `test` at module level, and each
    such method of a class at module level whose name starts with `Test` (`<Class>.<name>`; a class nested in one is
    not read); each by its name, in the order of the file, to its source from its first decorator to its end, the
    indentation of its first line taken off every line. A parametrized function is one. Empty for None (a side where
    the file is not); ValueError when the text is not Python."""
    if text is None:
        return {}
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        raise ValueError(f"not Python: {e}") from e
    lines = text.splitlines(keepends=True)

    def source(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
        start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
        return textwrap.dedent("".join(lines[start - 1:node.end_lineno])).rstrip("\n")

    def is_test(node: ast.stmt) -> TypeGuard[ast.FunctionDef | ast.AsyncFunctionDef]:
        return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test")

    found: dict[str, str] = {}
    for node in tree.body:
        if is_test(node):
            found[node.name] = source(node)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            found.update({f"{node.name}.{m.name}": source(m) for m in node.body if is_test(m)})
    return found


def mutation_list(text: str | None) -> tuple[dict[str, dict], dict[str, object]]:
    """(each mutation of a mutation list's text by its `name`, the list's keys other than `mutations`), the text read as
    YAML and not loaded (mutate.load refuses a stale `old`); a mutation with no name is left out. Both empty for None
    (a side where the list is not); ValueError when the text is not YAML."""
    if text is None:
        return {}, {}
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise ValueError(f"not YAML: {' '.join(str(e).split())}") from e
    data = data if isinstance(data, dict) else {}
    entries = data.get("mutations") if isinstance(data.get("mutations"), list) else []
    mutations = {m["name"]: m for m in entries if isinstance(m, dict) and isinstance(m.get("name"), str)}
    return mutations, {k: v for k, v in data.items() if k != "mutations"}


def compare(before: dict, after: dict) -> tuple[int, int, int]:
    """(added, changed, removed): the keys only `after` has, those both have with values that differ, those only
    `before` has."""
    return (len(after.keys() - before.keys()), sum(before[k] != after[k] for k in before.keys() & after.keys()),
            len(before.keys() - after.keys()))


def _git(a: argparse.Namespace, *args: str) -> str:
    """What git prints, read as UTF-8; CalledProcessError, with git's stderr, when it fails."""
    return subprocess.run([*git_prefix(a.repo), *args], capture_output=True, encoding="utf-8", errors="replace",
                          check=True).stdout


def changed_paths(a: argparse.Namespace, base: str) -> list[str]:
    """The paths the change (GLOSSARY.md) `a` names changes, adds or deletes over the merge base `base`, sorted, a
    rename as the path it deleted and the one it added."""
    names = _git(a, "diff", "--name-only", "--no-renames", "-z", base if a.worktree else f"{base}..{a.head}")
    if a.worktree:
        names += _git(a, "ls-files", "--others", "--exclude-standard", "-z")
    return sorted(set(filter(None, names.split("\0"))))


def _text(a: argparse.Namespace, ref: str | None, path: str) -> str | None:
    """The text of `path` at `ref`, or in the working tree when `ref` is None; None where the file is not."""
    if ref is None:  # what is not UTF-8 replaced, as in _git's reading of the other side
        return (a.repo / path).read_text(encoding="utf-8", errors="replace") if (a.repo / path).is_file() else None
    if subprocess.run([*git_prefix(a.repo), "cat-file", "-e", f"{ref}:{path}"], capture_output=True).returncode != 0:
        return None
    return _git(a, "show", f"{ref}:{path}")


def _counted(added: int, changed: int, removed: int) -> str:
    return f"{added} added, {changed} changed, {removed} removed"


def main(argv: list[str] | None = None) -> int:
    a = parse_args(__doc__.splitlines()[0], argv)
    try:
        base = _git(a, "merge-base", a.base, a.head).strip()
        paths = changed_paths(a, base)
        after = None if a.worktree else a.head  # the ref the change's side is read at; the working tree when None
        lines, totals = [], {"mutations": [0, 0, 0], "tests": [0, 0, 0]}
        for path in paths:
            if path.startswith(LISTS) and "/" not in path[len(LISTS):] and path.endswith(".yaml"):
                base_text, change_text = _text(a, base, path), _text(a, after, path)
                (base_mutations, base_keys), (change_mutations, change_keys) = mutation_list(base_text), mutation_list(change_text)
                both = base_text is not None and change_text is not None  # a list added or deleted edits no key
                edited = sorted(k for k in base_keys.keys() | change_keys.keys() if both and base_keys.get(k) != change_keys.get(k))
                counts, kind = compare(base_mutations, change_mutations), "mutations"
                lines.append(f"{path}: {_counted(*counts)} ({len(change_mutations)} in all)"
                             + "".join(f"; {k} changed" for k in edited))
            elif path.startswith(TESTS) and fnmatch.fnmatch(path.rsplit("/", 1)[-1], "test_*.py"):
                counts, kind = compare(test_functions(_text(a, base, path)), test_functions(_text(a, after, path))), "tests"
                lines.append(f"{path}: {_counted(*counts)}")
            else:
                continue
            totals[kind] = [t + c for t, c in zip(totals[kind], counts, strict=True)]
    except subprocess.CalledProcessError as e:
        return git_error(e, a)
    except ValueError as e:
        print(f"ERROR: {path}: {e}", file=sys.stderr)
        return 2
    for line in lines:
        print(line)
    for kind, counts in totals.items():
        print(f"{kind}: {_counted(*counts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
