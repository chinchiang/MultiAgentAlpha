"""A child process's output is read as UTF-8, whatever the machine's locale: a call that reads it as text says so.

`text=True` alone decodes with the locale's encoding, which on Windows is the ANSI code page (cp950) and on a C locale
ASCII; the tools the scripts and the review run (git, gh, trivy, semgrep, osv-scanner, cosign, node) write UTF-8, so a
commit author, an issue title or a rule message beyond that code page raises UnicodeDecodeError, or is read wrong,
for a reason that has nothing to do with the tool having run. `errors="replace"` keeps one bad byte from failing the
whole run.

Pure: it reads the source files of `scripts/` and runs nothing. It sees a call that writes
`text=True` (or `universal_newlines=True`) and takes the child's output or input (`capture_output`, `stdout`,
`stderr`, `input`) as a keyword; a call that builds its keywords with `**` or imports `run` from subprocess by name is
not seen, and neither of those is used there today.
"""

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.locale_env import not_utf8_env

ROOT = Path(__file__).resolve().parents[1]
PIPED = ("capture_output", "stdout", "stderr", "input")


def _is_true(node: ast.expr | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is(node: ast.expr | None, value: str) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def _calls_reading_text_without_utf8(path: Path) -> list[str]:
    offenders = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if not (_is_true(kw.get("text")) or _is_true(kw.get("universal_newlines"))) or not any(k in kw for k in PIPED):
            continue
        if not (_is(kw.get("encoding"), "utf-8") and _is(kw.get("errors"), "replace")):
            offenders.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
    return offenders


@pytest.mark.parametrize("where", ["scripts"])
def test_every_call_that_reads_a_child_process_as_text_reads_it_as_utf8(where):
    offenders = sorted(o for f in (ROOT / where).rglob("*.py") for o in _calls_reading_text_without_utf8(f))
    assert offenders == [], 'add encoding="utf-8", errors="replace" to: ' + ", ".join(offenders)


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in for gh is an executable script")
@pytest.mark.parametrize("written,read", [
    ("e8adb0e9a18ce6a899e9a18c", "'\\u8b70\\u984c\\u6a19\\u984c'"),   # an issue title in Chinese, as gh writes it
    ("6f6bff", "'ok\\ufffd'"),                                          # one byte that is no UTF-8: replaced, not fatal
], ids=["utf8-beyond-ascii", "invalid-byte"])
def test_the_output_of_gh_is_read_as_utf8_on_a_machine_whose_locale_is_not(tmp_path, written, read):
    """scripts/human_queue_issues.py reads gh's output; its locale here is ASCII (the code page of a Windows host)."""
    stand_in = tmp_path / "gh"
    stand_in.write_text(f"#!{sys.executable}\nimport os, sys\nsys.stdout.buffer.write(bytes.fromhex(os.environ['GH_WRITES']))\n",
                        encoding="utf-8")
    stand_in.chmod(0o755)
    env = {**not_utf8_env(), "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "GH_WRITES": written}
    code = f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r}); import human_queue_issues as h; print(ascii(h.gh(['x'])))"
    cp = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert cp.returncode == 0, cp.stderr[-600:]
    assert cp.stdout.strip() == read
