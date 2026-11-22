"""What a bundle's scope is (mara.context.repo_map.build_context): in a git target every tracked file is source, whatever
directory holds it, and a file that reads as text is source whatever its name says. Only a binary, a file never opened
and, in a directory that is walked, a generated directory are excluded; what is in scope and cannot be bundled is
omitted, which leaves the coverage incomplete."""

import subprocess

import pytest

from mara import exchange
from mara.context.repo_map import CANARY_PATH, MAX_FILE_BYTES, build_context, looks_like_text

PNG = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"


def git_target(root, files: dict[str, bytes]):
    """`files` committed in a new repository at `root`."""
    root.mkdir()
    for rel, data in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"]):
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
    return root


@pytest.mark.parametrize("rel", ["build/backdoor.py", "dist/app.js", "node_modules/x/index.js", "venv/sitecustomize.py"])
def test_a_tracked_file_in_a_generated_directory_is_in_the_bundle(tmp_path, rel):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", rel: b"import os\nos.system(input())\n"}))
    assert rel in ctx.content
    assert rel not in ctx.excluded


@pytest.mark.parametrize("rel", ["src/evil.mjs", "native/hook.c", "infra/main.tf", "Makefile", "bin/run", "scripts/x.ps1"])
def test_a_text_file_of_no_known_format_is_in_the_bundle(tmp_path, rel):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", rel: b"eval(process.argv[2])\n"}))
    assert rel in ctx.content and rel not in ctx.excluded
    assert ctx.content[rel] == "eval(process.argv[2])\n"


@pytest.mark.parametrize("rel, data", [("src/evil.mjs", b"// \0\neval(process.argv[2])\n"), ("native/hook.c", b"/* \0 */ int main(){}\n"),
                                       ("bin/run", b"#!/bin/sh\n# \0\ncurl x | sh\n"), ("Makefile", b"# \0\nall:\n\tcurl x | sh\n")])
def test_a_source_file_of_a_known_format_is_not_taken_for_a_binary_for_one_nul_byte(tmp_path, rel, data):
    """One NUL in a comment made a file read as binary, so it was excluded and the coverage stayed complete while the
    interpreter still ran it. A known format, a known name or a script (`#!`) is bundled as it is."""
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", rel: data}))
    assert rel in ctx.content and rel not in ctx.excluded and "\0" in ctx.content[rel]


def test_a_source_file_of_a_known_format_that_is_not_utf8_is_omitted_so_the_coverage_is_incomplete(tmp_path):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", "src/evil.mjs": b"// caf\xe9\neval(1)\n"}))
    assert ctx.omitted == {"src/evil.mjs": "unreadable_unsafe_or_oversize"} and not ctx.complete


def test_a_binary_file_is_excluded_and_the_coverage_stays_complete(tmp_path):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", "logo.png": PNG, "blob.bin": b"\xff\xfe\x00\x01" * 8}))
    assert ctx.excluded == {"logo.png": "unsupported_format", "blob.bin": "unsupported_format"}
    assert ctx.complete


def test_a_text_file_of_no_known_format_over_the_size_limit_is_omitted_so_the_coverage_is_incomplete(tmp_path):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", "src/big.mjs": b"x = 1;\n" * (MAX_FILE_BYTES // 7 + 1)}))
    assert ctx.omitted == {"src/big.mjs": "unreadable_unsafe_or_oversize"}
    assert not ctx.complete


def test_a_binary_file_over_the_size_limit_is_excluded(tmp_path):
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", "big.png": PNG * (MAX_FILE_BYTES // len(PNG) + 1)}))
    assert ctx.excluded == {"big.png": "unsupported_format"}
    assert ctx.complete


def test_a_generated_directory_of_a_walked_directory_is_still_excluded(tmp_path):
    root = tmp_path / "plain"
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "index.js").write_text("module.exports = 1\n", encoding="utf-8")
    (root / "app.py").write_text("print(1)\n", encoding="utf-8")
    ctx = build_context(root)
    assert ctx.excluded == {"node_modules/x/index.js": "generated_directory"}
    assert list(ctx.content) == ["app.py"]


def test_a_targets_own_file_at_the_canarys_path_is_omitted_so_the_coverage_is_incomplete(tmp_path):
    """Bundled beside the planted canary, it was read by the models, and every finding citing it was set aside as a
    canary report (mara.exchange.cites_canary): whatever the target put at that path went unreviewed, unseen."""
    ctx = build_context(git_target(tmp_path / "t", {"src/ok.py": b"print(1)\n", CANARY_PATH: b"eval(input())\n",
                                                    "docs/" + CANARY_PATH: b"only the top-level path is the plant's\n"}))
    assert ctx.omitted == {CANARY_PATH: "reserved_path"} and not ctx.complete
    assert sorted(ctx.content) == ["docs/" + CANARY_PATH, "src/ok.py"]
    assert exchange.CANARY_PATH == CANARY_PATH, "one path: the plant's and the one the bundle keeps free"


@pytest.mark.parametrize("data, text", [(b"plain\n", True), ("中文\n".encode(), True), ("中文".encode()[:-1], True), (b"", True),
                                        (b"a\0b", False), (b"\xff\xfe", False), (b"ok \xc3\x28 bad", False)])
def test_what_reads_as_text(data, text):
    assert looks_like_text(data) is text
