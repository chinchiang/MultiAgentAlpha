"""What a bundle's scope is (mara.context.repo_map.build_context): in a git target every tracked file is source, whatever
directory holds it, and a file that reads as text is source whatever its name says. Only a binary, a file never opened
and, in a directory that is walked, a generated directory are excluded; what is in scope and cannot be bundled is
omitted, which leaves the coverage incomplete."""

import subprocess

import pytest

from mara.context.repo_map import MAX_FILE_BYTES, build_context, looks_like_text

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


@pytest.mark.parametrize("data, text", [(b"plain\n", True), ("中文\n".encode(), True), ("中文".encode()[:-1], True), (b"", True),
                                        (b"a\0b", False), (b"\xff\xfe", False), (b"ok \xc3\x28 bad", False)])
def test_what_reads_as_text(data, text):
    assert looks_like_text(data) is text
