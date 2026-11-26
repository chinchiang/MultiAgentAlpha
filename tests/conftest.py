import os
import sys
from pathlib import Path

import pytest

from mara.workspace import Workspace  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# The credential guard (GLOSSARY.md): the variables of the credential sources no test may see. GitHub's tokens; every key
# variable MARA reads (each api_key_env of the configs below config/, mara.credentials.VENDOR_KEY_ENV and
# mara.model_eval's); and the AWS chain's (botocore's providers and profile variables). tests/test_credential_guard.py
# holds the list to them.
CREDENTIAL_VARIABLES = (
    "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENAICOMPATIBLE_API_KEY",
    "DEEPSEEK_LOCAL_KEY", "GLM_LOCAL_KEY", "NIM_LOCAL_KEY",
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_FILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
)
GUARD_GH = '#!/bin/sh\necho "a test reached the real gh: gh $*" >&2\nexit 97\n'  # the guard's gh: it refuses every call
GUARD_DIR = pytest.StashKey[Path]()  # the guard's directory: made by pytest_configure, removed by pytest_unconfigure


def pytest_configure(config):
    """The credential guard, before any test module is imported, whoever started pytest (a developer, check_local.py,
    mutate.py, CI): remove CREDENTIAL_VARIABLES; give gh an empty config directory, so no login; point the AWS chain's
    config, credentials and boto config files at files that do not exist and turn its instance metadata lookup off; and,
    on POSIX, put the guard's gh first on PATH. A test that sets a variable with monkeypatch, puts a stand-in gh first
    on PATH or names one with --gh still gets its own."""
    import tempfile

    guard_dir = Path(tempfile.mkdtemp(prefix="mara-credential-guard-"))
    config.stash[GUARD_DIR] = guard_dir
    for name in CREDENTIAL_VARIABLES:
        os.environ.pop(name, None)
    (guard_dir / "gh-config").mkdir()
    os.environ["GH_CONFIG_DIR"] = str(guard_dir / "gh-config")
    os.environ["AWS_CONFIG_FILE"] = str(guard_dir / "aws" / "config")
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(guard_dir / "aws" / "credentials")
    os.environ["BOTO_CONFIG"] = str(guard_dir / "boto")
    os.environ["AWS_EC2_METADATA_DISABLED"] = "true"
    if sys.platform != "win32":
        (guard_dir / "bin").mkdir()
        (guard_dir / "bin" / "gh").write_text(GUARD_GH, encoding="utf-8")
        (guard_dir / "bin" / "gh").chmod(0o755)
        os.environ["PATH"] = str(guard_dir / "bin") + os.pathsep + os.environ.get("PATH", "")


def pytest_unconfigure(config):
    import shutil

    guard_dir = config.stash.get(GUARD_DIR, None)
    if guard_dir is not None:
        shutil.rmtree(guard_dir, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def isolate_mara_tools_dir(tmp_path_factory):
    # Tests must never execute whatever happens to be installed under .mara-tools (a real scan takes seconds
    # and depends on what the developer installed). Point the runner at an empty directory; tests that need a
    # tool create their own fake and name its directory (Workspace(root, tools_dir=...), or MARA_TOOLS_DIR for a test of the entry),
    # or opt in to the real .mara-tools explicitly.
    tools_dir = tmp_path_factory.mktemp("mara-no-tools")
    old = os.environ.get("MARA_TOOLS_DIR")
    os.environ["MARA_TOOLS_DIR"] = str(tools_dir)
    yield tools_dir
    if old is None:
        os.environ.pop("MARA_TOOLS_DIR", None)
    else:
        os.environ["MARA_TOOLS_DIR"] = old


@pytest.fixture(scope="session", autouse=True)
def windows_shell_for_fake_tools():
    # Several tests fake a tool with a shell script. Windows cannot execute one directly (WinError 193), and the
    # runner never looks for a shell on PATH: it runs only the interpreter MARA_WINDOWS_SH names. The test suite
    # names Git for Windows' sh, found here (test-only) next to git.
    if sys.platform != "win32" or os.environ.get("MARA_WINDOWS_SH"):
        yield
        return
    import shutil

    git = shutil.which("git")
    candidates = [Path(git).parent.parent / sub / "sh.exe" for sub in ("bin", "usr/bin")] if git else []
    sh = next((str(c) for c in candidates if c.is_file()), shutil.which("sh") or "")
    if sh:
        os.environ["MARA_WINDOWS_SH"] = sh
    yield
    os.environ.pop("MARA_WINDOWS_SH", None)


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def mock_report(root, tmp_path_factory):
    from mara.config import load_config
    from mara.pipeline import Pipeline

    cfg = load_config(root / "config" / "mara.mock.yaml", Workspace(ROOT))
    out = tmp_path_factory.mktemp("out")
    pipe = Pipeline(cfg, mock_fixtures=str(root / "fixtures" / "mock-responses"), out_dir=out)
    report = pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=root / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    return pipe, report
