import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


@pytest.fixture(scope="session", autouse=True)
def isolate_mara_tools_dir(tmp_path_factory):
    # Tests must never execute whatever happens to be installed under .mara-tools (a real scan takes seconds
    # and depends on what the developer installed). Point the runner at an empty directory; tests that need a
    # tool create their own fake via MARA_TOOLS_DIR, or opt in to the real .mara-tools explicitly.
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

    cfg = load_config(root / "config" / "mara.mock.yaml")
    out = tmp_path_factory.mktemp("out")
    pipe = Pipeline(cfg, mock_fixtures=str(root / "fixtures" / "mock-responses"), out_dir=out)
    report = pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=root / "fixtures" / "vuln-sample-sarif", provider_mode="mock")
    return pipe, report
