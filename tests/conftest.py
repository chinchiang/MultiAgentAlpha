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
    report = pipe.run(root / "fixtures" / "vuln-sample", sarif_dir=root / "fixtures" / "vuln-sample-sarif", mode="mock")
    return pipe, report
