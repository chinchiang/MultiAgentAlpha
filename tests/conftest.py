import os
import tempfile

# Tests must never execute whatever happens to be installed under .mara-tools (a real scan takes seconds
# and depends on what the developer installed). Point the runner at an empty directory; tests that need a
# tool create their own fake via MARA_TOOLS_DIR, or opt in to the real .mara-tools explicitly.
os.environ["MARA_TOOLS_DIR"] = tempfile.mkdtemp(prefix="mara-no-tools-")

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import pytest  # noqa: E402


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
