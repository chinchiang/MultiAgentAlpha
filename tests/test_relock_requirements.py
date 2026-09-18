"""scripts/relock_requirements.py turns a pip --report into a hash-pinned closure: every entry carries the
index's SHA-256, entries are sorted, sdists are named in the header and refused unless allowed, an
entry without a hash aborts, and the repository's own lockfiles are complete and consistent."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "relock_requirements.py"
sys.path.insert(0, str(ROOT / "scripts"))

import relock_requirements as rl  # noqa: E402

LINE_RE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^ \\]+) \\$")
HASH_RE = re.compile(r"^    --hash=sha256:([0-9a-f]{64})$")


def _entry(name, version, sha, filename):
    return {"metadata": {"name": name, "version": version},
            "download_info": {"url": f"https://files.pythonhosted.org/x/{filename}", "archive_info": {"hashes": {"sha256": sha}}}}


REPORT = {"pip_version": "24.0", "install": [
    _entry("rich", "15.0.0", "b" * 64, "rich-15.0.0-py3-none-any.whl"),
    _entry("PyYAML", "6.0.3", "a" * 64, "pyyaml-6.0.3-cp311-cp311-manylinux2014_x86_64.whl"),
    _entry("ecoji", "0.1.1", "c" * 64, "ecoji-0.1.1.tar.gz"),
]}


def _parse_lock(text: str) -> list[tuple[str, str, str]]:
    rows, lines = [], [line for line in text.splitlines() if not line.startswith("#")]
    assert len(lines) % 2 == 0, "every requirement line must be followed by exactly one hash line"
    for req, h in zip(lines[::2], lines[1::2], strict=True):
        m, mh = LINE_RE.match(req), HASH_RE.match(h)
        assert m and mh, (req, h)
        rows.append((m.group(1), m.group(2), mh.group(1)))
    return rows


def test_entries_are_sorted_and_carry_hashes():
    entries = rl.entries_from_report(REPORT)
    assert [e["name"] for e in entries] == ["ecoji", "PyYAML", "rich"]
    assert entries[0]["sdist"] and not entries[1]["sdist"]
    text = rl.render(entries, title="t", source="s", host="h", pip_version="24.0", regenerate="cmd", allow_sdist=True)
    assert any("Source distributions" in line and "ecoji==0.1.1" in line for line in text.splitlines())
    assert "--no-build-isolation" in text and "tools/build-requirements.txt" in text
    assert _parse_lock(text) == [("ecoji", "0.1.1", "c" * 64), ("PyYAML", "6.0.3", "a" * 64), ("rich", "15.0.0", "b" * 64)]


def test_missing_hash_and_unexpected_sdist_are_refused(tmp_path):
    bad = {"pip_version": "24.0", "install": [_entry("rich", "15.0.0", "", "rich-15.0.0-py3-none-any.whl")]}
    with pytest.raises(rl.RelockError, match="no sha256"):
        rl.entries_from_report(bad)
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(REPORT), encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--from-pyproject", "--out", str(tmp_path / "x.txt"), "--report", str(rep), "--any-platform"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 1 and "--allow-sdist" in r.stderr and not (tmp_path / "x.txt").exists()
    r = subprocess.run([sys.executable, str(SCRIPT), "--from-pyproject", "dev", "--out", str(tmp_path / "x.txt"), "--report", str(rep), "--any-platform", "--allow-sdist"],
                       capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "3 distributions, 1 sdist" in r.stdout and "pyproject.toml [dev]" in (tmp_path / "x.txt").read_text()


def test_pyproject_requirements_include_the_dev_extra():
    reqs = rl.requirements_from_pyproject(ROOT / "pyproject.toml", ["dev"])
    assert any(r.startswith("pydantic") for r in reqs) and any(r.startswith("pytest") for r in reqs)
    with pytest.raises(rl.RelockError, match="no optional-dependencies group"):
        rl.requirements_from_pyproject(ROOT / "pyproject.toml", ["nope"])


@pytest.mark.parametrize("lock, top_level, wheels_only", [
    ("tools/dev-requirements.txt", ["anthropic", "pydantic", "pyyaml", "httpx", "typer", "rich", "pytest", "ruff", "markdown", "jsonschema"], True),
    ("tools/model-eval-requirements.txt", ["garak"], False),
])
def test_repository_lockfiles_are_complete(lock, top_level, wheels_only):
    text = (ROOT / lock).read_text(encoding="utf-8")
    rows = _parse_lock(text)
    names = {n.lower().replace("_", "-") for n, _, _ in rows}
    for pkg in top_level:
        assert pkg in names, f"{lock} lacks {pkg}"
    assert len({n.lower() for n, _, _ in rows}) == len(rows), "one entry per distribution"
    assert "--require-hashes" in text.splitlines()[3]
    if wheels_only:
        assert "Source distributions" not in text
    else:
        assert "garak==0.17.0" in text, "the garak version pinned in config/mara.yaml model_eval.garak_version"


def test_workflows_never_pip_install_without_hashes():
    """The Scorecard Pinned-Dependencies rule, enforced here so a regression is caught before CI."""
    offenders = []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
            if "pip install" not in line or line.lstrip().startswith("#"):
                continue
            ok = "--require-hashes" in line or ("--no-deps" in line and " -e " in line)
            if not ok:
                offenders.append(f"{wf.name}:{n}: {line.strip()}")
    assert not offenders, "pip install without --require-hashes (or --no-deps -e .): " + "; ".join(offenders)
