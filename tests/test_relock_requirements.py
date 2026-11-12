"""scripts/relock_requirements.py turns a pip --report into a hash-pinned closure: every entry carries the
index's SHA-256, entries are sorted, sdists are named in the header and refused unless allowed, an
entry without a hash aborts, and the repository's own lockfiles are complete and consistent: each `>=` floor of the
garak closure's .in file is at the release its comment says fixes it, and its lockfile pins every floor or later."""

import json
import re
import subprocess
import sys
import tomllib
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


@pytest.mark.parametrize("minor", [12, 13])
def test_a_closure_can_be_locked_for_each_other_supported_cpython(tmp_path, minor):
    """CI tests on 3.12 and 3.13 too (tools/dev-requirements-py312.txt, -py313.txt): the script accepts --python 3.NN,
    and a host that is not that version is refused."""
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(REPORT), encoding="utf-8")
    out = tmp_path / "x.txt"
    r = subprocess.run([sys.executable, str(SCRIPT), "--from-pyproject", "dev", "--python", f"3.{minor}", "--out", str(out),
                        "--report", str(rep), "--any-platform", "--allow-sdist"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"--python 3.{minor}" in out.read_text(encoding="utf-8")
    if sys.version_info[:2] != (3, minor):
        with pytest.raises(rl.RelockError, match=f"resolve on CPython 3.{minor}"):
            rl.check_host(False, (3, minor))


def test_pyproject_requirements_include_the_dev_extra():
    reqs = rl.requirements_from_pyproject(ROOT / "pyproject.toml", ["dev"])
    assert any(r.startswith("pydantic") for r in reqs) and any(r.startswith("pytest") for r in reqs)
    with pytest.raises(rl.RelockError, match="no optional-dependencies group"):
        rl.requirements_from_pyproject(ROOT / "pyproject.toml", ["nope"])


@pytest.mark.parametrize("lock, top_level, wheels_only", [
    ("tools/dev-requirements.txt", ["anthropic", "pydantic", "pyyaml", "httpx", "typer", "rich", "pytest", "ruff", "markdown", "jsonschema"], True),
    ("tools/dev-requirements-py312.txt", ["anthropic", "pydantic", "pyyaml", "httpx", "typer", "rich", "pytest", "ruff", "markdown", "jsonschema"], True),
    ("tools/typecheck-requirements.txt", ["mypy", "types-jsonschema", "types-pyyaml"], True),
    ("tools/model-eval-requirements.txt", ["garak"], False),
    ("tools/cyberseceval-requirements.txt", ["openai", "boto3", "semgrep", "pillow", "paramiko", "pypdf", "pyyaml"], True),
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
        import yaml

        garak = yaml.safe_load((ROOT / "config/mara.yaml").read_text(encoding="utf-8"))["model_eval"]["garak_version"]
        assert f"garak=={garak}" in text, "the garak version pinned in config/mara.yaml model_eval.garak_version"


@pytest.mark.parametrize("minor", ["12", "13"])
def test_the_other_closures_pin_the_same_versions_as_the_311_one(minor):
    """Only wheels and hashes may differ: the 3.12 and 3.13 jobs must test the versions the 3.11 job and L0 check."""
    base = _parse_lock((ROOT / "tools/dev-requirements.txt").read_text(encoding="utf-8"))
    text = (ROOT / f"tools/dev-requirements-py3{minor}.txt").read_text(encoding="utf-8")
    assert [(n, v) for n, v, _ in _parse_lock(text)] == [(n, v) for n, v, _ in base], "relock with --same-versions-as tools/dev-requirements.txt"
    assert f"CPython 3.{minor}" in text.splitlines()[1] and "--same-versions-as tools/dev-requirements.txt" in text.splitlines()[2]


def test_the_typecheck_closure_agrees_with_the_312_closure_it_is_installed_over():
    # Installed on top of tools/dev-requirements-py312.txt: a shared package with another version would
    # replace the tested one (or fail the hash check), so every shared name must carry the same pin.
    base = {n.lower(): (v, h) for n, v, h in _parse_lock((ROOT / "tools/dev-requirements-py312.txt").read_text(encoding="utf-8"))}
    text = (ROOT / "tools/typecheck-requirements.txt").read_text(encoding="utf-8")
    shared = [(n, v, h) for n, v, h in _parse_lock(text) if n.lower() in base]
    assert shared, "expected shared packages (typing_extensions, referencing, ...)"
    assert all(base[n.lower()] == (v, h) for n, v, h in shared), "relock with --same-versions-as tools/dev-requirements-py312.txt"
    assert "--same-versions-as tools/dev-requirements-py312.txt" in text.splitlines()[2]


def test_the_build_system_requires_the_build_closures_pins():
    """pyproject.toml's [build-system] and tools/build-requirements.in pin the same setuptools and wheel: a bump of one
    alone builds the package with a setuptools the closure, and its advisory scan, does not hold."""
    requires = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["build-system"]["requires"]
    pins = [line.strip() for line in (ROOT / "tools/build-requirements.in").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    assert sorted(requires) == sorted(pins) and len(pins) == 2, "pin setuptools and wheel alike in both"


def _parse_uv_lock(text: str) -> dict[str, tuple[str, set[str]]]:
    """tools/build-requirements.txt is uv pip compile output: each entry carries a hash per file (wheel and sdist),
    then `# via` lines, which are skipped."""
    pins: dict[str, tuple[str, set[str]]] = {}
    name = ""
    for line in text.splitlines():
        if m := LINE_RE.match(line):
            name = m.group(1).lower()
            pins[name] = (m.group(2), set())
        elif m := re.match(r"^    --hash=sha256:([0-9a-f]{64})(?: \\)?$", line):
            pins[name][1].add(m.group(1))
    return pins


@pytest.mark.parametrize("lock", ["tools/dev-requirements.txt", "tools/dev-requirements-py312.txt", "tools/dev-requirements-py313.txt",
                                  "tools/model-eval-requirements.txt"])
def test_the_closures_installed_with_the_build_closure_pin_its_shared_packages_alike(lock):
    """Installed in one environment with tools/build-requirements.txt (dev then build in the workflows' jobs, py312 in
    the type-check job, build then garak in docs/model-eval-runbook.md): the later install of a shared package with
    another pin replaces the earlier one, so every shared name carries the build closure's version and one of its
    hashes. The semgrep closure is installed in its own venv and is not checked."""
    build = _parse_uv_lock((ROOT / "tools/build-requirements.txt").read_text(encoding="utf-8"))
    shared = [(n, v, h) for n, v, h in _parse_lock((ROOT / lock).read_text(encoding="utf-8")) if n.lower() in build]
    assert shared, f"expected {lock} to share packages (packaging, ...) with tools/build-requirements.txt"
    for n, v, h in shared:
        version, hashes = build[n.lower()]
        assert v == version and h in hashes, (
            f"{lock} pins {n}=={v} (sha256 {h[:12]}…), tools/build-requirements.txt {n}=={version}: "
            "pin it as tools/build-requirements.txt does")


def test_the_cyberseceval_closure_keeps_the_floors_that_fix_its_advisories():
    """tools/cyberseceval-requirements.in replaces five of upstream's exact pins with floors, because osv-scanner reports
    advisories against the upstream versions. A floor lowered or dropped lets a relock go back to them; each one is
    asserted against the release that fixes the last of them (scripts/advisory_facts.py names it), and the lockfile has to
    be at or above it. setuptools is the reverse: it stays below 82.0.0, the release that removed pkg_resources, which
    CyberSecEval imports."""
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    lock_text = (ROOT / "tools/cyberseceval-requirements.txt").read_text(encoding="utf-8")
    pins = {canonicalize_name(n): Version(v) for n, v, _ in _parse_lock(lock_text)}
    floors = {name: floor for name, (floor, _) in _floors(ROOT / "tools/cyberseceval-requirements.in").items()}
    above_pin = sorted(f"{name} {floor} > {pins[name]}" for name, floor in floors.items() if floor > pins[name])
    assert not above_pin, above_pin
    fixed_in = {"pillow": "13.0.0", "pypdf": "6.21.4", "paramiko": "5.0.0", "langchain-core": "1.3.3", "urllib3": "2.8.0"}
    for name, version in fixed_in.items():
        assert floors.get(name, Version("0")) >= Version(version), f"{name}: no floor at the fixed release {version}"
        assert pins[name] >= Version(version), f"{name} {pins[name]} in the lockfile is below the fixed release {version}"
    assert pins["setuptools"] < Version("82"), "setuptools 82.0.0 removed pkg_resources, which CyberSecEval imports"


def test_pins_from_lock_and_python_choice(tmp_path):
    assert rl.pins_from_lock(ROOT / "tools/dev-requirements.txt")[0].startswith("annotated-doc==")
    bad = tmp_path / "x.txt"
    bad.write_text("rich>=1\n", encoding="utf-8")
    with pytest.raises(rl.RelockError, match="not an exact pin"):
        rl.pins_from_lock(bad)
    other = (3, 12) if sys.version_info[:2] != (3, 12) else (3, 11)
    with pytest.raises(rl.RelockError, match=f"resolve on CPython {other[0]}.{other[1]}"):
        rl.check_host(False, other)


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


def _floors(in_file: Path) -> dict:
    """The `>=` floors of a requirements .in file: canonical name -> (floor, the text of its comment). A comment goes on
    past its line only through lines that start with `#   ` (a hash and three spaces); any other line ends it."""
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    floors: dict[str, tuple[Version, str]] = {}
    last = None
    for line in in_file.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            req = Requirement(line.split("#", 1)[0].strip())
            last = None
            for spec in req.specifier:
                if spec.operator == ">=":
                    last = canonicalize_name(req.name)
                    floors[last] = (Version(spec.version), line.partition("#")[2])
        elif line.startswith("#   ") and last:
            floors[last] = (floors[last][0], floors[last][1] + " " + line[1:].strip())
        else:
            last = None
    return floors


def test_each_model_eval_floor_is_at_the_release_its_comment_says_fixes_it():
    """A floor in tools/model-eval-requirements.in is there for an advisory its comment closes with `fixed in X`: the floor is
    X or later, so lowering the floor, or naming a later fix without raising it, is caught. A floor whose whole line is
    removed is not caught."""
    from packaging.version import Version

    floors = _floors(ROOT / "tools/model-eval-requirements.in")
    assert len(floors) >= 11, sorted(floors)
    below = {}
    for name, (floor, comment) in floors.items():
        fixed = re.search(r"fixed in (\d[\w.]*\d)", comment)
        assert fixed, f"{name}: no release of the form `fixed in X` could be read from its comment"
        if floor < Version(fixed.group(1)):
            below[name] = f"floor {floor} < fixed in {fixed.group(1)}"
    assert not below, below


def test_the_model_eval_lockfile_pins_every_floor_or_later():
    """tools/model-eval-requirements.txt pins each floor of the .in file at or above it: a relock cannot go back, and a
    floor cannot be raised without a relock. A package missing from the lockfile is not caught."""
    from packaging.utils import canonicalize_name
    from packaging.version import Version

    lock_text = (ROOT / "tools/model-eval-requirements.txt").read_text(encoding="utf-8")
    pins = {canonicalize_name(name): Version(version) for name, version, _ in _parse_lock(lock_text)}
    floors = _floors(ROOT / "tools/model-eval-requirements.in")
    assert len(floors) >= 11, sorted(floors)
    below = {name: f"pin {pins[name]} < floor {floor}" for name, (floor, _) in floors.items() if name in pins and pins[name] < floor}
    assert not below, below
