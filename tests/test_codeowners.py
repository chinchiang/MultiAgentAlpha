""".github/CODEOWNERS: the files that decide whether a change passes keep a named owner, and every
pattern still matches something (a stale entry after a rename would silently own nothing)."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CODEOWNERS = ROOT / ".github" / "CODEOWNERS"
# workflows, locked tools and their triage/suppression/policy files, the scripts applying them, review config and policies
MUST_OWN = [".github/workflows/mara-review.yml", ".github/CODEOWNERS", "tools/versions.lock", "tools/semgrep-triage.yaml",
            "tools/csp-triage.yaml", "tools/trivyignore.yaml", "tools/osv-scanner.toml", "tools/scorecard-policy.yaml",
            "scripts/semgrep_ci.py", "scripts/csp_ci.py", "scripts/scorecard_ci.py", "scripts/install_tools.py",
            "config/mara.yaml", "src/mara/policy.py", "SECURITY.md"]


def _rules() -> list[tuple[str, list[str]]]:
    rules = []
    for line in CODEOWNERS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            rules.append((pattern, owners))
    return rules


def _matches(pattern: str, path: str) -> bool:
    """The subset of CODEOWNERS syntax this file uses: `*`, `/dir/`, `/file` and `/dir/*.ext`."""
    if pattern == "*":
        return True
    p = pattern.lstrip("/")
    if p.endswith("/"):
        return path.startswith(p)
    return re.fullmatch(re.escape(p).replace(r"\*", "[^/]*"), path) is not None


def _owners(path: str) -> list[str]:
    owners: list[str] = []
    for pattern, o in _rules():  # last match wins
        if _matches(pattern, path):
            owners = o
    return owners


def test_every_rule_names_an_owner_and_uses_only_the_supported_syntax():
    rules = _rules()
    assert rules and rules[0][0] == "*"
    for pattern, owners in rules:
        assert owners and all(re.fullmatch(r"@[\w-]+(/[\w-]+)?", o) for o in owners), pattern
        assert pattern == "*" or pattern.startswith("/"), f"{pattern}: anchor to the root so it cannot match elsewhere"


def test_the_gating_files_have_an_owner_by_a_specific_rule():
    specific = [(p, o) for p, o in _rules() if p != "*"]
    for path in MUST_OWN:
        assert (ROOT / path).exists(), path
        assert any(_matches(p, path) for p, _ in specific), f"{path} is covered only by the catch-all"
        assert _owners(path), path


def test_no_pattern_is_stale():
    tracked = [p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file() and ".git" not in p.parts]
    for pattern, _ in _rules():
        assert any(_matches(pattern, t) for t in tracked), f"{pattern} matches no file"
