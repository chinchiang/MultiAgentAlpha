"""The credential guard (GLOSSARY.md, tests/conftest.py): whoever starts pytest, a test sees no GitHub token or gh
login, no key variable and no credential of the AWS chain, and a gh it reaches is the guard's, which refuses every
call. The outer test runs pytest as a child, with the suite's conftest loaded as a plugin, over a test of its own, in
an environment it builds as a caller holding every credential would (tests/SEAMS.md, "The credential guard")."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the guard's gh is a shell script; CI runs no Windows job")

# The variables of the credential sources, written from the sources and not from the guard, so that a name the guard
# drops fails here: gh's tokens (gh help environment), and the AWS chain's (the providers of botocore.credentials and
# the profile variables of botocore's session).
GITHUB_VARIABLES = ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
AWS_VARIABLES = ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "AWS_SECURITY_TOKEN", "AWS_CREDENTIAL_FILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                 "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                 "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")

INNER = '''
import json, os, subprocess
from pathlib import Path

NAMES = json.loads(os.environ["GUARD_TEST_NAMES"])


def test_what_a_test_sees(monkeypatch):
    seen = {}
    seen["variables"] = sorted(n for n in NAMES if n in os.environ)
    gh_config = Path(os.environ.get("GH_CONFIG_DIR", Path.home() / ".config" / "gh"))
    seen["gh_login"] = sorted(p.name for p in gh_config.iterdir()) if gh_config.is_dir() else []
    gh = subprocess.run(["gh", "--version"], capture_output=True, text=True)
    seen["gh"] = [gh.returncode, (gh.stdout + gh.stderr).strip()]
    import boto3
    try:
        seen["aws"] = repr(boto3.Session().get_credentials())
    except Exception as e:
        seen["aws"] = f"{type(e).__name__}: {e}"
    seen["metadata_disabled"] = os.environ.get("AWS_EC2_METADATA_DISABLED")
    monkeypatch.setenv("GEMINI_API_KEY", "set-in-the-test")
    seen["monkeypatched"] = os.environ.get("GEMINI_API_KEY")
    seen["guard_dir"] = str(gh_config.parent)
    Path(os.environ["GUARD_TEST_OUT"]).write_text(json.dumps(seen))
'''


def _what_a_test_sees(tmp_path: Path, names: set[str]) -> dict:
    """Run INNER as a test of its own, under the suite's conftest, as a caller holding every credential would: each of
    `names` set, gh's config directory, the AWS chain's files and the boto config all pointing at files of a home that
    hold a login or keys, the instance metadata lookup on, and a gh of the caller's own first on PATH, one that
    succeeds and says whose it is (so no real gh runs, guard or no guard); what the test saw."""
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    keys = "aws_access_key_id = AKIAEXAMPLEEXAMPLE\naws_secret_access_key = example-secret\n"
    (home / ".aws" / "credentials").write_text("[default]\n" + keys, encoding="utf-8")
    (home / ".aws" / "config").write_text("[default]\n" + keys, encoding="utf-8")
    (home / ".aws" / "ec2-credentials").write_text("AWSAccessKeyId=AKIAEXAMPLEEXAMPLE\nAWSSecretKey=example-secret\n",
                                                   encoding="utf-8")
    (home / ".boto").write_text("[Credentials]\n" + keys, encoding="utf-8")
    (home / ".config" / "gh").mkdir(parents=True)
    (home / ".config" / "gh" / "hosts.yml").write_text("github.com:\n    oauth_token: gho_example\n    user: someone\n",
                                                       encoding="utf-8")
    (tmp_path / "caller-bin").mkdir()
    (tmp_path / "caller-bin" / "gh").write_text("#!/bin/sh\necho the caller's gh\n", encoding="utf-8")
    (tmp_path / "caller-bin" / "gh").chmod(0o755)
    (tmp_path / "test_inner.py").write_text(INNER, encoding="utf-8")
    out = tmp_path / "seen.json"
    env = {**os.environ, **dict.fromkeys(names, "set-by-the-caller"), "HOME": str(home), "PYTHONPATH": str(ROOT),
           "AWS_CREDENTIAL_FILE": str(home / ".aws" / "ec2-credentials"),
           "GH_CONFIG_DIR": str(home / ".config" / "gh"), "AWS_CONFIG_FILE": str(home / ".aws" / "config"),
           "AWS_SHARED_CREDENTIALS_FILE": str(home / ".aws" / "credentials"), "BOTO_CONFIG": str(home / ".boto"),
           "AWS_EC2_METADATA_DISABLED": "false",
           "PATH": str(tmp_path / "caller-bin") + os.pathsep + os.environ.get("PATH", ""),
           "GUARD_TEST_NAMES": json.dumps(sorted(names)), "GUARD_TEST_OUT": str(out)}
    cp = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "tests.conftest",
                         "--rootdir", str(tmp_path), str(tmp_path / "test_inner.py")],
                        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert cp.returncode == 0, cp.stdout[-2000:] + cp.stderr[-2000:]
    return json.loads(out.read_text(encoding="utf-8"))


@POSIX_ONLY
def test_a_test_sees_no_credential_the_caller_holds(tmp_path):
    from tests import conftest

    seen = _what_a_test_sees(tmp_path, {*GITHUB_VARIABLES, *AWS_VARIABLES, *conftest.CREDENTIAL_VARIABLES})
    assert seen["variables"] == [], "a credential variable of the caller reached the test"
    assert seen["gh_login"] == [], "gh's login of the caller's home reached the test"
    assert seen["gh"][0] != 0 and "a test reached the real gh" in seen["gh"][1], f"the gh a test reached: {seen['gh']}"
    assert seen["aws"] == "None", "the AWS chain found a credential: " + seen["aws"]
    assert seen["metadata_disabled"] == "true", "the AWS instance metadata lookup is not turned off"
    assert seen["monkeypatched"] == "set-in-the-test", "a variable a test sets is not seen"
    assert not Path(seen["guard_dir"]).exists(), "the guard's directory outlives the run"


@POSIX_ONLY
def test_a_script_run_with_no_gh_of_its_own_meets_the_guards_gh(tmp_path, monkeypatch, capsys):
    """Never run where tests/conftest.py has no guard: there the real gh posts, as the developer (tests/SEAMS.md)."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import governance_weekly

    monkeypatch.setenv("MARA_HOME", str(tmp_path))
    assert governance_weekly.main(["--repo", "org/private", "--config", str(ROOT / "config" / "mara.mock.yaml"),
                                   "--date", "2026-11-26"]) == 1
    assert "a test reached the real gh: gh label create governance-check" in capsys.readouterr().err


def test_the_guard_removes_every_variable_of_the_credential_sources():
    import yaml

    from mara import model_eval
    from mara.credentials import VENDOR_KEY_ENV
    from tests import conftest

    named = {m["api_key_env"] for p in sorted((ROOT / "config").rglob("*.yaml"))
             for m in (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("models") or []
             if isinstance(m, dict) and m.get("api_key_env")}
    key_variables = {*named, *VENDOR_KEY_ENV.values(), model_eval.GARAK_KEY_ENV, model_eval.ANTHROPIC_KEY_ENV}
    assert named, "no config below config/ names an api_key_env: the scan reads nothing"
    assert key_variables - set(conftest.CREDENTIAL_VARIABLES) == set(), "a key variable MARA reads is left to the tests"
    assert {*GITHUB_VARIABLES, *AWS_VARIABLES} - set(conftest.CREDENTIAL_VARIABLES) == set(), \
        "a variable of gh or of the AWS chain is left to the tests"
