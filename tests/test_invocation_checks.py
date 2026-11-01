"""The review invocation's checks of the target's own options (GLOSSARY.md: Review invocation, Usage error): a `--base`
that git cannot read as a revision, and a `--calibration-sample` whose target is not a labelled sample, are usage errors
on their own option, found before a review starts, by the command line, the workbench and the pipeline alike
(docs/adr/0006-local-web-workbench.md). Tests call `invocation.check_base` and so on by module, so a missing function
fails its own test."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mara import cli, invocation
from mara.cli import app
from mara.config import load_config
from mara.invocation import InvocationError
from mara.pipeline import Pipeline
from tests import cli_output

ROOT = Path(__file__).resolve().parents[1]
MOCK_CONFIG = ROOT / "config" / "mara.mock.yaml"
FIXTURES = str(ROOT / "fixtures" / "mock-responses")
LABELS = {"sample": "s1", "labels": [{"dimension": "secrets", "cwe": "CWE-798", "file": "app.py", "line": 3, "quote": "q", "title": "t"}]}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A git repository on main with two commits, the tag `release+1` on the first, and a branch `unrelated` that shares no
    history with main."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "test@example.com")
    _git(r, "config", "user.name", "test")
    (r / "app.py").write_text("def main():\n    return 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "first")
    _git(r, "tag", "release+1")
    (r / "app.py").write_text("def main():\n    return 2\n")
    _git(r, "commit", "-q", "-am", "second")
    _git(r, "checkout", "-q", "--orphan", "unrelated")
    _git(r, "rm", "-rfq", ".")
    (r / "other.py").write_text("x = 1\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "unrelated history")
    _git(r, "checkout", "-q", "main")
    return r


def _sample(workspace: Path, labels: object = LABELS) -> Path:
    sample = workspace / "calib" / "samples" / "s1"
    sample.mkdir(parents=True)
    (sample / "app.py").write_text("x = 1\n")
    (sample / "labels.json").write_text(json.dumps(labels), encoding="utf-8")
    return sample


# ---------------------------------------------------------------- check_base


@pytest.mark.parametrize("base", ["-x", "--output=/tmp/pwned", "main; rm -rf /", "a\tb", "a\x01b", "no-such-ref", "unrelated", "HEAD@{1 day ago}"],
                         ids=["dash", "option", "space", "tab", "control", "unknown", "no-common-history", "space-git-accepts"])
def test_a_base_git_cannot_diff_against_head_is_a_usage_error_on_base(repo, base):
    """The last one is a revision git itself resolves: only the rule against whitespace refuses it."""
    with pytest.raises(InvocationError) as e:
        invocation.check_base(repo, base)
    assert (e.value.param, e.value.kind) == ("--base", "bad_base_ref")


@pytest.mark.parametrize("base", ["HEAD", "HEAD~1", "main", "release+1"])
def test_a_base_git_resolves_is_accepted_whatever_its_characters(repo, base):
    """`release+1` is a tag git takes and the workbench used to refuse."""
    invocation.check_base(repo, base)


def test_a_target_that_is_not_a_git_repository_has_no_base_to_diff_against(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(InvocationError) as e:
        invocation.check_base(plain, "HEAD")
    assert e.value.param == "--base"


# ---------------------------------------------------------------- check_calibration_sample


def test_a_labelled_sample_below_the_workspaces_calib_samples_is_a_calibration_sample(tmp_path):
    invocation.check_calibration_sample(_sample(tmp_path), tmp_path)


def test_a_target_that_is_not_a_labelled_sample_is_a_usage_error_on_calibration_sample(tmp_path, repo):
    with pytest.raises(InvocationError, match="needs a target below") as e:
        invocation.check_calibration_sample(repo, tmp_path)  # a reviewed repository cannot claim the exemption
    assert (e.value.param, e.value.kind) == ("--calibration-sample", "bad_calibration_sample")
    with pytest.raises(InvocationError, match="not a calibration answer key"):
        invocation.check_calibration_sample(_sample(tmp_path / "other", labels=[]), tmp_path / "other")


# ---------------------------------------------------------------- the command line


def _review(tmp_path: Path, target: Path, *args: str):
    return CliRunner().invoke(app, ["review", str(target), "--provider", "mock", "--config", str(MOCK_CONFIG),
                                    "--out", str(tmp_path / "out"), *args], env={"MARA_HOME": str(ROOT)})


def test_a_calibration_sample_that_is_not_one_is_named_even_when_a_base_is_given(tmp_path, repo):
    res = _review(tmp_path, repo, "--base", "HEAD", "--calibration-sample")
    out = cli_output.plain(res.output)
    assert res.exit_code == 2 and isinstance(res.exception, SystemExit), res.exception
    assert "Invalid value for --calibration-sample" in out and "--base" not in out, out
    assert not (tmp_path / "out" / "report.json").exists()


def test_a_base_that_cannot_be_diffed_is_a_usage_error_on_base_before_a_review_starts(tmp_path, repo):
    res = _review(tmp_path, repo, "--base", "no-such-ref")
    assert res.exit_code == 2 and isinstance(res.exception, SystemExit), res.exception
    assert "Invalid value for --base" in cli_output.plain(res.output)


def test_a_value_error_of_the_review_itself_is_not_a_usage_error_on_base(tmp_path, repo, monkeypatch):
    """With `--base` given, any ValueError out of the pipeline used to read as a broken base."""
    def run(self, target, **kw):
        raise ValueError("boom")

    monkeypatch.setattr(cli.Pipeline, "run", run)
    res = _review(tmp_path, repo, "--base", "HEAD")
    assert res.exit_code == 1 and not isinstance(res.exception, SystemExit), (res.exit_code, res.exception)
    assert isinstance(res.exception, ValueError) and str(res.exception) == "boom"


def test_an_empty_base_is_no_base_as_the_pipeline_always_read_it(tmp_path, repo, monkeypatch):
    seen: dict = {}

    class Stop(Exception):
        pass

    def run(self, target, **kw):
        seen.update(kw)
        raise Stop

    monkeypatch.setattr(cli.Pipeline, "run", run)
    res = _review(tmp_path, repo, "--base", "")
    assert isinstance(res.exception, Stop), (res.exit_code, res.exception, res.output)
    assert seen["base_ref"] == ""


# ---------------------------------------------------------------- the pipeline's own check


def _pipeline(tmp_path: Path, workspace: Path) -> Pipeline:
    return Pipeline(load_config(MOCK_CONFIG), mock_fixtures=FIXTURES, out_dir=tmp_path / "out", workspace=workspace)


def test_the_pipeline_refuses_a_base_it_cannot_diff_against_before_it_makes_its_output_directory(tmp_path, repo):
    with pytest.raises(InvocationError) as e:
        _pipeline(tmp_path, tmp_path / "ws").run(repo, provider_mode="mock", base_ref="no-such-ref")
    assert (e.value.param, e.value.kind) == ("--base", "bad_base_ref")
    assert not (tmp_path / "out").exists()


def test_the_pipeline_reads_an_empty_base_as_no_base(tmp_path, repo):
    report = _pipeline(tmp_path, ROOT).run(repo, sarif_dir=ROOT / "fixtures" / "vuln-sample-sarif", provider_mode="mock", base_ref="")
    assert report.review_scope == "full"


def test_the_pipeline_refuses_a_target_that_is_not_a_sample_of_its_workspace(tmp_path, repo):
    """Still a ValueError, which InvocationError is, for a caller that caught it."""
    with pytest.raises(ValueError) as e:
        _pipeline(tmp_path, tmp_path / "ws").run(repo, provider_mode="mock", calibration_sample=True)
    assert isinstance(e.value, InvocationError)
    assert (e.value.param, e.value.kind) == ("--calibration-sample", "bad_calibration_sample")
