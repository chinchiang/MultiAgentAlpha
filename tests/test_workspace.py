"""The MARA workspace as a value (mara.workspace.Workspace): where its tool directory and its trivy cache are, and that
building one reads nothing from the environment."""

from __future__ import annotations

import pytest

from mara.workspace import Workspace


def test_a_workspace_derives_its_tool_directory_and_trivy_cache_from_its_root_and_reads_no_environment(tmp_path, monkeypatch):
    """The tool directory is <root>/.mara-tools and the trivy cache <tool directory>/trivy-cache, wherever
    MARA_TOOLS_DIR and MARA_TRIVY_CACHE_DIR point: only Workspace.from_env reads them."""
    monkeypatch.setenv("MARA_TOOLS_DIR", str(tmp_path / "elsewhere-tools"))
    monkeypatch.setenv("MARA_TRIVY_CACHE_DIR", str(tmp_path / "elsewhere-cache"))
    root = tmp_path / "ws"
    ws = Workspace(root)
    assert ws.root == root
    assert ws.tools_dir == root / ".mara-tools"
    assert ws.trivy_cache == root / ".mara-tools" / "trivy-cache"


def test_a_workspace_given_a_tool_directory_derives_the_trivy_cache_below_it_and_keeps_either_it_is_given(tmp_path):
    tools = tmp_path / "tools"
    assert Workspace(tmp_path, tools_dir=tools).trivy_cache == tools / "trivy-cache"
    cache = tmp_path / "cache"
    ws = Workspace(tmp_path, tools_dir=tools, trivy_cache=cache)
    assert (ws.tools_dir, ws.trivy_cache) == (tools, cache)


def _environment(monkeypatch, **variables):
    for name in ("MARA_HOME", "MARA_TOOLS_DIR", "MARA_TRIVY_CACHE_DIR"):
        monkeypatch.delenv(name, raising=False)
    for name, value in variables.items():
        monkeypatch.setenv(name, str(value))


def test_a_workspace_from_the_environment_is_MARA_HOME_or_the_working_directory_and_derives_the_rest(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    _environment(monkeypatch, MARA_HOME=home)
    ws = Workspace.from_env()
    assert (ws.root, ws.tools_dir, ws.trivy_cache) == (home, home / ".mara-tools", home / ".mara-tools" / "trivy-cache")

    cwd = tmp_path / "cwd"
    cwd.mkdir()
    _environment(monkeypatch)
    monkeypatch.chdir(cwd)
    ws = Workspace.from_env()
    assert (ws.root, ws.tools_dir) == (cwd, cwd / ".mara-tools")


def test_a_workspace_from_the_environment_takes_its_tool_directory_and_trivy_cache_from_the_variables(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    tools, cache = tmp_path / "tools", tmp_path / "cache"
    _environment(monkeypatch, MARA_HOME=home, MARA_TOOLS_DIR=tools, MARA_TRIVY_CACHE_DIR=cache)
    ws = Workspace.from_env()
    assert (ws.tools_dir, ws.trivy_cache) == (tools, cache)

    _environment(monkeypatch, MARA_HOME=home, MARA_TOOLS_DIR=tools)  # a cache not named is below the tool directory
    assert Workspace.from_env().trivy_cache == tools / "trivy-cache"


def test_a_relative_MARA_TOOLS_DIR_is_below_the_root(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    _environment(monkeypatch, MARA_HOME=home, MARA_TOOLS_DIR="bin-of-tools")
    ws = Workspace.from_env()
    assert (ws.tools_dir, ws.trivy_cache) == (home / "bin-of-tools", home / "bin-of-tools" / "trivy-cache")


def test_a_workspace_from_the_environment_at_a_given_root_ignores_MARA_HOME_and_keeps_the_other_variables(tmp_path, monkeypatch):
    given, home, tools = tmp_path / "given", tmp_path / "home", tmp_path / "tools"
    given.mkdir()
    home.mkdir()
    _environment(monkeypatch, MARA_HOME=home)
    ws = Workspace.from_env(root=given)
    assert (ws.root, ws.tools_dir) == (given, given / ".mara-tools")

    _environment(monkeypatch, MARA_HOME=home, MARA_TOOLS_DIR=tools)
    assert Workspace.from_env(root=given).tools_dir == tools
    _environment(monkeypatch, MARA_HOME=home, MARA_TOOLS_DIR="relative")
    assert Workspace.from_env(root=given).tools_dir == given / "relative"


def test_a_relative_MARA_TRIVY_CACHE_DIR_is_below_the_root_not_the_working_directory(tmp_path, monkeypatch):
    """Like a relative MARA_TOOLS_DIR and every other relative path of MARA's own: below the root, wherever the process
    runs. An absolute one is taken as it is."""
    home, given, cwd = tmp_path / "home", tmp_path / "given", tmp_path / "cwd"
    for d in (home, given, cwd):
        d.mkdir()
    monkeypatch.chdir(cwd)
    _environment(monkeypatch, MARA_HOME=home, MARA_TRIVY_CACHE_DIR="db-cache")
    assert Workspace.from_env().trivy_cache == home / "db-cache"
    assert Workspace.from_env(root=given).trivy_cache == given / "db-cache"

    absolute = tmp_path / "absolute-cache"
    _environment(monkeypatch, MARA_HOME=home, MARA_TRIVY_CACHE_DIR=absolute)
    assert Workspace.from_env().trivy_cache == absolute


def test_a_relative_path_is_resolved_below_a_base_that_is_named_and_a_target_is_checked_against_a_workspace_that_is_named(tmp_path):
    """Neither `resolve` nor `check_outside` falls back to the environment's workspace: the caller says which one."""
    from mara.workspace import check_outside, resolve

    with pytest.raises(TypeError):
        resolve("calib/latest.json")
    with pytest.raises(TypeError):
        check_outside(tmp_path / "target")


def test_a_path_a_user_writes_is_expanded_then_resolved_below_the_root_of_the_environments_workspace(tmp_path, monkeypatch):
    """`~` is the user's home, a relative path lies below MARA_HOME (else the working directory), an absolute one is as given:
    the one rule of a CA bundle named in a config (providers) and in a model evaluation."""
    from mara.workspace import resolve_user_path

    home, mara_home = tmp_path / "home", tmp_path / "mara-home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("MARA_HOME", str(mara_home))
    assert resolve_user_path("~/ca.pem") == home / "ca.pem"
    assert resolve_user_path("certs/ca.pem") == mara_home.resolve() / "certs" / "ca.pem"
    assert resolve_user_path(str(tmp_path / "abs.pem")) == tmp_path / "abs.pem"
