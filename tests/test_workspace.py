"""The MARA workspace as a value (mara.workspace.Workspace): where its tool directory and its trivy cache are, and that
building one reads nothing from the environment."""

from __future__ import annotations

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
