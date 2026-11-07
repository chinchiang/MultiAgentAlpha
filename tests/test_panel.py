"""The panel of a config (GLOSSARY.md: Panel): the models it names and the role each plays, described once by
`mara.web.panel` for everything the workbench shows of it: the run record's `models` and `roles`
(`RunRegistry.prepare`), the environment page's config list (`env.configs`), and a report's provider manifest read
back for a run that has no run record (`views.roles`).

A model's host is the one thing of its endpoint the workbench shows (`endpoint_host`: never the URL, its credentials,
port, path or query), and the demo's scrub (scripts/build_workbench_demo.py) finds it by that key, so every description
of a model carries it. The cases of the last group describe behaviour that was already there (marked
"characterization"): they passed on their first run, before `mara.web.panel` existed, and hold the refactor to it."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlparse

import pytest

from mara.config import ModelSpec, RolesConfig, load_config
from mara.schemas import ModelFamily, ReviewReport
from mara.web import env, runs, views

ROOT = Path(__file__).resolve().parents[1]
CORE = ("name", "family", "provider", "model", "data_residency", "region", "endpoint_host")
ROLE_KEYS = {"context", "reviewers", "skeptic", "redteam", "judges"}
SECRET_URL = "https://user:secret@llm.example.com:8443/v1/chat?key=abc#frag"


def _spec(**fields) -> ModelSpec:
    """A model as the panel meets it, built without ModelSpec's validation: the validator refuses an endpoint with
    credentials, a query or a port-less non-loopback http one, and the host must be all the panel keeps whatever the
    validator let through."""
    return ModelSpec.model_construct(**{"name": "m", "family": ModelFamily.GLM, "provider": "openai_compatible", "model": "glm-x", **fields})


def _demo():
    spec = importlib.util.spec_from_file_location("build_workbench_demo", ROOT / "scripts" / "build_workbench_demo.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_model_row_holds_the_seven_core_keys():
    from mara.web import panel

    row = panel.model_row(_spec(base_url=SECRET_URL, region="eu", data_residency="on_prem"))
    assert tuple(sorted(row)) == tuple(sorted(CORE))
    assert row["name"] == "m" and row["family"] == "glm" and type(row["family"]) is str
    assert (row["provider"], row["model"], row["data_residency"], row["region"]) == ("openai_compatible", "glm-x", "on_prem", "eu")
    assert row["endpoint_host"] == "llm.example.com"


def test_a_model_without_an_endpoint_has_a_null_host_not_a_missing_key():
    from mara.web import panel

    assert panel.model_row(_spec())["endpoint_host"] is None


@pytest.mark.parametrize(("url", "host"), [
    (SECRET_URL, "llm.example.com"),
    ("http://10.0.0.5:8000", "10.0.0.5"),
    ("https://LLM.Example.com/v1", "llm.example.com"),
    (None, None),
    ("", None),
], ids=["credentials port path query", "address and port", "upper case", "none", "empty"])
def test_the_endpoint_host_is_the_host_and_nothing_else_of_the_url(url, host):
    from mara.web import panel

    assert panel.endpoint_host(url) == host
    assert "secret" not in repr(panel.model_row(_spec(base_url=url)))


def test_a_roles_row_holds_the_five_roles_and_copies_the_lists():
    from mara.web import panel

    roles = RolesConfig(context="c", reviewers=["r1", "r2"], skeptic="s", redteam="t", judges=["j1"])  # reviewers and judges differ
    row = panel.roles_row(roles)
    assert set(row) == ROLE_KEYS
    assert row == {"context": roles.context, "reviewers": roles.reviewers, "skeptic": roles.skeptic, "redteam": roles.redteam,
                   "judges": roles.judges}
    row["reviewers"].append("added")
    row["judges"].clear()
    assert "added" not in roles.reviewers and roles.judges, "the row's lists are copies"


def test_a_manifest_entry_is_read_back_with_its_type_as_the_provider():
    from mara.web import panel

    entry = {"name": "a", "type": "bedrock", "family": "anthropic", "model": "m", "served_models": ["x"]}
    assert panel.manifest_row(entry) == {"name": "a", "family": "anthropic", "provider": "bedrock", "model": "m"}
    assert panel.manifest_row({}) == {"name": None, "family": None, "provider": None, "model": None}


def test_the_providers_manifest_a_review_writes_reads_back_as_the_models_of_its_config(tmp_path):
    from mara.pipeline import Pipeline
    from mara.web import panel

    cfg = load_config(ROOT / "config" / "mara.mock.yaml")
    manifest = Pipeline(cfg, mock_fixtures=str(ROOT / "fixtures" / "mock-responses"), out_dir=tmp_path)._provider_manifest()
    assert manifest
    for entry in manifest:
        row = panel.model_row(cfg.model_by_name(entry["name"]))
        assert panel.manifest_row(entry) == {k: row[k] for k in ("name", "family", "provider", "model")}


def test_the_demos_scrub_finds_the_host_of_every_model_row():
    """scripts/build_workbench_demo.py removes the host by its key; a description of a model without the key would
    show a host the scrub does not see."""
    from mara.web import panel

    assert "endpoint_host" in panel.ModelRow.__annotations__
    row = panel.model_row(_spec(base_url=SECRET_URL))
    assert row["endpoint_host"] == "llm.example.com" and _demo()._strip_hosts(row)["endpoint_host"] is None


def test_a_report_without_a_run_record_lists_a_model_only_under_the_roles_the_audit_counted_it_calling():
    """The report holds no roles, so the page lists a model under a role only on the evidence of the audit (its family
    has calls counted for that role), names its provider by the manifest's `type`, and does not claim the model was
    configured for the role (`configured` is None: the report does not say, which is not a reassignment, False)."""
    from mara.audit import Audit
    from tests.reply_records import ballot, extraction

    entries = [{"name": "a", "type": "bedrock", "family": "anthropic", "model": "m1", "served_models": ["s1"]},
               {"name": "b", "type": "gemini", "family": "gemini", "model": "m2", "served_models": []},
               {"name": "c", "type": "openai_compatible", "family": "glm", "model": "m3", "served_models": []},
               {"name": "d", "type": "openai_compatible", "family": "deepseek", "model": "m4", "served_models": []}]
    a = Audit()
    a.record(extraction("reviewer", "anthropic"))
    a.record(extraction("reviewer", "gemini"))
    a.record(ballot("judge", "anthropic", 1))
    a.record(ballot("skeptic", "glm", 1))
    report = ReviewReport.model_construct(bias_audit=dict(a), provider_manifest=entries)
    groups = {g["role"]: g["members"] for g in views.roles({}, report)}
    assert list(groups) == ["reviewers", "skeptic", "judges"]
    row = lambda m: (m["name"], m["family"], m["provider"], m["model"], m["configured"])  # noqa: E731
    assert [row(m) for m in groups["reviewers"]] == [("a", "anthropic", "bedrock", "m1", None), ("b", "gemini", "gemini", "m2", None)]
    assert [row(m) for m in groups["skeptic"]] == [("c", "glm", "openai_compatible", "m3", None)]
    assert [row(m) for m in groups["judges"]] == [("a", "anthropic", "bedrock", "m1", None)]
    assert views.roles({}, ReviewReport.model_construct(bias_audit={}, provider_manifest=entries)) == []
    assert views.roles({}, None) == []


# characterization: the builders as they were before they shared a description. They pass on their first run.


def _loaded_configs():
    """Every config the workbench lists that loads: path -> the config as the validator reads it."""
    return {entry["path"]: load_config(ROOT / entry["path"], enforce_policies=False) for entry in env.configs(ROOT) if entry["structure_ok"]}


def test_characterization_the_environment_page_shows_each_model_with_its_host_and_never_its_url():
    hosts = 0
    for entry in env.configs(ROOT):
        if not entry["structure_ok"]:
            continue
        cfg = load_config(ROOT / entry["path"], enforce_policies=False)
        assert [m["name"] for m in entry["models"]] == [m.name for m in cfg.models]
        for shown, spec in zip(entry["models"], cfg.models, strict=True):
            assert set(shown) == {*CORE, "weight", "credential"}, entry["path"]
            assert shown["endpoint_host"] == (urlparse(spec.base_url).hostname if spec.base_url else None)
            assert set(shown["credential"]) == {"kind", "env", "present"}
            hosts += shown["endpoint_host"] is not None
        assert set(entry["roles"]) == ROLE_KEYS
    assert hosts, "some shipped config names an endpoint, or the cases above say nothing about hosts"


def _launches(tmp_path):
    """The run record fields of every launch the workbench accepts, over the shipped configs: (config, mode) -> fields."""
    reg = runs.RunRegistry(ROOT, tmp_path)
    out = {}
    for path in _loaded_configs():
        for mode in ("mock", "live"):
            try:
                out[(path, mode)] = reg.prepare(runs.LaunchRequest(target="fixtures/vuln-sample", provider=mode, config=path))[1]
            except runs.LaunchError:
                pass
    return out


def test_characterization_a_run_record_holds_each_model_with_its_host_and_key_name_and_the_five_roles(tmp_path):
    launches = _launches(tmp_path)
    assert launches
    hosts = 0
    for (path, _), fields in launches.items():
        cfg = _loaded_configs()[path]
        assert [m["name"] for m in fields["models"]] == [m.name for m in cfg.models]
        for shown, spec in zip(fields["models"], cfg.models, strict=True):
            assert set(shown) == {*CORE, "api_key_env"}, path
            assert shown["api_key_env"] == spec.api_key_env
            assert shown["endpoint_host"] == (urlparse(spec.base_url).hostname if spec.base_url else None)
            hosts += shown["endpoint_host"] is not None
        assert set(fields["roles"]) == ROLE_KEYS
    assert hosts


def test_characterization_a_run_record_and_the_environment_page_describe_a_model_alike(tmp_path):
    page = {e["path"]: {m["name"]: m for m in e["models"]} for e in env.configs(ROOT) if e["structure_ok"]}
    page_roles = {e["path"]: e["roles"] for e in env.configs(ROOT) if e["structure_ok"]}
    launches = _launches(tmp_path)
    assert launches
    for (path, _), fields in launches.items():
        for shown in fields["models"]:
            assert {k: shown[k] for k in CORE} == {k: page[path][shown["name"]][k] for k in CORE}, (path, shown["name"])
        assert fields["roles"] == page_roles[path]


def test_the_environment_page_lists_policies_as_the_workspace_it_is_given_holds_evidence_for_them(tmp_path, monkeypatch):
    """P8 of a listed config reads the Evidence record of the workspace the page lists, not of MARA_HOME."""
    import datetime as dt
    import json

    import yaml

    from mara.policy import AAT_METHOD

    allow = dict(yaml.safe_load((ROOT / "config" / "mara.yaml").read_text(encoding="utf-8")), gate=dict(unsupervised_reject_allowed=True))
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "allow.yaml").write_text(yaml.safe_dump(allow), encoding="utf-8")
    (tmp_path / "calib").mkdir()
    record = {"date": dt.date.today().isoformat(), "mode": "live", "aat": {
        "method": AAT_METHOD, "passed": True, "n": 12, "agreement": 1.0, "chance_agreement": 0.5, "p_value": 0.0002,
        "rejection": {"n": 59, "misses": 0, "miss_rate_upper": 0.0495, "passed": True}}}
    (tmp_path / "calib" / "latest.json").write_text(json.dumps(record), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.setenv("MARA_HOME", str(elsewhere))

    (entry,) = env.configs(tmp_path)
    assert entry["structure_ok"] and entry["loadable"], [p for p in entry["policies"] if not p["passed"]]
