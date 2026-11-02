"""The panel of a config (GLOSSARY.md: Panel): the models it names and the role each plays, described once for
everything the workbench shows of it: a run's record (`runs.RunRegistry.prepare`), the environment page's config list
(`env.configs`), and, for a run that has no record, the models a report's provider manifest lists (`views.roles`).

A model's row holds seven keys, `model_row`, and each place adds the keys of its own on top (the run record the name of
the key's environment variable, the environment page the weight and whether the credential is present). Of a model's
endpoint a row holds the host and nothing else (`endpoint_host`: never the URL, its credentials, port, path or
query); the demo's scrub (scripts/build_workbench_demo.py) finds a host by that key, so a row of a model always has it.
A report names a model's provider `type` (`pipeline.Pipeline._provider_manifest` writes it, and reports already
written keep it); `manifest_row` is the one place that reads it back as `provider`.

Pure: it reads only what it is given."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypedDict
from urllib.parse import urlparse

from ..config import ModelSpec, RolesConfig


class ModelRow(TypedDict):
    name: str
    family: str
    provider: str
    model: str
    data_residency: str
    region: str | None
    endpoint_host: str | None


class RolesRow(TypedDict):
    context: str
    reviewers: list[str]
    skeptic: str
    redteam: str
    judges: list[str]


class ManifestRow(TypedDict):
    name: str | None
    family: str | None
    provider: str | None
    model: str | None


def endpoint_host(base_url: str | None) -> str | None:
    """The host of an endpoint's URL, None without one: what the workbench shows of where a model is called."""
    return urlparse(base_url).hostname if base_url else None


def model_row(m: ModelSpec) -> ModelRow:
    return {"name": m.name, "family": m.family.value, "provider": m.provider, "model": m.model, "data_residency": m.data_residency,
            "region": m.region, "endpoint_host": endpoint_host(m.base_url)}


def roles_row(r: RolesConfig) -> RolesRow:
    """The five roles; the lists are copies, so a caller adding to a row does not change the config."""
    return {"context": r.context, "reviewers": list(r.reviewers), "skeptic": r.skeptic, "redteam": r.redteam, "judges": list(r.judges)}


def manifest_row(entry: Mapping[str, Any]) -> ManifestRow:
    """One entry of a report's provider manifest as a model of the panel: its `type` is the provider, and what the
    manifest does not hold (the data residency, the endpoint) is not here."""
    return {"name": entry.get("name"), "family": entry.get("family"), "provider": entry.get("type"), "model": entry.get("model")}
