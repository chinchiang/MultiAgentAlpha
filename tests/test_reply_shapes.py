"""Each ballot role's reply shape is written three times: the JSON schema the model is asked to answer in, the raw model
its reply items are parsed with (mara.agents.*), and the domain model the pipeline keeps (mara.schemas). The three must
agree, field for field, on which fields there are, which are required, the values an enum allows and the longest text a
field takes; otherwise a reply the schema admits is voided as an invalid item, or the other way round (GLOSSARY.md:
invalid item, ballot role)."""

from __future__ import annotations

import typing

import pytest
from pydantic import BaseModel

from mara import schemas
from mara.agents import judge, redteam, skeptic

ROLES = {
    "skeptic": (skeptic.SKEPTIC_SCHEMA, skeptic._SkepticRaw, schemas.SkepticVerdict),
    "red team": (redteam.REDTEAM_SCHEMA, redteam._RedRaw, schemas.RedTeamNote),
    "judge": (judge.JUDGE_SCHEMA, judge._JudgeRaw, schemas.JudgeVote),
}
# Strict on the wire, lenient when a report is read back: a skeptic reply without sanitizer_or_control is an invalid
# item (agents/skeptic.py, _SkepticRaw), but a report an older version wrote without it still loads (the owner's call,
# 2026-11-01). Every other difference fails.
DOMAIN_OPTIONAL = {("skeptic", "sanitizer_or_control")}


def _item(schema: dict) -> dict:
    return schema["properties"]["items"]["items"]


def _enum(model: type[BaseModel], name: str) -> list[str] | None:
    annotation = model.model_fields[name].annotation
    return list(typing.get_args(annotation)) if typing.get_origin(annotation) is typing.Literal else None


def _max_length(model: type[BaseModel], name: str) -> int | None:
    return next((m.max_length for m in model.model_fields[name].metadata if hasattr(m, "max_length")), None)


@pytest.mark.parametrize("role", ROLES)
def test_a_roles_schema_and_raw_model_name_the_same_fields_and_require_the_same(role):
    schema, raw, _ = ROLES[role]
    item = _item(schema)
    assert set(item["properties"]) == set(raw.model_fields)
    assert set(item["required"]) == {n for n, f in raw.model_fields.items() if f.is_required()}
    assert item.get("additionalProperties") is False, "an item with a field the role does not ask for is invalid"


@pytest.mark.parametrize("role", ROLES)
def test_a_roles_schema_and_raw_model_allow_the_same_values_and_lengths(role):
    schema, raw, _ = ROLES[role]
    for name, prop in _item(schema)["properties"].items():
        assert prop.get("enum") == _enum(raw, name), (role, name)
        assert prop.get("maxLength") == _max_length(raw, name), (role, name)


@pytest.mark.parametrize("role", ROLES)
def test_a_roles_domain_model_keeps_every_field_of_its_reply_with_the_same_constraints(role):
    _, raw, domain = ROLES[role]
    for name, field in raw.model_fields.items():
        assert name in domain.model_fields, (role, name)
        assert _enum(domain, name) == _enum(raw, name), (role, name)
        assert _max_length(domain, name) == _max_length(raw, name), (role, name)
        required = domain.model_fields[name].is_required()
        assert required == field.is_required() or (role, name) in DOMAIN_OPTIONAL, (role, name)
    for role_name, name in DOMAIN_OPTIONAL:
        assert role_name != role or not domain.model_fields[name].is_required(), "a listed exception that no longer is one"
