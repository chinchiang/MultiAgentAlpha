from mara.agents import base
from mara.context.repo_map import RepoContext, build_context


def test_canary_is_planted_and_detected(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    c = base.Canary()
    block = base.untrusted_block(ctx, c)
    assert c.token in block and "<untrusted_repository_data>" in block
    assert c.echoed(f"sure, {c.token}") and not c.echoed("no token here")


def test_verify_quote_requires_verbatim_text_near_line(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    assert base.verify_quote(ctx, "app.py", 32, 'cur.execute("SELECT * FROM orders WHERE id = " + order_id)')
    assert base.verify_quote(ctx, "app.py", 30, "SELECT * FROM orders")  # within +-3 lines
    assert not base.verify_quote(ctx, "app.py", 60, "SELECT * FROM orders")  # too far away
    assert not base.verify_quote(ctx, "app.py", 41, "user_id + \"'\"")  # fabricated
    assert not base.verify_quote(ctx, "missing.py", 1, "anything")


def test_verify_quote_rejects_quotes_too_trivial_to_pin_anything(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    # each of these really occurs within +-3 lines of app.py:32, so the substring test alone passed them
    for trivial in ["def", "id =", "()", ")", "\"", "cur.", "  (  )  "]:
        assert not base.verify_quote(ctx, "app.py", 32, trivial), trivial
    assert base.MIN_QUOTE_CHARS == 8
    assert base.verify_quote(ctx, "app.py", 32, "+ order_id")  # 9 non-whitespace characters: long enough
    # a short quote that is exactly the claimed line still verifies, but not from a neighbouring line
    assert base.verify_quote(ctx, "requirements.txt", 1, "flask")
    assert base.verify_quote(ctx, "requirements.txt", 1, "  flask ")
    assert not base.verify_quote(ctx, "requirements.txt", 2, "flask")
    # a whole line without a letter or digit pins nothing either
    brace = RepoContext(root=root, content={"a.js": "function f() {\n  return 1;\n}\n"})
    assert not base.verify_quote(brace, "a.js", 3, "}")
    assert base.verify_quote(brace, "a.js", 2, "return 1;")


def test_context_strips_nothing_but_records_entry_points(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    assert "flask:/orders/<order_id>" in ctx.entry_points
    assert any(w.name == "deploy.yml" for w in ctx.workflows)
    assert ctx.content_hash and len(ctx.content_hash) == 64


# ------------------------------------------------------------------ refusals vs invalid output (#29)

import json  # noqa: E402

from mara.agents import context_agent, skeptic  # noqa: E402
from mara.config import load_config  # noqa: E402
from mara.providers.base import Completion, Provider  # noqa: E402
from mara.schemas import Finding, ModelFamily, Provenance  # noqa: E402

VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _static(root, data, refused=False):
    class Static(Provider):
        def __init__(self):
            super().__init__(load_config(root / "config" / "mara.mock.yaml").models[0])

        def complete(self, **kwargs):
            if refused:
                return Completion(data=None, raw_text="", refused=True)
            return Completion(data=data, raw_text=json.dumps(data))

    return Static()


def _finding():
    return Finding(id="F-1", dimension="vulnerabilities", title="SQL finding", cwe="CWE-89",
                   provenance=[Provenance(file="app.py", line=1, quote="def get(u):", verified=True)],
                   reachability="reachable", reachability_argument="public", exploit_sketch="input",
                   cvss4_vector=VECTOR, model_confidence=0.9, source_family=ModelFamily.ANTHROPIC, source_model="test")


def test_parse_items_separates_refusals_from_empty_and_invalid_output():
    from pydantic import BaseModel

    class Item(BaseModel):
        a: int

    assert base.parse_items(Completion(data=None, raw_text="", refused=True), Item) == ([], ["refused"])
    assert base.parse_items(Completion(data=None, raw_text="{}"), Item) == ([], ["empty"])
    assert base.parse_items(Completion(data={"items": "nope"}, raw_text="x"), Item) == ([], ["invalid_response_shape"])
    valid, errors = base.parse_items(Completion(data={"items": [1, {"a": 1}]}, raw_text="x"), Item)
    assert len(valid) == 1 and len(errors) == 1 and errors[0].startswith("invalid_item:")


# ------------------------------------------------------------------ control citation verification (#33)

def test_skeptic_keeps_a_refutation_whose_control_citation_is_in_the_bundle(root):
    ctx = RepoContext(root=root, content={"app.py": "import sqlite3\n\n\ndef get(u):\n    return u\n"})
    p = _static(root, {"items": [{"finding_id": "F-1", "verdict": "refuted", "reason": "already parameterised",
                                  "sanitizer_or_control": "app.py:5 uses the parameterised cursor"}]})
    v, errors, unverified = skeptic.run_skeptic(p, ctx, [_finding()])
    assert not errors and unverified == 0
    assert v[0].verdict == "refuted" and "not verifiable" not in v[0].reason


def test_skeptic_downgrades_refutations_without_a_locatable_control_citation(root):
    ctx = RepoContext(root=root, content={"app.py": "def get(u):\n    return u\n"})
    for cite in ["parameterised query in the data layer", "hardened.py:1 prepared statements"]:
        p = _static(root, {"items": [{"finding_id": "F-1", "verdict": "refuted", "reason": "mitigated",
                                      "sanitizer_or_control": cite}]})
        v, errors, unverified = skeptic.run_skeptic(p, ctx, [_finding()])
        assert not errors and unverified == 1, cite
        assert v[0].verdict == "weakened" and "control citation not verifiable in bundle" in v[0].reason, cite


# ------------------------------------------------------------------ L1 context agent (#19)

def test_context_agent_keeps_only_quote_verified_facts(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    data = {
        "containers": [{"name": "dashboard", "technology": "flask", "file": "app.py", "line": 13, "quote": "app = Flask(__name__)"}],
        "external_systems": [{"name": "package registry", "file": "requirements.txt", "line": 1, "quote": "flask"}],
        "trust_boundaries": [{"name": "orders", "file": "app.py", "line": 999, "quote": "def get_order(order_id):"}],  # out of range
        "data_stores": [{"name": "orders.db", "file": "app.py", "line": 19, "quote": 'return sqlite3.connect("orders.db")'}],
    }
    view, audit = context_agent.run_context_agent(_static(root, data), ctx)
    assert audit["unverified"] == 1 and audit["invalid"] == 0 and not audit["refused"]
    assert [(i.kind, i.name) for i in view.items] == [
        ("container", "dashboard"), ("external_system", "package registry"), ("data_store", "orders.db")]
    block = view.facts_block()
    assert "<trusted_context_facts>" in block and "orders.db" in block and "not part of the untrusted data" in block


def test_context_agent_yields_no_view_on_refusal_or_canary_echo(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    view, audit = context_agent.run_context_agent(_static(root, None, refused=True), ctx)
    assert view is None and audit["refused"]

    class Echo(Provider):
        def __init__(self):
            super().__init__(load_config(root / "config" / "mara.mock.yaml").models[0])

        def complete(self, *, user, **kwargs):
            return Completion(data=None, raw_text=user)  # echoes the prompt, canary token included

    view, audit = context_agent.run_context_agent(Echo(), ctx)
    assert view is None and audit["canary_echoed"]


def test_reviewer_receives_trusted_facts_only_for_context_dimensions(root):
    from mara.agents.reviewer import CONTEXT_DIMENSIONS, review_dimension

    ctx = build_context(root / "fixtures" / "vuln-sample")
    view = context_agent.ContextView(source_family="anthropic", source_model="test", items=[
        context_agent.ContextItem(kind="trust_boundary", name="orders", file="app.py", line=22, quote='@app.route("/search")')])
    seen = {}

    class Capture(Provider):
        def __init__(self):
            super().__init__(load_config(root / "config" / "mara.mock.yaml").models[0])

        def complete(self, *, user, **kwargs):
            seen["user"] = user
            return Completion(data={"findings": []}, raw_text="{}")

    canary = base.Canary()
    review_dimension(Capture(), ctx, "architecture", canary, view)
    assert "<trusted_context_facts>" in seen["user"] and "app.route" in seen["user"]
    review_dimension(Capture(), ctx, "xss", canary, view)
    assert "<trusted_context_facts>" not in seen["user"]
    assert set(CONTEXT_DIMENSIONS) == {"architecture", "authn_authz"}


# ------------------------------------------------------------------ mock behaviour

def test_mock_fills_control_citation_from_finding_evidence():
    from mara.providers.mock import _fill_control_citation

    data = {"items": [
        {"finding_id": "F-1", "verdict": "refuted", "reason": "r", "sanitizer_or_control": "parameterised query"},
        {"finding_id": "F-2", "verdict": "weakened", "reason": "r", "sanitizer_or_control": "weak validation"},
        {"finding_id": "F-3", "verdict": "refuted", "reason": "r", "sanitizer_or_control": "app.py:41 prepared statements"},
    ]}
    user = 'BEGIN_JSON_ARRAY\n[{"finding_id": "F-1", "evidence": [{"file": "app.py", "line": 41, "quote": "q"}]}]'
    out = _fill_control_citation(data, user)
    assert out["items"][0]["sanitizer_or_control"].startswith("app.py:41 ")
    assert out["items"][1]["sanitizer_or_control"] == "weak validation"  # only refutations get pinned
    assert out["items"][2]["sanitizer_or_control"] == "app.py:41 prepared statements"  # already pinned
