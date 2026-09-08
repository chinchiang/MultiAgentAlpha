from mara.agents import base
from mara.context.repo_map import build_context


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


def test_context_strips_nothing_but_records_entry_points(root):
    ctx = build_context(root / "fixtures" / "vuln-sample")
    assert "flask:/orders/<order_id>" in ctx.entry_points
    assert any(w.name == "deploy.yml" for w in ctx.workflows)
    assert ctx.content_hash and len(ctx.content_hash) == 64
