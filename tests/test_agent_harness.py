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
