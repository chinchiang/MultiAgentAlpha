"""Vibe-coded order dashboard (deliberately vulnerable fixture for MARA tests).

DO NOT DEPLOY. Every defect here is seeded on purpose and referenced by the test-suite.
"""

import logging
import sqlite3

from flask import Flask, jsonify, make_response, redirect, render_template_string, request

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
log = logging.getLogger("dashboard")


def db():
    return sqlite3.connect("orders.db")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # TODO: sanitize later
    return render_template_string("<h1>Results for " + q + "</h1>")


@app.route("/orders/<order_id>")
def get_order(order_id):
    cur = db().cursor()
    cur.execute("SELECT * FROM orders WHERE id = " + order_id)
    row = cur.fetchone()
    return jsonify(row)


@app.route("/api/users/<int:user_id>/profile")
def profile(user_id):
    # any logged-in user can read any profile by changing the id
    cur = db().cursor()
    cur.execute("SELECT name, email, address FROM users WHERE id = ?", (user_id,))
    return jsonify(cur.fetchone())


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    pw = request.form.get("password")
    log.info("login attempt user=%s password=%s", user, pw)
    cur = db().cursor()
    cur.execute("SELECT id FROM users WHERE name = ? AND password = ?", (user, pw))
    if cur.fetchone():
        resp = make_response(redirect(request.args.get("next", "/")))
        resp.set_cookie("session", user)
        return resp
    return "invalid user or password", 401


@app.route("/admin/export")
def export():
    if request.headers.get("X-Admin") == "1":
        return jsonify(config.EXPORT_TOKEN)
    return "forbidden", 403


@app.errorhandler(Exception)
def on_error(e):
    import traceback

    return "<pre>" + traceback.format_exc() + "</pre>", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
