"""
Deliberately vulnerable Flask application for DAST testing.

SECURITY WARNING:
  This application intentionally contains vulnerabilities.
  It must only run in an isolated local environment.
  Never expose it to the internet or a production network.

Vulnerabilities present (for testing only):
  - Reflected XSS via /search?q=
  - Missing security headers (no CSP, X-Frame-Options, etc.)
  - Verbose error disclosure
  - No CSRF protection on POST endpoints
  - Insecure direct object reference on /user/<id>

Vulnerabilities ABSENT (for regression testing):
  - SQL injection (parameterized queries used)
  - Command injection (no shell execution)
  - Path traversal (no file system reads from user input)
"""

from __future__ import annotations

import html
import os

from flask import Flask, jsonify, render_template_string, request

# Guard: refuse to start if not in test/local mode
_ALLOWED_ENVS = frozenset({"test", "local", "development"})
_APP_ENV = os.environ.get("APP_ENV", "local").lower()

if _APP_ENV not in _ALLOWED_ENVS:
    raise RuntimeError(
        f"This vulnerable app must only run in test/local environments. "
        f"Current APP_ENV='{_APP_ENV}'. Set APP_ENV=local or APP_ENV=test."
    )

app = Flask(__name__)
app.config["DEBUG"] = False  # debug off even in test mode
app.config["TESTING"] = _APP_ENV == "test"

# Fake user database (no real data)
_USERS = {
    "1": {"id": "1", "name": "Alice Demo", "role": "user"},
    "2": {"id": "2", "name": "Bob Demo", "role": "admin"},
}

# ── Intentionally vulnerable endpoints ────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string("""
        <html>
        <head><title>DAST Test Target</title></head>
        <body>
          <h1>DAST Test Application</h1>
          <p>Endpoints: /search?q=, /user/1, /items, /login, /health</p>
          <form action="/search" method="get">
            <input name="q" placeholder="Search...">
            <button type="submit">Search</button>
          </form>
        </body>
        </html>
    """)


@app.route("/search")
def search():
    # INTENTIONAL: XSS — user input reflected without escaping
    # In a fixed version: use html.escape(q)
    q = request.args.get("q", "")
    # nosec B703 B308 — intentional for DAST test target
    return render_template_string(  # noqa: S701
        f"<html><body><h1>Results for: {q}</h1></body></html>"  # noqa: S608
    )


@app.route("/search/safe")
def search_safe():
    """Fixed version of /search — used for regression verification."""
    q = request.args.get("q", "")
    safe_q = html.escape(q)
    return render_template_string(
        "<html><body><h1>Results for: {{ q }}</h1></body></html>",
        q=safe_q,
    )


@app.route("/user/<user_id>")
def get_user(user_id: str):
    # INTENTIONAL: IDOR — no access control check
    user = _USERS.get(user_id)
    if user is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user)


@app.route("/items")
def items():
    return jsonify({"items": ["item1", "item2", "item3"]})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        # Fake auth — no real credentials stored
        if username == "demo" and request.form.get("password") == "demo":
            return jsonify({"status": "ok", "user": "demo"})
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    return render_template_string("""
        <html><body>
        <form method="post">
          <input name="username" placeholder="Username">
          <input name="password" type="password" placeholder="Password">
          <button type="submit">Login</button>
        </form>
        </body></html>
    """)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "env": _APP_ENV})


if __name__ == "__main__":
    # Bind only to localhost — never 0.0.0.0 in this test app
    app.run(host="127.0.0.1", port=5000, debug=False)
