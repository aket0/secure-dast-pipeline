"""
Tests for the DAST target application.

Two categories:
  1. Functional tests — application works as expected
  2. Security control tests — verify known vulnerabilities exist for DAST,
     and that fixes work in the safe endpoints (regression tests)
"""

from __future__ import annotations

import os

import pytest

os.environ["APP_ENV"] = "test"

from src.target_app.app import app  # noqa: E402


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestFunctional:
    def test_index_200(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_health_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_items_returns_list(self, client):
        r = client.get("/items")
        assert r.status_code == 200
        data = r.get_json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_user_found(self, client):
        r = client.get("/user/1")
        assert r.status_code == 200
        assert r.get_json()["name"] == "Alice Demo"

    def test_user_not_found_404(self, client):
        r = client.get("/user/999")
        assert r.status_code == 404

    def test_login_valid_credentials(self, client):
        r = client.post("/login", data={"username": "demo", "password": "demo"})
        assert r.status_code == 200
        assert r.get_json()["status"] == "ok"

    def test_login_invalid_credentials(self, client):
        r = client.post("/login", data={"username": "bad", "password": "bad"})
        assert r.status_code == 401


class TestVulnerabilityPresence:
    """
    These tests verify that intentional vulnerabilities are present.
    They document what DAST scanners like ZAP should detect.
    """

    def test_xss_reflected_in_search(self, client):
        """Verify XSS is reflected — this is the DAST scan target."""
        payload = "<script>alert(1)</script>"
        r = client.get(f"/search?q={payload}")
        assert r.status_code == 200
        # In the vulnerable endpoint, the script tag is reflected unescaped
        assert payload in r.data.decode()

    def test_idor_any_user_accessible(self, client):
        """IDOR: user 2 (admin) is accessible without authentication."""
        r = client.get("/user/2")
        assert r.status_code == 200
        assert r.get_json()["role"] == "admin"


class TestRegressionAfterFix:
    """
    These tests verify that the fixed /search/safe endpoint does NOT reflect XSS.
    Use these to confirm fixes before running DAST again.
    """

    def test_xss_escaped_in_safe_search(self, client):
        """After fix: raw script tag must not appear in the response."""
        payload = "<script>alert(1)</script>"
        r = client.get(f"/search/safe?q={payload}")
        assert r.status_code == 200
        body = r.data.decode()
        # Raw unescaped script tag must NOT appear
        assert "<script>" not in body, (
            "XSS fix failed: unescaped <script> tag appears in /search/safe response"
        )

    def test_safe_search_normal_input(self, client):
        """Safe endpoint works for normal input."""
        r = client.get("/search/safe?q=hello+world")
        assert r.status_code == 200
        assert "hello" in r.data.decode()


class TestEnvironmentGuard:
    def test_app_env_is_test(self, client):
        """Application must refuse to start outside test/local environments."""
        r = client.get("/health")
        assert r.get_json()["env"] == "test"

    def test_debug_mode_off(self):
        """Debug mode must be off even in test environment."""
        assert app.config["DEBUG"] is False
