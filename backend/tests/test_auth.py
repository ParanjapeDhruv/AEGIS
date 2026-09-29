"""
Auth endpoint tests against the real MySQL database.

Coverage:
  - POST /api/auth/register  — success, duplicate email
  - POST /api/auth/login     — success, wrong password, unknown email
  - GET  /api/auth/me        — valid token, missing token, invalid token
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.app.models.user import User
from backend.app.main import app

client = TestClient(app, raise_server_exceptions=True)

# Unique email per test run so re-runs don't conflict
_RUN = uuid.uuid4().hex[:8]
ALICE = {
    "name": "Alice Test",
    "email": f"alice_{_RUN}@example.com",
    "password": "SecurePass1",
}
BOB = {
    "name": "Bob Test",
    "email": f"bob_{_RUN}@example.com",
    "password": "BobPass99!",
}


@pytest.fixture(autouse=True, scope="module")
def cleanup_users():
    """Remove test users from DB after the module finishes."""
    yield
    db = SessionLocal()
    try:
        for email in [ALICE["email"], BOB["email"]]:
            user = db.query(User).filter(User.email == email).first()
            if user:
                db.delete(user)
        db.commit()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register(payload):
    return client.post("/api/auth/register", json=payload)

def _login(email, password):
    return client.post("/api/auth/login", json={"email": email, "password": password})


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_register_success():
    res = _register(ALICE)
    assert res.status_code == 201, res.text
    body = res.json()
    assert "access_token" in body
    assert body["user"]["email"] == ALICE["email"]
    assert body["user"]["role"] == "user"
    # plaintext password must never appear in the response
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]


def test_register_second_user_success():
    res = _register(BOB)
    assert res.status_code == 201, res.text
    assert res.json()["user"]["email"] == BOB["email"]


def test_register_duplicate_email_returns_409():
    res = _register(ALICE)   # already registered above
    assert res.status_code == 409
    assert "already exists" in res.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def test_login_success():
    res = _login(ALICE["email"], ALICE["password"])
    assert res.status_code == 200, res.text
    body = res.json()
    assert "access_token" in body
    assert body["user"]["email"] == ALICE["email"]


def test_login_wrong_password_returns_401():
    res = _login(ALICE["email"], "WrongPassword99")
    assert res.status_code == 401


def test_login_unknown_email_returns_401():
    res = _login("nobody_at_all@example.com", "Whatever123")
    assert res.status_code == 401


# ---------------------------------------------------------------------------
# Protected endpoint — GET /api/auth/me
# ---------------------------------------------------------------------------

def test_me_with_valid_token():
    token = _login(ALICE["email"], ALICE["password"]).json()["access_token"]
    res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["email"] == ALICE["email"]


def test_me_without_token_returns_4xx():
    res = client.get("/api/auth/me")
    assert res.status_code in (401, 403)


def test_me_with_invalid_token_returns_401():
    res = client.get("/api/auth/me", headers={"Authorization": "Bearer thisisnotvalid"})
    assert res.status_code == 401
