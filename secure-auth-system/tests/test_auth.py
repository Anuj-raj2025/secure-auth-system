from datetime import datetime, timedelta, timezone

import jwt
import pytest

import security
from app import create_app
from config import Config
from models import User, db

USER = {"username": "alice", "email": "alice@example.com", "password": "Str0ng!Pass"}


@pytest.fixture()
def client():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
    with app.test_client() as c:
        c.app = app
        yield c


def register(client, **overrides):
    return client.post("/api/register", json={**USER, **overrides})


def login(client, password=USER["password"], email=USER["email"]):
    return client.post("/api/login", json={"email": email, "password": password})


def auth(token):
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------ registration
def test_register_success(client):
    res = register(client)
    assert res.status_code == 201
    assert "password" not in res.get_json()["user"]


def test_password_is_hashed_with_bcrypt(client):
    register(client)
    with client.app.app_context():
        user = User.query.filter_by(email=USER["email"]).first()
        assert user.password_hash != USER["password"]
        assert user.password_hash.startswith("$2")


@pytest.mark.parametrize("password", ["short1!", "alllowercase1!", "ALLUPPERCASE1!", "NoNumber!!", "NoSpecial123"])
def test_weak_passwords_rejected(client, password):
    assert register(client, password=password).status_code == 400


def test_invalid_email_and_username(client):
    assert register(client, email="not-an-email").status_code == 400
    assert register(client, username="a").status_code == 400


def test_duplicate_email(client):
    register(client)
    assert register(client).status_code == 409


# ------------------------------------------------------------ login
def test_login_success_returns_tokens(client):
    register(client)
    data = login(client).get_json()
    assert data["access_token"] and data["refresh_token"]


def test_login_wrong_password_and_unknown_user_same_message(client):
    register(client)
    a = login(client, password="Wrong!Pass1")
    b = login(client, email="nobody@example.com")
    assert a.status_code == b.status_code == 401
    assert a.get_json() == b.get_json()


def test_account_lockout_after_failed_attempts(client):
    register(client)
    for _ in range(Config.MAX_FAILED_ATTEMPTS):
        login(client, password="Wrong!Pass1")
    assert login(client).status_code == 429  # even the correct password is refused now


# ------------------------------------------------------------ protected routes / JWT
def test_profile_requires_token(client):
    assert client.get("/api/profile").status_code == 401


def test_profile_with_valid_token(client):
    register(client)
    token = login(client).get_json()["access_token"]
    res = client.get("/api/profile", headers=auth(token))
    assert res.status_code == 200 and res.get_json()["email"] == USER["email"]


def test_tampered_token_rejected(client):
    register(client)
    token = login(client).get_json()["access_token"]
    assert client.get("/api/profile", headers=auth(token[:-3] + "abc")).status_code == 401


def test_expired_token_rejected(client):
    register(client)
    now = datetime.now(timezone.utc)
    expired = jwt.encode({"sub": "1", "type": "access", "jti": "x", "iat": now - timedelta(hours=2),
                          "exp": now - timedelta(hours=1)}, Config.JWT_SECRET_KEY, algorithm="HS256")
    res = client.get("/api/profile", headers=auth(expired))
    assert res.status_code == 401 and "expired" in res.get_json()["error"].lower()


def test_refresh_token_cannot_be_used_as_access_token(client):
    register(client)
    refresh = login(client).get_json()["refresh_token"]
    assert client.get("/api/profile", headers=auth(refresh)).status_code == 401


def test_token_signed_with_other_key_rejected(client):
    register(client)
    now = datetime.now(timezone.utc)
    forged = jwt.encode({"sub": "1", "type": "access", "jti": "x", "iat": now, "exp": now + timedelta(minutes=5)},
                        "attacker-key-attacker-key-attacker-key", algorithm="HS256")
    assert client.get("/api/profile", headers=auth(forged)).status_code == 401


# ------------------------------------------------------------ sessions (refresh / logout)
def test_refresh_rotation_and_reuse_detection(client):
    register(client)
    first = login(client).get_json()
    second = client.post("/api/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    new_refresh = second.get_json()["refresh_token"]

    # old token reused -> rejected AND all sessions revoked
    assert client.post("/api/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.post("/api/refresh", json={"refresh_token": new_refresh}).status_code == 401


def test_logout_revokes_refresh_token(client):
    register(client)
    refresh = login(client).get_json()["refresh_token"]
    assert client.post("/api/logout", json={"refresh_token": refresh}).status_code == 200
    assert client.post("/api/refresh", json={"refresh_token": refresh}).status_code == 401


def test_logout_all(client):
    register(client)
    data = login(client).get_json()
    assert client.post("/api/logout-all", headers=auth(data["access_token"])).status_code == 200
    assert client.post("/api/refresh", json={"refresh_token": data["refresh_token"]}).status_code == 401


# ------------------------------------------------------------ encryption + password change
def test_phone_is_encrypted_at_rest(client):
    register(client)
    token = login(client).get_json()["access_token"]
    assert client.put("/api/profile", json={"phone": "+91 98765 43210"}, headers=auth(token)).status_code == 200
    with client.app.app_context():
        stored = User.query.filter_by(email=USER["email"]).first().phone_encrypted
        assert "98765" not in stored
        assert security.decrypt(stored) == "+91 98765 43210"
    assert client.get("/api/profile", headers=auth(token)).get_json()["phone"] == "+91 98765 43210"


def test_change_password_flow(client):
    register(client)
    data = login(client).get_json()
    bad = client.post("/api/change-password", headers=auth(data["access_token"]),
                      json={"old_password": "Wrong!Pass1", "new_password": "N3w!Password"})
    assert bad.status_code == 400
    ok = client.post("/api/change-password", headers=auth(data["access_token"]),
                     json={"old_password": USER["password"], "new_password": "N3w!Password"})
    assert ok.status_code == 200
    assert client.post("/api/refresh", json={"refresh_token": data["refresh_token"]}).status_code == 401
    assert login(client).status_code == 401
    assert login(client, password="N3w!Password").status_code == 200


def test_login_history_and_security_headers(client):
    register(client)
    token = login(client).get_json()["access_token"]
    login(client, password="Wrong!Pass1")
    history = client.get("/api/login-history", headers=auth(token)).get_json()
    assert [h["success"] for h in history] == [False, True]
    res = client.get("/")
    assert res.status_code == 200 and res.headers["X-Frame-Options"] == "DENY"
