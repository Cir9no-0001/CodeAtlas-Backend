import hashlib

import httpx
import pytest
from fastapi import HTTPException

from app.core.deps import get_current_user
from app.db.models import Session as SessionModel

STRONG_PASSPHRASE = "correct-horse-battery-staple"  # long, skips complexity rules


def test_signup_success(client):
    response = client.post("/auth/signup", json={
        "email": "newuser@example.com",
        "password": STRONG_PASSPHRASE,
    })
    assert response.status_code == 201
    assert "user_id" in response.json()


def test_signup_duplicate_email_fails(client):
    client.post("/auth/signup", json={
        "email": "dupe@example.com",
        "password": STRONG_PASSPHRASE,
    })
    response = client.post("/auth/signup", json={
        "email": "dupe@example.com",
        "password": "another-long-passphrase-here",
    })
    assert response.status_code == 400


def test_signup_short_password_fails(client):
    response = client.post("/auth/signup", json={
        "email": "shortpw@example.com",
        "password": "short1",
    })
    assert response.status_code == 422  # Pydantic validation error


def test_signup_short_password_meeting_complexity_succeeds(client):
    # 10 chars with upper, lower, digit and special: allowed by the complexity rules.
    response = client.post("/auth/signup", json={
        "email": "complex@example.com",
        "password": "Abcdef1!xy",
    })
    assert response.status_code == 201


def test_signup_password_missing_special_character_fails(client):
    # 13 chars (under the 16-char passphrase threshold), no special character.
    response = client.post("/auth/signup", json={
        "email": "nospecial@example.com",
        "password": "Password12345",
    })
    assert response.status_code == 422
    assert "special character" in response.text


def test_signup_rejects_breached_password(client, hibp):
    password = "Sup3r-Secret-Pass!"
    suffix = hashlib.sha1(password.encode()).hexdigest().upper()[5:]
    hibp["text"] = f"0000000000000000000000000000000000A:1\n{suffix}:42"

    response = client.post("/auth/signup", json={
        "email": "breached@example.com",
        "password": password,
    })
    assert response.status_code == 422
    assert "data breach" in response.text


def test_signup_allowed_when_breach_api_is_down(client, hibp):
    # The breach check fails open: an outage must not block signups.
    hibp["error"] = httpx.ConnectError("HIBP unreachable")

    response = client.post("/auth/signup", json={
        "email": "outage@example.com",
        "password": STRONG_PASSPHRASE,
    })
    assert response.status_code == 201


def test_login_success(client):
    client.post("/auth/signup", json={
        "email": "loginuser@example.com",
        "password": STRONG_PASSPHRASE,
    })
    response = client.post("/auth/login", json={
        "identifier": "loginuser@example.com",
        "password": STRONG_PASSPHRASE,
    })
    assert response.status_code == 200
    assert "session_token" in response.cookies


def test_login_wrong_password_fails(client):
    client.post("/auth/signup", json={
        "email": "wrongpw@example.com",
        "password": STRONG_PASSPHRASE,
    })
    response = client.post("/auth/login", json={
        "identifier": "wrongpw@example.com",
        "password": "totally-wrong-password-here",
    })
    assert response.status_code == 401


def test_login_nonexistent_user_fails(client):
    response = client.post("/auth/login", json={
        "identifier": "doesnotexist@example.com",
        "password": "whatever-password-here",
    })
    assert response.status_code == 401


def test_login_is_rate_limited(client):
    # Limit is 5/minute per client address: the sixth attempt must be refused.
    for _ in range(5):
        response = client.post("/auth/login", json={
            "identifier": "nobody@example.com",
            "password": "whatever-password-here",
        })
        assert response.status_code == 401

    response = client.post("/auth/login", json={
        "identifier": "nobody@example.com",
        "password": "whatever-password-here",
    })
    assert response.status_code == 429


def test_logout_clears_cookie(client):
    client.post("/auth/signup", json={
        "email": "logoutuser@example.com",
        "password": STRONG_PASSPHRASE,
    })
    client.post("/auth/login", json={
        "identifier": "logoutuser@example.com",
        "password": STRONG_PASSPHRASE,
    })
    response = client.post("/auth/logout")
    assert response.status_code == 200


def test_logout_deletes_server_side_session(client, db_session):
    client.post("/auth/signup", json={
        "email": "sessiondelete@example.com",
        "password": STRONG_PASSPHRASE,
    })
    login = client.post("/auth/login", json={
        "identifier": "sessiondelete@example.com",
        "password": STRONG_PASSPHRASE,
    })
    token = login.cookies["session_token"]
    assert db_session.query(SessionModel).count() == 1

    # The cookie is marked Secure, so the test client (plain http) won't send
    # it back on its own; pass it explicitly.
    response = client.post(
        "/auth/logout", headers={"Cookie": f"session_token={token}"})

    assert response.status_code == 200
    assert db_session.query(SessionModel).count() == 0


def _login(client, email):
    client.post("/auth/signup", json={
        "email": email,
        "password": STRONG_PASSPHRASE,
    })
    response = client.post("/auth/login", json={
        "identifier": email,
        "password": STRONG_PASSPHRASE,
    })
    return response.cookies["session_token"]


def test_database_stores_only_the_token_hash(client, db_session):
    token = _login(client, "hashed@example.com")

    row = db_session.query(SessionModel).one()
    assert row.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert row.token_hash != token


def test_stored_hash_is_not_a_valid_credential(client, db_session):
    # If the database leaks, the stored hashes must not work as session tokens.
    _login(client, "leak@example.com")
    stored_hash = db_session.query(SessionModel).one().token_hash

    with pytest.raises(HTTPException) as exc:
        get_current_user(session_token=stored_hash,
                         authorization=None, db=db_session)
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException) as exc:
        get_current_user(session_token=None,
                         authorization=f"Bearer {stored_hash}", db=db_session)
    assert exc.value.status_code == 401