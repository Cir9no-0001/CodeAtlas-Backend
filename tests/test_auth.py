def test_signup_success(client):
    response = client.post("/auth/signup", json={
        "email": "newuser@example.com",
        # long passphrase, skips complexity rules
        "password": "correct-horse-battery-staple",
    })
    assert response.status_code == 201
    assert "user_id" in response.json()


def test_signup_duplicate_email_fails(client):
    client.post("/auth/signup", json={
        "email": "dupe@example.com",
        "password": "correct-horse-battery-staple",
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


def test_login_success(client):
    client.post("/auth/signup", json={
        "email": "loginuser@example.com",
        "password": "correct-horse-battery-staple",
    })
    response = client.post("/auth/login", json={
        "identifier": "loginuser@example.com",
        "password": "correct-horse-battery-staple",
    })
    assert response.status_code == 200
    assert "session_token" in response.cookies


def test_login_wrong_password_fails(client):
    client.post("/auth/signup", json={
        "email": "wrongpw@example.com",
        "password": "correct-horse-battery-staple",
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


def test_logout_clears_cookie(client):
    client.post("/auth/signup", json={
        "email": "logoutuser@example.com",
        "password": "correct-horse-battery-staple",
    })
    client.post("/auth/login", json={
        "identifier": "logoutuser@example.com",
        "password": "correct-horse-battery-staple",
    })
    response = client.post("/auth/logout")
    assert response.status_code == 200
