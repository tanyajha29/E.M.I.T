import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.session_repository import SessionRepository

client = TestClient(app)

pytestmark = pytest.mark.no_auth_override

def test_signup_success():
    payload = {
        "full_name": "Alice Smith",
        "email": "alice.smith@emit.local",
        "password": "SecurePassword123!"
    }
    res = client.post("/auth/signup", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    user = data["user"]
    assert user["email"] == "alice.smith@emit.local"
    assert user["full_name"] == "Alice Smith"
    assert user["role"] == "INVESTIGATOR"
    assert user["badge_id"].startswith("EMIT-IR-")

    # Verify password is not in plaintext in MongoDB
    user_repo = UserRepository()
    stored = user_repo.get_by_email("alice.smith@emit.local")
    assert stored is not None
    assert stored["password_hash"] != "SecurePassword123!"
    assert stored["password_hash"].startswith("$2b$")

def test_signup_cannot_self_elevate_to_admin():
    # Attempting to send role: ADMIN in body must not grant admin
    payload = {
        "full_name": "Eve Malicious",
        "email": "eve@emit.local",
        "password": "SecurePassword123!",
        "role": "ADMIN"
    }
    res = client.post("/auth/signup", json=payload)
    assert res.status_code == 201
    user = res.json()["user"]
    assert user["role"] == "INVESTIGATOR"

def test_signup_duplicate_email():
    payload = {
        "full_name": "Bob Jones",
        "email": "bob.jones@emit.local",
        "password": "SecurePassword123!"
    }
    res1 = client.post("/auth/signup", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/auth/signup", json=payload)
    assert res2.status_code == 409
    assert "already registered" in res2.json()["detail"].lower()

def test_signup_weak_passwords():
    base = {"full_name": "Weak Pass User", "email": "weak@emit.local"}
    
    # Short (<8 chars triggers schema validation 422 or password complexity 400)
    res = client.post("/auth/signup", json={**base, "password": "Short1!"})
    assert res.status_code in [400, 422]
    
    # No uppercase
    res = client.post("/auth/signup", json={**base, "password": "lowercase123!"})
    assert res.status_code in [400, 422]

    # No number
    res = client.post("/auth/signup", json={**base, "password": "NoNumberHere!"})
    assert res.status_code in [400, 422]

    # No special char
    res = client.post("/auth/signup", json={**base, "password": "NoSpecialChar123"})
    assert res.status_code in [400, 422]

def test_login_success():
    signup_payload = {
        "full_name": "Charlie Brown",
        "email": "charlie@emit.local",
        "password": "Password123#"
    }
    client.post("/auth/signup", json=signup_payload)

    login_payload = {
        "email": "charlie@emit.local",
        "password": "Password123#"
    }
    res = client.post("/auth/login", json=login_payload)
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["email"] == "charlie@emit.local"

def test_login_invalid_credentials():
    login_payload = {
        "email": "nonexistent@emit.local",
        "password": "Password123#"
    }
    res = client.post("/auth/login", json=login_payload)
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()

def test_auth_me_endpoint():
    signup_payload = {
        "full_name": "David Miller",
        "email": "david@emit.local",
        "password": "Password123#"
    }
    reg = client.post("/auth/signup", json=signup_payload)
    token = reg.json()["access_token"]

    res = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["email"] == "david@emit.local"

def test_logout_revokes_session():
    signup_payload = {
        "full_name": "Frank White",
        "email": "frank@emit.local",
        "password": "Password123#"
    }
    reg = client.post("/auth/signup", json=signup_payload)
    token = reg.json()["access_token"]

    # Verify authenticated
    res1 = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res1.status_code == 200

    # Logout
    logout_res = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert logout_res.status_code == 200

    # Verify that the revoked token is no longer accepted (Server-side revocation!)
    res2 = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401
    assert "revoked" in res2.json()["detail"].lower()
