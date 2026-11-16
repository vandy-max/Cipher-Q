from tests.conftest import PASSWORD


def test_health_is_minimal(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_register_login_me(client, user):
    r = user.get("/api/auth/me")
    assert r.status_code == 200 and r.json()["username"] == user.username


def test_unauthenticated_rejected(client):
    assert client.get("/api/users").status_code == 401
