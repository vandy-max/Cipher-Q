"""Phase 2: authentication, session lifecycle, RBAC, request hardening (real app + real DB)."""
import base64
import json
import time
import uuid

import jwt as pyjwt
import pytest

from tests.conftest import PASSWORD


def _name(p="x"):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _reg(client, name=None, password=PASSWORD, **extra):
    name = name or _name()
    return client.post("/api/auth/register",
                       json={"username": name, "email": f"{name}@example.test", "password": password, **extra})


# ---------------------------------------------------------------- registration
def test_self_register_ignores_requested_role(client):
    for role in ("ADMIN", "USER_LEVEL_2", "USER_LEVEL_1"):
        r = _reg(client, role=role)
        assert r.status_code == 201 and r.json()["role"] == "USER_LEVEL_1"


@pytest.mark.parametrize("pw", ["short", "password1234", "a" * 129, "aaaaaaaaaaaa"])
def test_weak_passwords_rejected(client, pw):
    assert _reg(client, password=pw).status_code in (400, 422)


def test_password_may_not_contain_username(client):
    n = "alicewonder"
    assert _reg(client, name=n, password="Xalicewonder-7788").status_code == 400


def test_username_unique_case_insensitive(client):
    n = _name("Case")
    assert _reg(client, name=n).status_code == 201
    assert _reg(client, name=n.upper()).status_code == 409
    assert _reg(client, name=n.lower()).status_code == 409


def test_concurrent_duplicate_registration_single_winner(client):
    from concurrent.futures import ThreadPoolExecutor
    n = _name("race")
    with ThreadPoolExecutor(8) as ex:
        codes = list(ex.map(lambda _: _reg(client, name=n).status_code, range(8)))
    assert codes.count(201) == 1 and set(codes) <= {201, 409}


def test_bad_username_and_email_rejected(client):
    assert client.post("/api/auth/register", json={"username": "a b", "email": "x@y.zz", "password": PASSWORD}).status_code == 400
    assert client.post("/api/auth/register", json={"username": _name(), "email": "nope", "password": PASSWORD}).status_code == 400


def test_register_rejects_unknown_fields(client):
    assert _reg(client, is_admin=True).status_code == 422


# ---------------------------------------------------------------- login / lockout
def test_login_failure_is_uniform(client, user):
    a = client.post("/api/auth/login", json={"username": user.username, "password": "wrong-Password-1"})
    b = client.post("/api/auth/login", json={"username": _name("ghost"), "password": "wrong-Password-1"})
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_login_throttle_record_survives_wrapper_reload_and_success_clears(client, user, raw_db):
    from database.encrypted_store import EncryptedDatabase
    from database.models import LOGIN_THROTTLE_COLLECTION
    from security.keyring import get_keyring

    rejected = client.post("/api/auth/login", json={"username": user.username, "password": "wrong-Password-1"})
    assert rejected.status_code == 401
    raw = raw_db[LOGIN_THROTTLE_COLLECTION].find_one({"_id": user.username.lower()})
    assert raw["_enc"] == "CIPHERQ-WHOLE-DOC-v2"

    reopened = EncryptedDatabase(raw_db, get_keyring())
    assert reopened[LOGIN_THROTTLE_COLLECTION].find_one({"_id": user.username.lower()})["fails"] == 1

    accepted = client.post("/api/auth/login", json={"username": user.username, "password": PASSWORD})
    assert accepted.status_code == 200
    assert reopened[LOGIN_THROTTLE_COLLECTION].find_one({"_id": user.username.lower()}) is None


def test_corrupt_login_throttle_fails_closed_without_authenticating(client, user, db, raw_db):
    from database.models import LOGIN_THROTTLE_COLLECTION
    from authentication.throttle import LoginThrottle

    LoginThrottle(db, max_failures=5, lockout_seconds=60).begin_attempt(user.username)
    collection = raw_db[LOGIN_THROTTLE_COLLECTION]
    raw = collection.find_one({"_id": user.username.lower()})
    ciphertext = bytearray(raw["ciphertext"])
    ciphertext[0] ^= 1
    collection.update_one({"_id": user.username.lower()}, {"$set": {"ciphertext": bytes(ciphertext)}})
    corrupted = collection.find_one({"_id": user.username.lower()})

    response = client.post("/api/auth/login", json={"username": user.username, "password": PASSWORD})

    assert response.status_code == 503
    assert "token" not in response.json()
    assert collection.find_one({"_id": user.username.lower()}) == corrupted


def test_lockout_after_repeated_failures_and_admin_unlock(client, make_user, admin):
    u = make_user()
    for _ in range(5):
        assert client.post("/api/auth/login", json={"username": u.username, "password": "bad-Password-123"}).status_code == 401
    r = client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0       # even the right password is refused
    assert admin.post(f"/api/users/{u.id}/unlock").status_code == 204
    assert client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD}).status_code == 200


def test_lockout_applies_to_unknown_usernames_too(client):
    g = _name("ghost")
    for _ in range(5):
        client.post("/api/auth/login", json={"username": g, "password": "bad-Password-123"})
    assert client.post("/api/auth/login", json={"username": g, "password": "bad-Password-123"}).status_code == 429


def test_ip_rate_limit_on_login(client, monkeypatch):
    from config import get_settings
    import dataclasses, api.routers.auth as ar
    st = dataclasses.replace(get_settings(), login_ip_per_10min=3)
    monkeypatch.setattr(ar, "get_settings", lambda: st)
    codes = [client.post("/api/auth/login", json={"username": _name("z"), "password": "x" * 12}).status_code for _ in range(5)]
    assert codes[:3] == [401] * 3 and codes[3:] == [429, 429]


# ---------------------------------------------------------------- JWT attacks
def _claims(user, **over):
    from config import get_settings
    st = get_settings()
    now = int(time.time())
    c = {"sub": str(user.id), "jti": uuid.uuid4().hex, "tv": 0, "iat": now, "nbf": now, "exp": now + 600,
         "iss": st.jwt_issuer, "aud": st.jwt_audience, "username": user.username, "role": "ADMIN"}
    c.update(over)
    return c


def _hit(client, token):
    return client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code


def test_jwt_forgery_variants_rejected(client, user):
    from config import get_settings
    st = get_settings()
    # unsigned alg=none
    h = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(_claims(user)).encode()).rstrip(b"=").decode()
    assert _hit(client, f"{h}.{p}.") == 401
    # wrong secret
    assert _hit(client, pyjwt.encode(_claims(user), "x" * 48, algorithm="HS256")) == 401
    # right secret but unregistered jti (forged by someone who knows the secret is out of scope; jti must still exist)
    assert _hit(client, pyjwt.encode(_claims(user), st.jwt_secret, algorithm="HS256")) == 401
    # expired / wrong aud / wrong iss / missing claims / HS512
    assert _hit(client, pyjwt.encode(_claims(user, exp=int(time.time()) - 5), st.jwt_secret, algorithm="HS256")) == 401
    assert _hit(client, pyjwt.encode(_claims(user, aud="other"), st.jwt_secret, algorithm="HS256")) == 401
    assert _hit(client, pyjwt.encode(_claims(user, iss="evil"), st.jwt_secret, algorithm="HS256")) == 401
    c = _claims(user); c.pop("jti")
    assert _hit(client, pyjwt.encode(c, st.jwt_secret, algorithm="HS256")) == 401
    assert _hit(client, pyjwt.encode(_claims(user), st.jwt_secret, algorithm="HS512")) == 401
    # tampered payload on a genuine token
    good = user.token.split(".")
    bad_payload = base64.urlsafe_b64encode(json.dumps({**json.loads(base64.urlsafe_b64decode(good[1] + "==")), "role": "ADMIN"}).encode()).rstrip(b"=").decode()
    assert _hit(client, f"{good[0]}.{bad_payload}.{good[2]}") == 401
    assert _hit(client, "garbage") == 401 and _hit(client, "") == 401


def test_role_claim_in_token_is_not_trusted(client, user):
    # token says USER_LEVEL_1; privilege comes from the DB.  No admin access either way.
    assert user.get("/api/users").status_code == 403


# ---------------------------------------------------------------- session lifecycle
def test_logout_revokes_only_that_token(client, make_user):
    u = make_user()
    r2 = client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD}).json()["token"]
    assert u.post("/api/auth/logout").status_code == 204
    assert u.get("/api/auth/me").status_code == 401
    assert _hit(client, r2) == 200


def test_logout_all_revokes_every_token(client, make_user):
    u = make_user()
    t2 = client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD}).json()["token"]
    assert u.post("/api/auth/logout-all").status_code == 204
    assert u.get("/api/auth/me").status_code == 401 and _hit(client, t2) == 401


def test_disabled_account_loses_access_immediately_and_cannot_login(client, make_user, admin):
    u = make_user()
    assert u.get("/api/auth/me").status_code == 200
    assert admin.post(f"/api/users/{u.id}/disable").status_code == 200
    assert u.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD}).status_code == 401
    assert admin.post(f"/api/users/{u.id}/enable").status_code == 200
    assert client.post("/api/auth/login", json={"username": u.username, "password": PASSWORD}).status_code == 200


def test_demotion_invalidates_old_admin_token(client, make_user, admin):
    other = make_user("ADMIN", "adm2")
    assert other.get("/api/users").status_code == 200
    assert admin.put(f"/api/users/{other.id}/role", {"role": "USER_LEVEL_1"}).status_code == 200
    assert other.get("/api/users").status_code == 401          # old token dead
    relog = client.post("/api/auth/login", json={"username": other.username, "password": PASSWORD}).json()
    assert relog["role"] == "USER_LEVEL_1"


def test_last_admin_cannot_be_demoted_or_disabled(client, db, make_user):
    from api.repositories import MongoUserRepository
    repo = MongoUserRepository(db)
    # make this the only enabled admin by disabling every other admin directly (test setup)
    for u in repo.list_all():
        if u.role == "ADMIN":
            repo.set_disabled(u.id, True)
    sole = make_user("ADMIN", "sole")
    assert sole.put(f"/api/users/{sole.id}/role", {"role": "USER_LEVEL_1"}).status_code == 409
    assert sole.post(f"/api/users/{sole.id}/disable").status_code == 409


def test_non_admin_cannot_manage_users(client, user, user2):
    assert user.put(f"/api/users/{user2.id}/role", {"role": "ADMIN"}).status_code == 403
    assert user.post(f"/api/users/{user2.id}/disable").status_code == 403
    assert user.post(f"/api/users/{user.id}/unlock").status_code == 403


def test_role_change_rejects_unknown_role(admin, user):
    assert admin.put(f"/api/users/{user.id}/role", {"role": "ROOT"}).status_code == 422


# ---------------------------------------------------------------- request hardening
def test_security_headers_present(client):
    r = client.get("/api/health")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert "default-src 'none'" in h["content-security-policy"] and h["cache-control"] == "no-store"
    assert h["x-request-id"]


def test_oversized_body_rejected(client):
    r = client.post("/api/auth/login", content=b'{"username":"a","password":"' + b"x" * 2_000_000 + b'"}',
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_non_json_content_type_rejected(client):
    r = client.post("/api/auth/login", content=b"username=a&password=b",
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_validation_errors_do_not_echo_secret_values(client):
    secret = "Sup3r-Secret-Value-xyz"
    r = client.post("/api/auth/login", json={"username": 5, "password": secret, "evil": secret})
    assert r.status_code == 422 and secret not in r.text


def test_internal_errors_are_sanitised(app, client):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get("/api/_boom")
    def boom():
        raise RuntimeError("DB password is hunter2")
    app.include_router(router)
    try:
        r = client.get("/api/_boom")
        assert r.status_code == 500 and "hunter2" not in r.text and "request_id" in r.json()
    finally:                                   # do not leave the test-only route in the shared app
        app.router.routes[:] = [x for x in app.router.routes if getattr(x, "path", "") != "/api/_boom"]


def test_cors_rejects_unlisted_origin(client):
    r = client.options("/api/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in r.headers
    ok = client.options("/api/auth/login", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-credentials" not in ok.headers
