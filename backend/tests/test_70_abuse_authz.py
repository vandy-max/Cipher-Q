"""Authentication, authorization matrix and input / resource abuse (real app, real DB)."""
import json
import re
import threading
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from config import get_settings
from .conftest import PASSWORD

PUBLIC = {("POST", "/api/auth/register"), ("POST", "/api/auth/login"), ("GET", "/api/health"),
          ("GET", "/api/quantum/info")}


def _fill(path):
    return re.sub(r"\{[^}]+\}", "1", path)


def test_every_protected_route_rejects_missing_authentication(app, client):
    from security.ratelimit import limiter
    limiter.reset()
    n = 0
    for path, ops in app.openapi()["paths"].items():      # robust across FastAPI router-inclusion internals
        if not path.startswith("/api") or path == "/api/_boom":    # _boom: test-only route added by test_03
            continue
        for m in ops:
            m = m.upper()
            if (m, path) in PUBLIC:
                continue
            resp = client.request(m, _fill(path), json={} if m != "GET" else None)
            assert resp.status_code == 401, (m, path, resp.status_code)
            n += 1
    assert n >= 60


def test_invalid_credentials_and_tokens(client, user):
    assert client.post("/api/auth/login", json={"username": user.username, "password": "wrong-password-1"}).status_code == 401
    for tok in ("", "abc", "a.b.c", user.token[:-3] + "AAA"):
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": user.token}).status_code == 401      # no scheme
    assert client.get("/api/auth/me", headers={"Authorization": "Basic Zm9vOmJhcg=="}).status_code == 401


def _forge(**over):
    st = get_settings()
    now = datetime.now(timezone.utc)
    p = {"sub": "1", "jti": "a" * 32, "tv": 0, "iat": now, "nbf": now, "exp": now + timedelta(minutes=5),
         "iss": "cipherq", "aud": "cipherq-api", "role": "ADMIN", "username": "x"}
    p.update(over)
    return pyjwt.encode(p, st.jwt_secret, algorithm="HS256")


def test_expired_token_rejected(client, user):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    tok = _forge(sub=str(user.id), iat=past, nbf=past, exp=past + timedelta(minutes=1))
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_validly_signed_but_unregistered_token_rejected(client, user):
    """Even a token signed with the real secret is useless unless the server issued that jti."""
    tok = _forge(sub=str(user.id), role="ADMIN")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    assert client.get("/api/users", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_wrong_audience_issuer_and_unsigned(client, user):
    for over in ({"aud": "other"}, {"iss": "evil"}):
        tok = _forge(sub=str(user.id), **over)
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401
    unsigned = pyjwt.encode({"sub": str(user.id)}, None, algorithm="none")
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {unsigned}"}).status_code == 401


def test_revoked_session_token_and_logout(client, make_user):
    u = make_user()
    assert u.get("/api/auth/me").status_code == 200
    assert u.post("/api/auth/logout").status_code == 204
    assert u.get("/api/auth/me").status_code == 401


# ---------------- authorization matrix --------------------------------------------------------
ADMIN_ONLY = [("GET", "/api/users", None), ("PUT", "/api/users/1/role", {"role": "USER_LEVEL_1"}),
              ("POST", "/api/users/1/disable", {}), ("POST", "/api/users/1/enable", {}),
              ("POST", "/api/users/1/unlock", {}), ("PUT", "/api/evidence/cases/CASE-123456",
              {"title": "x" * 5, "classification_cap": "PUBLIC", "allowed_resources": [], "assigned_user_ids": []}),
              ("POST", "/api/evidence/cases/CASE-123456/close", {}),
              ("POST", "/api/evidence/cases/CASE-123456/assign", {"user_id": 1}),
              ("POST", "/api/evidence/cases/CASE-123456/unassign", {"user_id": 1}),
              ("DELETE", "/api/face/enrollment/1", None),
              ("GET", "/api/security/risk-overview", None), ("GET", "/api/security/incidents", None),
              ("POST", "/api/policies", {"name": "p", "rule_type": "allowed_operation", "config": {}}),
              ("GET", "/api/audit/logs", None), ("GET", "/api/audit/verify", None)]


@pytest.mark.parametrize("method,path,body", ADMIN_ONLY)
def test_vertical_privilege_escalation_blocked(user, method, path, body):
    r = user.client.request(method, path, headers=user.h, json=body)
    assert r.status_code == 403, (method, path, r.status_code, r.text[:100])


def test_cannot_self_promote(client, user):
    assert user.put(f"/api/users/{user.id}/role", {"role": "ADMIN"}).status_code == 403
    assert client.post("/api/auth/register", json={"username": "evil_admin_1", "email": "e@e.test",
                       "password": PASSWORD, "role": "ADMIN"}).status_code in (201, 422)
    r = client.post("/api/auth/login", json={"username": "evil_admin_1", "password": PASSWORD})
    if r.status_code == 200:
        assert r.json()["role"] == "USER_LEVEL_1"


def test_horizontal_access_to_devices_sessions_blocked(user, user2):
    dev = user.post("/api/authorization/devices").json()["device_id"]
    sess = user.post("/api/authorization/sessions", {"device_id": dev}).json()["session_id"]
    for m, p in (("get", f"/api/authorization/devices/{dev}"), ("post", f"/api/authorization/devices/{dev}/revoke"), ("post", f"/api/authorization/devices/{dev}/unrevoke"),
                 ("get", f"/api/authorization/sessions/{sess}"), ("post", f"/api/authorization/sessions/{sess}/revoke"),
                 ("post", f"/api/authorization/sessions/{sess}/refresh")):
        r = getattr(user2, m)(p, **({"json": {"device_id": dev, "ttl_minutes": 60}} if p.endswith("/refresh") else {}))
        assert r.status_code in (403, 404), (p, r.status_code)
    t = user2.get(f"/api/authorization/devices/{dev}/trust")      # by design: trust is relative to the caller
    assert t.status_code == 200 and t.json()["status"] == "foreign" and t.json()["is_own_device"] is False
    assert "owner_user_id" not in t.text and str(user.id) not in json.dumps(t.json())
    # user2 cannot attach a session to user's device, nor claim the device
    assert user2.post("/api/authorization/sessions", {"device_id": dev}).status_code == 403
    assert user.get(f"/api/authorization/sessions/{sess}").status_code == 200       # untouched


def test_cannot_start_monitoring_on_foreign_session(client, user, user2, admin):
    from .flow import Flow
    f = Flow(client, user, admin, monitoring=False)
    r = user2.post("/api/monitoring/start", {"device_id": f.device, "session_id": f.session})
    assert r.status_code == 403


def test_other_users_decisions_records_and_cases_invisible(client, user, user2, admin):
    from .flow import Flow
    f = Flow(client, user, admin).ready()
    d = f.decide().json()
    assert user2.get(f"/api/decisions/{d['decision_id']}").status_code == 404
    assert user2.post(f"/api/decisions/{d['decision_id']}/revoke", {"reason": "sabotage"}).status_code == 404
    assert user2.get(f"/api/evidence/cases/{f.ref}").status_code == 404
    assert f.user.get(f"/api/evidence/cases/{f.ref}").status_code == 200


def test_disabled_account_and_revoked_admin_privileges(client, make_user, admin):
    u = make_user("ADMIN", "tmpadm")
    assert u.get("/api/users").status_code == 200
    assert admin.put(f"/api/users/{u.id}/role", {"role": "USER_LEVEL_1"}).status_code == 200
    assert u.get("/api/users").status_code == 401                         # old token dies with the role change
    v = make_user()
    assert admin.post(f"/api/users/{v.id}/disable").status_code in (200, 204)
    assert v.get("/api/auth/me").status_code == 401


# ---------------- input / resource abuse --------------------------------------------------------
def test_malformed_json_and_wrong_types(client, user):
    h = {**user.h, "Content-Type": "application/json"}
    for body in (b"{", b"[]", b'{"n_qubits": "abc"}', b"\xff\xfe", b'{"a":' + b"[" * 5000 + b"]" * 5000 + b"}"):
        r = client.post("/api/key-sessions", headers=h, content=body)
        assert r.status_code in (400, 413, 422), (body[:20], r.status_code)
        assert "Traceback" not in r.text


def test_invalid_content_types(client, user):
    for ct in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/xml"):
        r = client.post("/api/key-sessions", headers={**user.h, "Content-Type": ct}, content=b"x=1")
        assert r.status_code == 415, ct


def test_oversized_bodies_and_strings(client, user):
    big = "A" * 3_000_000
    r = client.post("/api/auth/register", json={"username": big, "email": "a@b.test", "password": PASSWORD})
    assert r.status_code in (413, 422)
    r = client.post("/api/auth/login", json={"username": "u" * 100_000, "password": "p" * 100_000})
    assert r.status_code in (413, 422)
    assert client.post("/api/auth/register", json={"username": "x" * 65, "email": "a@b.test",
                       "password": PASSWORD}).status_code == 422
    assert client.post("/api/auth/register", json={"username": "okname_1", "email": "a@b.test",
                       "password": "p" * 1000}).status_code == 422


def test_invalid_numeric_values(client, user):
    h = {**user.h, "Content-Type": "application/json"}
    for body in ('{"n_qubits": 1e309}', '{"n_qubits": -1}', '{"n_qubits": 1.5}', '{"simulate_eavesdropper_prob": 1e-400}',
                 '{"n_qubits": Infinity}', '{"n_qubits": true}'):
        r = client.post("/api/key-sessions", headers=h, content=body)
        assert r.status_code in (400, 422, 201), body
        assert r.status_code != 500, body


def test_nan_face_descriptor_not_500(client, user):
    h = {**user.h, "Content-Type": "application/json"}
    body = json.dumps({"descriptor": [float("nan")] * 128, "password": PASSWORD}, allow_nan=True)
    assert client.post("/api/face/enroll", headers=h, content=body).status_code == 422


def test_concurrent_login_attempts_are_throttled(client, user):
    codes = []
    def go():
        codes.append(client.post("/api/auth/login", json={"username": user.username, "password": "wrong-password-9"}).status_code)
    ts = [threading.Thread(target=go) for _ in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert 200 not in codes and codes.count(429) >= 10 and set(codes) <= {401, 429}
    # correct password is also refused while locked (no oracle)
    assert client.post("/api/auth/login", json={"username": user.username, "password": PASSWORD}).status_code == 429


def test_repeated_expensive_simulation_requests_limited(make_user, monkeypatch):
    import dataclasses
    import api.routers.key_sessions as ks
    monkeypatch.setattr(ks, "get_settings", lambda: dataclasses.replace(get_settings(), heavy_ip_per_minute=3))
    u = make_user()
    codes = [u.post("/api/key-sessions", {"n_qubits": 128}).status_code for _ in range(6)]
    assert 429 in codes


def test_unknown_routes_and_methods_sanitised(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and "Traceback" not in r.text
    assert client.delete("/api/health").status_code == 405


def test_docs_disabled_in_strict_env_config():
    import dataclasses
    from config import ConfigurationError, validate_settings
    st = dataclasses.replace(get_settings(), app_env="production")
    with pytest.raises(ConfigurationError):
        validate_settings(st)            # test settings are not production-safe: must be refused


def test_policy_changes_are_audited(admin):
    """F-22: policy create/update/delete leave POLICY_CHANGED audit entries naming the acting admin."""
    body = {"name": "audit-probe", "rule_type": "allowed_operation", "config": {"operations": ["encrypt"]}, "active": False}
    r = admin.post("/api/policies", body)
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert admin.put(f"/api/policies/{pid}", {**body, "active": True}).status_code == 200
    assert admin.delete(f"/api/policies/{pid}").status_code == 204
    logs = [e for e in admin.get("/api/audit/logs").json()
            if e["action"] == "POLICY_CHANGED" and f"policy={pid} " in ((e["reason"] or "") + " ")]
    kinds = " ".join(e["reason"] for e in logs)
    assert "created" in kinds and "updated" in kinds and "deleted" in kinds
    assert all(e["user_id"] == admin.id for e in logs)
