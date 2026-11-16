"""Shared test harness.

Tests run the REAL FastAPI app (no mocked auth) against a REAL MongoDB-wire
database (FerretDB/SQLite or mongod, whatever ``TEST_MONGODB_URI`` points to).
Each test session uses a fresh, uniquely named database that is dropped at the end.
Secrets are generated per run and never written to disk.
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ---- environment must be fixed BEFORE any application import -----------------
os.environ["APP_ENV"] = "test"
os.environ["JWT_SECRET"] = secrets.token_urlsafe(48)
os.environ["CIPHERQ_KEYRING"] = "1:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
os.environ["CIPHERQ_ACTIVE_KEY_ID"] = "1"
os.environ["MONGODB_URI"] = os.environ.get("TEST_MONGODB_URI", "mongodb://127.0.0.1:27017")
_DB_NAME = "cipherq_t_" + uuid.uuid4().hex[:12]
os.environ["MONGODB_DATABASE"] = _DB_NAME
os.environ["PASSWORD_SCRYPT_LOG_N"] = "10"          # speed only; production minimum is 15 (enforced by config)
os.environ["LOGIN_IP_PER_10MIN"] = "100000"
os.environ["REGISTER_IP_PER_HOUR"] = "100000"
os.environ["HEAVY_IP_PER_MINUTE"] = "100000"
os.environ["QUANTUM_PER_USER_PER_HOUR"] = "10000"
os.environ["AUDIT_SINK_PATH"] = str(Path(tempfile.gettempdir()) / f"cipherq_audit_sink_{_DB_NAME}.jsonl")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture(scope="session")
def app():
    from api.main import app as _app
    return _app


@pytest.fixture(scope="session")
def raw_db():
    from database.session import raw_db as _raw
    return _raw


@pytest.fixture(scope="session")
def db():
    from database.session import db as _db
    return _db


@pytest.fixture(scope="session", autouse=True)
def _cleanup_db():
    yield
    try:
        from database.session import client
        client.drop_database(_DB_NAME)
    except Exception:
        pass
    try:
        Path(os.environ["AUDIT_SINK_PATH"]).unlink(missing_ok=True)
    except Exception:
        pass


@pytest.fixture(autouse=True)
def _reset_limiter():
    from security.ratelimit import limiter
    limiter.reset()
    yield


@pytest.fixture()
def client(app):
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class Actor:
    def __init__(self, client, user_id, username, role, token):
        self.client, self.id, self.username, self.role, self.token = client, user_id, username, role, token

    @property
    def h(self):
        return {"Authorization": f"Bearer {self.token}"}

    def get(self, url, **kw):
        return self.client.get(url, headers=self.h, **kw)

    def post(self, url, json=None, **kw):
        return self.client.post(url, headers=self.h, json=json if json is not None else {}, **kw)

    def put(self, url, json=None, **kw):
        return self.client.put(url, headers=self.h, json=json if json is not None else {}, **kw)

    def delete(self, url, **kw):
        return self.client.delete(url, headers=self.h, **kw)


def _uname(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


@pytest.fixture()
def make_user(client, db):
    from api.repositories import MongoUserRepository

    def _make(role="USER_LEVEL_1", prefix="u"):
        name = _uname(prefix)
        r = client.post("/api/auth/register",
                        json={"username": name, "email": f"{name}@example.test", "password": PASSWORD})
        assert r.status_code == 201, r.text
        body = r.json()
        if role != "USER_LEVEL_1":
            MongoUserRepository(db).update_role(body["user_id"], role)   # test setup only
            r = client.post("/api/auth/login", json={"username": name, "password": PASSWORD})
            assert r.status_code == 200, r.text
            body = r.json()
        return Actor(client, body["user_id"], name, body["role"], body["token"])
    return _make


@pytest.fixture()
def user(make_user):
    return make_user("USER_LEVEL_1")


@pytest.fixture()
def user2(make_user):
    return make_user("USER_LEVEL_1", "v")


@pytest.fixture()
def admin(make_user):
    return make_user("ADMIN", "adm")
