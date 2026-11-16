"""Cryptography: record format v3 (unit) + API-level tamper / key-lifecycle behaviour."""
import base64
import copy
import os

import pytest

from crypto import records as R
from .flow import Flow

CTX = dict(record_id="rec_1", owner_user_id=7, intent_id=3, intent_version=1, intent_body_hash="ab" * 32,
           resource="vault:x", classification="CONFIDENTIAL", size=5)


def _sealed(pt=b"hello", key=None):
    key = key or os.urandom(32)
    return key, R.seal(pt, key, R.static_context(**CTX), "ks_abcdef12", 1)


# ---------------------------------------------------------------- unit (no mocks needed: pure crypto)
def test_unit_roundtrip_and_fresh_randomness():
    key, a = _sealed(b"hello", os.urandom(32))
    assert R.open_(a, key) == b"hello"
    b = R.seal(b"hello", key, R.static_context(**CTX), "ks_abcdef12", 1)
    assert a["ciphertext"] != b["ciphertext"] and a["wrapped_dek"] != b["wrapped_dek"]     # per-record DEK / nonces


@pytest.mark.parametrize("field", ["ciphertext", "data_nonce", "wrapped_dek", "wrap_nonce", "wrap_salt"])
def test_unit_modified_bytes_fail(field):
    key, rec = _sealed()
    bad = copy.deepcopy(rec)
    v = bytearray(bytes(bad[field])); v[0] ^= 1; bad[field] = bytes(v)
    with pytest.raises(R.RecordError):
        R.open_(bad, key)


def test_unit_modified_authentication_tag_fails():
    key, rec = _sealed()
    bad = copy.deepcopy(rec)
    v = bytearray(bytes(bad["ciphertext"])); v[-1] ^= 0x80; bad["ciphertext"] = bytes(v)     # GCM tag = last 16 bytes
    with pytest.raises(R.RecordError):
        R.open_(bad, key)


@pytest.mark.parametrize("field,val", [("record_id", "rec_2"), ("owner_user_id", 8), ("intent_id", 4),
                                       ("intent_version", 2), ("intent_body_hash", "cd" * 32),
                                       ("resource", "vault:y"), ("classification", "PUBLIC"), ("size", 6)])
def test_unit_incorrect_associated_data_fails(field, val):
    key, rec = _sealed()
    bad = copy.deepcopy(rec); bad["static_ctx"][field] = val
    with pytest.raises(R.RecordError):
        R.open_(bad, key)


def test_unit_wrong_key_and_wrong_binding_fail():
    key, rec = _sealed()
    with pytest.raises(R.RecordError):
        R.open_(rec, os.urandom(32))
    bad = copy.deepcopy(rec); bad["key_session_id"] = "ks_other000"
    with pytest.raises(R.RecordError):
        R.open_(bad, key)
    bad = copy.deepcopy(rec); bad["key_generation"] = 2
    with pytest.raises(R.RecordError):
        R.open_(bad, key)
    bad = copy.deepcopy(rec); bad["schema"] = 2
    with pytest.raises(R.RecordError):
        R.open_(bad, key)


def test_unit_rewrap_keeps_ciphertext_and_changes_key():
    k1, rec = _sealed(b"payload")
    k2 = os.urandom(32)
    new = R.rewrap(rec, k1, k2, "ks_new00000", 2)
    assert new["ciphertext"] == rec["ciphertext"] and R.open_(new, k2) == b"payload"
    with pytest.raises(R.RecordError):
        R.open_(new, k1)


def test_unit_canonicalisation_is_unambiguous():
    from security.canonical import CanonicalizationError, canonical_bytes, frame
    assert frame(b"a", b"bc") != frame(b"ab", b"c")
    assert canonical_bytes({"a": 1, "b": "é"}) == canonical_bytes({"b": "é", "a": 1})
    for bad in (1.5, float("nan"), b"x", {1: 2}, {"a": {1, 2}}):
        with pytest.raises(CanonicalizationError):
            canonical_bytes(bad)


# ---------------------------------------------------------------- API level
@pytest.fixture()
def flow(client, user, admin):
    return Flow(client, user, admin, max_uses=20).ready()


def _record(flow, pt=b"classified-bytes"):
    r = flow.encrypt(pt)
    assert r.status_code == 201, r.text
    return r.json()["record_id"]


def test_api_ciphertext_not_plaintext_and_no_key_in_responses(flow, db):
    rid = _record(flow, b"PLAINTEXT-MARKER-12345")
    stored = db["crypto_records"].find_one({"_id": rid})
    assert b"PLAINTEXT-MARKER" not in bytes(stored["sealed"]["ciphertext"])
    r = flow.user.get(f"/api/crypto/records/{rid}")
    assert r.status_code == 200
    body = (r.text + flow.user.get("/api/key-sessions").text + flow.user.get(f"/api/key-sessions/{flow.ks}").text).lower()
    for forbidden in ("quantum_key", "qkey", "wrapped", "dek", "plaintext"):
        assert forbidden not in body


def test_owner_can_decrypt_saved_record_from_new_authorized_device(flow, db):
    """A fresh login/device changes session IDs, not the saved record's key or owner."""
    import base64
    from .flow import jitter

    plaintext = b"cross-device-key-continuity"
    rid = _record(flow, plaintext)

    device_resp = flow.user.post("/api/authorization/devices")
    assert device_resp.status_code == 201, device_resp.text
    new_device = device_resp.json()["device_id"]
    session_resp = flow.user.post("/api/authorization/sessions", {"device_id": new_device})
    assert session_resp.status_code == 201, session_resp.text
    new_session = session_resp.json()["session_id"]
    assert new_device != flow.device and new_session != flow.session

    challenge = flow.user.post("/api/identity/challenges", {"session_id": new_session})
    assert challenge.status_code == 201, challenge.text
    verified = flow.user.post("/api/identity/verify", {
        "challenge_id": challenge.json()["challenge_id"], "session_id": new_session,
        "descriptor": jitter(),
    })
    assert verified.status_code == 200, verified.text
    monitoring = flow.user.post("/api/monitoring/start", {
        "device_id": new_device, "session_id": new_session,
    })
    assert monitoring.status_code == 200, monitoring.text

    decision = flow.user.post("/api/decisions", {
        "intent_id": flow.intent_id, "operation": "decrypt", "resource": flow.resource,
        "purpose_code": flow.purpose, "session_id": new_session, "device_id": new_device,
        "record_id": rid,
    })
    assert decision.status_code == 200, decision.text
    assert decision.json()["outcome"] == "PERMIT", decision.json()
    decrypted = flow.user.post("/api/crypto/decrypt", {
        "context_id": decision.json()["context_id"], "intent_id": flow.intent_id,
        "resource": flow.resource, "purpose_code": flow.purpose,
        "session_id": new_session, "device_id": new_device, "record_id": rid,
    })
    assert decrypted.status_code == 200, decrypted.text
    assert base64.b64decode(decrypted.json()["plaintext_base64"]) == plaintext


def test_key_session_lifetime_covers_record_validity(flow, db):
    rid = _record(flow, b"key continuity")
    record = db["crypto_records"].find_one({"_id": rid})
    key_session = db["key_sessions"].find_one({"_id": flow.ks})
    assert record is not None and key_session is not None
    assert record["expires_ts"] <= key_session["expires_ts"]

def test_api_modified_ciphertext_and_tag_rejected(flow, db):
    for idx in (0, -1):
        rid = _record(flow)
        ct = bytearray(bytes(db["crypto_records"].find_one({"_id": rid})["sealed"]["ciphertext"]))
        ct[idx] ^= 1
        db["crypto_records"].update_one({"_id": rid}, {"$set": {"sealed.ciphertext": bytes(ct)}})
        r = flow.decrypt(rid)
        assert r.status_code == 422 and "plaintext_base64" not in r.text


def test_api_incorrect_associated_data_rejected(flow, db):
    rid = _record(flow)
    db["crypto_records"].update_one({"_id": rid}, {"$set": {"sealed.static_ctx.intent_version": 9}})
    assert flow.decrypt(rid).status_code == 422


def test_api_incorrect_key_rejected(flow, user, db):
    rid = _record(flow)
    other = user.post("/api/key-sessions", {}).json()["key_session_id"]
    db["crypto_records"].update_one({"_id": rid}, {"$set": {"key_session_id": other}})
    r = flow.decrypt(rid)
    assert r.status_code == 422


def test_api_wrong_intent_wrong_resource_rejected(flow, client, user, admin):
    rid = _record(flow)
    # another intent of the same user on a different resource cannot decrypt this record
    f2 = Flow(client, user, admin, resource="vault:other-resource", case_ref=None)
    f2.ready()
    d = f2.decide(operation="decrypt", record_id=rid, key_session_id=None, requested_bytes=None,
                  session_id=f2.session, device_id=f2.device).json()
    assert d["outcome"] == "DENY" and "RESOURCE_DRIFT" in {x["code"] for x in d["reasons"]}


def test_api_cross_user_record_access_denied(flow, user2, client, admin):
    rid = _record(flow)
    assert user2.get(f"/api/crypto/records/{rid}").status_code == 404
    assert rid not in user2.get("/api/crypto/records").text
    f2 = Flow(client, user2, admin).ready()
    r = f2.decide(operation="decrypt", record_id=rid, key_session_id=None, requested_bytes=None)
    assert r.json()["outcome"] == "DENY" and "RECORD_NOT_OWNED" in {x["code"] for x in r.json()["reasons"]}
    assert f2.decrypt(rid, ctx="ctx_" + "1" * 32).status_code == 403


def test_api_key_lifecycle_revoked(flow, user):
    rid = _record(flow)
    d = flow.decide().json()
    assert user.post(f"/api/key-sessions/{flow.ks}/revoke").status_code == 200
    assert flow.encrypt(ctx=d["context_id"]).status_code == 403
    r = flow.decide()
    assert r.json()["outcome"] == "DENY" and "KEY_SESSION_REVOKED" in {x["code"] for x in r.json()["reasons"]}
    r = flow.decide(operation="decrypt", record_id=rid, key_session_id=None, requested_bytes=None)
    assert r.json()["outcome"] == "DENY"          # key material destroyed => old records are unreadable
    assert user.post(f"/api/key-sessions/{flow.ks}/revoke").status_code == 404      # already ended


def test_api_key_lifecycle_rotation_and_rewrap(flow, user):
    rid = _record(flow, b"survives rotation")
    r = user.post(f"/api/key-sessions/{flow.ks}/rotate", {})
    assert r.status_code == 201
    new_ks = r.json()["key_session_id"]
    assert user.get(f"/api/key-sessions/{flow.ks}").json()["status"] == "ROTATED"
    # ROTATED keys may no longer encrypt, but can still decrypt
    r = flow.decide()
    assert r.json()["outcome"] == "DENY" and "KEY_SESSION_ROTATED" in {x["code"] for x in r.json()["reasons"]}
    assert flow.decrypt(rid).status_code == 200
    assert user.post(f"/api/key-sessions/{flow.ks}/rewrap", {"to_key_session_id": new_ks}).json()["moved"] == 1
    assert flow.decrypt(rid).status_code == 200
    flow.ks = new_ks
    assert flow.encrypt(b"under new key").status_code == 201


def test_api_other_user_cannot_touch_key_session(flow, user2):
    assert user2.get(f"/api/key-sessions/{flow.ks}").status_code == 404
    assert user2.post(f"/api/key-sessions/{flow.ks}/revoke").status_code == 404
    assert user2.post(f"/api/key-sessions/{flow.ks}/rotate", {}).status_code in (404, 409)


def test_api_using_someone_elses_key_session_denied(client, user, user2, admin):
    f = Flow(client, user, admin).ready()
    foreign = user2.post("/api/key-sessions", {}).json()["key_session_id"]
    r = f.decide(key_session_id=foreign)
    assert r.json()["outcome"] == "DENY" and "KEY_SESSION_NOT_FOUND" in {x["code"] for x in r.json()["reasons"]}


def test_api_invalid_base64_and_empty_plaintext(flow):
    d = flow.decide().json()
    r = flow.encrypt(ctx=d["context_id"], plaintext_base64="@@@not-base64@@@")
    assert r.status_code == 400
    d = flow.decide().json()
    r = flow.encrypt(ctx=d["context_id"], plaintext_base64="")
    assert r.status_code == 422


def test_api_key_sessions_not_stored_in_clear(flow, db):
    from database.session import raw_db
    doc = raw_db["key_sessions"].find_one({})
    assert doc is not None and set(doc) <= {"_id", "_enc", "kid", "nonce", "ciphertext"}
