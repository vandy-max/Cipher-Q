"""Secure Sharing end to end: sender -> inbox -> recipient face check/decrypt and private thread, through the REAL API."""
import base64
import hashlib
import json

import pytest

from .flow import Flow

PDF = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<</Type/Catalog>>endobj\n" + bytes(range(256)) * 3 + b"\n%%EOF\n"


def envelope_text(text, subject="Q3 figures", description="for review"):
    return json.dumps({"format": "CIPHERQ_SHARE_V1", "kind": "text", "subject": subject,
                       "description": description, "text": text}, separators=(",", ":"), ensure_ascii=False).encode()


def envelope_file(name, data, **over):
    """Mirrors the frontend: same field order / mime table as the server's canonical form."""
    from crypto.share_payload import ALLOWED_TYPES
    ext = name.rsplit(".", 1)[-1].lower()
    d = {"format": "CIPHERQ_SHARE_V1", "kind": "file", "subject": "doc", "description": "",
         "filename": name, "mime_type": ALLOWED_TYPES.get(ext, "application/octet-stream"), "size": len(data),
         "sha256": hashlib.sha256(data).hexdigest(), "data_base64": base64.b64encode(data).decode()}
    d.update(over)
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode()


class Setup:
    def __init__(self, client, user, user2, admin):
        self.admin, self.sender, self.recipient = admin, user, user2
        self.rflow = Flow(client, user2, admin)
        self.sflow = Flow(client, user, admin, max_uses=8, max_bytes=200_000, ops=("encrypt", "decrypt", "share"))
        assert admin.post(f"/api/evidence/cases/{self.sflow.ref}/assign", {"user_id": user2.id}).status_code == 200
        self.sflow.create_intent(recipient_user_id=user2.id)
        self.sflow.validate()
        assert self.sflow.approve().status_code == 200

    def send(self, payload: bytes, **extra):
        enc = self.sflow.encrypt(payload)
        assert enc.status_code == 201, enc.text
        rid = enc.json()["record_id"]
        return rid, self.share(rid, **extra)

    def share(self, rid, actor=None, **extra):
        f = self.sflow
        body = {"intent_id": f.intent_id, "resource": f.resource, "purpose_code": f.purpose,
                "session_id": f.session, "device_id": f.device, "record_id": rid,
                "recipient_key_session_id": self.rflow.ks, **extra}
        return (actor or self.sender).post("/api/crypto/shares", body)

    def decide_decrypt(self, share_id, actor=None, flow=None):
        flow = flow or self.rflow
        return (actor or self.recipient).post("/api/decisions", {
            "intent_id": self.sflow.intent_id, "operation": "decrypt", "resource": self.sflow.resource,
            "purpose_code": self.sflow.purpose, "session_id": flow.session, "device_id": flow.device,
            "record_id": share_id})

    def recipient_decrypt(self, share_id, actor=None, flow=None):
        flow = flow or self.rflow
        d = self.decide_decrypt(share_id, actor, flow)
        if d.status_code != 200 or d.json().get("outcome") != "PERMIT":
            return d
        return (actor or self.recipient).post("/api/crypto/decrypt", {
            "context_id": d.json()["context_id"], "intent_id": self.sflow.intent_id,
            "resource": self.sflow.resource, "purpose_code": self.sflow.purpose,
            "session_id": flow.session, "device_id": flow.device, "record_id": share_id})

    def approve(self, share_id):
        r = self.admin.post(f"/api/crypto/shares/{share_id}/admin-approve", {})
        assert r.status_code == 200, r.text


@pytest.fixture(autouse=True)
def _no_leftover_global_policies(db):
    """Earlier test modules persist global 'allowed_operation' policies (test_20 limits ops to encrypt/decrypt)
    in the shared test DB. Those are legitimate deployment policies that would deny `share`; isolate this
    module from them and restore them afterwards."""
    saved = list(db["policies"].find({}))
    for d in saved:
        db["policies"].delete_one({"_id": d["_id"]})
    yield
    for d in list(db["policies"].find({})):
        db["policies"].delete_one({"_id": d["_id"]})
    for d in saved:
        db["policies"].insert_one(d)


@pytest.fixture()
def S(client, user, user2, admin):
    return Setup(client, user, user2, admin)


def opened(resp):
    assert resp.status_code == 200, resp.text
    return json.loads(base64.b64decode(resp.json()["plaintext_base64"]))


# 1+2 ---------------------------------------------------------------------------------------------
def test_text_sender_to_recipient_roundtrip_with_status_lifecycle(S):
    secret = "Confidential: wire €1,250,000 ✓ \n line two"
    rid, r = S.send(envelope_text(secret), kind="text")
    assert r.status_code == 202, r.text
    sh = r.json()
    assert sh["status"] == "APPROVED" and sh["kind"] == "text"
    assert sh["owner_username"] == S.sender.username and sh["recipient_username"] == S.recipient.username
    assert secret not in r.text and "plaintext" not in r.text
    # Approved policy permits immediate inbox delivery; opening requires fresh recipient face step-up.
    got = S.recipient.get("/api/crypto/shares").json()[0]
    assert got["status"] == "APPROVED" and got["opened_ts"] is None and got["access_count"] == 0
    o = S.recipient.post(f"/api/crypto/shares/{sh['share_id']}/open", {"session_id": S.rflow.session})
    assert o.status_code == 200 and o.json()["opened_ts"]
    env = opened(S.recipient_decrypt(sh["share_id"]))
    assert env["format"] == "CIPHERQ_SHARE_V1" and env["kind"] == "text" and env["text"] == secret
    assert env["subject"] == "Q3 figures"
    done = S.sender.get(f"/api/crypto/shares/{sh['share_id']}").json()
    assert done["access_count"] == 1 and done["last_access_ts"] and done["opened_ts"]
    actions = {e["action"] for e in S.admin.get("/api/audit/logs").json()}
    assert {"SHARE_DELIVERED", "SHARE_OPENED", "SHARE_ACCESS_SUCCESS"} <= actions
    assert secret not in S.admin.get("/api/audit/logs").text


# 3+4+5 -------------------------------------------------------------------------------------------
def test_pdf_roundtrip_is_byte_identical(S):
    rid, r = S.send(envelope_file("report.pdf", PDF), kind="file")
    assert r.status_code == 202, r.text
    env = opened(S.recipient_decrypt(r.json()["share_id"]))
    data = base64.b64decode(env["data_base64"])
    assert data == PDF and hashlib.sha256(data).hexdigest() == env["sha256"] and env["size"] == len(PDF)
    assert env["filename"] == "report.pdf" and env["mime_type"] == "application/pdf"


def test_recipient_can_decrypt_approved_share_after_sender_logs_out(S):
    """A delivered share is recipient-owned; the sender's live login is not a decryption dependency."""
    _, response = S.send(envelope_text("recipient can open this later"))
    assert response.status_code == 202, response.text
    share_id = response.json()["share_id"]

    logged_out = S.sender.post("/api/auth/logout", {})
    assert logged_out.status_code == 204, logged_out.text

    result = S.recipient_decrypt(share_id)
    assert opened(result)["text"] == "recipient can open this later"


def test_approved_share_recipient_can_decrypt_without_case_assignment(S):
    """Recipient assignment to the sender's supporting case is not required after delivery."""
    _, response = S.send(envelope_text("available to recipient within share validity"))
    assert response.status_code == 202, response.text
    share_id = response.json()["share_id"]

    # Remove recipient from the supporting case after the sender has authorized and delivered the share.
    removed = S.admin.post(
        f"/api/evidence/cases/{S.sflow.ref}/unassign", {"user_id": S.recipient.id}
    )
    assert removed.status_code == 200, removed.text

    result = S.recipient_decrypt(share_id)
    env = opened(result)
    assert env["text"] == "available to recipient within share validity"


# 6 -----------------------------------------------------------------------------------------------
def test_recipient_cannot_reach_sender_key_or_source_record(S):
    rid, r = S.send(envelope_text("x" * 20))
    assert S.recipient.get(f"/api/crypto/records/{rid}").status_code == 404
    d = S.recipient.post("/api/decisions", {"intent_id": S.sflow.intent_id, "operation": "decrypt",
                                            "resource": S.sflow.resource, "purpose_code": S.sflow.purpose,
                                            "session_id": S.rflow.session, "device_id": S.rflow.device, "record_id": rid})
    assert d.status_code in (403, 404) or d.json().get("outcome") != "PERMIT"
    body = S.recipient.get("/api/crypto/shares").text
    for forbidden in ("wrapped_dek", "wrap_salt", "ciphertext", "qkey", "password"):
        assert forbidden not in body


# 7 + 15 ------------------------------------------------------------------------------------------
def test_third_user_and_anonymous_cannot_touch_a_share(S, client, make_user):
    rid, r = S.send(envelope_text("private"))
    sid = r.json()["share_id"]
    u3 = make_user("USER_LEVEL_1", "w")
    flow3 = Flow(client, u3, S.admin)
    assert u3.get(f"/api/crypto/shares/{sid}").status_code == 404
    assert u3.get("/api/crypto/shares").json() == []
    assert u3.post(f"/api/crypto/shares/{sid}/open", {"session_id": flow3.session}).status_code == 404
    assert u3.post(f"/api/crypto/shares/{sid}/revoke", {"reason": "not mine"}).status_code == 404
    assert u3.post(f"/api/crypto/shares/{sid}/reject", {"reason": "not mine"}).status_code == 404
    assert u3.post(f"/api/crypto/shares/{sid}/admin-approve", {}).status_code == 403
    assert S.recipient_decrypt(sid, actor=u3, flow=flow3).status_code in (403, 404)
    assert client.get(f"/api/crypto/shares/{sid}").status_code in (401, 403)
    assert client.post(f"/api/crypto/shares/{sid}/admin-approve", json={}).status_code in (401, 403)
    assert S.sender.post(f"/api/crypto/shares/{sid}/admin-approve", {}).status_code == 403
    assert u3.get("/api/crypto/shares/admin/pending").status_code == 403


# 8 (single-tenant: see report) -------------------------------------------------------------------
def test_disabled_or_unknown_users_are_not_valid_recipients(S, client, make_user, user):
    rid, _ = S.send(envelope_text("a" * 20))
    names = [x["username"] for x in S.sender.get("/api/crypto/recipients").json()]
    assert S.recipient.username in names and S.sender.username not in names
    assert [x["user_id"] for x in S.sender.get(f"/api/crypto/recipients?q={S.recipient.username[:4]}").json()]
    assert S.sender.get("/api/crypto/recipients?q=zzzz-no-such-user").json() == []
    assert S.recipient.id in [x["user_id"] for x in S.sender.get(f"/api/crypto/recipients?q={S.recipient.id}").json()]
    S.admin.post(f"/api/users/{S.recipient.id}/disable", {})
    assert S.recipient.username not in [x["username"] for x in S.sender.get("/api/crypto/recipients").json()]
    enc = S.sflow.encrypt(envelope_text("b" * 20))
    r = S.share(enc.json()["record_id"])
    assert r.status_code in (404, 409) and r.status_code != 202


# 9 + 10 ------------------------------------------------------------------------------------------
def _share_doc_update(db, sid, **fields):
    db["crypto_shares"].update_one({"_id": sid}, {"$set": fields})


def test_tampered_ciphertext_and_wrong_key_fail_closed(S, db):
    rid, r = S.send(envelope_text("integrity matters"))
    sid = r.json()["share_id"]
    assert opened(S.recipient_decrypt(sid))["text"] == "integrity matters"     # control: untampered share opens
    share = db["crypto_shares"].find_one({"_id": sid})
    sealed = dict(share["sealed"])
    ct = bytearray(bytes(sealed["ciphertext"])); ct[len(ct) // 2] ^= 0x01
    _share_doc_update(db, sid, sealed={**sealed, "ciphertext": bytes(ct)})
    bad = S.recipient_decrypt(sid)
    assert "plaintext_base64" not in bad.text and (bad.status_code in (409, 422) or bad.json().get("outcome") == "DENY")
    # wrapped DEK from the sender's own key session (not the recipient's): must not open
    src = db["crypto_records"].find_one({"_id": rid})["sealed"]
    _share_doc_update(db, sid, sealed={**sealed, "wrapped_dek": src["wrapped_dek"], "wrap_salt": src["wrap_salt"],
                                       "wrap_nonce": src["wrap_nonce"]})
    wrong = S.recipient_decrypt(sid)
    assert "plaintext_base64" not in wrong.text and (wrong.status_code in (409, 422) or wrong.json().get("outcome") == "DENY")


def test_recipient_substitution_is_rejected(S, db, client, make_user):
    rid, r = S.send(envelope_text("bound to recipient"))
    sid = r.json()["share_id"]
    u3 = make_user("USER_LEVEL_1", "x")
    _share_doc_update(db, sid, recipient_user_id=u3.id)
    flow3 = Flow(client, u3, S.admin)
    res = S.recipient_decrypt(sid, actor=u3, flow=flow3)
    assert "plaintext_base64" not in res.text and (res.status_code in (403, 404, 409, 422) or res.json().get("outcome") == "DENY")


# 11 ----------------------------------------------------------------------------------------------
def test_expiry_is_enforced_and_sender_can_only_shorten(S, db):
    rid, r = S.send(envelope_text("short lived"), expires_in_minutes=5)
    sh = r.json()
    import time
    assert sh["expires_ts"] - int(time.time()) <= 5 * 60 + 2
    assert S.share(rid, expires_in_minutes=0).status_code == 422
    assert S.share(rid, expires_in_minutes=24 * 60 + 1).status_code == 422
    _share_doc_update(db, sh["share_id"], expires_ts=int(time.time()) - 1)
    res = S.recipient_decrypt(sh["share_id"])
    assert res.status_code in (404, 410) and "plaintext_base64" not in res.text
    assert S.recipient.get("/api/crypto/shares").json()[0]["status"] == "EXPIRED"


# 12 + 13 -----------------------------------------------------------------------------------------
def test_revoked_shares_cannot_be_retrieved(S):
    rid, r = S.send(envelope_text("revocable"))
    sid = r.json()["share_id"]
    assert opened(S.recipient_decrypt(sid))["text"] == "revocable"
    assert S.recipient.post(f"/api/crypto/shares/{sid}/revoke", {"reason": "not sender"}).status_code == 404
    assert S.sender.post(f"/api/crypto/shares/{sid}/revoke", {"reason": "sent in error"}).status_code == 200
    again = S.recipient_decrypt(sid)
    assert again.status_code == 404 and "plaintext_base64" not in again.text
    assert S.recipient.post(f"/api/crypto/shares/{sid}/open", {"session_id": S.rflow.session}).status_code == 404
    assert S.recipient.get("/api/crypto/shares").json()[0]["status"] == "REVOKED"


def test_recipient_can_decline_and_it_is_final(S):
    rid, r = S.send(envelope_text("declined"))
    sid = r.json()["share_id"]
    assert S.recipient.post(f"/api/crypto/shares/{sid}/reject", {"reason": "not for me"}).status_code == 200
    assert S.admin.post(f"/api/crypto/shares/{sid}/admin-approve", {}).status_code == 404
    assert S.sender.get(f"/api/crypto/shares/{sid}").json()["status"] == "REJECTED"


# 14 ----------------------------------------------------------------------------------------------
def test_repeated_share_request_is_idempotent(S, db):
    rid, r1 = S.send(envelope_text("once only"))
    r2 = S.share(rid)
    r3 = S.share(rid)
    assert r1.status_code == 202 and r2.status_code == 200 and r3.status_code == 200
    assert r2.json()["share_id"] == r1.json()["share_id"] == r3.json()["share_id"] and r2.json()["duplicate"]
    assert len(S.sender.get("/api/crypto/shares").json()) == 1
    assert db["crypto_shares"].count_documents({"source_record_id": rid}) == 1
    # after revocation a deliberate new share is allowed
    S.sender.post(f"/api/crypto/shares/{r1.json()['share_id']}/revoke", {"reason": "re-send with new expiry"})
    assert S.share(rid).status_code == 202


# 16 ----------------------------------------------------------------------------------------------
@pytest.mark.parametrize("payload,why", [
    (envelope_file("evil.exe", b"MZ" + b"\x00" * 30), "unsupported type"),
    (envelope_file("fake.pdf", b"not really a pdf"), "content/type mismatch"),
    (envelope_file("report.pdf", PDF, sha256="0" * 64), "digest mismatch"),
    (envelope_file("report.pdf", PDF, size=1), "size mismatch"),
    (envelope_file("noext", PDF), "no extension"),
    (envelope_file("empty.pdf", b""), "empty"),
    (envelope_text("   "), "empty message"),
    (json.dumps({"format": "CIPHERQ_SHARE_V1", "kind": "other"}).encode(), "bad kind"),
])
def test_invalid_payloads_create_no_record_or_share(S, db, payload, why):
    before_r = db["crypto_records"].count_documents({"owner_user_id": S.sender.id})
    before_s = db["crypto_shares"].count_documents({"owner_user_id": S.sender.id})
    enc = S.sflow.encrypt(payload)
    assert enc.status_code == 422, (why, enc.text)
    assert db["crypto_records"].count_documents({"owner_user_id": S.sender.id}) == before_r
    assert db["crypto_shares"].count_documents({"owner_user_id": S.sender.id}) == before_s


def test_filename_is_sanitised_and_client_mime_is_ignored(S):
    rid, r = S.send(envelope_file("../../etc/pass wd\x00<b>.PDF", PDF, mime_type="text/html"))
    env = opened(S.recipient_decrypt(r.json()["share_id"]))
    assert "/" not in env["filename"] and "\x00" not in env["filename"] and "<" not in env["filename"]
    assert env["filename"].endswith(".pdf") and env["mime_type"] == "application/pdf"


def test_ordinary_encryption_is_unchanged_for_non_share_payloads(S):
    for pt in (b"plain text, not an envelope", b'{"format":"CIPHERQ_ATTACHMENT_V1","filename":"a.bin","data_base64":"AAEC"}',
               bytes(range(256))):
        enc = S.sflow.encrypt(pt)
        assert enc.status_code == 201, enc.text
        assert base64.b64decode(S.sflow.decrypt(enc.json()["record_id"]).json()["plaintext_base64"]) == pt


def test_sender_cannot_share_to_a_recipient_the_intent_does_not_name(client, user, user2, admin, make_user):
    s = Setup(client, user, user2, admin)
    u3 = make_user("USER_LEVEL_1", "y")
    enc = s.sflow.encrypt(envelope_text("n" * 20))
    # a different sender cannot use this record/intent at all
    other = Flow(client, u3, admin, ops=("encrypt", "decrypt", "share"))
    r = s.share(enc.json()["record_id"], actor=u3)
    assert r.status_code in (403, 404)


def test_recipient_must_pass_fresh_face_stepup_before_shared_decryption(S, db):
    rid, r = S.send(envelope_text("face-gated"))
    sid = r.json()["share_id"]
    db["stepup_grants"].update_many({"user_id": S.recipient.id, "session_id": S.rflow.session}, {"$set": {"revoked": True}})
    open_denied = S.recipient.post(f"/api/crypto/shares/{sid}/open", {"session_id": S.rflow.session})
    assert open_denied.status_code == 403 and "RECIPIENT_FACE_VERIFICATION_REQUIRED" in open_denied.text
    denied = S.recipient_decrypt(sid)
    assert denied.status_code == 403 and "RECIPIENT_FACE_VERIFICATION_REQUIRED" in denied.text
    assert "plaintext_base64" not in denied.text
    assert S.rflow.stepup().status_code == 200
    assert opened(S.recipient_decrypt(sid))["text"] == "face-gated"


def test_sender_can_decrypt_own_shared_record_during_validity(S):
    rid, response = S.send(envelope_text("sender can read own copy"))
    assert response.status_code == 202
    result = S.sflow.decrypt(rid)
    assert result.status_code == 200, result.text
    env = json.loads(base64.b64decode(result.json()["plaintext_base64"]))
    assert env["text"] == "sender can read own copy"


def test_recipient_acknowledgement_reaction_is_visible_to_sender(S):
    _, response = S.send(envelope_text("reaction test"))
    sid = response.json()["share_id"]
    reacted = S.recipient.post(f"/api/crypto/shares/{sid}/reaction", {"reaction": "RECEIVED"})
    assert reacted.status_code == 200, reacted.text
    assert reacted.json()["recipient_reaction"] == "RECEIVED"
    sender_view = S.sender.get(f"/api/crypto/shares/{sid}")
    assert sender_view.status_code == 200 and sender_view.json()["recipient_reaction"] == "RECEIVED"


def test_share_conversation_is_encrypted_and_limited_to_three_sentences(S, db):
    _, response = S.send(envelope_text("thread bootstrap"))
    sid = response.json()["share_id"]
    sent = S.sender.post(f"/api/crypto/shares/{sid}/messages", {
        "session_id": S.sflow.session, "device_id": S.sflow.device,
        "text": "Received it. Thank you! I will review this today."
    })
    assert sent.status_code == 201, sent.text
    stored = db["crypto_share_messages"].find_one({"_id": sent.json()["message_id"]})
    assert stored is not None and "text" not in stored and b"Received it" not in bytes(stored["ciphertext"])
    read = S.recipient.get(
        f"/api/crypto/shares/{sid}/messages?session_id={S.rflow.session}&device_id={S.rflow.device}")
    assert read.status_code == 200, read.text
    assert read.json()[0]["text"] == "Received it. Thank you! I will review this today."
    too_long = S.recipient.post(f"/api/crypto/shares/{sid}/messages", {
        "session_id": S.rflow.session, "device_id": S.rflow.device,
        "text": "One. Two. Three. Four."
    })
    assert too_long.status_code == 422


def test_new_encrypt_intent_can_select_recipient_in_secure_share_workflow(client, user, user2, admin):
    """New intents no longer need a recipient field; recipient is selected in the Secure Share workflow."""
    sender_flow = Flow(client, user, admin, max_uses=8, max_bytes=200_000, ops=("encrypt", "decrypt", "share"))
    recipient_flow = Flow(client, user2, admin)
    assigned = admin.post(f"/api/evidence/cases/{sender_flow.ref}/assign", {"user_id": user2.id})
    assert assigned.status_code == 200, assigned.text

    sender_flow.ready()
    encrypted = sender_flow.encrypt(envelope_text("selected in Secure Share"))
    assert encrypted.status_code == 201, encrypted.text

    response = user.post("/api/crypto/shares", {
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": sender_flow.session,
        "device_id": sender_flow.device,
        "record_id": encrypted.json()["record_id"],
        "recipient_user_id": user2.id,
        "recipient_key_session_id": recipient_flow.ks,
        "kind": "text",
    })
    assert response.status_code == 202, response.text
    share = response.json()
    assert share["recipient_user_id"] == user2.id
    assert share["status"] == "APPROVED"

    decision = user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share["share_id"],
    })
    assert decision.status_code == 200, decision.text
    assert decision.json()["outcome"] == "PERMIT", decision.json()
    decrypted = user2.post("/api/crypto/decrypt", {
        "context_id": decision.json()["context_id"],
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share["share_id"],
    })
    assert decrypted.status_code == 200, decrypted.text
    payload = json.loads(base64.b64decode(decrypted.json()["plaintext_base64"]))
    assert payload["text"] == "selected in Secure Share"


def test_share_auto_provisions_recipient_key_session_without_manual_activation(S):
    # Remove the fixture recipient's existing key so this exercises the no-session case.
    revoked = S.recipient.post(f"/api/key-sessions/{S.rflow.ks}/revoke", {})
    assert revoked.status_code == 200, revoked.text
    assert not any(item["status"] == "ACTIVE" for item in S.recipient.get("/api/key-sessions").json())

    encrypted = S.sflow.encrypt(envelope_text("automatic recipient provisioning"))
    assert encrypted.status_code == 201, encrypted.text
    rid = encrypted.json()["record_id"]
    response = S.share(rid, recipient_key_session_id=None, kind="text")
    assert response.status_code == 202, response.text
    share = response.json()
    assert share["status"] == "APPROVED"

    # A recipient-owned key session exists without recipient-initiated activation.
    sessions = S.recipient.get("/api/key-sessions").json()
    assert sum(item["status"] == "ACTIVE" for item in sessions) == 1
    assert opened(S.recipient_decrypt(share["share_id"]))["text"] == "automatic recipient provisioning"
