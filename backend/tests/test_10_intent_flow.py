"""Intent lifecycle + happy path through the real stack."""
import base64

import pytest
from pymongo.errors import DuplicateKeyError

from .conftest import PASSWORD
from .flow import Flow


def test_full_happy_path(client, user, admin, db):
    f = Flow(client, user, admin)
    created = f.create_intent()
    assert created["version"] == 1 and created["status"] == "DRAFT"
    validated = f.validate()
    assert validated["outcome"] == "VERIFIED"
    assert validated["intent"]["status"] == "PENDING_APPROVAL"
    approved = f.approve()
    assert approved.status_code == 200, approved.text
    assert f.view()["status"] == "APPROVED"
    message = b"CipherQ test message 001"
    r = f.encrypt(message)
    assert r.status_code == 201, r.text
    rid = r.json()["record_id"]
    assert "key" not in r.text.lower().replace("key_session_id", "")
    r = f.decrypt(rid)
    assert r.status_code == 200, r.text
    assert base64.b64decode(r.json()["plaintext_base64"]) == message
    actions = {entry["action"] for entry in admin.get("/api/audit/logs").json()}
    assert {"EVIDENCE_VALIDATED", "INTENT_APPROVED", "ENCRYPT_SUCCESS", "DECRYPT_SUCCESS"} <= actions
    validations = list(db["intent_evidence_validations"].find({"intent_id": f.intent_id}))
    assert validations
    assert all(v["version"] == 1 and v["body_hash"] == f.view()["body_hash"] for v in validations)
    assert all(v["outcome"] == "VERIFIED" and v["evidence_source"] == "local-case-table" for v in validations)


def test_admin_can_list_saved_evidence_cases_and_non_admin_cannot(client, user, admin):
    refs = ("CASE-876541", "CASE-876542")
    for ref in refs:
        response = admin.put(f"/api/evidence/cases/{ref}", {
            "title": f"Evidence case {ref}",
            "classification_cap": "CONFIDENTIAL",
            "allowed_resources": ["vault:customer-records"],
            "assigned_user_ids": [user.id],
            "status": "OPEN",
        })
        assert response.status_code == 200, response.text
        assert response.json()["updated_at"]

    page = admin.get("/api/evidence/cases?limit=100&offset=0")
    assert page.status_code == 200, page.text
    cases = {case["ref"]: case for case in page.json()["cases"] if case["ref"] in refs}
    assert set(cases) == set(refs)
    assert cases[refs[0]]["assigned_user_ids"] == [user.id]
    assert cases[refs[0]]["revision"] == 1
    assert page.json()["has_more"] is False
    assert user.get("/api/evidence/cases").status_code == 403


def test_approved_cid_attachment_download_requires_owner_key_session(client, user, admin):
    f = Flow(client, user, admin, max_bytes=4096, max_uses=4, ops=("encrypt", "share"))
    pdf_bytes = b"%PDF-1.7\\nCipherQ CID attachment"
    attachment = {"filename": "cid-evidence.pdf", "content_type": "application/pdf",
                  "content_base64": base64.b64encode(pdf_bytes).decode("ascii")}
    f.create_intent(attachment=attachment)
    f.validate()
    approved = f.approve()
    assert approved.status_code == 200, approved.text

    url = (f"/api/intents/{f.intent_id}/attachment?session_id={f.session}"
           f"&device_id={f.device}&key_session_id={f.ks}")
    response = user.get(url)
    assert response.status_code == 200, response.text
    assert response.content == pdf_bytes
    assert "cid-evidence.pdf" in response.headers.get("content-disposition", "")

    # A caller cannot omit the key-session binding to retrieve the intent attachment.
    missing_key = user.get(
        f"/api/intents/{f.intent_id}/attachment?session_id={f.session}&device_id={f.device}"
    )
    assert missing_key.status_code == 422


def test_pdf_attachment_allowed_and_mismatched_content_rejected_at_intent_api(client, user, admin):
    import base64

    f = Flow(client, user, admin)
    pdf = {"filename": "case-notes.pdf", "content_type": "application/pdf",
           "content_base64": base64.b64encode(b"%PDF-1.7\\nCipherQ evidence").decode()}
    created = user.post("/api/intents", f.intent_payload(attachment=pdf))
    assert created.status_code == 201, created.text
    assert created.json()["body"]["attachment"]["filename"] == "case-notes.pdf"

    invalid_pdf = {**pdf, "content_base64": base64.b64encode(b"not a PDF").decode()}
    rejected = user.post("/api/intents", f.intent_payload(attachment=invalid_pdf))
    assert rejected.status_code == 422
    assert any("filename, content type, and file signature" in item["msg"]
               for item in rejected.json()["errors"])


def test_intent_attachment_size_is_limited_to_one_mib(client, user, admin):
    import base64

    f = Flow(client, user, admin)
    oversized = {"filename": "oversized.pdf", "content_type": "application/pdf",
                 "content_base64": base64.b64encode(b"%PDF-" + b"x" * (1024 * 1024)).decode()}
    rejected = user.post("/api/intents", f.intent_payload(attachment=oversized))
    assert rejected.status_code == 422


def test_logout_login_and_fresh_database_wrapper_preserve_record(client, user, admin, raw_db, monkeypatch):
    from database import session as db_session
    from database.encrypted_store import EncryptedDatabase
    from security import keyring as keyring_module

    f = Flow(client, user, admin, max_uses=4).ready()
    message = b"still available after a new login"
    encrypted = f.encrypt(message)
    assert encrypted.status_code == 201, encrypted.text
    record_id = encrypted.json()["record_id"]
    expires_ts = encrypted.json()["expires_ts"]

    assert user.post("/api/auth/logout").status_code == 204
    login = client.post("/api/auth/login", json={"username": user.username, "password": PASSWORD})
    assert login.status_code == 200, login.text
    user.token = login.json()["token"]

    monkeypatch.setattr(keyring_module, "_keyring", None)
    reopened_keyring = keyring_module.get_keyring()
    monkeypatch.setattr(db_session, "db", EncryptedDatabase(raw_db, reopened_keyring))
    listed = user.get("/api/crypto/records")
    assert listed.status_code == 200, listed.text
    assert next(r for r in listed.json() if r["record_id"] == record_id)["expires_ts"] == expires_ts

    decrypted = f.decrypt(record_id)
    assert decrypted.status_code == 200, decrypted.text
    assert base64.b64decode(decrypted.json()["plaintext_base64"]) == message


def test_expired_record_is_rejected_using_server_timestamp(client, user, admin, db):
    import time

    f = Flow(client, user, admin, max_uses=4).ready()
    encrypted = f.encrypt(b"expires")
    assert encrypted.status_code == 201, encrypted.text
    record_id = encrypted.json()["record_id"]
    assert encrypted.json()["expires_ts"] - encrypted.json()["created_ts"] == 24 * 60 * 60
    db["crypto_records"].update_one({"_id": record_id}, {"$set": {"expires_ts": int(time.time()) - 1}})

    response = f.decide(operation="decrypt", record_id=record_id, key_session_id=None, requested_bytes=None)

    assert response.status_code == 410
    assert response.json()["detail"] == "record expired"


def test_modified_record_metadata_is_rejected(client, user, admin, db):
    f = Flow(client, user, admin, max_uses=4).ready()
    encrypted = f.encrypt(b"bound metadata")
    assert encrypted.status_code == 201, encrypted.text
    record_id = encrypted.json()["record_id"]
    db["crypto_records"].update_one(
        {"_id": record_id}, {"$set": {"resource": "vault:other-records"}})

    response = f.decide(operation="decrypt", record_id=record_id, key_session_id=None, requested_bytes=None,
                        resource="vault:other-records")

    assert response.status_code == 422
    assert response.json()["detail"] == "record metadata failed authentication"


def test_share_is_bound_to_recipient_and_revocable(client, user, user2, make_user, admin):
    recipient_flow = Flow(client, user2, admin)
    sender_flow = Flow(client, user, admin, max_uses=8, ops=("encrypt", "decrypt", "share"))
    assigned = admin.post(f"/api/evidence/cases/{sender_flow.ref}/assign", {"user_id": user2.id})
    assert assigned.status_code == 200, assigned.text
    sender_flow.create_intent(recipient_user_id=user2.id)
    sender_flow.validate()
    assert sender_flow.approve().status_code == 200

    message = b"recipient-only plaintext"
    encrypted = sender_flow.encrypt(message)
    assert encrypted.status_code == 201, encrypted.text
    share_response = user.post("/api/crypto/shares", {
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": sender_flow.session,
        "device_id": sender_flow.device,
        "record_id": encrypted.json()["record_id"],
        "recipient_key_session_id": recipient_flow.ks,
    })
    assert share_response.status_code == 202, share_response.text
    share_id = share_response.json()["share_id"]
    assert share_response.json()["recipient_user_id"] == user2.id
    assert share_response.json()["status"] == "PENDING_ADMIN"
    assert user2.get("/api/crypto/shares").json()[0]["status"] == "PENDING_ADMIN"
    assert user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id, "operation": "decrypt", "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose, "session_id": recipient_flow.session,
        "device_id": recipient_flow.device, "record_id": share_id,
    }).status_code == 404
    assert user.post(f"/api/crypto/shares/{share_id}/admin-approve", {}).status_code == 403
    assert admin.post(f"/api/crypto/shares/{share_id}/admin-approve", {}).status_code == 200
    assert user2.get("/api/crypto/shares").json()[0]["status"] == "APPROVED"

    decision = user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share_id,
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
        "record_id": share_id,
    })
    assert decrypted.status_code == 200, decrypted.text
    assert base64.b64decode(decrypted.json()["plaintext_base64"]) == message

    old_recipient_key = recipient_flow.ks
    rotation = user2.post(f"/api/key-sessions/{old_recipient_key}/rotate", {})
    assert rotation.status_code == 201, rotation.text
    new_recipient_key = rotation.json()["key_session_id"]
    rewrapped = user2.post(f"/api/key-sessions/{old_recipient_key}/rewrap",
                           {"to_key_session_id": new_recipient_key})
    assert rewrapped.status_code == 200, rewrapped.text
    assert rewrapped.json()["shares_moved"] == 1
    recipient_flow.ks = new_recipient_key

    rotated_decision = user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share_id,
    })
    assert rotated_decision.status_code == 200
    rotated_decrypt = user2.post("/api/crypto/decrypt", {
        "context_id": rotated_decision.json()["context_id"],
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share_id,
    })
    assert rotated_decrypt.status_code == 200, rotated_decrypt.text
    assert base64.b64decode(rotated_decrypt.json()["plaintext_base64"]) == message

    other_user = make_user(prefix="other")
    assert other_user.get(f"/api/crypto/shares/{share_id}").status_code == 404
    other_decision = other_user.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share_id,
    })
    assert other_decision.status_code == 404
    changed_recipient = user.post("/api/crypto/shares", {
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": sender_flow.session,
        "device_id": sender_flow.device,
        "record_id": encrypted.json()["record_id"],
        "recipient_key_session_id": recipient_flow.ks,
        "recipient_user_id": other_user.id,
    })
    assert changed_recipient.status_code == 422

    revoked = user.post(f"/api/crypto/shares/{share_id}/revoke", {"reason": "sharing no longer required"})
    assert revoked.status_code == 200
    assert user2.get(f"/api/crypto/shares/{share_id}").json()["status"] == "REVOKED"
    assert user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": share_id,
    }).status_code == 404

    withdrawn = admin.post(f"/api/intents/{sender_flow.intent_id}/withdraw-approval",
                           {"reason": "approval review required"})
    assert withdrawn.status_code == 200, withdrawn.text
    pending = user.post("/api/crypto/shares", {
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": sender_flow.session,
        "device_id": sender_flow.device,
        "record_id": encrypted.json()["record_id"],
        "recipient_key_session_id": recipient_flow.ks,
    })
    assert pending.status_code == 202, pending.text
    assert pending.json()["status"] == "PENDING"
    pending_share_id = pending.json()["share_id"]
    assert sender_flow.approve().status_code == 200
    activated = user.post(f"/api/crypto/shares/{pending_share_id}/activate", {
        "session_id": sender_flow.session, "device_id": sender_flow.device,
    })
    assert activated.status_code == 200, activated.text
    assert activated.json()["status"] == "PENDING_ADMIN"
    assert admin.post(f"/api/crypto/shares/{pending_share_id}/admin-approve", {}).status_code == 200
    recipient_decision = user2.post("/api/decisions", {
        "intent_id": sender_flow.intent_id,
        "operation": "decrypt",
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": pending_share_id,
    })
    assert recipient_decision.status_code == 200
    assert recipient_decision.json()["outcome"] == "PERMIT"
    recipient_decrypt = user2.post("/api/crypto/decrypt", {
        "context_id": recipient_decision.json()["context_id"],
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": recipient_flow.session,
        "device_id": recipient_flow.device,
        "record_id": pending_share_id,
    })
    assert recipient_decrypt.status_code == 200, recipient_decrypt.text
    assert base64.b64decode(recipient_decrypt.json()["plaintext_base64"]) == message

    assert admin.post(f"/api/intents/{sender_flow.intent_id}/withdraw-approval",
                      {"reason": "second share requires review"}).status_code == 200
    pending_again = user.post("/api/crypto/shares", {
        "intent_id": sender_flow.intent_id,
        "resource": sender_flow.resource,
        "purpose_code": sender_flow.purpose,
        "session_id": sender_flow.session,
        "device_id": sender_flow.device,
        "record_id": encrypted.json()["record_id"],
        "recipient_key_session_id": recipient_flow.ks,
    })
    assert pending_again.status_code == 202, pending_again.text
    rejected = user2.post(f"/api/crypto/shares/{pending_again.json()['share_id']}/reject",
                          {"reason": "not required"})
    assert rejected.status_code == 200
    assert user.get(f"/api/crypto/shares/{pending_again.json()['share_id']}").json()["status"] == "REJECTED"
    audit_actions = {entry["action"] for entry in admin.get("/api/audit/logs").json()}
    assert {"SHARE_PENDING", "SHARE_APPROVED", "SHARE_REJECTED", "SHARE_REVOKED",
            "SHARE_ACCESS_SUCCESS", "SHARE_ACCESS_REJECTED"} <= audit_actions


def test_requester_cannot_approve_own_intent(client, make_user):
    adm = make_user("ADMIN", "adm")
    f = Flow(client, adm, adm)
    f.create_intent(); f.validate()
    r = f.approve(approver=adm)
    assert r.status_code == 403


def test_non_admin_cannot_approve(client, user, admin, user2):
    f = Flow(client, user, admin)
    f.create_intent(); f.validate()
    assert f.approve(approver=user2).status_code == 403


def test_unapproved_intent_requires_approval(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent(); f.validate()
    d = f.decide().json()
    assert d["outcome"] == "REQUIRE_APPROVAL" and d["context_id"] is None


def test_draft_intent_cannot_be_approved(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent()

    approval = f.approve()

    assert approval.status_code == 409
    assert f.view()["status"] == "DRAFT"
    assert f.view()["approvals"] == []


def test_client_cannot_set_server_fields(client, user, admin):
    f = Flow(client, user, admin)
    for extra in ({"sender": "root"}, {"owner_user_id": 1}, {"required_approvals": 0}, {"status": "APPROVED"},
                  {"policy_version": "x"}):
        r = user.post("/api/intents", f.intent_payload(**extra))
        assert r.status_code == 422, extra


def test_malformed_intents_rejected(client, user, admin):
    f = Flow(client, user, admin)
    bad = [{"purpose_code": "WORLD_DOMINATION"}, {"operations": []}, {"operations": ["encrypt", "encrypt"]},
           {"resource": "../etc/passwd"}, {"purpose_statement": "short"}, {"business_reference": "x"},
           {"data_scope": {"classification": "SECRET", "max_bytes": 10}},
           {"data_scope": {"classification": "PUBLIC", "max_bytes": 10**9}},
           {"valid_until": "2000-01-01T00:00:00Z"}]
    for b in bad:
        assert user.post("/api/intents", f.intent_payload(**b)).status_code == 422, b


def test_validity_over_24h_rejected(client, user, admin):
    from datetime import datetime, timedelta, timezone
    from .flow import iso
    f = Flow(client, user, admin)
    now = datetime.now(timezone.utc)
    r = user.post("/api/intents", f.intent_payload(valid_from=iso(now), valid_until=iso(now + timedelta(hours=25))))
    assert r.status_code == 422


def test_evidence_missing_blocks_validation_progress(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent(evidence_refs=[])
    rep = f.validate()
    assert rep["evidence_ok"] is False
    assert f.view()["status"] == "DRAFT"


def test_user_declared_claim_is_not_evidence(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent(business_reference="CASE-999999", evidence_refs=[{"kind": "CASE", "ref": "CASE-999999"}])
    rep = f.validate()
    assert rep["evidence_ok"] is False          # case does not exist in the authoritative table
    assert rep["outcome"] == "CASE_NOT_FOUND"
    assert f.view()["status"] == "DRAFT"
    assert f.view()["approvals"] == []
    assert f.decide().json()["outcome"] != "PERMIT"


def test_evidence_provider_failure_fails_closed(client, user, admin, monkeypatch):
    from intent_engine.evidence import EvidenceProviderUnavailable, LocalEvidenceProvider

    f = Flow(client, user, admin)
    f.create_intent()

    def unavailable(_self, _ref):
        raise EvidenceProviderUnavailable("test outage")

    monkeypatch.setattr(LocalEvidenceProvider, "get_case", unavailable)
    report = f.validate()

    assert report["outcome"] == "EVIDENCE_PROVIDER_UNAVAILABLE"
    assert report["evidence_source"] == "local-case-table"
    assert report["evidence_ok"] is False
    assert f.view()["status"] == "DRAFT"
    assert f.view()["approvals"] == []


def test_approval_rechecks_case_evidence(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent()
    assert f.validate()["intent"]["status"] == "PENDING_APPROVAL"
    assert admin.post(f"/api/evidence/cases/{f.ref}/close").status_code == 200

    approval = f.approve()

    assert approval.status_code == 409
    assert approval.json()["detail"].startswith("EVIDENCE_INVALID")
    assert f.view()["status"] == "DRAFT"
    assert not any(a["verdict"] == "APPROVE" for a in f.view()["approvals"])


def test_development_fixture_insert_never_replaces_a_case(db, user):
    from intent_engine.evidence import DEVELOPMENT_FIXTURE_MARKER, LocalEvidenceProvider

    ref = "CASE-900777"
    provider = LocalEvidenceProvider(db)
    case = provider.create_case(
        ref,
        title="CipherQ development fixture",
        classification_cap="CONFIDENTIAL",
        allowed_resources=["vault:customer-records"],
        assigned_user_ids=[user.id],
        fixture_marker=DEVELOPMENT_FIXTURE_MARKER,
    )

    with pytest.raises(DuplicateKeyError):
        provider.create_case(
            ref,
            title="replacement case",
            classification_cap="PUBLIC",
            allowed_resources=[],
            assigned_user_ids=[user.id],
            fixture_marker=DEVELOPMENT_FIXTURE_MARKER,
        )

    assert provider.get_case(ref) == case


def test_case_not_assigned_to_requester_is_not_evidence(client, user, user2, admin):
    f = Flow(client, user, admin)
    admin.post(f"/api/evidence/cases/{f.ref}/unassign", {"user_id": user.id})
    f.create_intent()
    assert f.validate()["evidence_ok"] is False


def test_other_user_cannot_see_intent(client, user, user2, admin):
    f = Flow(client, user, admin).ready()
    assert user2.get(f"/api/intents/{f.intent_id}").status_code == 404
    assert user2.post(f"/api/intents/{f.intent_id}/revoke", {"reason": "mine now"}).status_code == 404
    assert user2.post(f"/api/intents/{f.intent_id}/validate").status_code == 404
