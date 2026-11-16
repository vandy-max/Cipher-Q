"""Phase 4 acceptance tests: purpose drift + authorization-bound cryptography (all against the real stack)."""
import base64

import pytest

from .flow import Flow


@pytest.fixture()
def flow(client, user, admin):
    return Flow(client, user, admin).ready()


def _codes(resp):
    return {r["code"] for r in resp.json()["reasons"]}


# 1
def test_01_purpose_change_after_approval_rejected(flow, user):
    r = flow.decide(purpose_code="AUDIT_REVIEW")
    assert r.json()["outcome"] == "DENY" and "PURPOSE_DRIFT" in _codes(r) and r.json()["context_id"] is None
    # an in-place edit is impossible: a new version is a new, unapproved intent version
    r = user.post(f"/api/intents/{flow.intent_id}/versions", flow.intent_payload(purpose_code="AUDIT_REVIEW"))
    assert r.status_code == 201 and r.json()["version"] == 2 and r.json()["status"] == "DRAFT"
    assert flow.decide().json()["outcome"] != "PERMIT"


# 2
def test_02_resource_change_rejected(flow):
    r = flow.decide(resource="vault:other-customers")
    assert r.json()["outcome"] == "DENY" and "RESOURCE_DRIFT" in _codes(r)


# 3
def test_03_operation_change_rejected(client, user, admin):
    f = Flow(client, user, admin, ops=("decrypt",)).ready()
    r = f.decide(operation="encrypt")
    assert r.json()["outcome"] == "DENY" and "OPERATION_DRIFT" in _codes(r)


# 4
def test_04_reuse_under_another_user_rejected(flow, user, user2):
    d = flow.decide().json()
    assert d["outcome"] == "PERMIT"
    r = flow.encrypt(ctx=d["context_id"], actor=user2)
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_INVALID"
    r2 = flow.decide(actor=user2)
    assert r2.json()["outcome"] == "DENY" and "USER_MISMATCH" in _codes(r2)
    assert flow.encrypt(ctx=d["context_id"]).status_code == 201     # the real owner is unaffected


# 5
def test_05_reuse_under_another_session_rejected(flow, user):
    s2 = user.post("/api/authorization/sessions", {"device_id": flow.device}).json()["session_id"]
    d = flow.decide().json()
    r = flow.encrypt(ctx=d["context_id"], session_id=s2)
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_BINDING_MISMATCH"
    assert "SESSION_MISMATCH" in _codes(flow.decide(session_id=s2))


# 6
def test_06_reuse_under_another_device_rejected(flow, user):
    dev2 = user.post("/api/authorization/devices").json()["device_id"]
    d = flow.decide().json()
    r = flow.encrypt(ctx=d["context_id"], device_id=dev2)
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_BINDING_MISMATCH"
    assert "DEVICE_MISMATCH" in _codes(flow.decide(device_id=dev2))


# 7
def test_07_expired_decision_rejected(flow, monkeypatch):
    import intent_engine.engine as eng
    d = flow.decide().json()
    real = eng.now_ts
    monkeypatch.setattr(eng, "now_ts", lambda: real() + 100000)
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] in ("CONTEXT_EXPIRED", "DECISION_EXPIRED")


# 8
def test_08_revoked_decision_rejected(flow, user):
    d = flow.decide().json()
    assert user.post(f"/api/decisions/{d['decision_id']}/revoke", {"reason": "no longer needed"}).status_code == 200
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] in ("CONTEXT_INVALIDATED", "DECISION_REVOKED")
    assert user.get(f"/api/decisions/{d['decision_id']}").json()["status"] == "REVOKED"


# 9
def test_09_closing_case_invalidates_access(flow, admin):
    d = flow.decide().json()
    assert admin.post(f"/api/evidence/cases/{flow.ref}/close").status_code == 200
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "AUTHORIZATION_CHANGED"
    r = flow.decide()
    assert r.json()["outcome"] == "DENY" and "CASE_CLOSED" in _codes(r)


# 10
def test_10_removing_user_from_case_invalidates_access(flow, admin, user):
    d = flow.decide().json()
    assert admin.post(f"/api/evidence/cases/{flow.ref}/unassign", {"user_id": user.id}).status_code == 200
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "AUTHORIZATION_CHANGED"
    assert "USER_REMOVED_FROM_CASE" in _codes(flow.decide())


# 11
def test_11_operation_outside_data_scope_rejected(flow):
    r = flow.decide(requested_bytes=flow.max_bytes + 1)
    assert r.json()["outcome"] == "DENY" and "SCOPE_EXCEEDED" in _codes(r)
    # the *actual* payload is checked too: permit for 16 bytes cannot be used to encrypt 5000 bytes
    d = flow.decide(requested_bytes=16).json()
    r = flow.encrypt(plaintext=b"x" * 5000, ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "AUTHORIZATION_CHANGED"


# 12
def test_12_modified_authorization_records_fail_integrity(flow, user, db):
    ver = db["intent_versions2"].find_one({"_id": f"{flow.intent_id}:1"})
    assert ver["body"]["data_scope"]["max_bytes"] == flow.max_bytes
    db["intent_versions2"].update_one({"_id": f"{flow.intent_id}:1"},
                                      {"$set": {"body.data_scope.max_bytes": 1048576}})
    assert db["intent_versions2"].find_one({"_id": f"{flow.intent_id}:1"})["body"]["data_scope"]["max_bytes"] == 1048576
    assert user.get(f"/api/intents/{flow.intent_id}").json()["integrity_ok"] is False
    r = flow.decide()
    assert r.json()["outcome"] == "DENY" and "INTENT_RECORD_TAMPERED" in _codes(r)


def test_12b_modified_decision_fails_integrity(flow, user, db):
    d = flow.decide().json()
    db["authz_decisions"].update_one({"_id": d["decision_id"]}, {"$set": {"outcome": "PERMIT", "resource": "vault:x"}})
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "DECISION_INTEGRITY_FAILED"
    assert user.get(f"/api/decisions/{d['decision_id']}").json()["integrity_ok"] is False


# 13
def test_13_stale_policy_decision_not_honoured(flow, admin):
    d = flow.decide().json()
    r = admin.post("/api/policies", {"name": "ops", "rule_type": "allowed_operation",
                                     "config": {"operations": ["encrypt", "decrypt"]}, "active": True})
    assert r.status_code in (200, 201), r.text
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] in ("CONTEXT_STALE", "AUTHORIZATION_CHANGED")
    # re-evaluation under the new policy yields a fresh, valid decision
    assert flow.encrypt().status_code == 201


# 14
def test_14_replayed_operation_rejected(flow):
    d = flow.decide().json()
    assert flow.encrypt(ctx=d["context_id"]).status_code == 201
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 409 and r.json()["detail"] == "CONTEXT_ALREADY_USED"


def test_14b_concurrent_replay_has_one_winner(flow):
    import threading
    d = flow.decide().json()
    out = []

    def go():
        out.append(flow.encrypt(ctx=d["context_id"]).status_code)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert out.count(201) == 1, out


def test_14c_max_uses_enforced(client, user, admin):
    f = Flow(client, user, admin, max_uses=1).ready()
    assert f.encrypt().status_code == 201
    r = f.decide()
    assert r.json()["outcome"] == "DENY" and "INTENT_EXHAUSTED" in _codes(r)


# 15
def test_15_authorization_change_invalidates_previous_context(flow, admin):
    d = flow.decide().json()
    r = admin.post(f"/api/intents/{flow.intent_id}/withdraw-approval", {"reason": "reviewing"})
    assert r.status_code == 200
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_INVALIDATED"
    assert flow.decide().json()["outcome"] == "REQUIRE_APPROVAL"


def test_15b_state_change_without_violation_makes_context_stale(flow, admin, user):
    """Evidence case revision changes (no rule violated): the AEAD-wrapped key must still refuse to open."""
    d = flow.decide().json()
    r = admin.put(f"/api/evidence/cases/{flow.ref}", {"title": "Fraud investigation (updated)",
                  "classification_cap": "RESTRICTED", "allowed_resources": [flow.resource],
                  "assigned_user_ids": [user.id], "status": "OPEN"})
    assert r.status_code == 200
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_STALE"


# 16
def test_16_fresh_authorization_creates_valid_context(flow, admin):
    d1 = flow.decide().json()
    admin.post(f"/api/intents/{flow.intent_id}/withdraw-approval", {"reason": "reviewing"})
    assert flow.encrypt(ctx=d1["context_id"]).status_code == 403
    assert flow.approve().status_code == 200
    d2 = flow.decide().json()
    assert d2["outcome"] == "PERMIT" and d2["context_id"] != d1["context_id"]
    assert flow.encrypt(ctx=d2["context_id"]).status_code == 201


# 17
def test_17_frontend_manipulation_cannot_bypass(flow, user):
    # forged / guessed context
    r = flow.encrypt(ctx="ctx_" + "0" * 32)
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_INVALID"
    # client-supplied "authorization hash / decision / state / key" fields are not accepted at all
    d = flow.decide().json()
    for extra in ({"authorization_hash": "a" * 64}, {"decision_id": d["decision_id"]}, {"quantum_key": "00" * 32},
                  {"role": "ADMIN"}):
        r = flow.encrypt(ctx=d["context_id"], **extra)
        assert r.status_code == 422, extra
    # swapping the purpose / resource in the operation call is caught by the binding check
    r = flow.encrypt(ctx=d["context_id"], purpose_code="AUDIT_REVIEW")
    assert r.status_code == 403 and r.json()["detail"] == "CONTEXT_BINDING_MISMATCH"
    # decrypting somebody else's record id with own intent
    assert flow.decide(record_id="rec_" + "0" * 32, operation="decrypt").status_code == 404


# 18
def test_18_every_decision_is_audited(flow, admin, user):
    ok = flow.decide().json()
    bad = flow.decide(resource="vault:elsewhere").json()
    logs = admin.get("/api/audit/logs").json()
    mine = [e for e in logs if e["action"] == "AUTHZ_DECISION"]
    text = " ".join(e["reason"] or "" for e in mine)
    assert ok["decision_id"] in text and bad["decision_id"] in text
    assert any(e["action"] == "PURPOSE_DRIFT_DETECTED" and bad["decision_id"] in (e["reason"] or "") for e in logs)
    assert any(e["action"] == "CONTEXT_ISSUED" for e in logs)
    assert admin.get("/api/audit/verify").json()["valid"] is True


# ---- the 10-step workflow of Phase 4.G ------------------------------------------------------------
def test_workflow_authorization_state_change(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent()                                   # 1 create
    rep = f.validate()                                  # 2 validate
    assert rep["evidence_ok"]
    assert f.approve().status_code == 200               # 3 policy / approver approves
    d1 = f.decide().json()                              # 4 decision + bound crypto context
    assert d1["outcome"] == "PERMIT"
    assert f.encrypt(ctx=d1["context_id"]).status_code == 201     # 5 protected operation succeeds
    d2 = f.decide().json()
    admin.post(f"/api/evidence/cases/{f.ref}/close")    # 6 authorization state changes
    assert f.encrypt(ctx=d2["context_id"]).status_code == 403    # 7 previous context invalid
    assert f.decide().json()["outcome"] == "DENY"       # 8 new authorization decision required (denied)
    admin.put(f"/api/evidence/cases/{f.ref}", {"title": "Reopened", "classification_cap": "RESTRICTED",
              "allowed_resources": [f.resource], "assigned_user_ids": [user.id], "status": "OPEN"})
    d3 = f.decide().json()                              # 9 fresh context
    assert d3["outcome"] == "PERMIT" and d3["context_id"] not in (d1["context_id"], d2["context_id"])
    assert f.encrypt(ctx=d3["context_id"]).status_code == 201     # 10 succeeds only because new decision permits
