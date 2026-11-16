"""Evidence case assignment: admin-created cases must work for the assigned requester and only for them."""
from .flow import Flow


def test_assigned_requester_enters_approval_queue(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent()
    v = f.validate()
    assert v["outcome"] == "VERIFIED" and v["intent"]["status"] == "PENDING_APPROVAL"


def test_unassigned_requester_gets_user_not_assigned_then_works_after_admin_assigns(client, user, user2, admin):
    f = Flow(client, user, admin)
    f.create_intent()
    assert admin.post(f"/api/evidence/cases/{f.ref}/unassign", {"user_id": user.id}).status_code == 200
    v = f.validate()
    assert v["intent"]["status"] == "DRAFT" and "USER_NOT_ASSIGNED" in str(v)
    assert admin.post(f"/api/evidence/cases/{f.ref}/assign", {"user_id": user.id}).status_code == 200
    v2 = f.validate()
    assert v2["outcome"] == "VERIFIED" and v2["intent"]["status"] == "PENDING_APPROVAL"


def test_case_save_rejects_nonexistent_user_ids(client, user, admin):
    f = Flow(client, user, admin)
    f.create_intent()
    body = {"title": "Case investigation", "classification_cap": "CONFIDENTIAL",
            "allowed_resources": ["vault:customer-records"], "assigned_user_ids": [user.id, 99999]}
    r = admin.put(f"/api/evidence/cases/{f.ref}", body)
    assert r.status_code == 422 and "99999" in r.text
    body["assigned_user_ids"] = [user.id]
    assert admin.put(f"/api/evidence/cases/{f.ref}", body).status_code == 200


def test_non_admin_cannot_edit_assignments(client, user, user2, admin):
    f = Flow(client, user, admin)
    f.create_intent()
    assert user2.post(f"/api/evidence/cases/{f.ref}/assign", {"user_id": user2.id}).status_code in (401, 403)
