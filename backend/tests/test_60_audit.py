"""Audit chain: keyed MAC, sequence, head anchor, secondary sink, concurrency, access control."""
import os
import threading

import pytest

from audit.hash_chain import verify_chain
from audit.service import AuditLogService, AuditSinkError, FileSink, InMemoryAuditLogRepository
from security.keyring import get_keyring


@pytest.fixture()
def snapshot(db):
    """Restore the shared audit collections after a destructive test."""
    logs = list(db["audit_logs"].find({}).sort("_id", 1))
    head = db["audit_head"].find_one({"_id": "head"})
    sink = os.environ["AUDIT_SINK_PATH"]
    sink_bytes = open(sink, "rb").read() if os.path.exists(sink) else b""
    yield
    db["audit_logs"].delete_many({})
    if logs:
        db["audit_logs"].insert_many(logs)
    db["audit_head"].delete_many({})
    if head:
        db["audit_head"].insert_one(head)
    open(sink, "wb").write(sink_bytes)


def _seed(client, n=6):
    for i in range(n):
        client.post("/api/auth/login", json={"username": f"nobody{i}", "password": "x" * 12})


def test_audit_access_control(client, user, admin):
    assert client.get("/api/audit/logs").status_code == 401
    assert client.get("/api/audit/verify").status_code == 401
    assert user.get("/api/audit/logs").status_code == 403
    assert user.get("/api/audit/verify").status_code == 403
    assert admin.get("/api/audit/logs").status_code == 200
    # there is no write / delete surface
    for m in ("post", "put", "delete", "patch"):
        r = getattr(client, m)("/api/audit/logs", headers=admin.h)
        assert r.status_code in (404, 405)


def test_clean_chain_verifies(client, admin):
    _seed(client)
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is True and r["security_state"] == "normal" and r["checked_entries"] >= 6
    assert all(r["checks"].values())


def test_modified_record_detected(client, admin, db, snapshot):
    _seed(client)
    docs = list(db["audit_logs"].find({}).sort("_id", 1))
    target = docs[len(docs) // 2]
    db["audit_logs"].update_one({"_id": target["_id"]}, {"$set": {"result": "success", "reason": "edited by attacker"}})
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is False and r["checks"]["mac_verification"] is False
    assert r["first_invalid_index"] == target["_id"] - 1 and r["security_state"] == "compromised"


def test_attacker_cannot_recompute_chain_without_key(client, admin, db, snapshot):
    """The v17 attack: edit an entry and re-derive every following unkeyed SHA-256. With HMAC this fails."""
    import hashlib
    _seed(client)
    docs = list(db["audit_logs"].find({}).sort("_id", 1))
    prev = "0" * 64
    for d in docs[:8]:
        d["action"] = "EDITED" if d["_id"] == 2 else d["action"]
        h = hashlib.sha256((prev + d["action"] + d["result"]).encode()).hexdigest()
        db["audit_logs"].update_one({"_id": d["_id"]}, {"$set": {"action": d["action"], "prev_log_hash": prev,
                                                                  "current_log_hash": h}})
        prev = h
    assert admin.get("/api/audit/verify").json()["valid"] is False


def test_deleted_middle_record_detected(client, admin, db, snapshot):
    _seed(client)
    db["audit_logs"].delete_one({"_id": 3})
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is False and r["checks"]["sequence"] is False


def test_deleted_last_record_detected(client, admin, db, snapshot):
    """v17 reported VALID after deleting the newest entry."""
    _seed(client)
    last = db["audit_logs"].find({}).sort("_id", -1).limit(1)
    last = list(last)[0]
    db["audit_logs"].delete_one({"_id": last["_id"]})
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is False and r["checks"]["head_anchor"] is False


def test_truncation_with_head_also_deleted_detected(client, admin, db, snapshot):
    _seed(client)
    last = list(db["audit_logs"].find({}).sort("_id", -1).limit(1))[0]
    db["audit_logs"].delete_one({"_id": last["_id"]})
    db["audit_head"].delete_many({})
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is False


def test_secondary_sink_catches_full_db_rewrite(client, admin, db, snapshot):
    """Attacker with DB write access truncates entries AND forges a consistent head (impossible without the key),
    or simply wipes the DB: the sink still holds the newest seq/mac."""
    _seed(client)
    db["audit_logs"].delete_many({})
    db["audit_head"].delete_many({})
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is False or r["checked_entries"] == 0
    # with the DB wiped the sink still proves entries existed
    svc = AuditLogService(__import__("api.repositories", fromlist=["x"]).MongoAuditLogRepository(db),
                          get_keyring(), FileSink(os.environ["AUDIT_SINK_PATH"]))
    res = svc.verify_integrity()
    assert res.valid is False and res.checks["secondary_sink"] is False


def test_sink_tampering_detected(client, admin, snapshot):
    _seed(client)
    path = os.environ["AUDIT_SINK_PATH"]
    lines = open(path).read().splitlines()
    open(path, "w").write("\n".join(lines[:-3]) + "\n")                 # drop the newest three sink lines
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is True or r["checks"]["secondary_sink"] is False   # within the tolerated lag window
    open(path, "w").write("\n".join(lines[:-12]) + "\n")                # far behind
    assert admin.get("/api/audit/verify").json()["valid"] is False
    open(path, "w").write("garbage\n")
    assert admin.get("/api/audit/verify").json()["valid"] is False


def test_concurrent_audit_writes_keep_a_valid_chain(client, admin):
    def go(i):
        client.post("/api/auth/login", json={"username": f"racer{i}", "password": "x" * 12})
    ts = [threading.Thread(target=go, args=(i,)) for i in range(30)]
    [t.start() for t in ts]; [t.join() for t in ts]
    r = admin.get("/api/audit/verify").json()
    assert r["valid"] is True, r
    seqs = [e["seq"] for e in admin.get("/api/audit/logs").json()]
    assert seqs == list(range(1, len(seqs) + 1))


def test_unit_reordered_and_forged_entries_fail_without_db():
    kr = get_keyring()
    svc = AuditLogService(InMemoryAuditLogRepository(), kr)
    for i in range(5):
        svc.record("E", "ok", user_id=i)
    entries = list(svc.list_entries())
    head = svc._repository.get_head()
    assert verify_chain(kr, entries, head).valid
    swapped = [entries[0], entries[2], entries[1], *entries[3:]]
    assert not verify_chain(kr, swapped, head).valid
    import dataclasses
    forged = list(entries); forged[2] = dataclasses.replace(entries[2], user_id=999)
    assert not verify_chain(kr, forged, head).valid
    assert not verify_chain(kr, entries[:-1], head).valid                      # truncated tail
    assert not verify_chain(kr, entries, None).valid                           # missing head


def test_sink_failure_fails_closed_when_required(tmp_path):
    kr = get_keyring()
    bad = FileSink(str(tmp_path / "no" / "such" / "dir" / "sink.jsonl"))
    open_svc = AuditLogService(InMemoryAuditLogRepository(), kr, bad, sink_fail_closed=False)
    open_svc.record("E", "ok")                                                  # logs an error, continues
    closed = AuditLogService(InMemoryAuditLogRepository(), kr, bad, sink_fail_closed=True)
    with pytest.raises(AuditSinkError):
        closed.record("E", "ok")


def test_sink_file_mode_is_private(client):
    if os.name != "posix":
        pytest.skip("POSIX permission bits do not report Windows file ACLs")
    _seed(client, 1)
    assert oct(os.stat(os.environ["AUDIT_SINK_PATH"]).st_mode & 0o777) == "0o600"


def test_audit_does_not_contain_secrets(client, user, admin):
    from .flow import ENROLLED, Flow
    f = Flow(client, user, admin).ready()
    f.encrypt(b"SUPER-SECRET-PLAINTEXT")
    blob = admin.get("/api/audit/logs").text + open(os.environ["AUDIT_SINK_PATH"]).read()
    assert "SUPER-SECRET-PLAINTEXT" not in blob
    assert "Correct-Horse-Battery-9" not in blob
    assert str(ENROLLED[0]) + "," + str(ENROLLED[1]) not in blob
    assert "U1VQRVItU0VDUkVU" not in blob                                       # base64 of the plaintext


def test_events_recorded_for_key_operations(client, user, admin):
    from .flow import Flow
    f = Flow(client, user, admin).ready()
    f.encrypt(b"x")
    actions = {e["action"] for e in admin.get("/api/audit/logs").json()}
    for needed in ("USER_REGISTERED", "INTENT_CREATED", "EVIDENCE_VALIDATED", "INTENT_APPROVED", "AUTHZ_DECISION",
                   "CONTEXT_ISSUED", "ENCRYPT_SUCCESS", "KEY_SESSION_CREATED", "STEPUP_SUCCESS"):
        assert needed in actions, needed
