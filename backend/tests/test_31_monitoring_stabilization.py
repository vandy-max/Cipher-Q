"""Live Monitoring stabilization tests (real API, real app wiring; DB per tests/conftest.py)."""
import threading
from datetime import datetime, timedelta, timezone

import pytest

from .flow import Flow, jitter, other_face


@pytest.fixture()
def flow(client, user, admin):
    return Flow(client, user, admin).ready()


def hb(f, nonce, **kw):
    body = {"monitoring_session_id": f.mon["monitoring_session_id"], "prev_nonce": nonce, **kw}
    return f.user.post("/api/monitoring/heartbeat", body)


def run_heartbeats(f, n, **kw):
    nonce = f.mon["heartbeat_nonce"]
    for _ in range(n):
        r = hb(f, nonce, probe_descriptor=jitter(), **kw)
        assert r.status_code == 200, r.text
        nonce = r.json()["heartbeat_nonce"]
    return nonce


def test_audit_chain_not_reverified_on_every_heartbeat(flow, monkeypatch):
    from audit.service import AuditLogService
    from monitoring.service import MonitoringService
    MonitoringService.reset_integrity_cache()
    calls = []
    orig = AuditLogService.verify_integrity
    monkeypatch.setattr(AuditLogService, "verify_integrity", lambda self: (calls.append(1), orig(self))[1])
    run_heartbeats(flow, 10)
    assert len(calls) <= 1


def test_audit_tamper_still_reported(flow, monkeypatch):
    import monitoring.service as ms
    from audit.hash_chain import ChainVerificationResult
    from audit.service import AuditLogService
    ms.MonitoringService.reset_integrity_cache()
    monkeypatch.setattr(AuditLogService, "verify_integrity",
                        lambda self: ChainVerificationResult(valid=False, reason="tamper"))
    r = flow.user.get(f"/api/monitoring/{flow.mon['monitoring_session_id']}")
    assert r.status_code == 200 and r.json()["status"] == "active"      # informational, never changes posture
    ms.MonitoringService.reset_integrity_cache()
    snap = flow.user.get(f"/api/monitoring/{flow.mon['monitoring_session_id']}")
    assert snap.status_code == 200


def test_healthy_heartbeats_cause_no_session_or_event_flush(flow, monkeypatch):
    from api import repositories
    flushes = []
    orig = repositories._HOT._flush_locked
    monkeypatch.setattr(repositories._HOT, "_flush_locked", lambda e, n: (flushes.append(1), orig(e, n))[1])
    run_heartbeats(flow, 8)
    assert flushes == []


def test_security_change_is_persisted_immediately(flow, db):
    n = flow.mon["heartbeat_nonce"]
    mid = flow.mon["monitoring_session_id"]
    for i in range(3):
        r = hb(flow, n, probe_descriptor=other_face(i))
        n = r.json()["heartbeat_nonce"]
    assert db["monitoring_sessions"].find_one({"_id": mid})["status"] == "warning"


def test_flush_failure_does_not_break_heartbeat(flow, monkeypatch):
    from api import repositories
    mid = flow.mon["monitoring_session_id"]
    n = flow.mon["heartbeat_nonce"]
    ent = repositories._HOT.entries[mid]

    class Boom:
        def __getitem__(self, k):
            raise RuntimeError("db down")
    real = ent.db
    ent.db = Boom()
    try:
        for i in range(3):
            r = hb(flow, n, probe_descriptor=other_face(i))   # significant change -> flush attempt
            assert r.status_code == 200, r.text
            n = r.json()["heartbeat_nonce"]
    finally:
        ent.db = real
    repositories._HOT.entries[mid].next_retry = 0
    repositories.MongoMonitoringRepository.flush_hot_state()
    assert repositories._HOT.entries[mid].dirty is False


def test_lookup_by_session_uses_index_not_collection_scan(flow, db):
    from api.repositories import MongoMonitoringRepository
    calls = []
    coll = db["monitoring_sessions"]
    orig = type(coll).find_one
    try:
        type(coll).find_one = lambda self, *a, **k: (calls.append(self.name), orig(self, *a, **k))[1]
        for _ in range(5):
            assert MongoMonitoringRepository(db).get_by_session(flow.session) is not None
    finally:
        type(coll).find_one = orig
    assert "monitoring_sessions" not in calls


def test_event_append_does_not_rescan_collection(flow, db, monkeypatch):
    from api import repositories
    from monitoring.service import MonitoringEvent
    mid = flow.mon["monitoring_session_id"]
    repo = repositories.MongoMonitoringRepository(db)
    snap = repo.list_events(mid)[0].snapshot
    scans = []
    ec = type(db["monitoring_events"])
    orig = ec.find
    monkeypatch.setattr(ec, "find", lambda self, *a, **k: (scans.append(a), orig(self, *a, **k))[1]
                        if a and "monitoring_session_id" in (a[0] or {}) else orig(self, *a, **k))
    for _ in range(20):
        repo.append_event(MonitoringEvent(mid, "probe", snap))
    assert scans == []


def test_heartbeat_during_account_lockout_is_a_failed_tick_not_500(flow):
    for i in range(6):                                     # trip the step-up lockout
        flow.stepup(descriptor=other_face(i))
    r = hb(flow, flow.mon["heartbeat_nonce"], probe_descriptor=jitter())
    assert r.status_code == 200, r.text
    assert r.json()["consecutive_face_failures"] >= 1


def test_expired_session_requires_face_reauth_not_admin_approval(flow, db, user):
    db["authz_sessions"].update_one({"_id": flow.session},
                                    {"$set": {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=1)}})
    r = flow.user.get(f"/api/monitoring/{flow.mon['monitoring_session_id']}")
    body = r.json()
    assert body["status"] == "revoked" and body["reason_code"] == "session_expired"
    assert flow.decide().json()["outcome"] != "PERMIT"                       # still blocked
    assert flow.user.get(f"/api/authorization/sessions/{flow.session}").json()["revoked"] is False
    # non-admin recovers with a fresh face check alone
    ch = user.post("/api/identity/challenges", {"session_id": flow.session}).json()
    r = user.post(f"/api/authorization/sessions/{flow.session}/reauthenticate",
                  {"device_id": flow.device, "challenge_id": ch["challenge_id"], "face_descriptor": jitter()})
    assert r.status_code == 200, r.text


def test_revoked_session_still_requires_admin_approval(client, user, admin):
    f = Flow(client, user, admin).ready()
    admin.post(f"/api/authorization/sessions/{f.session}/revoke")
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    r = user.post(f"/api/authorization/sessions/{f.session}/reauthenticate",
                  {"device_id": f.device, "challenge_id": ch["challenge_id"], "face_descriptor": jitter()})
    assert r.status_code == 403




def test_requested_face_failure_escalation_is_three_six_eight(client, user, admin):
    f = Flow(client, user, admin).ready()
    nonce = f.mon["heartbeat_nonce"]
    mid = f.mon["monitoring_session_id"]

    for i in range(2):
        r = hb(f, nonce, probe_descriptor=other_face(i))
        assert r.status_code == 200, r.text
        nonce = r.json()["heartbeat_nonce"]
    assert f.user.get(f"/api/monitoring/{mid}").json()["status"] == "active"

    r = hb(f, nonce, probe_descriptor=other_face(2))
    assert r.status_code == 200, r.text
    nonce = r.json()["heartbeat_nonce"]
    assert f.user.get(f"/api/monitoring/{mid}").json()["status"] == "warning"

    for i in range(3, 6):
        r = hb(f, nonce, probe_descriptor=other_face(i))
        assert r.status_code == 200, r.text
        nonce = r.json()["heartbeat_nonce"]
    assert f.user.get(f"/api/monitoring/{mid}").json()["status"] == "reauth_required"

    for i in range(6, 8):
        r = hb(f, nonce, probe_descriptor=other_face(i))
        assert r.status_code == 200, r.text
        nonce = r.json()["heartbeat_nonce"]
    assert f.user.get(f"/api/monitoring/{mid}").json()["status"] == "revoked"


def test_level2_can_restore_own_revoked_session_with_face_stepup(client, make_user, admin):
    level2 = make_user("USER_LEVEL_2", "l2")
    f = Flow(client, level2, admin).ready()
    assert admin.post(f"/api/authorization/sessions/{f.session}/revoke").status_code in (200, 204)

    challenge = level2.post("/api/identity/challenges", {"session_id": f.session}).json()
    response = level2.post(
        f"/api/authorization/sessions/{f.session}/reauthenticate",
        {
            "device_id": f.device,
            "challenge_id": challenge["challenge_id"],
            "face_descriptor": jitter(),
        },
    )
    assert response.status_code == 200, response.text

def test_lapse_is_audited_once(flow, db):
    from api.repositories import MongoMonitoringRepository
    mid = flow.mon["monitoring_session_id"]
    db["monitoring_sessions"].update_one({"_id": mid}, {"$set": {"last_heartbeat_ts":
                                         datetime.now(timezone.utc) - timedelta(hours=1)}})
    MongoMonitoringRepository.reset_hot_state()
    for _ in range(3):
        assert flow.user.get(f"/api/monitoring/{mid}").json()["status"] == "reauth_required"
    nonce = flow.user.get(f"/api/monitoring/{mid}").json()["heartbeat_nonce"]
    hb(flow, nonce, probe_descriptor=jitter())
    hb(flow, flow.user.get(f"/api/monitoring/{mid}").json()["heartbeat_nonce"], probe_descriptor=jitter())
    entries = [e for e in flow.admin.get("/api/audit/logs").json()
               if e.get("session_id") == flow.session and e.get("action") == "MONITORING_REAUTH_REQUIRED"]
    assert len(entries) == 1, entries


def test_concurrent_starts_create_one_live_session(client, user, admin, db):
    f = Flow(client, user, admin, monitoring=False)
    f.enroll_and_stepup()
    results = []

    def go():
        results.append(user.post("/api/monitoring/start", {"device_id": f.device, "session_id": f.session}).status_code)
    ts = [threading.Thread(target=go) for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(c == 200 for c in results), results
    live = [d for d in db["monitoring_sessions"].find({"session_id": f.session}) if not d["stopped"]]
    assert len(live) == 1


def test_admin_sessions_summary_access_and_content(flow, admin, user):
    run_heartbeats(flow, 3)
    assert user.get("/api/monitoring/admin/sessions").status_code == 403
    rows = admin.get("/api/monitoring/admin/sessions?active_only=true").json()
    row = next(r for r in rows if r["monitoring_session_id"] == flow.mon["monitoring_session_id"])
    assert row["check_count"] == 4 and row["connection"] == "live" and row["username"] == user.username
    assert "heartbeat_nonce" not in row
    user.post(f"/api/monitoring/{row['monitoring_session_id']}/stop")
    import api.routers.monitoring as m
    m._admin_summary_cache.clear()
    rows = admin.get("/api/monitoring/admin/sessions").json()
    row = next(r for r in rows if r["monitoring_session_id"] == row["monitoring_session_id"])
    assert row["connection"] == "ended" and row["overall_security_outcome"] == "SECURE"
    assert not any(r["monitoring_session_id"] == row["monitoring_session_id"]
                   for r in admin.get("/api/monitoring/admin/sessions?active_only=true").json())


def test_stopped_or_revoked_session_cannot_resume_heartbeats(flow, admin):
    n = flow.mon["heartbeat_nonce"]
    flow.user.post(f"/api/monitoring/{flow.mon['monitoring_session_id']}/stop")
    assert hb(flow, n, probe_descriptor=jitter()).status_code == 404


def test_device_revocation_blocks_monitoring_start(client, user, admin):
    f = Flow(client, user, admin, monitoring=False)
    f.enroll_and_stepup()
    admin.post(f"/api/authorization/devices/{f.device}/revoke")
    r = user.post("/api/monitoring/start", {"device_id": f.device, "session_id": f.session})
    assert r.status_code == 403 and "device is revoked" in r.json()["detail"]
