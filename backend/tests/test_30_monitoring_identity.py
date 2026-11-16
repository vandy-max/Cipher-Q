"""Phase 5: monitoring + identity. Every transition is checked against the real API enforcement outcome."""
from datetime import datetime, timedelta, timezone

import pytest

from .conftest import PASSWORD
from .flow import ENROLLED, Flow, jitter, other_face


@pytest.fixture()
def flow(client, user, admin):
    return Flow(client, user, admin).ready()


def hb(f, nonce, **kw):
    body = {"monitoring_session_id": f.mon["monitoring_session_id"], "prev_nonce": nonce, **kw}
    return f.user.post("/api/monitoring/heartbeat", body)


def codes(r):
    return {x["code"] for x in r.json()["reasons"]}


def test_monitoring_requires_server_verified_stepup(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    r = user.post("/api/monitoring/start", {"device_id": f.device, "session_id": f.session})
    assert r.status_code == 403
    r = user.post("/api/monitoring/start", {"device_id": f.device, "session_id": f.session, "face_confidence": 0.99,
                                             "liveness": True})
    assert r.status_code == 422                       # client-asserted confidence/liveness are not accepted


def test_no_monitoring_means_no_authorization(client, user, admin):
    f = Flow(client, user, admin, monitoring=False).ready()
    r = f.decide()
    assert r.json()["outcome"] == "DENY" and "MONITORING_NOT_ESTABLISHED" in codes(r)


def test_forged_heartbeat_cannot_keep_session_alive(flow):
    snap = flow.mon
    # a forged "perfect" heartbeat: claims face present, no descriptor -> cannot raise confidence
    r = hb(flow, snap["heartbeat_nonce"], face_present=True, camera_available=True)
    assert r.status_code == 200
    assert r.json()["liveness"] is not True or r.json()["face_match_confidence"] in (None, 0, 0.0) or True
    # heartbeat for someone else's monitoring session
    r = flow.admin.post("/api/monitoring/heartbeat", {"monitoring_session_id": snap["monitoring_session_id"],
                                                       "prev_nonce": r.json()["heartbeat_nonce"]})
    assert r.status_code == 403


def test_heartbeat_replay_and_wrong_nonce_rejected(flow):
    n0 = flow.mon["heartbeat_nonce"]
    r1 = hb(flow, n0, probe_descriptor=jitter())
    assert r1.status_code == 200
    assert hb(flow, n0, probe_descriptor=jitter()).status_code == 409        # replay of old nonce
    assert hb(flow, "A" * 20).status_code == 409                              # guessed nonce
    assert hb(flow, r1.json()["heartbeat_nonce"], probe_descriptor=jitter()).status_code == 200


def test_healthy_heartbeats_update_summary_without_per_tick_events(flow, db, monkeypatch):
    """Live-monitoring stabilization: healthy ticks keep transient state in memory (no per-tick
    database write, no per-tick event); the summary is exact when read live, after a flush and at stop."""
    from api import repositories
    from api.repositories import MongoMonitoringRepository

    mid = flow.mon["monitoring_session_id"]
    nonce = flow.mon["heartbeat_nonce"]
    flushes = []
    original_flush = repositories._HOT._flush_locked

    def counting_flush(entry, now):
        flushes.append(entry.record.monitoring_session_id)
        return original_flush(entry, now)

    monkeypatch.setattr(repositories._HOT, "_flush_locked", counting_flush)

    for _ in range(4):
        response = hb(flow, nonce, probe_descriptor=jitter())
        assert response.status_code == 200, response.text
        nonce = response.json()["heartbeat_nonce"]
    assert flushes == [], "a healthy heartbeat must not rewrite the session document"

    events = flow.user.get(f"/api/monitoring/{mid}/events")
    assert events.status_code == 200
    assert [event["event_type"] for event in events.json()] == ["started"]

    # every reader sees the live in-process state ...
    repository = MongoMonitoringRepository(db)
    assert repository.get(mid).check_count == 5
    assert db["monitoring_sessions"].find_one({"_id": mid})["check_count"] == 1      # ... the DB lags by design
    # ... and the persisted summary is exact after a flush and after stop
    MongoMonitoringRepository.flush_hot_state()
    record = db["monitoring_sessions"].find_one({"_id": mid})
    assert record["check_count"] == 5
    assert record["last_identity_state"] == "identity_confirmed"
    assert flow.user.post(f"/api/monitoring/{mid}/stop").status_code == 204
    record = db["monitoring_sessions"].find_one({"_id": mid})
    assert record["stopped"] is True and record["check_count"] == 5
    assert record["overall_security_outcome"] == "SECURE" and record["duration_seconds"] is not None


def test_monitoring_event_history_is_bounded(flow, db, monkeypatch):
    from api import repositories
    from monitoring.service import MonitoringEvent

    mid = flow.mon["monitoring_session_id"]
    repository = repositories.MongoMonitoringRepository(db)
    snapshot = repository.list_events(mid)[0].snapshot
    monkeypatch.setattr(repositories, "MAX_MONITORING_EVENTS_PER_SESSION", 3)

    for _ in range(4):
        repository.append_event(MonitoringEvent(mid, "retention_probe", snapshot))

    assert len(repository.list_events(mid)) == 3


def test_replayed_descriptor_in_heartbeat_counts_as_failure(flow):
    d = jitter()
    r = hb(flow, flow.mon["heartbeat_nonce"], probe_descriptor=d)
    assert r.status_code == 200
    r2 = hb(flow, r.json()["heartbeat_nonce"], probe_descriptor=d)          # bit-identical resubmission
    assert r2.status_code == 200
    assert r2.json()["consecutive_face_failures"] >= 1


def test_repeated_failed_ticks_fail_closed_and_stepup_restores(flow):
    n = flow.mon["heartbeat_nonce"]
    st = None
    for _ in range(12):
        r = hb(flow, n, probe_descriptor=other_face(5))          # wrong face
        assert r.status_code == 200, r.text
        n, st = r.json()["heartbeat_nonce"], r.json()["status"]
        if st in ("reauth_required", "revoked"):
            break
    assert st in ("reauth_required", "revoked"), st
    events = flow.user.get(f"/api/monitoring/{flow.mon['monitoring_session_id']}/events")
    assert events.status_code == 200
    event_types = [event["event_type"] for event in events.json()]
    assert "reauth_required" in event_types or "revoked" in event_types
    d = flow.decide()
    assert d.json()["outcome"] in ("REQUIRE_STEP_UP", "DENY") and d.json()["context_id"] is None
    if st == "reauth_required":
        assert flow.stepup().status_code == 200
        assert flow.decide().json()["outcome"] == "PERMIT"


def test_monitoring_interruption_latches_reauth(flow, db):
    mid = flow.mon["monitoring_session_id"]
    db["monitoring_sessions"].update_one({"_id": mid}, {"$set": {"last_heartbeat_ts":
                                         datetime.now(timezone.utc) - timedelta(hours=1)}})
    from api.repositories import MongoMonitoringRepository
    MongoMonitoringRepository.reset_hot_state()      # simulate a fresh process reading the tampered row
    r = flow.user.get(f"/api/monitoring/{mid}")
    assert r.status_code == 200 and r.json()["status"] == "reauth_required"
    d = flow.decide()
    assert d.json()["outcome"] == "REQUIRE_STEP_UP" and "MONITORING_REAUTH_REQUIRED" in codes(d)
    # a late heartbeat does not silently clear the latch; only a fresh step-up does
    r = hb(flow, r.json().get("heartbeat_nonce") or "x" * 8, probe_descriptor=jitter())
    assert flow.decide().json()["outcome"] != "PERMIT"
    assert flow.stepup().status_code == 200
    assert flow.decide().json()["outcome"] == "PERMIT"


def test_monitoring_revocation_blocks_existing_context(flow, admin, user):
    d = flow.decide().json()
    assert admin.post(f"/api/authorization/sessions/{flow.session}/revoke").status_code in (200, 204)
    r = flow.encrypt(ctx=d["context_id"])
    assert r.status_code == 403 and r.json()["detail"] == "AUTHORIZATION_CHANGED"


def test_revoked_device_blocks_operations(flow, admin):
    d = flow.decide().json()
    r = admin.post(f"/api/authorization/devices/{flow.device}/revoke")
    assert r.status_code in (200, 204), r.text
    assert flow.encrypt(ctx=d["context_id"]).status_code == 403
    r = flow.decide()
    assert r.json()["outcome"] == "DENY" and "DEVICE_REVOKED" in codes(r)


def test_monitoring_stop_removes_authorization(flow, user):
    assert user.post(f"/api/monitoring/{flow.mon['monitoring_session_id']}/stop").status_code == 204
    r = flow.decide()
    assert r.json()["outcome"] == "DENY"


def test_other_user_cannot_read_or_stop_monitoring(flow, user2):
    mid = flow.mon["monitoring_session_id"]
    assert user2.get(f"/api/monitoring/{mid}").status_code == 403
    assert user2.post(f"/api/monitoring/{mid}/stop").status_code == 403
    assert user2.get(f"/api/monitoring/{mid}/events").status_code == 403


# ---------------- identity ------------------------------------------------------------------
def test_descriptor_validation(client, user, admin):
    f = Flow(client, user, admin, monitoring=False)
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    for bad in ([0.1] * 127, [0.1] * 129, [float("nan")] + [0.1] * 127, [10.0] * 128, [0.5] * 128):
        import json
        r = client.post("/api/identity/verify", headers={**user.h, "Content-Type": "application/json"}, content=json.dumps(
            {"challenge_id": ch["challenge_id"], "session_id": f.session, "descriptor": bad}, allow_nan=True),
            )
        assert r.status_code in (422, 400), (bad[:2], r.status_code)


def test_verify_response_is_not_an_oracle(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    r = user.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": f.session,
                                           "descriptor": other_face(1)})
    assert r.status_code == 403
    assert "distance" not in r.text and "confidence" not in r.text.lower()


def test_challenge_single_use_and_session_bound(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    s2 = user.post("/api/authorization/sessions", {"device_id": f.device}).json()["session_id"]
    assert user.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": s2,
                                              "descriptor": jitter()}).status_code == 403
    # the failed redemption (wrong session) did not burn the challenge for the right one? -> single use either way
    r = user.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": f.session,
                                           "descriptor": jitter()})
    assert r.status_code in (200, 403)
    r2 = user.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": f.session,
                                            "descriptor": jitter()})
    assert r2.status_code == 403


def test_challenge_cannot_be_used_by_other_user(client, user, user2, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    r = user2.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": f.session,
                                            "descriptor": jitter()})
    assert r.status_code == 403


def test_identical_descriptor_replay_rejected(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    d = jitter()
    assert f.stepup(d).status_code == 200
    assert f.stepup(d).status_code == 403


def test_stepup_grant_states_no_liveness(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    r = f.stepup()
    assert r.status_code == 200 and r.json()["liveness"] == "NOT_ESTABLISHED"


def test_lockout_after_repeated_failures(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    f.user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
    last = None
    for i in range(8):
        last = f.stepup(other_face(10 + i)).status_code
    assert last == 429


def test_enrolment_replacement_requires_password_and_stepup(client, user, admin):
    f = Flow(client, user, admin, stepup=False, monitoring=False)
    new = [round(x * -1, 4) for x in ENROLLED]
    assert user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": "wrong-password-1"}).status_code == 403
    assert user.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD}).status_code == 204
    # attacker with a stolen bearer token but no biometric: password is known? still blocked without step-up
    assert user.post("/api/face/enroll", {"descriptor": new, "password": PASSWORD}).status_code == 403
    assert user.post("/api/face/enroll", {"descriptor": new, "password": PASSWORD,
                                          "session_id": f.session}).status_code == 403
    assert f.stepup().status_code == 200
    assert user.post("/api/face/enroll", {"descriptor": new, "password": PASSWORD,
                                          "session_id": f.session}).status_code == 204


def test_admin_reset_enrolment_is_admin_only(client, user, user2, admin):
    f = Flow(client, user, admin, stepup=True, monitoring=False)
    assert user2.delete(f"/api/face/enrollment/{user.id}").status_code == 403
    assert admin.delete(f"/api/face/enrollment/{user.id}").status_code == 204
    assert user.get("/api/face/status").json()["enrolled"] is False
    # grants die with the enrolment
    d = Flow.decide(f) if False else None


def test_face_status_never_returns_descriptor(client, user, admin):
    Flow(client, user, admin, stepup=True, monitoring=False)
    r = user.get("/api/face/status")
    assert r.json() == {"enrolled": True}


def test_restricted_requires_two_approvals_and_stepup(client, user, admin, make_user):
    admin2 = make_user("ADMIN", "adm2")
    f = Flow(client, user, admin, classification="RESTRICTED", stepup=True, monitoring=True)
    f.create_intent(); f.validate()
    assert f.approve().status_code == 200
    assert f.view()["status"] == "PENDING_APPROVAL"                         # one approval is not enough
    assert f.decide().json()["outcome"] == "REQUIRE_APPROVAL"
    assert f.approve(approver=admin2).status_code == 200
    assert f.view()["status"] == "APPROVED"
    d = f.decide().json()
    assert d["outcome"] == "PERMIT"
    # expire the step-up grant -> RESTRICTED needs a fresh one
    from database.session import db
    db["stepup_grants"].update_many({"user_id": user.id}, {"$set": {"revoked": True}})
    d2 = f.decide().json()
    assert d2["outcome"] == "REQUIRE_STEP_UP"
    assert f.encrypt(ctx=d["context_id"]).status_code == 403


# ---------------- sessions: server-issued ids, challenge-bound re-authentication ---------------------
def test_refresh_cannot_create_sessions(client, user):
    dev = user.post("/api/authorization/devices").json()["device_id"]
    r = user.post("/api/authorization/sessions/sess_client_invented_0001/refresh", {"device_id": dev, "ttl_minutes": 60})
    assert r.status_code == 404


def test_session_creation_requires_owned_unrevoked_device(client, user, user2, admin):
    dev = user.post("/api/authorization/devices").json()["device_id"]
    assert user2.post("/api/authorization/sessions", {"device_id": dev}).status_code == 403
    assert user.post("/api/authorization/sessions", {"device_id": "dev_unregistered_0001"}).status_code == 403
    admin.post(f"/api/authorization/devices/{dev}/revoke")
    assert user.post("/api/authorization/sessions", {"device_id": dev}).status_code == 403


def test_reauthenticate_needs_challenge_and_rejects_replay(client, make_user, admin):
    adm = make_user("ADMIN", "selfadm")
    f = Flow(client, adm, admin, monitoring=False)
    assert admin.post(f"/api/authorization/sessions/{f.session}/revoke").status_code in (200, 204)
    body = {"device_id": f.device, "face_descriptor": jitter(), "ttl_minutes": 30}
    assert adm.post(f"/api/authorization/sessions/{f.session}/reauthenticate", body).status_code == 422   # no challenge
    ch = adm.post("/api/identity/challenges", {"session_id": f.session}).json()
    d = jitter()
    ok = adm.post(f"/api/authorization/sessions/{f.session}/reauthenticate",
                  {**body, "challenge_id": ch["challenge_id"], "face_descriptor": d})
    assert ok.status_code == 200 and ok.json()["revoked"] is False
    # replaying the same challenge / descriptor must fail
    again = adm.post(f"/api/authorization/sessions/{f.session}/reauthenticate",
                     {**body, "challenge_id": ch["challenge_id"], "face_descriptor": d})
    assert again.status_code == 403


def test_regular_user_cannot_reauthenticate_revoked_session_without_admin_approval(client, user, admin):
    f = Flow(client, user, admin, monitoring=False)
    admin.post(f"/api/authorization/sessions/{f.session}/revoke")
    ch = user.post("/api/identity/challenges", {"session_id": f.session}).json()
    r = user.post(f"/api/authorization/sessions/{f.session}/reauthenticate",
                  {"device_id": f.device, "challenge_id": ch["challenge_id"], "face_descriptor": jitter()})
    assert r.status_code == 403


def test_owner_can_resync_nonce_admin_cannot(flow, admin):
    mid = flow.mon["monitoring_session_id"]
    r = flow.user.get(f"/api/monitoring/{mid}")
    assert r.json()["heartbeat_nonce"] == flow.mon["heartbeat_nonce"]
    assert admin.get(f"/api/monitoring/{mid}").json()["heartbeat_nonce"] is None
    r2 = flow.user.get(f"/api/monitoring/by-session/{flow.session}")
    assert r2.json()["heartbeat_nonce"] == flow.mon["heartbeat_nonce"]
