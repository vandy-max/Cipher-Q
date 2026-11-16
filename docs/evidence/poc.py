"""Baseline runtime verification against the ORIGINAL v17 code (copy in baseline_run/).
Real app (FastAPI TestClient) + real Mongo-wire server (FerretDB). Results -> baseline_results.json"""
import os, sys, json, time, uuid, threading, base64
os.environ.update(MONGODB_URI="mongodb://127.0.0.1:27017", MONGODB_DATABASE="baseline_poc", JWT_SECRET="baseline-test-secret")
sys.path.insert(0, "/home/claude/work/baseline_run/backend"); os.chdir("/home/claude/work/baseline_run/backend")
import pymongo
pymongo.MongoClient("mongodb://127.0.0.1:27017").drop_database("baseline_poc")
from fastapi.testclient import TestClient
from api.main import app
from database.session import db
from datetime import datetime, timezone
from audit.service import AuditLogService
from api.repositories import MongoAuditLogRepository
import jwt as pyjwt
c = TestClient(app, raise_server_exceptions=False)
R = {}
def rec(k, v): R[k] = v; print(k, "=>", json.dumps(v, default=str)[:300])
rec("B01_health", c.get("/api/health").json())
h = c.get("/api/health"); rec("B02_security_headers", {k: h.headers.get(k) for k in ["strict-transport-security","x-content-type-options","x-frame-options","content-security-policy"]})
rec("B03_docs_unauth", c.get("/docs").status_code)
def reg(u, role="USER_LEVEL_1"):
    return c.post("/api/auth/register", json={"username":u,"email":u+"@x.io","password":"Passw0rd!x","role":role})
H = lambda r: {"Authorization": "Bearer " + r.json()["token"]}
a = reg("alice"); b = reg("bob"); l2 = reg("lead", "USER_LEVEL_2")
rec("B04_register_status_and_roles", [a.status_code, b.status_code, l2.status_code, l2.json().get("role")])
rec("B05_jwt_claims", sorted(pyjwt.decode(a.json()["token"], options={"verify_signature": False})))
db.users.update_one({"username":"lead"},{"$set":{"role":"ADMIN"}})
adm = c.post("/api/auth/login", json={"username":"lead","password":"Passw0rd!x"})
rec("B06a_admin_list_users", c.get("/api/users", headers=H(adm)).status_code)
db.users.update_one({"username":"lead"},{"$set":{"role":"USER_LEVEL_1"}})
rec("B06b_downgraded_admin_old_token_still_lists_users", c.get("/api/users", headers=H(adm)).status_code)
db.users.delete_one({"username":"lead"})
rec("B06c_deleted_user_old_token_still_valid", c.get("/api/face/status", headers=H(adm)).status_code)
tok = a.json()["token"]; bad = tok[:-3] + ("AAA" if tok[-3:] != "AAA" else "BBB")
rec("B07a_tampered_token", c.get("/api/face/status", headers={"Authorization":"Bearer "+bad}).status_code)
none_tok = pyjwt.encode({"sub":"1","username":"alice","role":"ADMIN","exp":int(time.time())+999}, key=None, algorithm="none")
rec("B07b_alg_none", c.get("/api/users", headers={"Authorization":"Bearer "+none_tok}).status_code)
codes = [c.post("/api/auth/login", json={"username":"alice","password":"wrong%d"%i}).status_code for i in range(40)]
rec("B08_bruteforce_40_wrong_logins_status_set", sorted(set(codes)))
q = c.post("/api/quantum/generate-key", headers=H(a), json={"n_qubits":256}).json()
rec("B09a_quantum_key_in_response", {"has_quantum_key_hex": bool(q.get("quantum_key_hex")), "len": len(q.get("quantum_key_hex",""))})
t=time.time(); r=c.post("/api/quantum/generate-key", headers=H(a), json={"n_qubits":4000}); rec("B09b_4000_qubits", {"status":r.status_code,"seconds":round(time.time()-t,1)})
rec("B09c_prob_2", c.post("/api/quantum/generate-key", headers=H(a), json={"eavesdrop_prob":2}).status_code)
desc = [0.01*i for i in range(128)]
rec("B10a_enroll", c.post("/api/face/enroll", headers=H(a), json={"descriptor":desc}).status_code); c.post("/api/face/enroll", headers=H(b), json={"descriptor":desc})
probe=[x+0.01 for x in desc]; rec("B10b_verify_returns_distance", c.post("/api/face/verify", headers=H(a), json={"descriptor":probe}).json())
r = c.post("/api/face/verify", headers={**H(a),"Content-Type":"application/json"}, content='{"descriptor":[' + ",".join(["NaN"]*128)+']}')
rec("B10c_nan_descriptor", {"status": r.status_code, "body": r.text[:60]})
cc = reg("carol"); r1 = c.post("/api/face/enroll", headers=H(cc), json={"descriptor":desc}); r2 = c.post("/api/face/enroll", headers=H(cc), json={"descriptor":[5.0]*128})
rec("B10d_enroll_replace_without_reauth", [r1.status_code, r2.status_code])
rec("B11_1MB_username", reg("u"*1_000_000).status_code)
sid="sess-"+uuid.uuid4().hex[:8]; did="dev-"+uuid.uuid4().hex[:8]
rec("B12a_refresh_creates_session", c.post(f"/api/authorization/sessions/{sid}/refresh", headers=H(b), json={"device_id":did}).status_code)
ms = c.post("/api/monitoring/start", headers=H(b), json={"device_id":did,"session_id":sid,"face_confidence":0.99}); rec("B12b_monitor_start_self_asserted_conf", ms.status_code)
mid = ms.json().get("monitoring_session_id")
hb = c.post("/api/monitoring/heartbeat", headers=H(b), json={"monitoring_session_id":mid,"face_present":True,"face_match_confidence":0.99,"liveness":True}); rec("B12c_forged_heartbeat", {"code":hb.status_code,"status":hb.json().get("status"),"liveness":hb.json().get("liveness")})
now = datetime.now(timezone.utc)
def cid(**kw):
    d = dict(sender="alice", receiver="analyst", purpose="investigate case 42", resource="case-42", operation="encrypt", device_id=did, session_id=sid, valid_from=now.isoformat(), valid_until=now.replace(year=now.year+1).isoformat()); d.update(kw); return d
ci = c.post("/api/intent", headers=H(b), json={"cid":cid(sender="SOMEONE-ELSE")}); rec("B13_intent_sender_spoof_accepted", {"code":ci.status_code, "state": ci.json().get("lifecycle_state")})
l2b = reg("lead2","USER_LEVEL_2"); iid = ci.json().get("intent_id")
ap = c.post(f"/api/intent/{iid}/transition", headers=H(l2b), json={"target_state":"approved","reason":"ok"}); rec("B14a_approve_by_self_registered_L2", {"code":ap.status_code,"state":ap.json().get("lifecycle_state")})
key = q["quantum_key_hex"]
enc = c.post("/api/encrypt", headers=H(b), json={"intent_id":iid,"cid":cid(sender="SOMEONE-ELSE"),"plaintext_base64":base64.b64encode(b"secret-data").decode(),"quantum_key_hex":key,"face_descriptor":desc})
rec("B14b_encrypt", {"code":enc.status_code})
if enc.status_code==201:
    dec = c.post("/api/decrypt", headers=H(b), json={"record_id":enc.json()["record_id"],"cid":cid(sender="SOMEONE-ELSE"),"quantum_key_hex":key,"face_descriptor":desc})
    rec("B14c_decrypt", {"code":dec.status_code, "plain": base64.b64decode(dec.json().get("plaintext_base64","")).decode() if dec.status_code==200 else dec.text[:100]})
svc = AuditLogService(MongoAuditLogRepository(db)); raw = db._raw["audit_logs"]
pre = svc.verify_integrity().valid; last = raw.find_one(sort=[("_id",-1)]); raw.delete_one({"_id": last["_id"]})
rec("B18_audit_tail_truncation", {"chain_valid_before": pre, "verify_valid_after_deleting_last_entry": AuditLogService(MongoAuditLogRepository(db)).verify_integrity().valid})
import io, contextlib
errs = io.StringIO()
with contextlib.redirect_stderr(errs):
    ths=[threading.Thread(target=lambda i=i: svc.record("TEST_EVENT","success",user_id=i)) for i in range(16)]
    [t.start() for t in ths]; [t.join() for t in ths]
v = AuditLogService(MongoAuditLogRepository(db)).verify_integrity(); rec("B17_audit_concurrent_writes", {"valid":v.valid,"reason":v.reason, "lost_writes_duplicate_key_errors": errs.getvalue().count("DuplicateKeyError")})
rec("B19_audit_logs_as_plain_user", c.get("/api/audit/logs", headers=H(a)).status_code)
json.dump(R, open("/home/claude/work/evidence/baseline_results.json","w"), indent=2, default=str)
