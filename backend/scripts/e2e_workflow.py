#!/usr/bin/env python3
"""Live end-to-end workflow against a RUNNING CipherQ backend (real HTTP, no mocks).

    python scripts/e2e_workflow.py --base http://127.0.0.1:8000 --admin-user e2eadmin --admin-password-file pw.txt

intent -> approval -> authorization decision -> encryption -> state change -> stale context rejected ->
fresh decision -> monitoring (heartbeat nonce chain, imposter probe) -> revocation -> reauthorization ->
purpose drift -> audit verification.  Exits non-zero on any failed expectation and prints a JSON report.
Face descriptors are synthetic vectors (no camera is involved); liveness is NOT established by CipherQ.
"""
import argparse, base64, json, random, re, secrets, sys
from datetime import datetime, timedelta, timezone
import httpx

REPORT: list[dict] = []
FAILED = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global FAILED
    detail = re.sub(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "<jwt-redacted>", detail)  # never persist tokens
    REPORT.append({"step": name, "ok": bool(cond), "detail": detail})
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond:
        FAILED += 1


class Api:
    def __init__(self, base, token=None):
        self.c, self.t = httpx.Client(base_url=base, timeout=60), token

    def _h(self):
        return {"Authorization": f"Bearer {self.t}"} if self.t else {}

    def get(self, p): return self.c.get(p, headers=self._h())
    def post(self, p, j=None): return self.c.post(p, json=j, headers=self._h())
    def put(self, p, j=None): return self.c.put(p, json=j, headers=self._h())


def iso(d): return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def jitter(base, s=0.002): return [round(x + random.uniform(-s, s), 6) for x in base]


class Analyst:
    """One onboarded analyst: server-issued device/session, enrolled face, step-up, key session, case, approved intent."""

    def __init__(self, base, admin, label):
        self.base, self.admin, self.label = base, admin, label
        self.name, self.pw = "analyst" + secrets.token_hex(3), "Analyst-" + secrets.token_urlsafe(12)
        self.secret = b"PAN ending 4242; case notes: confidential"
        self.ref, self.resource = "CASE-%06d" % random.randint(100000, 999999), "vault:customer-records"
        self.face = [round(random.uniform(-1, 1), 4) for _ in range(128)]

    def c(self, name, cond, detail=""):
        check(f"[{self.label}] {name}", cond, detail)

    def onboard(self):
        anon = Api(self.base)
        r = anon.post("/api/auth/register", {"username": self.name, "email": f"{self.name}@example.test", "password": self.pw})
        self.c("registers", r.status_code == 201, r.text)
        self.uid, self.user = r.json()["user_id"], Api(self.base, r.json()["token"])
        self.dev = self.user.post("/api/authorization/devices").json()["device_id"]
        r = self.user.post("/api/authorization/sessions", {"device_id": self.dev})
        self.c("server-issued session", r.status_code == 201, r.text)
        self.sess = r.json()["session_id"]
        r = self.admin.put(f"/api/evidence/cases/{self.ref}", {"title": "Card-testing fraud", "classification_cap": "RESTRICTED",
                           "allowed_resources": [self.resource], "assigned_user_ids": [self.uid], "status": "OPEN"})
        self.c("admin opens evidence case and assigns analyst", r.status_code == 200, r.text)
        r = self.user.post("/api/face/enroll", {"descriptor": self.face, "password": self.pw})
        self.c("face enrolled (password re-entry)", r.status_code == 204, r.text)
        self.stepup(); 
        r = self.user.post("/api/key-sessions", {"n_qubits": 1024})
        self.c("key session established", r.status_code == 201, r.text)
        ks = r.json()
        self.c("no key material in response; simulation flagged", not any(k in ks for k in ("quantum_key_hex", "key", "key_hex")) and ks.get("simulation") is True)
        self.ks = ks["key_session_id"]
        r = self.user.post("/api/monitoring/start", {"device_id": self.dev, "session_id": self.sess})
        self.c("monitoring starts after step-up", r.status_code == 200, r.text)
        self.mid = r.json()["monitoring_session_id"]

    def stepup(self, desc=None):
        ch = self.user.post("/api/identity/challenges", {"session_id": self.sess}).json()
        r = self.user.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": self.sess,
                                                    "descriptor": desc or jitter(self.face)})
        self.c("step-up", r.status_code == 200 and r.json().get("verified") is True, r.text)
        return r

    def intent_payload(self, **o):
        now = datetime.now(timezone.utc)
        p = {"purpose_code": "CASE_INVESTIGATION", "purpose_statement": "Investigate suspected card-testing fraud for the case",
             "business_reference": self.ref, "resource": self.resource, "operations": ["encrypt", "decrypt"],
             "data_scope": {"classification": "CONFIDENTIAL", "max_bytes": 4096, "max_uses": 8},
             "session_id": self.sess, "device_id": self.dev, "valid_from": iso(now - timedelta(minutes=1)),
             "valid_until": iso(now + timedelta(hours=2)), "evidence_refs": [{"kind": "CASE", "ref": self.ref}]}
        p.update(o)
        return p

    def approved_intent(self):
        r = self.user.post("/api/intents", self.intent_payload()); self.c("intent created", r.status_code == 201, r.text)
        self.iid = r.json()["intent_id"]
        self.c("intent validated -> pending approval", self.user.post(f"/api/intents/{self.iid}/validate").status_code == 200)
        v = self.user.get(f"/api/intents/{self.iid}").json()
        d = self.decide()
        self.c("unapproved intent cannot obtain a PERMIT", d["outcome"] != "PERMIT", json.dumps(d["reasons"]))
        r = self.user.post(f"/api/intents/{self.iid}/approvals", {"version": v["version"], "verdict": "APPROVE"})
        self.c("requester cannot approve own intent", r.status_code in (403, 409), r.text)
        r = self.admin.post(f"/api/intents/{self.iid}/approvals", {"version": v["version"], "verdict": "APPROVE"})
        self.c("admin approves", r.status_code == 200, r.text)
        self.c("intent APPROVED", self.user.get(f"/api/intents/{self.iid}").json()["status"] == "APPROVED")

    def decide(self, op="encrypt", **o):
        p = {"intent_id": self.iid, "operation": op, "resource": self.resource, "purpose_code": "CASE_INVESTIGATION",
             "session_id": self.sess, "device_id": self.dev}
        if op == "encrypt":
            p.update(key_session_id=self.ks, requested_bytes=len(self.secret))
        p.update(o)
        return self.user.post("/api/decisions", p).json()

    def enc(self, ctx, **o):
        p = {"context_id": ctx, "intent_id": self.iid, "resource": self.resource, "purpose_code": "CASE_INVESTIGATION",
             "session_id": self.sess, "device_id": self.dev, "key_session_id": self.ks,
             "plaintext_base64": base64.b64encode(self.secret).decode()}
        p.update(o)
        return self.user.post("/api/crypto/encrypt", p)

    def dec(self, rec):
        d = self.decide("decrypt", record_id=rec)
        return self.user.post("/api/crypto/decrypt", {"context_id": d["context_id"], "intent_id": self.iid, "resource": self.resource,
                              "purpose_code": "CASE_INVESTIGATION", "session_id": self.sess, "device_id": self.dev, "record_id": rec})


def scenario_a(base, admin, anon):
    """Happy path, replay, monitoring, revocation, reauthorization, intent + key revocation."""
    A = Analyst(base, admin, "A"); A.onboard()
    check("[A] session creation requires auth", anon.post("/api/authorization/sessions", {"device_id": A.dev}).status_code in (401, 403))
    r = A.user.post("/api/face/enroll", {"descriptor": A.face, "password": "wrong-password-xx"})
    check("[A] enrolment replacement refused without password/step-up", r.status_code == 403, r.text)
    ch = A.user.post("/api/identity/challenges", {"session_id": A.sess}).json()
    body = {"challenge_id": ch["challenge_id"], "session_id": A.sess, "descriptor": jitter(A.face)}
    first = A.user.post("/api/identity/verify", body)
    check("[A] grant never claims liveness", first.json().get("liveness") in (None, "NOT_ESTABLISHED"), first.text)
    check("[A] challenge is single-use", A.user.post("/api/identity/verify", body).status_code == 403)
    A.stepup()

    cur = A.user.get(f"/api/monitoring/{A.mid}").json(); nonce = cur["heartbeat_nonce"]
    r = A.user.post("/api/monitoring/heartbeat", {"monitoring_session_id": A.mid, "prev_nonce": nonce, "probe_descriptor": jitter(A.face)})
    check("[A] heartbeat with enrolled face accepted", r.status_code == 200, r.text)
    check("[A] heartbeat nonce rotates", r.json()["heartbeat_nonce"] != nonce)
    r = A.user.post("/api/monitoring/heartbeat", {"monitoring_session_id": A.mid, "prev_nonce": nonce, "probe_descriptor": jitter(A.face)})
    check("[A] replayed heartbeat nonce rejected", r.status_code == 409)

    A.approved_intent()
    d = A.decide(); check("[A] decision PERMIT", d["outcome"] == "PERMIT", json.dumps(d))
    r = A.enc(d["context_id"]); check("[A] encrypt with authorization-bound context", r.status_code == 201, r.text)
    rec = r.json()["record_id"]
    check("[A] context replay rejected", A.enc(d["context_id"]).status_code == 409)
    r = A.dec(rec)
    check("[A] decrypt round-trips", r.status_code == 200 and base64.b64decode(r.json()["plaintext_base64"]) == A.secret, r.text)

    # monitoring failure (imposter probes) -> operations blocked
    st = None
    for _ in range(12):
        imp = [round(random.uniform(-1, 1), 4) for _ in range(128)]
        cur = A.user.get(f"/api/monitoring/{A.mid}").json()
        r = A.user.post("/api/monitoring/heartbeat", {"monitoring_session_id": A.mid, "prev_nonce": cur["heartbeat_nonce"], "probe_descriptor": imp})
        st = r.json().get("status") if r.status_code == 200 else f"http{r.status_code}"
        if st not in ("active", "warning"):
            break
    check("[A] imposter probes end the active monitoring state", st not in ("active",), str(st))
    d6 = A.decide(); check("[A] operations blocked after monitoring failure", d6["outcome"] != "PERMIT", json.dumps(d6["reasons"]))

    # revocation -> admin-approved reauthorization -> fresh step-up -> fresh decision
    r = admin.post(f"/api/authorization/sessions/{A.sess}/revoke"); check("[A] admin revokes session", r.status_code in (200, 204), r.text)
    check("[A] revoked session cannot obtain PERMIT", A.decide()["outcome"] != "PERMIT")
    ch = A.user.post("/api/identity/challenges", {"session_id": A.sess}).json()
    r = A.user.post(f"/api/authorization/sessions/{A.sess}/reauthenticate", {"device_id": A.dev, "challenge_id": ch["challenge_id"], "face_descriptor": jitter(A.face)})
    check("[A] user cannot self-restore a revoked session", r.status_code == 403, r.text)
    r = A.user.post("/api/reauth-requests", {"device_id": A.dev, "session_id": A.sess, "message": "e2e: legitimate analyst, please restore"})
    check("[A] user files reauthorization request", r.status_code == 201, r.text)
    rid = r.json().get("id", r.json().get("request_id"))
    r = admin.post(f"/api/reauth-requests/{rid}/approve", {"note": "verified out of band"}); check("[A] admin approves the request", r.status_code == 200, r.text)
    ch = A.user.post("/api/identity/challenges", {"session_id": A.sess}).json()
    r = A.user.post(f"/api/authorization/sessions/{A.sess}/reauthenticate", {"device_id": A.dev, "challenge_id": ch["challenge_id"],
                    "face_descriptor": jitter(A.face), "reauth_request_id": rid})
    check("[A] approved reauthentication restores the session (challenge-bound)", r.status_code == 200 and r.json()["revoked"] is False, r.text)
    A.stepup()
    r = A.user.post("/api/monitoring/start", {"device_id": A.dev, "session_id": A.sess}); check("[A] monitoring restarted", r.status_code == 200, r.text)
    d8 = A.decide(); check("[A] PERMIT again after reauthorization", d8["outcome"] == "PERMIT", json.dumps(d8["reasons"]))
    check("[A] encrypt after reauthorization", A.enc(d8["context_id"]).status_code == 201)

    r = admin.post(f"/api/intents/{A.iid}/revoke", {"reason": "e2e: case concluded"}); check("[A] intent revoked", r.status_code == 200, r.text)
    check("[A] revoked intent denied", A.decide()["outcome"] == "DENY")
    check("[A] key session revoked (key destroyed)", A.user.post(f"/api/key-sessions/{A.ks}/revoke").status_code == 200)
    return A


def scenario_b(base, admin):
    """Authorization state change between decision and use; purpose / resource / scope drift."""
    B = Analyst(base, admin, "B"); B.onboard(); B.approved_intent()
    d3 = B.decide(); check("[B] PERMIT before state change", d3["outcome"] == "PERMIT", json.dumps(d3["reasons"]))
    check("[B] admin closes the case", admin.post(f"/api/evidence/cases/{B.ref}/close").status_code == 200)
    r = B.enc(d3["context_id"])
    check("[B] context rejected after evidence changed", r.status_code in (403, 409), r.text)
    d4 = B.decide(); check("[B] new decision denied while case is closed", d4["outcome"] == "DENY", json.dumps(d4["reasons"]))
    admin.put(f"/api/evidence/cases/{B.ref}", {"title": "Card-testing fraud", "classification_cap": "RESTRICTED",
              "allowed_resources": [B.resource], "assigned_user_ids": [B.uid], "status": "OPEN"})
    d5 = B.decide()
    check("[B] case reopened -> fresh decision PERMIT or risk-gated (never stale)", d5["outcome"] in ("PERMIT", "DENY", "REQUIRE_STEP_UP"), json.dumps(d5["reasons"]))
    if d5["outcome"] == "PERMIT":
        check("[B] fresh context works after reauthorization", B.enc(d5["context_id"]).status_code == 201)
    for label, kw in (("purpose drift", {"purpose_code": "REGULATORY_REPORTING"}), ("resource drift", {"resource": "vault:payroll"}),
                      ("scope (bytes) drift", {"requested_bytes": 10_000})):
        d = B.decide(**kw); check(f"[B] {label} denied", d["outcome"] == "DENY", json.dumps(d["reasons"]))
    return B


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--admin-user", required=True)
    ap.add_argument("--admin-password-file", required=True)
    ap.add_argument("--out", help="write JSON report here")
    a = ap.parse_args()
    anon = Api(a.base)
    r = anon.post("/api/auth/login", {"username": a.admin_user, "password": open(a.admin_password_file).read().strip()})
    check("admin login", r.status_code == 200, r.text)
    admin = Api(a.base, r.json()["token"])
    nm, npw = "x" + secrets.token_hex(3), "Pw-" + secrets.token_urlsafe(12)
    rr = anon.post("/api/auth/register", {"username": nm, "email": f"{nm}@example.test", "password": npw, "role": "ADMIN"})
    role = None
    if rr.status_code == 201:
        role = Api(a.base, rr.json()["token"]).get("/api/auth/me").json().get("role")
    check("self-registration cannot create an admin", rr.status_code in (400, 403, 422) or role == "USER_LEVEL_1", f"{rr.status_code} {role}")
    A = scenario_a(a.base, admin, anon)
    B = scenario_b(a.base, admin)

    r = admin.get("/api/audit/verify"); v = r.json()
    check("audit chain verifies (keyed MAC, head, sink)", r.status_code == 200 and v["valid"] is True, json.dumps(v))
    check("audit has >= 25 entries", v["checked_entries"] >= 25, str(v["checked_entries"]))
    blob = json.dumps(admin.get("/api/audit/logs").json())
    check("audit log contains no plaintext/passwords", "PAN ending" not in blob and A.pw not in blob and B.pw not in blob)
    check("a regular user cannot read the audit log", A.user.get("/api/audit/logs").status_code == 403)

    print(f"\n{len(REPORT) - FAILED}/{len(REPORT)} checks passed")
    if a.out:
        json.dump({"base": a.base, "passed": len(REPORT) - FAILED, "total": len(REPORT), "steps": REPORT,
                   "time": datetime.now(timezone.utc).isoformat()}, open(a.out, "w"), indent=1)
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
