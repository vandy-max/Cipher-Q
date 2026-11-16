"""Helper that drives the REAL API through the full authorization workflow (no mocks)."""
from __future__ import annotations

import base64
import random
import time
import uuid
from datetime import datetime, timedelta, timezone

from .conftest import PASSWORD

_rnd = random.Random(1234)
ENROLLED = [round(_rnd.uniform(-1, 1), 4) for _ in range(128)]


def jitter(base=None, scale=0.002):
    base = base or ENROLLED
    return [round(x + random.uniform(-scale, scale), 6) for x in base]


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Flow:
    """One user + one admin + one case + device/session/key-session. Methods are explicit steps."""

    def __init__(self, client, user, admin, classification="CONFIDENTIAL", resource="vault:customer-records",
                 max_bytes=4096, max_uses=3, stepup=True, monitoring=True, case_ref=None, ops=("encrypt", "decrypt")):
        self.c, self.user, self.admin = client, user, admin
        self.cls, self.resource, self.max_bytes, self.max_uses = classification, resource, max_bytes, max_uses
        self.ref = case_ref or "CASE-%06d" % random.randint(100000, 999999)
        self.ops = list(ops)
        self.purpose = "CASE_INVESTIGATION"
        self._setup(stepup, monitoring)

    # ---- environment
    def _setup(self, stepup, monitoring):
        u, a = self.user, self.admin
        r = a.put(f"/api/evidence/cases/{self.ref}", {"title": "Fraud investigation", "classification_cap": "RESTRICTED",
                  "allowed_resources": [self.resource], "assigned_user_ids": [u.id], "status": "OPEN"})
        assert r.status_code == 200, r.text
        self.device = u.post("/api/authorization/devices").json()["device_id"]
        r = u.post("/api/authorization/sessions", {"device_id": self.device})
        assert r.status_code == 201, r.text
        self.session = r.json()["session_id"]
        r = u.post("/api/key-sessions", {})
        assert r.status_code == 201, r.text
        self.ks = r.json()["key_session_id"]
        if stepup:
            self.enroll_and_stepup()
        if monitoring:
            r = u.post("/api/monitoring/start", {"device_id": self.device, "session_id": self.session})
            assert r.status_code == 200, r.text
            self.mon = r.json()

    def enroll_and_stepup(self):
        u = self.user
        if not u.get("/api/face/status").json()["enrolled"]:
            r = u.post("/api/face/enroll", {"descriptor": ENROLLED, "password": PASSWORD})
            assert r.status_code == 204, r.text
        return self.stepup()

    def stepup(self, descriptor=None):
        u = self.user
        chr_ = u.post("/api/identity/challenges", {"session_id": self.session})
        if chr_.status_code != 201:
            return chr_                      # e.g. 429 when the account is locked out
        ch = chr_.json()
        return u.post("/api/identity/verify", {"challenge_id": ch["challenge_id"], "session_id": self.session,
                                                "descriptor": descriptor or jitter()})

    # ---- intent
    def intent_payload(self, **over):
        now = datetime.now(timezone.utc)
        p = {"purpose_code": self.purpose, "purpose_statement": "Investigate suspected card-testing fraud for case",
             "business_reference": self.ref, "resource": self.resource, "operations": self.ops,
             "data_scope": {"classification": self.cls, "max_bytes": self.max_bytes, "max_uses": self.max_uses},
             "session_id": self.session, "device_id": self.device,
             "valid_from": iso(now - timedelta(minutes=1)), "valid_until": iso(now + timedelta(hours=2)),
             "evidence_refs": [{"kind": "CASE", "ref": self.ref}]}
        p.update(over)
        return p

    def create_intent(self, **over):
        r = self.user.post("/api/intents", self.intent_payload(**over))
        assert r.status_code == 201, r.text
        self.intent = r.json()
        self.intent_id = self.intent["intent_id"]
        return self.intent

    def validate(self):
        r = self.user.post(f"/api/intents/{self.intent_id}/validate")
        assert r.status_code == 200, r.text
        return r.json()

    def approve(self, version=None, approver=None):
        approver = approver or self.admin
        v = version or self.view()["version"]
        return approver.post(f"/api/intents/{self.intent_id}/approvals", {"version": v, "verdict": "APPROVE"})

    def view(self):
        return self.user.get(f"/api/intents/{self.intent_id}").json()

    def ready(self):
        """create -> validate -> approve."""
        self.create_intent()
        self.validate()
        r = self.approve()
        assert r.status_code == 200, r.text
        assert self.view()["status"] == "APPROVED", self.view()
        return self

    # ---- decision + operation
    def decide(self, actor=None, **over):
        actor = actor or self.user
        p = {"intent_id": self.intent_id, "operation": "encrypt", "resource": self.resource,
             "purpose_code": self.purpose, "session_id": self.session, "device_id": self.device,
             "key_session_id": self.ks, "requested_bytes": 16}
        p.update(over)
        p = {k: v for k, v in p.items() if v is not None}
        return actor.post("/api/decisions", p)

    def encrypt(self, plaintext=b"top-secret-data", ctx=None, actor=None, **over):
        actor = actor or self.user
        if ctx is None:
            d = self.decide(actor, requested_bytes=len(plaintext)).json()
            assert d["outcome"] == "PERMIT", d
            ctx = d["context_id"]
        p = {"context_id": ctx, "intent_id": self.intent_id, "resource": self.resource,
             "purpose_code": self.purpose, "session_id": self.session, "device_id": self.device,
             "key_session_id": self.ks, "plaintext_base64": base64.b64encode(plaintext).decode()}
        p.update(over)
        return actor.post("/api/crypto/encrypt", p)

    def decrypt(self, record_id, ctx=None, actor=None, **over):
        actor = actor or self.user
        if ctx is None:
            d = self.decide(actor, operation="decrypt", record_id=record_id, key_session_id=None,
                            requested_bytes=None).json()
            assert d["outcome"] == "PERMIT", d
            ctx = d["context_id"]
        p = {"context_id": ctx, "intent_id": self.intent_id, "resource": self.resource,
             "purpose_code": self.purpose, "session_id": self.session, "device_id": self.device, "record_id": record_id}
        p.update(over)
        return actor.post("/api/crypto/decrypt", p)

    def reasons(self, resp):
        return {r["code"] for r in resp.json().get("reasons", [])}


def other_face(seed=0):
    """A non-degenerate descriptor that is far from ENROLLED (a different 'person')."""
    r = random.Random(900 + seed)
    return [round(r.uniform(-1, 1), 4) for _ in range(128)]
