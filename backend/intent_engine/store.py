"""Persistence for intents, versions, approvals, authorization decisions and crypto contexts.

All timestamps in these collections are integer epoch seconds (no naive/aware datetime
ambiguity after the BSON round trip).  Immutable records are MAC-sealed
(``security.integrity``); mutable status lives in separate documents so that "the record is
authentic" and "the record is still in force" are two independent questions.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from pymongo.collection import ReturnDocument

from database.session import get_next_id
from security import integrity
from security.canonical import canonical_bytes, digest
from security.keyring import Keyring

from .schema import IntentStatus

INTENTS = "intents2"
INTENT_VERSIONS = "intent_versions2"
APPROVALS = "intent_approvals"
DECISIONS = "authz_decisions"
DECISION_STATUS = "authz_decision_status"
CONTEXTS = "crypto_contexts"
EVIDENCE_VALIDATIONS = "intent_evidence_validations"

T_VERSION = "intent-version"
T_APPROVAL = "intent-approval"
T_DECISION = "authz-decision"


def now_ts() -> int:
    return int(time.time())


class EngineStore:
    def __init__(self, db, keyring: Keyring) -> None:
        self.db, self.kr = db, keyring

    # ------------------------------------------------------------- intents
    def create_intent(self, owner_user_id: int, body_fn) -> tuple[dict, dict]:
        """``body_fn(intent_id) -> version body`` (version 1)."""
        intent_id = get_next_id(INTENTS)
        body = body_fn(intent_id)
        ver = self._seal_version(body, author_id=owner_user_id, reason=body.pop("_reason", "initial creation"))
        self.db[INTENT_VERSIONS].insert_one(ver)
        ts = now_ts()
        head = {"_id": intent_id, "owner_user_id": owner_user_id, "status": IntentStatus.DRAFT.value,
                "current_version": 1, "uses": 0, "created_ts": ts, "updated_ts": ts}
        self.db[INTENTS].insert_one(head)
        return head, ver

    def _seal_version(self, body: dict, author_id: int, reason: str) -> dict:
        rec = {"_id": f"{body['intent_id']}:{body['version']}", "body": body,
               "body_hash": digest("CIPHERQ|INTENT-BODY|v2", body), "author_id": author_id,
               "reason": reason, "created_ts": now_ts()}
        return integrity.seal(self.kr, T_VERSION, rec)

    def add_version(self, intent_id: int, expected_version: int, body: dict, author_id: int, reason: str) -> dict | None:
        """Append version n+1 iff the head is still at ``expected_version`` (atomic claim of the number)."""
        claimed = self.db[INTENTS].find_one_and_update(
            {"_id": intent_id, "current_version": expected_version},
            {"$set": {"current_version": expected_version + 1, "status": IntentStatus.DRAFT.value,
                      "updated_ts": now_ts()}})
        if claimed is None:
            return None
        ver = self._seal_version(body, author_id=author_id, reason=reason)
        self.db[INTENT_VERSIONS].insert_one(ver)
        return ver

    def get_head(self, intent_id: int) -> dict | None:
        return self.db[INTENTS].find_one({"_id": intent_id})

    def list_heads(self, owner_user_id: int | None = None) -> list[dict]:
        q = {} if owner_user_id is None else {"owner_user_id": owner_user_id}
        return list(self.db[INTENTS].find(q).sort("_id", -1))

    def get_version(self, intent_id: int, version: int, verify: bool = True) -> dict | None:
        rec = self.db[INTENT_VERSIONS].find_one({"_id": f"{intent_id}:{version}"})
        if rec is None:
            return None
        if verify:
            integrity.require(self.kr, T_VERSION, rec)
        return rec

    def set_status(self, intent_id: int, from_statuses: set[str], to: IntentStatus) -> bool:
        res = self.db[INTENTS].update_one({"_id": intent_id, "status": {"$in": sorted(from_statuses)}},
                                          {"$set": {"status": to.value, "updated_ts": now_ts()}})
        return res.matched_count == 1

    def consume_use(self, intent_id: int, version: int, max_uses: int) -> dict | None:
        """Atomically take one use from an APPROVED intent at ``version``. Returns the head or None."""
        head = self.db[INTENTS].find_one_and_update(
            {"_id": intent_id, "status": IntentStatus.APPROVED.value, "current_version": version,
             "uses": {"$lt": max_uses}},
            {"$inc": {"uses": 1}, "$set": {"updated_ts": now_ts()}},
            return_document=ReturnDocument.AFTER)
        # return_document=True is truthy-equivalent to AFTER for our store; normalise below
        if head is not None and head["uses"] >= max_uses:
            self.db[INTENTS].update_one({"_id": intent_id, "status": IntentStatus.APPROVED.value},
                                        {"$set": {"status": IntentStatus.EXHAUSTED.value}})
        return head

    # ------------------------------------------------------------ approvals
    def add_approval(self, intent_id: int, version: int, approver_id: int, approver_role: str,
                     verdict: str, comment: str, policy_version: str) -> dict:
        rec = {"_id": get_next_id(APPROVALS), "intent_id": intent_id, "version": version,
               "approver_id": approver_id, "approver_role": approver_role, "verdict": verdict,
               "comment": comment, "policy_version": policy_version, "created_ts": now_ts()}
        rec = integrity.seal(self.kr, T_APPROVAL, rec)
        self.db[APPROVALS].insert_one(rec)
        return rec

    def approvals_for(self, intent_id: int, version: int) -> list[dict]:
        out = []
        for r in self.db[APPROVALS].find({"intent_id": intent_id, "version": version}).sort("_id", 1):
            if integrity.verify(self.kr, T_APPROVAL, r):       # a tampered approval simply does not count
                out.append(r)
        return out

    def record_evidence_validation(self, *, intent_id: int, version: int, body_hash: str,
                                   outcome: str, evidence_source: str, findings: list[dict],
                                   validated_by: int) -> None:
        rec = {"_id": uuid.uuid4().hex, "intent_id": intent_id, "version": version,
               "body_hash": body_hash, "outcome": outcome, "evidence_source": evidence_source,
               "findings": findings, "validated_by": validated_by, "validated_ts": now_ts()}
        self.db[EVIDENCE_VALIDATIONS].insert_one(
            integrity.seal(self.kr, "intent-evidence-validation", rec))

    # ------------------------------------------------------------ decisions
    def save_decision(self, body: dict) -> dict:
        rec = integrity.seal(self.kr, T_DECISION, body)
        self.db[DECISIONS].insert_one(rec)
        self.db[DECISION_STATUS].insert_one({"_id": rec["_id"], "status": "ACTIVE", "revision": 1,
                                             "reason": "", "updated_ts": now_ts(), "contexts_issued": 0})
        return rec

    def get_decision(self, decision_id: str) -> dict | None:
        return self.db[DECISIONS].find_one({"_id": decision_id})

    def decision_authentic(self, rec: dict) -> bool:
        return integrity.verify(self.kr, T_DECISION, rec)

    def decision_status(self, decision_id: str) -> dict | None:
        return self.db[DECISION_STATUS].find_one({"_id": decision_id})

    def revoke_decision(self, decision_id: str, reason: str) -> bool:
        res = self.db[DECISION_STATUS].update_one(
            {"_id": decision_id, "status": "ACTIVE"},
            {"$set": {"status": "REVOKED", "reason": reason[:200], "updated_ts": now_ts()}, "$inc": {"revision": 1}})
        return res.matched_count == 1

    def revoke_decisions_where(self, **match: Any) -> int:
        n = 0
        for d in self.db[DECISIONS].find(match):
            if self.revoke_decision(d["_id"], "bulk revocation"):
                n += 1
        return n

    def claim_context_slot(self, decision_id: str, max_contexts: int) -> bool:
        res = self.db[DECISION_STATUS].update_one(
            {"_id": decision_id, "status": "ACTIVE", "contexts_issued": {"$lt": max_contexts}},
            {"$inc": {"contexts_issued": 1}})
        return res.matched_count == 1

    # -------------------------------------------------------------- contexts
    def new_id(self) -> str:
        return uuid.uuid4().hex

    def save_context(self, doc: dict) -> None:
        self.db[CONTEXTS].insert_one(doc)

    def get_context(self, ctx_id: str) -> dict | None:
        return self.db[CONTEXTS].find_one({"_id": ctx_id})

    def consume_context(self, ctx_id: str) -> bool:
        """Single-use: exactly one caller wins."""
        res = self.db[CONTEXTS].update_one({"_id": ctx_id, "used": False},
                                           {"$set": {"used": True, "used_ts": now_ts()}})
        return res.matched_count == 1

    def invalidate_contexts_where(self, **match: Any) -> int:
        n = 0
        for c in self.db[CONTEXTS].find({"used": False, **match}):
            r = self.db[CONTEXTS].update_one({"_id": c["_id"], "used": False},
                                             {"$set": {"used": True, "invalidated": True, "used_ts": now_ts()}})
            n += r.matched_count
        return n
