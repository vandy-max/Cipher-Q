"""
MongoDB-backed (PyMongo) repositories.

Each class here satisfies a Protocol defined in a domain module
(`authentication.service.UserRepository`,
`authentication.face_auth.FaceDescriptorRepository`,
`audit.service.AuditLogRepository`) so those services stay unaware of
MongoDB entirely. 
"""
from __future__ import annotations

import atexit
import dataclasses
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Sequence

from pymongo.collection import ReturnDocument
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from audit.hash_chain import GENESIS_HASH, AuditEntry  # noqa: F401
from authentication.service import UserRecord
from authorization.devices import DeviceStatus
from authorization.sessions import SessionRevokedError, SessionState
from database.models import AUDIT_LOGS_COLLECTION
AUDIT_HEAD_COLLECTION = "audit_head"
from database.models import AuditLog as AuditLogModel
from database.models import AUTH_SESSIONS_COLLECTION
from database.models import DEVICES_COLLECTION
from database.models import MONITORING_EVENTS_COLLECTION
from database.models import MONITORING_SESSIONS_COLLECTION
from database.models import POLICIES_COLLECTION
from database.models import Policy as PolicyModel
from database.models import TRUSTED_LOCATIONS_COLLECTION
from database.models import AUTH_TOKENS_COLLECTION, USERNAME_INDEX_COLLECTION, USERS_COLLECTION
from database.models import User as UserModel
from database.session import get_next_id
from monitoring.service import (
    MAX_MONITORING_EVENTS_PER_SESSION,
    MonitoringEvent,
    MonitoringSessionRecord,
)
from monitoring.state import IdentityCheckState, MonitoringSnapshot, MonitoringStatus, MonitoringThresholds, SecurityPostureState
from policy.risk import RiskLevel
from policy.geofence import TrustedLocation


# ---------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------

def _to_user_record(row: UserModel) -> UserRecord:
    return UserRecord(
        id=row.id,
        username=row.username,
        email=row.email,
        password_hash=row.password_hash,
        salt=row.salt,
        role=row.role,
        disabled=row.disabled,
        token_version=row.token_version,
    )


class MongoUserRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_by_username(self, username: str) -> UserRecord | None:
        key = username.strip().lower()
        idx = self._db[USERNAME_INDEX_COLLECTION].find_one({"_id": key})
        if idx is not None:
            return self.get_by_id(idx["user_id"])
        # Legacy (v17) accounts have no index entry: fall back to one scan, then backfill.
        doc = self._db[USERS_COLLECTION].find_one({"username": username.strip()})
        if doc is None:
            return None
        try:
            self._db[USERNAME_INDEX_COLLECTION].insert_one({"_id": key, "user_id": doc["_id"]})
        except DuplicateKeyError:
            pass
        return _to_user_record(UserModel.from_document(doc))

    def get_by_id(self, user_id: int) -> UserRecord | None:
        doc = self._db[USERS_COLLECTION].find_one({"_id": user_id})
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def list_all(self) -> list[UserRecord]:
        return [
            _to_user_record(UserModel.from_document(doc))
            for doc in self._db[USERS_COLLECTION].find().sort("_id", 1)
        ]

    def count_enabled_admins(self) -> int:
        return sum(1 for u in self.list_all() if u.role == "ADMIN" and not u.disabled)

    def update_role(self, user_id: int, role: str) -> UserRecord | None:
        """Role change also bumps ``token_version``: every token issued before it dies."""
        doc = self._db[USERS_COLLECTION].find_one_and_update(
            {"_id": user_id}, {"$set": {"role": role}, "$inc": {"token_version": 1}},
            return_document=ReturnDocument.AFTER)
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def set_disabled(self, user_id: int, disabled: bool) -> UserRecord | None:
        doc = self._db[USERS_COLLECTION].find_one_and_update(
            {"_id": user_id}, {"$set": {"disabled": bool(disabled)}, "$inc": {"token_version": 1}},
            return_document=ReturnDocument.AFTER)
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def bump_token_version(self, user_id: int) -> None:
        self._db[USERS_COLLECTION].update_one({"_id": user_id}, {"$inc": {"token_version": 1}})

    def update_password_hash(self, user_id: int, password_hash: str) -> None:
        self._db[USERS_COLLECTION].update_one(
            {"_id": user_id}, {"$set": {"password_hash": password_hash, "salt": ""}})

    def create(
        self, username: str, email: str, password_hash: str, salt: str, role: str
    ) -> UserRecord:
        from authentication.service import UsernameTakenError
        key = username.strip().lower()
        user_id = get_next_id(USERS_COLLECTION)
        try:   # atomic, case-insensitive uniqueness via the _id of the index collection
            self._db[USERNAME_INDEX_COLLECTION].insert_one({"_id": key, "user_id": user_id})
        except DuplicateKeyError as exc:
            raise UsernameTakenError("username is already taken") from exc
        doc = {
            "_id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "salt": salt,
            "role": role,
            "face_descriptor": None,
            "disabled": False,
            "token_version": 0,
            "created_at": datetime.now(timezone.utc),
        }
        try:
            self._db[USERS_COLLECTION].insert_one(doc)
        except Exception:
            self._db[USERNAME_INDEX_COLLECTION].delete_one({"_id": key})
            raise
        stored = self._db[USERS_COLLECTION].find_one({"_id": user_id})
        if stored is None:
            raise RuntimeError("user registration was written but could not be read back")
        return _to_user_record(UserModel.from_document(stored))


class MongoTokenRepository:
    """Registry of issued JWT ids (``jti``) -- enables per-token revocation."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def register(self, jti: str, user_id: int, expires_at: datetime) -> None:
        self._db[AUTH_TOKENS_COLLECTION].insert_one(
            {"_id": jti, "user_id": user_id, "expires_at": expires_at, "revoked": False,
             "issued_at": datetime.now(timezone.utc)})

    def is_active(self, jti: str, user_id: int) -> bool:
        doc = self._db[AUTH_TOKENS_COLLECTION].find_one({"_id": jti})
        return bool(doc) and doc.get("user_id") == user_id and not doc.get("revoked", False)

    def revoke(self, jti: str) -> None:
        self._db[AUTH_TOKENS_COLLECTION].update_one({"_id": jti}, {"$set": {"revoked": True}})

    def purge_expired(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        return self._db[AUTH_TOKENS_COLLECTION].delete_many({"expires_at": {"$lt": now}}).deleted_count


# ---------------------------------------------------------------------
# Face descriptors (identity verification only)
# ---------------------------------------------------------------------

class MongoFaceDescriptorRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_enrolled_descriptor(self, user_id: int) -> Sequence[float] | None:
        doc = self._db[USERS_COLLECTION].find_one(
            {"_id": user_id}, {"face_descriptor": 1}
        )
        if doc is None or not doc.get("face_descriptor"):
            return None
        return doc["face_descriptor"]

    def save_enrolled_descriptor(self, user_id: int, descriptor: Sequence[float]) -> None:
        result = self._db[USERS_COLLECTION].update_one(
            {"_id": user_id}, {"$set": {"face_descriptor": list(descriptor)}}
        )
        if result.matched_count == 0:
            raise ValueError(f"no user with id {user_id}")


# ---------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------

class MongoAuditLogRepository:
    """Audit entries keyed by ``_id == seq`` (unique => concurrent writers cannot silently
    overwrite or fork the chain) plus a sealed head record used to detect tail truncation."""

    HEAD_ID = "head"

    def __init__(self, db: Database) -> None:
        self._db = db

    @staticmethod
    def _to_entry(doc: dict) -> AuditEntry:
        ts = doc["timestamp"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return AuditEntry(
            timestamp=ts, user_id=doc.get("user_id"), action=doc.get("action", ""),
            intent_hash=doc.get("intent_hash"), result=doc.get("result", ""),
            prev_log_hash=doc.get("prev_log_hash", ""), current_log_hash=doc.get("current_log_hash", ""),
            session_id=doc.get("session_id"), device_id=doc.get("device_id"), resource=doc.get("resource"),
            operation=doc.get("operation"), risk=doc.get("risk"), reason=doc.get("reason"),
            seq=int(doc.get("seq", 0) or 0), kid=int(doc.get("kid", 0) or 0))

    def get_head(self) -> dict | None:
        return self._db[AUDIT_HEAD_COLLECTION].find_one({"_id": self.HEAD_ID})

    def last_entry(self) -> AuditEntry | None:
        head = self.get_head()
        if head is None:
            docs = list(self._db[AUDIT_LOGS_COLLECTION].find().sort("_id", -1).limit(1))
            return self._to_entry(docs[0]) if docs else None
        seq = int(head["seq"])
        doc = self._db[AUDIT_LOGS_COLLECTION].find_one({"_id": seq}) if seq > 0 else None
        while True:                                   # head may lag by a crash / race window
            nxt = self._db[AUDIT_LOGS_COLLECTION].find_one({"_id": seq + 1})
            if nxt is None:
                break
            doc, seq = nxt, seq + 1
        return self._to_entry(doc) if doc else None

    def insert(self, entry: AuditEntry) -> bool:
        doc = {"_id": entry.seq, "seq": entry.seq, "kid": entry.kid, "timestamp": entry.timestamp,
               "user_id": entry.user_id, "action": entry.action, "intent_hash": entry.intent_hash,
               "result": entry.result, "prev_log_hash": entry.prev_log_hash,
               "current_log_hash": entry.current_log_hash, "session_id": entry.session_id,
               "device_id": entry.device_id, "resource": entry.resource, "operation": entry.operation,
               "risk": entry.risk, "reason": entry.reason}
        try:
            self._db[AUDIT_LOGS_COLLECTION].insert_one(doc)
            return True
        except DuplicateKeyError:
            return False

    def set_head(self, head: dict) -> None:
        cur = self.get_head()
        if cur is None or int(cur["seq"]) < int(head["seq"]):
            self._db[AUDIT_HEAD_COLLECTION].update_one({"_id": self.HEAD_ID}, {"$set": dict(head)}, upsert=True)

    def all_entries(self) -> Sequence[AuditEntry]:
        return [self._to_entry(d) for d in self._db[AUDIT_LOGS_COLLECTION].find().sort("_id", 1)]


# ---------------------------------------------------------------------
# Policies (config rows for the policy engine's allow-lists)
# ---------------------------------------------------------------------

class PolicyRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def list_all(self) -> Sequence[PolicyModel]:
        cursor = self._db[POLICIES_COLLECTION].find()
        return [PolicyModel.from_document(doc) for doc in cursor]

    def get(self, policy_id: int) -> PolicyModel | None:
        doc = self._db[POLICIES_COLLECTION].find_one({"_id": policy_id})
        return PolicyModel.from_document(doc) if doc is not None else None

    def create(self, name: str, rule_type: str, config: dict, active: bool) -> PolicyModel:
        doc = {
            "_id": get_next_id(POLICIES_COLLECTION),
            "name": name,
            "rule_type": rule_type,
            "config_json": config,
            "active": active,
            "created_at": datetime.now(timezone.utc),
        }
        self._db[POLICIES_COLLECTION].insert_one(doc)
        return PolicyModel.from_document(doc)

    def update(
        self, policy_id: int, name: str, rule_type: str, config: dict, active: bool
    ) -> PolicyModel | None:
        doc = self._db[POLICIES_COLLECTION].find_one_and_update(
            {"_id": policy_id},
            {
                "$set": {
                    "name": name,
                    "rule_type": rule_type,
                    "config_json": config,
                    "active": active,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return PolicyModel.from_document(doc) if doc is not None else None

    def delete(self, policy_id: int) -> bool:
        result = self._db[POLICIES_COLLECTION].delete_one({"_id": policy_id})
        return result.deleted_count > 0


# ---------------------------------------------------------------------
# Devices / sessions (continuous-authorization state — see
# `authorization/`). Satisfy the `authorization.devices.DeviceRepository`
# and `authorization.sessions.SessionRepository` Protocols.
# ---------------------------------------------------------------------

class MongoDeviceRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_status(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$setOnInsert": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    def revoke(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$set": {"revoked": True}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    def unrevoke(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$set": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    # -- Ownership (API-layer concern only, additive to the plain
    # DeviceStatus domain model used by authorization/monitoring
    # internals, which intentionally know nothing about "who owns
    # this device" — only whether it's revoked). --

    def get_owner(self, device_id: str) -> int | None:
        doc = self._db[DEVICES_COLLECTION].find_one({"_id": device_id})
        return doc.get("user_id") if doc is not None else None

    def claim_owner(self, device_id: str, user_id: int) -> int:
        """The first user to ever establish a session with this
        device becomes its recorded owner. Idempotent and atomic: if
        the device already has an owner (including this same caller),
        the existing owner is returned unchanged — this never silently
        transfers ownership of an already-owned device."""
        self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$setOnInsert": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        claimed = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id, "user_id": {"$exists": False}},
            {"$set": {"user_id": user_id}},
            return_document=ReturnDocument.AFTER,
        )
        if claimed is not None:
            return claimed["user_id"]
        existing = self._db[DEVICES_COLLECTION].find_one({"_id": device_id})
        return existing["user_id"]


def _to_session_state(doc: dict) -> SessionState:
    # MongoDB/BSON round-trips datetimes as timezone-naive UTC — every
    # datetime written here is UTC-aware (see get_or_create/refresh
    # below), so a naive value read back is always UTC and safe to
    # reattach tzinfo to. Without this, comparing against an
    # aware `datetime.now(timezone.utc)` elsewhere (e.g.
    # `authorization.sessions.is_session_valid`,
    # `monitoring.service`) raises TypeError. Same normalization
    # pattern already used in audit/hash_chain.py, intent/canonicalizer.py,
    # and intent/schema.py for this exact BSON behavior.
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return SessionState(
        session_id=doc["_id"],
        user_id=doc["user_id"],
        device_id=doc["device_id"],
        expires_at=expires_at,
        revoked=doc.get("revoked", False),
        version=doc.get("version", 1),
    )


class MongoSessionRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_or_create(self, session_id: str, user_id: int, device_id: str, ttl, now=None):
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {
                "$setOnInsert": {
                    "user_id": user_id,
                    "device_id": device_id,
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                    "revoked": False,
                    "version": 1,
                }
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return _to_session_state(doc)

    def get(self, session_id: str) -> SessionState | None:
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one({"_id": session_id})
        return _to_session_state(doc) if doc is not None else None

    def revoke(self, session_id: str) -> SessionState:
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {"$set": {"revoked": True}},
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)

    def refresh(self, session_id: str, ttl, now=None) -> SessionState:
        """Normal refresh: extends expiry for an ACTIVE session only.
        Filtering on `revoked: False` in the query means the update is
        a no-op against an already-revoked document — nothing about
        this call can flip `revoked` back to False. If the session
        exists but is revoked, `SessionRevokedError` is raised instead
        and the stored document is left completely untouched."""
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id, "revoked": {"$ne": True}},
            {
                "$set": {
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                },
            },   # NOTE: a plain refresh must NOT bump `version` -- only reauthorize() does
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            existing = self._db[AUTH_SESSIONS_COLLECTION].find_one({"_id": session_id})
            if existing is None:
                raise KeyError(f"no session '{session_id}'")
            if existing.get("revoked"):
                raise SessionRevokedError(session_id)
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)

    def reauthorize(self, session_id: str, ttl, now=None) -> SessionState:
        """Establish a fresh authorized session after explicit
        re-authentication has already been verified by the caller:
        un-revokes, extends expiry, and bumps `version`. Only ever
        invoked from the dedicated re-authentication endpoint."""
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {
                "$set": {
                    "revoked": False,
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                },
                "$inc": {"version": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)


# ---------------------------------------------------------------------
# Continuous monitoring (session-wide, not operation-specific — see
# `monitoring/`). Satisfies `monitoring.service.MonitoringRepository`.
# ---------------------------------------------------------------------

def _thresholds_to_doc(thresholds: MonitoringThresholds) -> dict:
    return {
        "warning_after": thresholds.warning_after,
        "risk_increase_after": thresholds.risk_increase_after,
        "reauth_required_after": thresholds.reauth_required_after,
        "invalidate_after": thresholds.invalidate_after,
    }


def _thresholds_from_doc(doc: dict) -> MonitoringThresholds:
    # Adopt the current application defaults for records written by either
    # previous default policy. Explicitly customized threshold tuples remain
    # untouched; no database migration or record rewrite is required.
    previous_defaults = {(2, 3, 8, 12), (2, 3, 4, 6)}
    stored = (
        int(doc.get("warning_after", 3)),
        int(doc.get("risk_increase_after", 3)),
        int(doc.get("reauth_required_after", 6)),
        int(doc.get("invalidate_after", 8)),
    )
    if stored in previous_defaults:
        stored = (3, 3, 6, 8)
    return MonitoringThresholds(
        warning_after=stored[0],
        risk_increase_after=stored[1],
        reauth_required_after=stored[2],
        invalidate_after=stored[3],
    )


def _to_monitoring_record(doc: dict) -> MonitoringSessionRecord:
    return MonitoringSessionRecord(
        monitoring_session_id=doc["_id"],
        user_id=doc["user_id"],
        device_id=doc["device_id"],
        session_id=doc["session_id"],
        intent_id=doc.get("intent_id"),
        status=MonitoringStatus(doc["status"]),
        consecutive_face_failures=doc["consecutive_face_failures"],
        thresholds=_thresholds_from_doc(doc["thresholds"]),
        started_at=doc["started_at"],
        updated_at=doc["updated_at"],
        stopped=doc.get("stopped", False),
        repeated_denied_requests=doc.get("repeated_denied_requests", 0),
        device_revoked_by_monitoring=doc.get("device_revoked_by_monitoring", False),
        audit_tamper_alerted=doc.get("audit_tamper_alerted", False),
        revoked_at_session_version=doc.get("revoked_at_session_version"),
        last_face_present=doc.get("last_face_present", False),
        last_face_match_confidence=doc.get("last_face_match_confidence"),
        last_liveness=doc.get("last_liveness", False),
        last_camera_available=doc.get("last_camera_available", False),
        last_identity_state=IdentityCheckState(doc.get("last_identity_state", "no_face")),
        last_expression_hint=doc.get("last_expression_hint"),
        last_reason_code=doc.get("last_reason_code"),
        last_reason=doc.get("last_reason"),
        snapshot_revision=doc.get("snapshot_revision", 0),
        check_count=doc.get("check_count", 0),
        successful_face_verifications=doc.get("successful_face_verifications", 0),
        face_liveness_failures=doc.get("face_liveness_failures", 0),
        warning_occurrences=doc.get("warning_occurrences", 0),
        recovery_count=doc.get("recovery_count", 0),
        camera_interruptions=doc.get("camera_interruptions", 0),
        highest_security_state=doc.get("highest_security_state", "SECURE"),
        last_security_state=doc.get("last_security_state", "SECURE"),
        final_security_state=doc.get("final_security_state"),
        overall_security_outcome=doc.get("overall_security_outcome"),
        ended_at=doc.get("ended_at"),
        duration_seconds=doc.get("duration_seconds"),
        heartbeat_nonce=doc.get("heartbeat_nonce"),
        last_heartbeat_ts=doc.get("last_heartbeat_ts"),
        reauth_latched=doc.get("reauth_latched", False),
        last_risk_level=RiskLevel(doc.get("last_risk_level", RiskLevel.LOW.value)),
        last_risk_score=doc.get("last_risk_score", 0.0),
    )


# ---------------------------------------------------------------------
# Monitoring sessions -- transient (hot) state vs persistent security records
# ---------------------------------------------------------------------
#
# A monitoring heartbeat arrives every ~2.5 s per user. Most of what changes on a healthy tick is
# TRANSIENT: the rotating replay nonce, the last-heartbeat timestamp, the snapshot revision, the
# latest confidence/risk numbers and the running session counters. Rewriting the whole (encrypted)
# session document for that on every tick was the largest source of database writes.
#
# This process-wide write-behind layer keeps the transient state in memory and persists a record:
#   * IMMEDIATELY when something security-relevant changes (status, revocation / re-auth latch,
#     identity-check state, risk level, denied-request counter, stop/summary, ...);
#   * otherwise at most every MONITORING_PERSIST_INTERVAL_SECONDS (default 30 s);
#   * on stop (final summary) and when the process exits.
# Security events (monitoring_events) and audit entries are never deferred.
#
# All readers go through the repository, so they always see the live in-process state; the database
# can lag only by the persist interval, and only after a crash. After a crash the nonce simply
# re-syncs (client gets 409 -> GET -> retry) and a stale `last_heartbeat_ts` can only make the
# heartbeat-gap check fail CLOSED.
#
# MULTI-PROCESS deployments (several uvicorn workers) must set MONITORING_PERSIST_INTERVAL_SECONDS=0,
# which restores plain write-through behaviour (the project already requires a real MongoDB for
# multi-process use, see PRODUCTION_READINESS.md).

def _env_seconds(name: str, default: float) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


MONITORING_PERSIST_INTERVAL_SECONDS = _env_seconds("MONITORING_PERSIST_INTERVAL_SECONDS", 30.0)
_HOT_IDLE_EVICT_SECONDS = 600.0
_HOUSEKEEPING_INTERVAL_SECONDS = 3600.0
_FLUSH_RETRY_SECONDS = 5.0
_log = logging.getLogger("cipherq.monitoring.store")


def _aware_dt(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _significance_key(r: MonitoringSessionRecord) -> tuple:
    """Fields whose change must reach the database immediately (everything else is transient)."""
    return (
        r.status, r.stopped, r.reauth_latched, r.revoked_at_session_version,
        r.device_revoked_by_monitoring, r.repeated_denied_requests, r.audit_tamper_alerted,
        r.last_identity_state, r.last_risk_level, r.warning_occurrences, r.recovery_count,
        r.highest_security_state, r.last_security_state, r.consecutive_face_failures > 0,
        r.final_security_state, r.ended_at,
    )


def _record_to_set_doc(record: MonitoringSessionRecord) -> dict:
    return {
        "status": record.status.value,
        "consecutive_face_failures": record.consecutive_face_failures,
        "updated_at": record.updated_at,
        "stopped": record.stopped,
        "repeated_denied_requests": record.repeated_denied_requests,
        "device_revoked_by_monitoring": record.device_revoked_by_monitoring,
        "audit_tamper_alerted": record.audit_tamper_alerted,
        "revoked_at_session_version": record.revoked_at_session_version,
        "last_face_present": record.last_face_present,
        "last_face_match_confidence": record.last_face_match_confidence,
        "last_liveness": record.last_liveness,
        "last_camera_available": record.last_camera_available,
        "last_identity_state": record.last_identity_state.value,
        "last_expression_hint": record.last_expression_hint,
        "last_reason_code": record.last_reason_code,
        "last_reason": record.last_reason,
        "snapshot_revision": record.snapshot_revision,
        "check_count": record.check_count,
        "last_risk_level": record.last_risk_level.value,
        "last_risk_score": record.last_risk_score,
        "successful_face_verifications": record.successful_face_verifications,
        "face_liveness_failures": record.face_liveness_failures,
        "warning_occurrences": record.warning_occurrences,
        "recovery_count": record.recovery_count,
        "camera_interruptions": record.camera_interruptions,
        "highest_security_state": record.highest_security_state,
        "last_security_state": record.last_security_state,
        "final_security_state": record.final_security_state,
        "overall_security_outcome": record.overall_security_outcome,
        "ended_at": record.ended_at,
        "duration_seconds": record.duration_seconds,
        "heartbeat_nonce": record.heartbeat_nonce,
        "last_heartbeat_ts": record.last_heartbeat_ts,
        "reauth_latched": record.reauth_latched,
    }


class _HotEntry:
    __slots__ = ("record", "db", "persisted_key", "dirty", "last_flush", "last_touch", "next_retry")

    def __init__(self, record, db, persisted_key, now):
        self.record = record
        self.db = db
        self.persisted_key = persisted_key       # None => never written by this layer yet
        self.dirty = False
        self.last_flush = now
        self.last_touch = now
        self.next_retry = 0.0


class _MonitoringHotState:
    """Process-wide registry shared by every per-request MongoMonitoringRepository instance."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.entries: dict[str, _HotEntry] = {}
        self.by_session: dict[str, str] = {}      # authorization session id -> live monitoring id
        self.event_counts: dict[str, int] = {}    # monitoring id -> stored event rows (lazy)
        self.last_housekeeping = 0.0
        self.last_sweep = 0.0

    @staticmethod
    def enabled() -> bool:
        return MONITORING_PERSIST_INTERVAL_SECONDS > 0

    # -- persistence -------------------------------------------------------
    def _flush_locked(self, entry: _HotEntry, now: float) -> bool:
        record = entry.record
        try:
            entry.db[MONITORING_SESSIONS_COLLECTION].update_one(
                {"_id": record.monitoring_session_id}, {"$set": _record_to_set_doc(record)})
        except Exception:  # noqa: BLE001 -- the in-process state stays authoritative; retry shortly
            entry.dirty = True
            entry.next_retry = now + _FLUSH_RETRY_SECONDS
            _log.error("monitoring session %s could not be persisted; will retry",
                       record.monitoring_session_id, exc_info=True)
            return False
        entry.persisted_key = _significance_key(record)
        entry.dirty = False
        entry.last_flush = now
        entry.next_retry = 0.0
        return True

    def flush_all(self) -> None:
        with self.lock:
            now = time.monotonic()
            for entry in list(self.entries.values()):
                if entry.dirty:
                    self._flush_locked(entry, now)

    def evict(self, monitoring_session_id: str, *, flush: bool = False) -> None:
        with self.lock:
            entry = self.entries.pop(monitoring_session_id, None)
            if entry is not None:
                if flush and entry.dirty:
                    self._flush_locked(entry, time.monotonic())
                self._drop_index_locked(entry.record)

    def clear(self) -> None:
        with self.lock:
            self.entries.clear()
            self.by_session.clear()
            self.event_counts.clear()
            self.last_housekeeping = 0.0

    def _drop_index_locked(self, record: MonitoringSessionRecord) -> None:
        if self.by_session.get(record.session_id) == record.monitoring_session_id:
            del self.by_session[record.session_id]

    # -- lifecycle ---------------------------------------------------------
    def adopt(self, record: MonitoringSessionRecord, db, *, persisted: bool) -> None:
        with self.lock:
            now = time.monotonic()
            entry = _HotEntry(dataclasses.replace(record), db,
                              _significance_key(record) if persisted else None, now)
            self.entries[record.monitoring_session_id] = entry
            if not record.stopped:
                self.by_session[record.session_id] = record.monitoring_session_id

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        with self.lock:
            now = time.monotonic()
            self._sweep_locked(now)
            entry = self.entries.get(monitoring_session_id)
            if entry is None:
                return None
            entry.last_touch = now
            return dataclasses.replace(entry.record)

    def put(self, record: MonitoringSessionRecord, db) -> None:
        with self.lock:
            now = time.monotonic()
            entry = self.entries.get(record.monitoring_session_id)
            if entry is None:
                entry = _HotEntry(dataclasses.replace(record), db, None, now)
                self.entries[record.monitoring_session_id] = entry
            else:
                entry.record = dataclasses.replace(record)
                entry.db = db
            entry.last_touch = now
            entry.dirty = True
            important = entry.persisted_key is None or _significance_key(record) != entry.persisted_key
            due = now - entry.last_flush >= MONITORING_PERSIST_INTERVAL_SECONDS
            if (important or due or record.stopped) and now >= entry.next_retry:
                self._flush_locked(entry, now)
            if record.stopped:
                self._drop_index_locked(record)
                if not entry.dirty:
                    self.entries.pop(record.monitoring_session_id, None)
            else:
                self.by_session[record.session_id] = record.monitoring_session_id
            self._sweep_locked(now)

    def _sweep_locked(self, now: float) -> None:
        """Flush stale dirty entries and evict idle ones (bounded memory, bounded data-loss window)."""
        if now - self.last_sweep < min(MONITORING_PERSIST_INTERVAL_SECONDS, 10.0):
            return
        self.last_sweep = now
        for mid, entry in list(self.entries.items()):
            if entry.dirty and now - entry.last_flush >= MONITORING_PERSIST_INTERVAL_SECONDS and now >= entry.next_retry:
                self._flush_locked(entry, now)
            if not entry.dirty and now - entry.last_touch > _HOT_IDLE_EVICT_SECONDS:
                del self.entries[mid]
                self._drop_index_locked(entry.record)

    def housekeeping_due(self) -> bool:
        with self.lock:
            now = time.monotonic()
            if self.last_housekeeping and now - self.last_housekeeping < _HOUSEKEEPING_INTERVAL_SECONDS:
                return False
            self.last_housekeeping = now
            return True


_HOT = _MonitoringHotState()
atexit.register(_HOT.flush_all)


class MongoMonitoringRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    # -- test / operations hooks ------------------------------------------
    @staticmethod
    def flush_hot_state() -> None:
        """Persist every pending transient change now (also runs at process exit)."""
        _HOT.flush_all()

    @staticmethod
    def reset_hot_state() -> None:
        """Forget all in-memory state WITHOUT writing it (simulates a fresh process)."""
        _HOT.clear()

    def create(
        self, user_id, device_id, session_id, intent_id, thresholds, now
    ) -> MonitoringSessionRecord:
        # Retention purge of >90-day-old sessions scans the whole (encrypted) collection, so it runs
        # at most once per housekeeping interval per process instead of on every monitoring start.
        if _HOT.housekeeping_due():
            cutoff = now - timedelta(days=90)
            if cutoff.tzinfo is not None:
                cutoff = cutoff.astimezone(timezone.utc).replace(tzinfo=None)
            expired = self._db[MONITORING_SESSIONS_COLLECTION].find(
                {"updated_at": {"$lt": cutoff}}
            )
            expired_ids = [doc["_id"] for doc in expired]
            if expired_ids:
                self._db[MONITORING_EVENTS_COLLECTION].delete_many(
                    {"monitoring_session_id": {"$in": expired_ids}}
                )
                self._db[MONITORING_SESSIONS_COLLECTION].delete_many(
                    {"_id": {"$in": expired_ids}}
                )
                for mid in expired_ids:
                    _HOT.evict(mid)
                    _HOT.event_counts.pop(mid, None)

        monitoring_session_id = uuid.uuid4().hex
        doc = {
            "_id": monitoring_session_id,
            "user_id": user_id,
            "device_id": device_id,
            "session_id": session_id,
            "intent_id": intent_id,
            "status": MonitoringStatus.ACTIVE.value,
            "consecutive_face_failures": 0,
            "thresholds": _thresholds_to_doc(thresholds),
            "started_at": now,
            "updated_at": now,
            "stopped": False,
            "repeated_denied_requests": 0,
            "device_revoked_by_monitoring": False,
            "audit_tamper_alerted": False,
            "revoked_at_session_version": None,
            "last_face_present": False,
            "last_face_match_confidence": None,
            "last_liveness": False,
            "last_camera_available": False,
            "last_identity_state": "no_face",
            "last_expression_hint": None,
            "last_reason_code": None,
            "last_reason": None,
            "snapshot_revision": 0,
            "check_count": 0,
            "last_risk_level": RiskLevel.LOW.value,
            "last_risk_score": 0.0,
            "successful_face_verifications": 0,
            "face_liveness_failures": 0,
            "warning_occurrences": 0,
            "recovery_count": 0,
            "camera_interruptions": 0,
            "highest_security_state": "SECURE",
            "last_security_state": "SECURE",
            "final_security_state": None,
            "overall_security_outcome": None,
            "ended_at": None,
            "duration_seconds": None,
            "heartbeat_nonce": None,
            "last_heartbeat_ts": now,
            "reauth_latched": False,
        }
        self._db[MONITORING_SESSIONS_COLLECTION].insert_one(doc)
        record = _to_monitoring_record(doc)
        if _HOT.enabled():
            _HOT.adopt(record, self._db, persisted=True)
            _HOT.event_counts[monitoring_session_id] = 0
        return record

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        if _HOT.enabled():
            hot = _HOT.get(monitoring_session_id)
            if hot is not None:
                return hot
        doc = self._db[MONITORING_SESSIONS_COLLECTION].find_one({"_id": monitoring_session_id})
        if doc is None:
            return None
        record = _to_monitoring_record(doc)
        if _HOT.enabled() and not record.stopped:
            _HOT.adopt(record, self._db, persisted=True)
        return record

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord:
        if _HOT.enabled():
            _HOT.put(record, self._db)
            return record
        self._db[MONITORING_SESSIONS_COLLECTION].update_one(
            {"_id": record.monitoring_session_id}, {"$set": _record_to_set_doc(record)}
        )
        return record

    def append_event(self, event: MonitoringEvent) -> None:
        snap = event.snapshot
        mid = event.monitoring_session_id
        doc = {
            "_id": get_next_id(MONITORING_EVENTS_COLLECTION),
            "monitoring_session_id": mid,
            "event_type": event.event_type,
            "snapshot": snap.as_dict(),
            "timestamp": snap.timestamp,
        }
        events = self._db[MONITORING_EVENTS_COLLECTION]
        events.insert_one(doc)
        # Retention: keep the newest MAX events per session. Counting/pruning by field query scans the
        # whole (encrypted) events collection, so the row count is tracked in memory (seeded by ONE
        # scan per session per process) and the scan only repeats when the bound is actually exceeded.
        limit = MAX_MONITORING_EVENTS_PER_SESSION
        count = _HOT.event_counts.get(mid)
        if count is None:
            count = sum(1 for _ in events.find({"monitoring_session_id": mid}))
        else:
            count += 1
        if count > limit + limit // 20:
            ids = sorted(item["_id"] for item in events.find({"monitoring_session_id": mid}))
            expired_ids = ids[:-limit] if limit > 0 else ids
            if expired_ids:
                events.delete_many({"_id": {"$in": expired_ids}})
            count = min(len(ids), limit)
        _HOT.event_counts[mid] = count

    def list_all(self) -> Sequence[MonitoringSessionRecord]:
        cursor = self._db[MONITORING_SESSIONS_COLLECTION].find({})
        records = [self._overlay(_to_monitoring_record(doc)) for doc in cursor]
        records.sort(key=lambda r: _aware_dt(r.updated_at), reverse=True)
        return tuple(records)

    def list_active(self) -> Sequence[MonitoringSessionRecord]:
        cursor = self._db[MONITORING_SESSIONS_COLLECTION].find({"stopped": {"$ne": True}})
        records = [self._overlay(_to_monitoring_record(doc)) for doc in cursor]
        records = [r for r in records if not r.stopped]
        records.sort(key=lambda r: _aware_dt(r.updated_at), reverse=True)
        return tuple(records)

    @staticmethod
    def _overlay(record: MonitoringSessionRecord) -> MonitoringSessionRecord:
        """Prefer the live in-process state over a (possibly slightly older) persisted copy."""
        if _HOT.enabled():
            hot = _HOT.get(record.monitoring_session_id)
            if hot is not None:
                return hot
        return record

    def get_by_session(self, session_id: str) -> MonitoringSessionRecord | None:
        if _HOT.enabled():
            with _HOT.lock:
                mid = _HOT.by_session.get(session_id)
            if mid is not None:
                hot = _HOT.get(mid)
                if hot is not None and not hot.stopped and hot.session_id == session_id:
                    return hot
                with _HOT.lock:
                    if _HOT.by_session.get(session_id) == mid:
                        del _HOT.by_session[session_id]
        doc = self._db[MONITORING_SESSIONS_COLLECTION].find_one(
            {"session_id": session_id, "stopped": {"$ne": True}},
            sort=[("updated_at", -1)],
        )
        if doc is None:
            return None
        record = self._overlay(_to_monitoring_record(doc))
        if record.stopped:
            return None
        if _HOT.enabled():
            if _HOT.get(record.monitoring_session_id) is None:
                _HOT.adopt(record, self._db, persisted=True)
            else:
                with _HOT.lock:
                    _HOT.by_session[session_id] = record.monitoring_session_id
        return record

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        cursor = self._db[MONITORING_EVENTS_COLLECTION].find(
            {"monitoring_session_id": monitoring_session_id}
        ).sort("_id", 1)
        events = []
        for doc in cursor:
            snap = doc["snapshot"]
            events.append(
                MonitoringEvent(
                    monitoring_session_id=doc["monitoring_session_id"],
                    event_type=doc["event_type"],
                    snapshot=MonitoringSnapshot(
                        monitoring_session_id=snap["monitoring_session_id"],
                        snapshot_revision=snap.get("snapshot_revision", 0),
                        current_user=snap["current_user"],
                        current_device=snap["current_device"],
                        current_session=snap["current_session"],
                        status=MonitoringStatus(snap["status"]),
                        face_present=snap["face_present"],
                        face_match_confidence=snap["face_match_confidence"],
                        liveness=snap["liveness"],
                        current_intent=snap["current_intent"],
                        current_lifecycle=snap["current_lifecycle"],
                        current_risk=RiskLevel(snap["current_risk"]),
                        risk_score=snap["risk_score"],
                        current_authorization_state=snap["current_authorization_state"],
                        authorization_state_hash=snap["authorization_state_hash"],
                        consecutive_face_failures=snap["consecutive_face_failures"],
                        warnings=tuple(snap.get("warnings", ())),
                        expression_hint=snap.get("expression_hint"),
                        timestamp=doc["timestamp"],
                        security_state=SecurityPostureState(snap.get("security_state", "normal")),
                        identity_state=IdentityCheckState(snap.get("identity_state", "no_face")),
                        reason_code=snap.get("reason_code"),
                        reason=snap.get("reason"),
                        audit_chain_intact=snap.get("audit_chain_intact", True),
                    ),
                )
            )
        return events


class MongoTrustedLocationRepository:
    """Mongo-backed `policy.geofence.TrustedLocationRepository`. One
    document per user, keyed by user id — `set()` always overwrites
    (upsert), never appends, so no location history accumulates."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, user_id: int) -> TrustedLocation | None:
        doc = self._db[TRUSTED_LOCATIONS_COLLECTION].find_one({"_id": user_id})
        if doc is None:
            return None
        established_at = doc["established_at"]
        if established_at.tzinfo is None:
            established_at = established_at.replace(tzinfo=timezone.utc)
        return TrustedLocation(
            user_id=user_id,
            latitude=doc["latitude"],
            longitude=doc["longitude"],
            accuracy_m=doc.get("accuracy_m"),
            established_at=established_at,
        )

    def set(self, location: TrustedLocation) -> TrustedLocation:
        self._db[TRUSTED_LOCATIONS_COLLECTION].find_one_and_update(
            {"_id": location.user_id},
            {
                "$set": {
                    "latitude": location.latitude,
                    "longitude": location.longitude,
                    "accuracy_m": location.accuracy_m,
                    "established_at": location.established_at,
                }
            },
            upsert=True,
        )
        return location

    def clear(self, user_id: int) -> None:
        self._db[TRUSTED_LOCATIONS_COLLECTION].delete_one({"_id": user_id})
