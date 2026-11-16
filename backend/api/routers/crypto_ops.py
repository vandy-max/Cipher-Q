"""Protected cryptographic operations. Keys never cross this API; authorization context is mandatory."""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from audit.events import AuditEvent
from audit.service import AuditLogService
from config import get_settings
from crypto import records as crec
from crypto import share_payload
from crypto.sharing import (SHARES_COLLECTION, authorization_metadata, find_record, record_expired,
                            record_expires_ts, sealed_context_matches, RECORD_VALIDITY_SECONDS)
from intent_engine.engine import Actor, EngineError, IntentEngine, OpenedContext, OperationRequest
from intent_engine.schema import ID_RE, RESOURCE_RE, Purpose
from keymgmt.key_sessions import KeySessionInfo, KeyUnavailableError
from security.ratelimit import limiter

from ..dependencies import get_actor, get_audit_service, get_db, get_intent_engine, get_user_repository

router = APIRouter(prefix="/api/crypto", tags=["crypto"])
RECORDS = "crypto_records"
_ID = Annotated[str, Field(pattern=ID_RE.pattern, max_length=128)]
_CTX = Annotated[str, Field(min_length=8, max_length=64)]


class EncryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: _CTX
    intent_id: Annotated[int, Field(ge=1)]
    resource: Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]
    purpose_code: Purpose
    session_id: _ID
    device_id: _ID
    key_session_id: Annotated[str, Field(min_length=8, max_length=64)]
    plaintext_base64: Annotated[str, Field(min_length=1, max_length=15_000_000)]


class DecryptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    context_id: _CTX
    intent_id: Annotated[int, Field(ge=1)]
    resource: Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]
    purpose_code: Purpose
    session_id: _ID
    device_id: _ID
    record_id: Annotated[str, Field(min_length=8, max_length=64)]


class ShareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent_id: Annotated[int, Field(ge=1)]
    resource: Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]
    purpose_code: Purpose
    session_id: _ID
    device_id: _ID
    record_id: Annotated[str, Field(min_length=8, max_length=64)]
    recipient_user_id: Annotated[int, Field(gt=0)] | None = None
    recipient_key_session_id: Annotated[str | None, Field(min_length=8, max_length=64)] = None
    # Optional Secure Sharing metadata. `kind` is sender-declared display metadata only (the authoritative
    # content type lives inside the encrypted envelope); expiry can only SHORTEN the existing bounds.
    kind: Literal["text", "file"] | None = None
    expires_in_minutes: Annotated[int | None, Field(ge=1, le=24 * 60)] = None


class ShareActivationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: _ID
    device_id: _ID


class ShareOpenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: _ID


class ShareReactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reaction: Literal["RECEIVED", "THANKS", "LIKE"]


class ShareMessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: _ID
    device_id: _ID
    text: Annotated[str, Field(min_length=1, max_length=500)]


class ShareRejectionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, Field(min_length=3, max_length=200)]


def _meta(rec: dict) -> dict:
    return {"record_id": rec["_id"], "resource": rec["resource"], "classification": rec["classification"],
            "size": rec["size"], "intent_id": rec["intent_id"], "key_session_id": rec["key_session_id"],
            "schema": rec["sealed"]["schema"], "created_ts": rec["created_ts"],
            "expires_ts": record_expires_ts(rec)}


def _share_meta(share: dict, names: dict | None = None) -> dict:
    names = names or {}
    return {"share_id": share["_id"], "record_id": share["source_record_id"],
            "owner_user_id": share["owner_user_id"], "recipient_user_id": share["recipient_user_id"],
            "owner_username": names.get(share["owner_user_id"]),
            "recipient_username": names.get(share["recipient_user_id"]),
            "intent_id": share["intent_id"], "purpose_code": share.get("purpose_code"),
            "resource": share["resource"], "classification": share.get("classification"),
            "size": share.get("size"), "key_session_id": share.get("key_session_id"), "status": share["status"],
            "kind": share.get("kind"), "created_ts": share["created_ts"], "expires_ts": record_expires_ts(share),
            "approved_ts": share.get("approved_ts"), "opened_ts": share.get("opened_ts"),
            "last_access_ts": share.get("last_access_ts"),
            "access_count": share.get("access_count", 0),
            "sender_reaction": share.get("sender_reaction"),
            "recipient_reaction": share.get("recipient_reaction")}


def _names(users, shares: list[dict]) -> dict:
    ids = {share[k] for share in shares for k in ("owner_user_id", "recipient_user_id")}
    out = {}
    for uid in ids:
        u = users.get_by_id(uid)
        if u is not None:
            out[uid] = u.username
    return out


_SHARE_LOCKS: dict[str, threading.Lock] = {}
_SHARE_LOCKS_GUARD = threading.Lock()


def _share_lock(key: str) -> threading.Lock:
    with _SHARE_LOCKS_GUARD:
        return _SHARE_LOCKS.setdefault(key, threading.Lock())


@router.get("/recipients")
def list_share_recipients(q: Annotated[str | None, Query(max_length=64)] = None,
                          actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    """Return minimal selectable identities (enabled users of this deployment); optional search by
    username or user ID. The server still binds shares to intent recipient IDs and re-checks eligibility."""
    needle = (q or "").strip().lower().lstrip("#")
    users = eng.d.users.list_all()
    return [{"user_id": u.id, "username": u.username, "role": u.role}
            for u in users if u.id != actor.user_id and not u.disabled
            and (not needle or needle in u.username.lower() or needle == str(u.id))]


def _intent_expiry(body: dict) -> int:
    return int(datetime.fromisoformat(body["valid_until"].replace("Z", "+00:00")).timestamp())


def _load_owned_source(db, actor: Actor, record_id: str) -> dict:
    record = db[RECORDS].find_one({"_id": record_id})
    if record is None or record.get("owner_user_id") != actor.user_id:
        raise HTTPException(404, "record not found")
    if not sealed_context_matches(record, shared=False):
        raise HTTPException(422, "record metadata failed authentication")
    if record_expired(record):
        raise HTTPException(410, "record expired")
    return record


def _share_intent(eng: IntentEngine, actor: Actor, intent_id: int) -> dict:
    head = eng.store.get_head(intent_id)
    if head is None or head["owner_user_id"] != actor.user_id:
        raise HTTPException(404, "intent not found")
    version = eng.store.get_version(intent_id, head["current_version"])
    if version is None:
        raise HTTPException(404, "intent not found")
    body = version["body"]
    operations = body.get("operations", [])
    if "share" not in operations or "encrypt" not in operations:
        raise HTTPException(403, "intent does not authorize secure sharing")
    return body


def _recipient_key_session(eng: IntentEngine, recipient_id: int, key_session_id: str) -> KeySessionInfo:
    recipient = eng.d.users.get_by_id(recipient_id)
    if recipient is None or recipient.disabled:
        raise HTTPException(404, "recipient not eligible")
    key_session = eng.d.keys.get(key_session_id, recipient_id)
    if key_session is None or key_session.status != "ACTIVE":
        raise HTTPException(409, "recipient key session is unavailable")
    return key_session


def _share_expiry(record: dict, body: dict, now: int) -> int:
    record_expiry = record_expires_ts(record)
    if record_expiry is None:
        raise HTTPException(410, "record expired")
    return min(record_expiry, _intent_expiry(body), now + RECORD_VALIDITY_SECONDS)


def _share_operation(record: dict, intent_id: int, resource: str, purpose_code: str,
                     session_id: str, device_id: str, recipient_id: int) -> OperationRequest:
    return OperationRequest(intent_id=intent_id, operation="share", resource=resource,
                            purpose_code=purpose_code, session_id=session_id, device_id=device_id,
                            intent_version=record.get("intent_version", record["sealed"]["static_ctx"]["intent_version"]),
                            key_session_id=record["key_session_id"], requested_bytes=record["size"],
                            record=authorization_metadata(record, shared=False),
                            recipient_user_id=recipient_id)


def _rewrap_for_recipient(eng: IntentEngine, opened: OpenedContext, record: dict, recipient_id: int,
                          recipient_key_session_id: str, generation: int) -> dict:
    recipient_qkey = b""
    try:
        recipient_qkey = eng.d.keys.unwrap(recipient_key_session_id, recipient_id, for_encrypt=True)
        return crec.rewrap(record["sealed"], opened.qkey, recipient_qkey,
                           recipient_key_session_id, generation)
    except KeyUnavailableError as exc:
        raise HTTPException(409, exc.code) from exc
    except crec.RecordError as exc:
        raise HTTPException(422, "record failed authentication") from exc
    finally:
        opened.qkey = b""
        recipient_qkey = b""


@router.post("/encrypt", status_code=201)
def encrypt(p: EncryptRequest, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine),
            db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service)):
    try:
        pt = base64.b64decode(p.plaintext_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(400, "plaintext_base64 is not valid base64") from exc
    if not pt:
        raise HTTPException(400, "empty plaintext")
    declared_len = len(pt)
    if share_payload.is_share_payload(pt) or share_payload.is_attachment_payload(pt):
        # File/message envelopes are canonicalised and content-validated server-side before sealing.
        # The authorization decision was made for declared_len bytes, so canonicalisation may not enlarge it.
        try:
            pt = (share_payload.validate_and_rebuild(pt) if share_payload.is_share_payload(pt)
                  else share_payload.validate_attachment_payload(pt))
            if len(pt) > declared_len:
                raise share_payload.SharePayloadError("payload is not in canonical form")
        except share_payload.SharePayloadError as exc:
            audit.record(AuditEvent.ENCRYPT_REJECTED, "rejected", user_id=actor.user_id, resource=p.resource,
                         operation="encrypt", reason="file/message payload rejected")
            raise HTTPException(422, str(exc)) from exc
    actual = OperationRequest(intent_id=p.intent_id, operation="encrypt", resource=p.resource,
                              purpose_code=p.purpose_code.value, session_id=p.session_id, device_id=p.device_id,
                              key_session_id=p.key_session_id, requested_bytes=declared_len)
    try:
        opened = eng.open_context(actor, p.context_id, actual)
    except EngineError as exc:
        audit.record(AuditEvent.ENCRYPT_REJECTED, "rejected", user_id=actor.user_id, resource=p.resource,
                     operation="encrypt", reason=exc.code)
        raise HTTPException(exc.status, exc.code) from exc
    ks = eng.d.keys.get(p.key_session_id, actor.user_id)
    rid = "rec_" + uuid.uuid4().hex
    body = opened.body
    sctx = crec.static_context(record_id=rid, owner_user_id=actor.user_id, intent_id=p.intent_id,
                               intent_version=opened.context["intent_version"],
                               intent_body_hash=opened.decision["intent_body_hash"], resource=p.resource,
                               classification=body["data_scope"]["classification"], size=len(pt))
    try:
        sealed = crec.seal(pt, opened.qkey, sctx, p.key_session_id, ks.generation if ks else 1)
    except Exception as exc:  # noqa: BLE001
        audit.record(AuditEvent.ENCRYPT_FAILURE, "failure", user_id=actor.user_id, resource=p.resource,
                     reason=type(exc).__name__)
        raise HTTPException(500, "encryption failed") from exc
    finally:
        opened.qkey = b""
    created_ts = int(time.time())
    # The record cannot outlive the approved intent window. Keeping this explicit
    # prevents a nominal 24-hour record TTL from contradicting a shorter intent.
    intent_expiry = _intent_expiry(body)
    expires_ts = min(created_ts + RECORD_VALIDITY_SECONDS, intent_expiry)
    if expires_ts <= created_ts:
        raise HTTPException(410, "intent validity window has ended")
    doc = {"_id": rid, "owner_user_id": actor.user_id, "resource": p.resource,
           "classification": body["data_scope"]["classification"], "size": len(pt), "intent_id": p.intent_id,
           "intent_version": opened.context["intent_version"], "key_session_id": p.key_session_id,
           "key_generation": ks.generation if ks else 1, "created_ts": created_ts,
           "expires_ts": expires_ts, "sealed": sealed}
    # BB84 simulation keys are non-reproducible. Keep this user's key material
    # available until the latest record using it expires, including after logout
    # or a device change. A revoked/corrupt/expired key is never silently replaced.
    if not eng.d.keys.extend_for_record(p.key_session_id, actor.user_id, expires_ts):
        opened.qkey = b""
        raise HTTPException(409, "key session is no longer active")
    db[RECORDS].insert_one(doc)
    audit.record(AuditEvent.ENCRYPT_SUCCESS, "success", user_id=actor.user_id, intent_hash=opened.decision["intent_body_hash"],
                 session_id=p.session_id, device_id=p.device_id, resource=p.resource, operation="encrypt",
                 reason=f"record={rid} decision={opened.decision['_id']} key_session={p.key_session_id}")
    return {**_meta(doc), "decision_id": opened.decision["_id"],
            "ciphertext_preview_b64": base64.b64encode(bytes(sealed["ciphertext"])[:32]).decode()}


@router.post("/decrypt")
def decrypt(p: DecryptRequest, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine),
            db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service)):
    rec, shared = find_record(db, p.record_id, include_shares=True)
    if rec is None:
        raise HTTPException(404, "record not found")
    if shared and rec.get("recipient_user_id") != actor.user_id:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec.get("resource"), reason=f"share={p.record_id} unavailable")
        raise HTTPException(404, "record not found")
    if not shared and rec.get("owner_user_id") != actor.user_id:
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec.get("resource"), operation="decrypt",
                     reason=f"record={p.record_id} ownership mismatch")
        raise HTTPException(403, "record authorization mismatch")
    if record_expired(rec):
        if shared and rec.get("status") in {"PENDING", "PENDING_ADMIN", "APPROVED"}:
            db[SHARES_COLLECTION].update_one(
                {"_id": p.record_id, "status": rec["status"]}, {"$set": {"status": "EXPIRED"}})
            audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id, resource=rec["resource"],
                         reason=f"share={p.record_id}")
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id, resource=rec["resource"],
                     operation="decrypt", reason=f"record={p.record_id} expired")
        raise HTTPException(410, "record expired")
    if shared and rec.get("status") != "APPROVED":
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec.get("resource"), reason=f"share={p.record_id} unavailable")
        raise HTTPException(404, "record not found")
    if shared and not eng.d.stepup.has_fresh_grant(actor.user_id, p.session_id):
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec.get("resource"), reason=f"share={p.record_id} recipient face step-up missing")
        raise HTTPException(403, "RECIPIENT_FACE_VERIFICATION_REQUIRED")
    if not sealed_context_matches(rec, shared=shared):
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec.get("resource"), operation="decrypt",
                     reason=f"record={p.record_id} metadata authentication failed")
        raise HTTPException(422, "record metadata failed authentication")
    if p.intent_id != rec.get("intent_id") or p.resource != rec.get("resource"):
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id,
                     resource=rec["resource"], operation="decrypt", reason=f"record={p.record_id} intent/resource mismatch")
        raise HTTPException(403, "record authorization mismatch")
    if shared:
        current = db[SHARES_COLLECTION].find_one({"_id": p.record_id})
        if current is None or current.get("recipient_user_id") != actor.user_id or current.get("status") != "APPROVED":
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={p.record_id} changed before access")
            raise HTTPException(404, "record not found")
        if record_expired(current):
            db[SHARES_COLLECTION].update_one(
                {"_id": p.record_id, "status": "APPROVED"}, {"$set": {"status": "EXPIRED"}})
            audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                         resource=current["resource"], reason=f"share={p.record_id}")
            raise HTTPException(410, "record expired")
        if (not sealed_context_matches(current, shared=True)
                or authorization_metadata(current, shared=True) != authorization_metadata(rec, shared=True)):
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={p.record_id} changed before access")
            raise HTTPException(409, "share state changed")
        rec = current
    meta = authorization_metadata(rec, shared=shared)
    actual = OperationRequest(intent_id=p.intent_id, operation="decrypt", resource=p.resource,
                              purpose_code=p.purpose_code.value, session_id=p.session_id, device_id=p.device_id,
                              key_session_id=rec["key_session_id"], requested_bytes=rec["size"], record=meta)
    try:
        opened = eng.open_context(actor, p.context_id, actual)
    except EngineError as exc:
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id, resource=p.resource,
                     operation="decrypt", reason=exc.code)
        raise HTTPException(exc.status, exc.code) from exc
    if shared:
        current = db[SHARES_COLLECTION].find_one({"_id": p.record_id})
        if current is None or current.get("recipient_user_id") != actor.user_id or current.get("status") != "APPROVED":
            opened.qkey = b""
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={p.record_id} revoked during access")
            raise HTTPException(404, "record not found")
        if record_expired(current) or authorization_metadata(current, shared=True) != meta:
            opened.qkey = b""
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={p.record_id} changed during access")
            raise HTTPException(410 if record_expired(current) else 409, "share state changed")
        rec = current
    try:
        pt = crec.open_(rec["sealed"], opened.qkey)
    except crec.RecordError:
        audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id, resource=p.resource,
                     operation="decrypt", reason=f"record={p.record_id} failed authentication")
        raise HTTPException(422, "record failed authentication") from None
    finally:
        opened.qkey = b""
    audit.record(AuditEvent.DECRYPT_SUCCESS, "success", user_id=actor.user_id,
                 intent_hash=opened.decision["intent_body_hash"], session_id=p.session_id, device_id=p.device_id,
                 resource=p.resource, operation="decrypt",
                 reason=f"record={p.record_id} decision={opened.decision['_id']}")
    if shared:
        db[SHARES_COLLECTION].update_one({"_id": p.record_id, "status": "APPROVED"},
                                         {"$inc": {"access_count": 1},
                                          "$set": {"last_access_ts": int(time.time())}})
        audit.record(AuditEvent.SHARE_ACCESS_SUCCESS, "success", user_id=actor.user_id,
                     intent_hash=opened.decision["intent_body_hash"], session_id=p.session_id,
                     device_id=p.device_id, resource=p.resource,
                     reason=f"share={p.record_id} sender={rec['owner_user_id']} recipient={actor.user_id}")
    return {"record_id": p.record_id, "plaintext_base64": base64.b64encode(pt).decode()}


# Only UNRESOLVED shares are de-duplicated (double clicks / client retries). A deliberate new share of a record
# that already has an approved one remains allowed, exactly as before.
_ACTIVE_SHARE = ["PENDING", "PENDING_ADMIN"]


@router.post("/shares")
def create_share(p: ShareRequest, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine),
                 db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service),
                 users=Depends(get_user_repository)):
    """Idempotent while unresolved: repeating the same request for a record+recipient that already has a share
    awaiting authorization/approval returns that share instead of creating (and re-wrapping for) a duplicate."""
    with _share_lock(p.record_id):
        source = _load_owned_source(db, actor, p.record_id)
        body = _share_intent(eng, actor, p.intent_id)
        existing = db[SHARES_COLLECTION].find_one(
            {"source_record_id": source["_id"], "owner_user_id": actor.user_id,
             "recipient_user_id": int(p.recipient_user_id or body.get("recipient_user_id") or 0),
              "status": {"$in": _ACTIVE_SHARE}})
        if existing is not None and not record_expired(existing):
            return JSONResponse(status_code=200, content={**_share_meta(existing, _names(users, [existing])),
                                                          "duplicate": True})
        resp = _create_share_impl(p, actor, eng, db, audit)
        if isinstance(resp, JSONResponse):
            created = db[SHARES_COLLECTION].find_one({"_id": json.loads(resp.body)["share_id"]})
            if created is not None:
                return JSONResponse(status_code=resp.status_code, content=_share_meta(created, _names(users, [created])))
        return resp


def _create_share_impl(p: ShareRequest, actor: Actor, eng: IntentEngine, db, audit: AuditLogService):
    source = _load_owned_source(db, actor, p.record_id)
    body = _share_intent(eng, actor, p.intent_id)
    selected_recipient = p.recipient_user_id if p.recipient_user_id is not None else body.get("recipient_user_id")
    if selected_recipient is None:
        raise HTTPException(422, "select a recipient for this secure share")
    recipient_id = int(selected_recipient)
    if body.get("recipient_user_id") is not None and int(body["recipient_user_id"]) != recipient_id:
        raise HTTPException(422, "selected recipient does not match the legacy intent recipient binding")
    recipient = eng.d.users.get_by_id(recipient_id)
    if recipient is None or recipient.disabled:
        raise HTTPException(404, "recipient not eligible")
    if recipient_id == actor.user_id:
        raise HTTPException(422, "sharing with yourself is not supported")
    if (source.get("intent_id") != p.intent_id or source.get("resource") != p.resource
            or source.get("intent_version", source["sealed"]["static_ctx"]["intent_version"]) != body["version"]):
        raise HTTPException(403, "record is not bound to this sharing intent")
    actual = _share_operation(source, p.intent_id, p.resource, p.purpose_code.value,
                              p.session_id, p.device_id, recipient_id)
    try:
        outcome = eng.decide(actor, actual)
    except EngineError as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=p.resource, operation="share", reason=exc.code)
        raise HTTPException(exc.status, exc.code) from exc

    # Provision a recipient-owned session automatically when needed. Key material stays
    # backend-side and is wrapped by the existing QKEY_WRAP keyring protection.
    # Explicit IDs remain supported for backwards compatibility.
    recipient_key_session_id = p.recipient_key_session_id
    try:
        if recipient_key_session_id:
            key_session = _recipient_key_session(eng, recipient_id, recipient_key_session_id)
        else:
            active_sessions = [item for item in eng.d.keys.list_for_user(recipient_id)
                               if item.status == "ACTIVE"]
            if active_sessions:
                key_session = active_sessions[0]
            else:
                # Share the ordinary key-session creation quota; sharing cannot bypass
                # the recipient's per-hour key-establishment limit.
                settings = get_settings()
                allowed, retry_after = limiter.check(
                    f"qks-user:{recipient_id}", settings.quantum_per_user_per_hour, 3600
                )
                if not allowed:
                    raise HTTPException(429, "recipient key-establishment rate limit reached",
                                        headers={"Retry-After": str(int(retry_after) + 1)})
                key_session = eng.d.keys.create(recipient_id)
                if key_session.status != "ACTIVE":
                    raise HTTPException(409, "recipient key establishment failed; no key was issued")
                audit.record(AuditEvent.KEY_SESSION_CREATED, "success", user_id=recipient_id,
                             reason=f"recipient key session provisioned automatically for secure share from user={actor.user_id}")
            recipient_key_session_id = key_session.key_session_id
    except HTTPException as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=p.resource, operation="share",
                     reason=f"recipient={recipient_id} key session unavailable")
        raise exc

    now = int(time.time())
    expires_ts = _share_expiry(source, body, now)
    if p.expires_in_minutes:  # sender-chosen expiry can only shorten the policy/record/intent bounds
        expires_ts = min(expires_ts, now + p.expires_in_minutes * 60)
    if expires_ts <= now:
        raise HTTPException(410, "record or intent expired")
    # Retain the recipient-owned key only through the share's computed validity window.
    if not eng.d.keys.extend_for_record(recipient_key_session_id, recipient_id, expires_ts):
        raise HTTPException(409, "recipient key session could not be retained for the share")
    share_id = "shr_" + uuid.uuid4().hex
    if outcome.outcome == "REQUIRE_APPROVAL":
        share = {"_id": share_id, "owner_user_id": actor.user_id, "recipient_user_id": recipient_id,
                 "source_record_id": source["_id"], "intent_id": p.intent_id, "intent_version": body["version"],
                 "purpose_code": body["purpose_code"], "resource": source["resource"], "classification": source["classification"], "size": source["size"],
                 "key_session_id": recipient_key_session_id, "key_generation": key_session.generation,
                 "created_ts": now, "expires_ts": expires_ts, "status": "PENDING", "sealed": None,
                 "access_count": 0, "kind": p.kind}
        db[SHARES_COLLECTION].insert_one(share)
        audit.record(AuditEvent.SHARE_PENDING, "success", user_id=actor.user_id, resource=source["resource"],
                     operation="share",
                     reason=f"share={share_id} sender={actor.user_id} recipient={recipient_id} intent={p.intent_id}")
        return JSONResponse(status_code=202, content=_share_meta(share))
    if outcome.outcome != "PERMIT":
        codes = [reason.code for reason in outcome.reasons]
        if "APPROVAL_REJECTED" in codes:
            share = {"_id": share_id, "owner_user_id": actor.user_id, "recipient_user_id": recipient_id,
                     "source_record_id": source["_id"], "intent_id": p.intent_id,
                     "intent_version": body["version"], "purpose_code": body["purpose_code"], "resource": source["resource"],
                     "classification": source["classification"], "size": source["size"],
                     "key_session_id": recipient_key_session_id, "key_generation": key_session.generation,
                     "created_ts": now, "expires_ts": expires_ts, "status": "REJECTED", "sealed": None,
                     "access_count": 0, "kind": p.kind}
            db[SHARES_COLLECTION].insert_one(share)
            audit.record(AuditEvent.SHARE_REJECTED, "rejected", user_id=actor.user_id,
                         resource=source["resource"], operation="share", reason=f"share={share_id} approval rejected")
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=source["resource"], operation="share",
                     reason=f"record={source['_id']} codes={codes}")
        raise HTTPException(403, {"code": "SHARE_NOT_AUTHORIZED", "reasons": codes})

    try:
        opened = eng.open_context(actor, outcome.context_id or "", actual)
    except EngineError as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=source["resource"], operation="share", reason=exc.code)
        raise HTTPException(exc.status, exc.code) from exc
    try:
        sealed = _rewrap_for_recipient(eng, opened, source, recipient_id, recipient_key_session_id,
                                       key_session.generation)
    except HTTPException as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "failure", user_id=actor.user_id,
                     resource=source["resource"], operation="share", reason="recipient key rewrap failed")
        raise exc
    share = {"_id": share_id, "owner_user_id": actor.user_id, "recipient_user_id": recipient_id,
             "source_record_id": source["_id"], "intent_id": p.intent_id, "intent_version": body["version"],
             "purpose_code": body["purpose_code"], "resource": source["resource"], "classification": source["classification"], "size": source["size"],
             "key_session_id": recipient_key_session_id, "key_generation": key_session.generation,
             "created_ts": now, "expires_ts": expires_ts, "status": "APPROVED", "sealed": sealed,
             "access_count": 0, "kind": p.kind, "sender_authorized_ts": int(time.time()),
             "approved_ts": now, "delivery_mode": "POLICY_PERMIT"}
    db[SHARES_COLLECTION].insert_one(share)
    audit.record(AuditEvent.SHARE_DELIVERED, "success", user_id=actor.user_id,
                 intent_hash=outcome.decision["intent_body_hash"], session_id=p.session_id,
                 device_id=p.device_id, resource=p.resource, operation="share",
                 reason=f"share={share_id} immediately delivered by approved policy sender={actor.user_id} recipient={recipient_id}")
    return JSONResponse(status_code=202, content=_share_meta(share))


@router.post("/shares/{share_id}/activate")
def activate_share(share_id: str, p: ShareActivationRequest, actor: Actor = Depends(get_actor),
                   eng: IntentEngine = Depends(get_intent_engine), db=Depends(get_db),
                   audit: AuditLogService = Depends(get_audit_service)):
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if share is None or share.get("owner_user_id") != actor.user_id:
        raise HTTPException(404, "share not found")
    if share.get("status") != "PENDING":
        raise HTTPException(409, "share is not pending")
    if record_expired(share):
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING"},
                                         {"$set": {"status": "EXPIRED"}})
        audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                     resource=share["resource"], reason=f"share={share_id}")
        raise HTTPException(410, "share expired")
    source = _load_owned_source(db, actor, share["source_record_id"])
    body = _share_intent(eng, actor, share["intent_id"])
    if ((body.get("recipient_user_id") is not None
             and body.get("recipient_user_id") != share["recipient_user_id"])
            or body["version"] != share["intent_version"]
            or source.get("intent_id") != share["intent_id"]):
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING"},
                                         {"$set": {"status": "REJECTED"}})
        audit.record(AuditEvent.SHARE_REJECTED, "rejected", user_id=actor.user_id,
                     resource=share["resource"], reason=f"share={share_id} intent binding changed")
        raise HTTPException(403, "share intent changed")
    try:
        key_session = _recipient_key_session(eng, share["recipient_user_id"], share["key_session_id"])
    except HTTPException as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=share["resource"], operation="share",
                     reason=f"share={share_id} recipient key session unavailable")
        raise exc
    actual = _share_operation(source, share["intent_id"], share["resource"], body["purpose_code"],
                              p.session_id, p.device_id, share["recipient_user_id"])
    try:
        outcome = eng.decide(actor, actual)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    if outcome.outcome == "REQUIRE_APPROVAL":
        return JSONResponse(status_code=202, content=_share_meta(share))
    if outcome.outcome != "PERMIT":
        codes = {reason.code for reason in outcome.reasons}
        new_status = "EXPIRED" if "INTENT_EXPIRED" in codes else (
            "REVOKED" if "INTENT_REVOKED" in codes else "REJECTED")
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING"},
                                         {"$set": {"status": new_status}})
        audit.record(AuditEvent.SHARE_REJECTED, "rejected", user_id=actor.user_id,
                     resource=share["resource"], reason=f"share={share_id} codes={sorted(codes)}")
        raise HTTPException(403, {"code": "SHARE_NOT_AUTHORIZED", "reasons": sorted(codes)})
    try:
        opened = eng.open_context(actor, outcome.context_id or "", actual)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    try:
        sealed = _rewrap_for_recipient(eng, opened, source, share["recipient_user_id"], share["key_session_id"],
                                       key_session.generation)
    except HTTPException as exc:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "failure", user_id=actor.user_id,
                     resource=share["resource"], operation="share",
                     reason=f"share={share_id} recipient key rewrap failed")
        raise exc
    updated = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "status": "PENDING"},
        {"$set": {"status": "PENDING_ADMIN", "sealed": sealed, "sender_authorized_ts": int(time.time()),
                  "key_generation": key_session.generation}})
    if not updated.matched_count:
        raise HTTPException(409, "share state changed")
    share.update({"status": "PENDING_ADMIN", "sealed": sealed, "sender_authorized_ts": int(time.time()),
                  "key_generation": key_session.generation})
    audit.record(AuditEvent.SHARE_PENDING, "success", user_id=actor.user_id,
                 intent_hash=outcome.decision["intent_body_hash"], session_id=p.session_id,
                 device_id=p.device_id, resource=share["resource"], operation="share",
                 reason=f"share={share_id} sender authorized; awaiting administrator approval")
    return _share_meta(share)


@router.get("/shares/admin/pending")
def list_pending_share_approvals(actor: Actor = Depends(get_actor), db=Depends(get_db),
                                 users=Depends(get_user_repository)):
    if actor.role != "ADMIN":
        raise HTTPException(403, "administrator role required")
    now = int(time.time())
    items = []
    for share in db[SHARES_COLLECTION].find({"status": "PENDING_ADMIN"}).sort("created_ts", 1):
        if record_expired(share, now):
            db[SHARES_COLLECTION].update_one({"_id": share["_id"], "status": "PENDING_ADMIN"},
                                             {"$set": {"status": "EXPIRED"}})
            continue
        items.append(share)
    names = _names(users, items)
    return [_share_meta(share, names) for share in items]


@router.post("/shares/{share_id}/admin-approve")
def admin_approve_share(share_id: str, actor: Actor = Depends(get_actor), db=Depends(get_db),
                        eng: IntentEngine = Depends(get_intent_engine),
                        audit: AuditLogService = Depends(get_audit_service)):
    if actor.role != "ADMIN":
        raise HTTPException(403, "administrator role required")
    share = db[SHARES_COLLECTION].find_one({"_id": share_id, "status": "PENDING_ADMIN"})
    if share is None or not isinstance(share.get("sealed"), dict):
        raise HTTPException(404, "pending share not found")
    if record_expired(share):
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING_ADMIN"},
                                         {"$set": {"status": "EXPIRED"}})
        audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                     resource=share.get("resource"), reason=f"share={share_id}")
        raise HTTPException(410, "share expired")
    recipient = eng.d.users.get_by_id(share["recipient_user_id"])
    if recipient is None or recipient.disabled:
        raise HTTPException(409, "recipient is no longer eligible")
    source = db[RECORDS].find_one({"_id": share["source_record_id"], "owner_user_id": share["owner_user_id"]})
    if source is None or record_expired(source) or not sealed_context_matches(source, shared=False):
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING_ADMIN"},
                                         {"$set": {"status": "REJECTED"}})
        raise HTTPException(409, "source record is no longer eligible for sharing")
    head = eng.store.get_head(share["intent_id"])
    if head is None or head.get("current_version") != share.get("intent_version"):
        db[SHARES_COLLECTION].update_one({"_id": share_id, "status": "PENDING_ADMIN"},
                                         {"$set": {"status": "REJECTED"}})
        raise HTTPException(409, "sharing intent changed; create a new sharing request")
    # The sender must have completed the existing share authorization and key rewrap first.
    changed = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "status": "PENDING_ADMIN", "recipient_user_id": share["recipient_user_id"],
         "source_record_id": share["source_record_id"]},
        {"$set": {"status": "APPROVED", "approved_ts": int(time.time()), "approved_by_user_id": actor.user_id}})
    if not changed.matched_count:
        raise HTTPException(409, "share state changed; refresh and retry")
    audit.record(AuditEvent.SHARE_APPROVED, "success", user_id=actor.user_id, resource=share["resource"],
                 operation="share", reason=f"share={share_id} administrator approved sender={share['owner_user_id']} recipient={share['recipient_user_id']}")
    share["status"] = "APPROVED"
    return _share_meta(share)


@router.post("/shares/{share_id}/reject")
def reject_share(share_id: str, p: ShareRejectionRequest, actor: Actor = Depends(get_actor),
                 db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service)):
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if (share is None or share.get("recipient_user_id") != actor.user_id
            or share.get("status") not in {"PENDING", "PENDING_ADMIN", "APPROVED"}
            or (share.get("status") == "APPROVED" and (share.get("opened_ts") or share.get("access_count", 0) > 0))):
        raise HTTPException(404, "share not found")
    result = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "recipient_user_id": actor.user_id,
         "status": {"$in": ["PENDING", "PENDING_ADMIN", "APPROVED"]},
         "opened_ts": {"$exists": False}, "access_count": 0},
        {"$set": {"status": "REJECTED", "rejected_ts": int(time.time()), "rejection_reason": p.reason}})
    if not result.matched_count:
        raise HTTPException(409, "share state changed")
    audit.record(AuditEvent.SHARE_REJECTED, "success", user_id=actor.user_id, resource=share["resource"],
                 reason=f"share={share_id} sender={share['owner_user_id']} recipient={actor.user_id}: {p.reason}")
    return {"share_id": share_id, "status": "REJECTED"}


def _thread_dek(share: dict, actor: Actor, session_id: str, device_id: str,
                eng: IntentEngine, db) -> bytes:
    """Release the shared DEK only after current intent authorization and fresh face step-up."""
    if share.get("status") != "APPROVED" or record_expired(share):
        raise HTTPException(404, "share not found")
    if actor.user_id not in {share.get("owner_user_id"), share.get("recipient_user_id")}:
        raise HTTPException(404, "share not found")
    if not eng.d.stepup.has_fresh_grant(actor.user_id, session_id):
        raise HTTPException(403, "FACE_VERIFICATION_REQUIRED_FOR_CONVERSATION")

    is_sender = actor.user_id == share.get("owner_user_id")
    if is_sender:
        record = db[RECORDS].find_one({"_id": share["source_record_id"], "owner_user_id": actor.user_id})
        shared = False
    else:
        record, shared = share, True
    if record is None or not sealed_context_matches(record, shared=shared) or record_expired(record):
        raise HTTPException(410, "shared record is no longer available")

    actual = OperationRequest(
        intent_id=share["intent_id"], operation="decrypt", resource=share["resource"],
        purpose_code=share["purpose_code"], session_id=session_id, device_id=device_id,
        key_session_id=record["key_session_id"], requested_bytes=record["size"],
        record=authorization_metadata(record, shared=shared))
    try:
        outcome = eng.decide(actor, actual)
        if outcome.outcome != "PERMIT" or not outcome.context_id:
            codes = [reason.code for reason in outcome.reasons]
            raise HTTPException(403, {"code": "CONVERSATION_NOT_AUTHORIZED", "reasons": codes})
        opened = eng.open_context(actor, outcome.context_id, actual)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    try:
        return crec.unwrap_dek(record["sealed"], opened.qkey)
    except crec.RecordError as exc:
        raise HTTPException(422, "shared record failed authentication") from exc
    finally:
        opened.qkey = b""


def _thread_key(dek: bytes, share_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=share_id.encode("utf-8"),
                info=b"CIPHERQ|SHARE-THREAD|v1").derive(dek)


def _thread_aad(share_id: str, message_id: str, sender_id: int) -> bytes:
    return f"CIPHERQ|SHARE-MESSAGE|v1|{share_id}|{message_id}|{sender_id}".encode("utf-8")


def _sentence_count(text: str) -> int:
    return len([part for part in re.findall(r"[^.!?]+(?:[.!?]+|$)", text) if part.strip()])


@router.get("/shares/{share_id}/messages")
def list_share_messages(share_id: str, session_id: _ID, device_id: _ID,
                        actor: Actor = Depends(get_actor), db=Depends(get_db),
                        eng: IntentEngine = Depends(get_intent_engine),
                        audit: AuditLogService = Depends(get_audit_service)):
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if share is None or actor.user_id not in {share.get("owner_user_id"), share.get("recipient_user_id")}:
        raise HTTPException(404, "share not found")
    dek = _thread_key(_thread_dek(share, actor, session_id, device_id, eng, db), share_id)
    messages = []
    for item in db["crypto_share_messages"].find({"share_id": share_id}).sort("created_ts", 1):
        try:
            plain = AESGCM(dek).decrypt(bytes(item["nonce"]), bytes(item["ciphertext"]),
                                        _thread_aad(share_id, item["_id"], item["sender_user_id"]))
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(422, "conversation integrity verification failed") from exc
        messages.append({"message_id": item["_id"], "sender_user_id": item["sender_user_id"],
                         "created_ts": item["created_ts"], "text": plain.decode("utf-8")})
    audit.record("SHARE_MESSAGE_READ", "success", user_id=actor.user_id,
                 resource=share.get("resource"), operation="share", reason=f"share={share_id} messages={len(messages)}")
    return messages


@router.post("/shares/{share_id}/messages", status_code=201)
def send_share_message(share_id: str, p: ShareMessageRequest, actor: Actor = Depends(get_actor),
                       db=Depends(get_db), eng: IntentEngine = Depends(get_intent_engine),
                       audit: AuditLogService = Depends(get_audit_service)):
    text = p.text.strip()
    if not text or _sentence_count(text) > 3:
        raise HTTPException(422, "conversation replies are limited to three sentences and 500 characters")
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if share is None or actor.user_id not in {share.get("owner_user_id"), share.get("recipient_user_id")}:
        raise HTTPException(404, "share not found")
    if db["crypto_share_messages"].count_documents({"share_id": share_id}) >= 40:
        raise HTTPException(429, "conversation message limit reached")
    dek = _thread_key(_thread_dek(share, actor, p.session_id, p.device_id, eng, db), share_id)
    message_id = "msg_" + uuid.uuid4().hex
    created_ts = int(time.time())
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, text.encode("utf-8"), _thread_aad(share_id, message_id, actor.user_id))
    db["crypto_share_messages"].insert_one({"_id": message_id, "share_id": share_id,
        "sender_user_id": actor.user_id, "created_ts": created_ts, "nonce": nonce, "ciphertext": ciphertext})
    audit.record("SHARE_MESSAGE_SENT", "success", user_id=actor.user_id, resource=share.get("resource"),
                 operation="share", reason=f"share={share_id} encrypted conversation message={message_id}")
    return {"message_id": message_id, "sender_user_id": actor.user_id, "created_ts": created_ts, "text": text}


@router.post("/shares/{share_id}/reaction")
def react_to_share(share_id: str, p: ShareReactionRequest, actor: Actor = Depends(get_actor),
                   db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service),
                   users=Depends(get_user_repository)):
    """Record a small, non-content acknowledgement from either participant."""
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if (share is None or actor.user_id not in {share.get("owner_user_id"), share.get("recipient_user_id")}
            or share.get("status") != "APPROVED" or record_expired(share)):
        raise HTTPException(404, "share not found")
    field = "sender_reaction" if actor.user_id == share["owner_user_id"] else "recipient_reaction"
    now = int(time.time())
    updated = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "status": "APPROVED", "expires_ts": {"$gt": now}},
        {"$set": {field: p.reaction, f"{field}_ts": now}})
    if not updated.matched_count:
        raise HTTPException(409, "share is no longer available")
    audit.record(AuditEvent.SHARE_REACTION, "success", user_id=actor.user_id,
                 resource=share.get("resource"), operation="share", reason=f"share={share_id} reaction={p.reaction}")
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    return _share_meta(share, _names(users, [share]))


@router.post("/shares/{share_id}/revoke")
def revoke_share(share_id: str, p: ShareRejectionRequest, actor: Actor = Depends(get_actor),
                 db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service)):
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if share is None or share.get("owner_user_id") != actor.user_id:
        raise HTTPException(404, "share not found")
    result = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "owner_user_id": actor.user_id, "status": {"$in": ["PENDING", "PENDING_ADMIN", "APPROVED"]}},
        {"$set": {"status": "REVOKED", "revoked_ts": int(time.time()), "revocation_reason": p.reason}})
    if not result.matched_count:
        raise HTTPException(409, "share is no longer revocable")
    audit.record(AuditEvent.SHARE_REVOKED, "success", user_id=actor.user_id, resource=share["resource"],
                 reason=f"share={share_id} sender={actor.user_id} recipient={share['recipient_user_id']}: {p.reason}")
    return {"share_id": share_id, "status": "REVOKED"}


@router.get("/shares")
def list_shares(actor: Actor = Depends(get_actor), db=Depends(get_db),
                audit: AuditLogService = Depends(get_audit_service), users=Depends(get_user_repository)):
    now = int(time.time())
    shares = []
    for share in db[SHARES_COLLECTION].find(
            {"$or": [{"owner_user_id": actor.user_id}, {"recipient_user_id": actor.user_id}]}).sort("created_ts", -1):
        if share["status"] in {"PENDING", "PENDING_ADMIN", "APPROVED"} and record_expired(share, now):
            db[SHARES_COLLECTION].update_one(
                {"_id": share["_id"], "status": share["status"]}, {"$set": {"status": "EXPIRED"}})
            audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                         resource=share["resource"], reason=f"share={share['_id']}")
            share["status"] = "EXPIRED"
        shares.append(share)
    names = _names(users, shares)
    return [_share_meta(share, names) for share in shares]


@router.get("/shares/{share_id}")
def get_share(share_id: str, actor: Actor = Depends(get_actor), db=Depends(get_db),
              audit: AuditLogService = Depends(get_audit_service), users=Depends(get_user_repository)):
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if share is None or actor.user_id not in {share.get("owner_user_id"), share.get("recipient_user_id")}:
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     reason=f"share={share_id} not available")
        raise HTTPException(404, "share not found")
    if share["status"] in {"PENDING", "PENDING_ADMIN", "APPROVED"} and record_expired(share):
        updated = db[SHARES_COLLECTION].update_one(
            {"_id": share_id, "status": share["status"]}, {"$set": {"status": "EXPIRED"}})
        if updated.matched_count:
            share["status"] = "EXPIRED"
            audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                         resource=share["resource"], reason=f"share={share_id}")
    return _share_meta(share, _names(users, [share]))


@router.post("/shares/{share_id}/open")
def open_share(share_id: str, p: ShareOpenRequest, actor: Actor = Depends(get_actor), db=Depends(get_db),
               eng: IntentEngine = Depends(get_intent_engine),
               audit: AuditLogService = Depends(get_audit_service), users=Depends(get_user_repository)):
    """Recipient acknowledges an available share (records the first time it was opened; no plaintext)."""
    share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    if (share is None or share.get("recipient_user_id") != actor.user_id or share.get("status") != "APPROVED"
            or record_expired(share)):
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     reason=f"share={share_id} not available")
        raise HTTPException(404, "share not found")
    if not eng.d.stepup.has_fresh_grant(actor.user_id, p.session_id):
        audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                     resource=share.get("resource"), reason=f"share={share_id} recipient face step-up missing")
        raise HTTPException(403, "RECIPIENT_FACE_VERIFICATION_REQUIRED")
    first = db[SHARES_COLLECTION].update_one(
        {"_id": share_id, "recipient_user_id": actor.user_id, "status": "APPROVED", "opened_ts": {"$exists": False}},
        {"$set": {"opened_ts": int(time.time())}})
    if first.matched_count:
        audit.record(AuditEvent.SHARE_OPENED, "success", user_id=actor.user_id, resource=share["resource"],
                     reason=f"share={share_id} sender={share['owner_user_id']} recipient={actor.user_id}")
        share = db[SHARES_COLLECTION].find_one({"_id": share_id})
    return _share_meta(share, _names(users, [share]))


@router.get("/records")
def list_records(actor: Actor = Depends(get_actor), db=Depends(get_db)):
    return [_meta(r) for r in db[RECORDS].find({"owner_user_id": actor.user_id}).sort("created_ts", -1)]


@router.get("/records/{record_id}")
def get_record(record_id: str, actor: Actor = Depends(get_actor), db=Depends(get_db)):
    r = db[RECORDS].find_one({"_id": record_id})
    if r is None or r["owner_user_id"] != actor.user_id:
        raise HTTPException(404, "record not found")
    return _meta(r)
