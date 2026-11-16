"""Simple authenticated encrypted user-to-user messaging.

This is intentionally separate from CipherQ's intent-bound crypto workflows. It adds a
small messaging path without changing existing intent, encryption, decryption, monitoring,
RBAC, QKD, or audit endpoints. Messages are AES-256-GCM encrypted with a fresh per-message
DEK. The DEK is separately wrapped for the sender and recipient using a purpose-separated
application key. Both participants can decrypt while the message is valid; only the sender
can revoke. This is server-side managed encryption, not end-to-end encryption.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import time
import uuid
from pathlib import PurePosixPath
from typing import Annotated, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator

from audit.service import AuditLogService
from intent_engine.engine import Actor
from security.keyring import DIRECT_MESSAGE_WRAP, Keyring, get_keyring
from ..dependencies import get_actor, get_audit_service, get_db, get_user_repository

router = APIRouter(prefix="/api/messages", tags=["messages"])
COLLECTION = "secure_messages"
MAX_ATTACHMENT_BYTES = 1 * 1024 * 1024
MAX_TEXT_CHARS = 20_000
MAX_TTL_MINUTES = 24 * 60


class MessageCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient_user_id: Annotated[int, Field(ge=1)]
    kind: Literal["text", "file"]
    subject: Annotated[str, Field(max_length=120)] = ""
    text: Annotated[str, Field(max_length=MAX_TEXT_CHARS)] | None = None
    filename: Annotated[str, Field(max_length=255)] | None = None
    mime_type: Annotated[str, Field(max_length=128)] | None = None
    file_base64: Annotated[str, Field(max_length=1_500_000)] | None = None
    expires_in_minutes: Annotated[int, Field(ge=1, le=MAX_TTL_MINUTES)] = MAX_TTL_MINUTES

    @model_validator(mode="after")
    def validate_content(self):
        if self.kind == "text":
            if not (self.text or "").strip():
                raise ValueError("message text is required")
            if self.filename or self.file_base64:
                raise ValueError("text messages cannot include file fields")
        else:
            if not self.filename or not self.file_base64:
                raise ValueError("file name and file data are required")
        return self


class RevokeMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, Field(min_length=3, max_length=200)] = "Sender revoked access"


def _aad(message_id: str, sender_id: int, recipient_id: int, created_ts: int,
         expires_ts: int, kid: int) -> bytes:
    return (f"CIPHERQ|DIRECT-MESSAGE|v1|{message_id}|{sender_id}|{recipient_id}|"
            f"{created_ts}|{expires_ts}|{kid}").encode("utf-8")


def _wrap_aad(message_id: str, user_id: int, kid: int) -> bytes:
    return f"CIPHERQ|DIRECT-MESSAGE-DEK|v1|{message_id}|{user_id}|{kid}".encode("utf-8")


def _user_wrap_key(keyring: Keyring, kid: int, message_id: str, user_id: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=message_id.encode("utf-8"),
                info=f"CIPHERQ|DIRECT-MESSAGE-WRAP|v1|user:{user_id}".encode("utf-8")
                ).derive(keyring.subkey(DIRECT_MESSAGE_WRAP, kid))


def _wrap_dek(keyring: Keyring, kid: int, message_id: str, user_id: int, dek: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    wrapped = AESGCM(_user_wrap_key(keyring, kid, message_id, user_id)).encrypt(
        nonce, dek, _wrap_aad(message_id, user_id, kid))
    return nonce, wrapped


def _unwrap_dek(keyring: Keyring, doc: dict, user_id: int) -> bytes:
    prefix = "sender" if user_id == doc["sender_user_id"] else "recipient"
    nonce = doc.get(f"{prefix}_wrap_nonce")
    wrapped = doc.get(f"{prefix}_wrapped_dek")
    if nonce is None or wrapped is None:
        raise HTTPException(422, "message key envelope is unavailable")
    try:
        return AESGCM(_user_wrap_key(keyring, int(doc["kid"]), doc["_id"], user_id)).decrypt(
            bytes(nonce), bytes(wrapped), _wrap_aad(doc["_id"], user_id, int(doc["kid"])))
    except (InvalidTag, KeyError, ValueError) as exc:
        raise HTTPException(422, "message key integrity check failed") from exc


def _public(doc: dict, users_by_id: dict[int, str], viewer_id: int) -> dict:
    return {
        "message_id": doc["_id"],
        "sender_user_id": doc["sender_user_id"],
        "sender_username": users_by_id.get(doc["sender_user_id"], f"User #{doc['sender_user_id']}"),
        "recipient_user_id": doc["recipient_user_id"],
        "recipient_username": users_by_id.get(doc["recipient_user_id"], f"User #{doc['recipient_user_id']}"),
        "kind": doc["kind"],
        "size": doc["size"],
        "created_ts": doc["created_ts"],
        "expires_ts": doc["expires_ts"],
        "status": doc["status"],
        "read_ts": doc.get("read_ts"),
        "is_unread": viewer_id == doc["recipient_user_id"] and doc["status"] == "DELIVERED",
        "revoked_ts": doc.get("revoked_ts"),
    }


def _load_participant(db, message_id: str, actor: Actor) -> dict:
    doc = db[COLLECTION].find_one({"_id": message_id})
    if doc is None or actor.user_id not in {doc.get("sender_user_id"), doc.get("recipient_user_id")}:
        raise HTTPException(404, "message not found")
    return doc


@router.get("/recipients")
def recipients(q: Annotated[str | None, Query(max_length=64)] = None,
              actor: Actor = Depends(get_actor), users=Depends(get_user_repository)):
    needle = (q or "").strip().lower().lstrip("#")
    results = []
    for user in users.list_all():
        if user.id == actor.user_id or user.disabled:
            continue
        if needle and needle not in user.username.lower() and needle != str(user.id):
            continue
        results.append({"user_id": user.id, "username": user.username})
    return results


@router.get("")
def list_messages(folder: Literal["inbox", "sent"] = "inbox", actor: Actor = Depends(get_actor),
                  db=Depends(get_db), users=Depends(get_user_repository)):
    field = "recipient_user_id" if folder == "inbox" else "sender_user_id"
    docs = list(db[COLLECTION].find({field: actor.user_id}).sort("created_ts", -1).limit(200))
    ids = {d["sender_user_id"] for d in docs} | {d["recipient_user_id"] for d in docs}
    names = {u.id: u.username for u in users.list_all() if u.id in ids}
    now = int(time.time())
    out = []
    for doc in docs:
        if doc["status"] not in {"REVOKED", "EXPIRED"} and doc["expires_ts"] <= now:
            db[COLLECTION].update_one({"_id": doc["_id"], "status": {"$nin": ["REVOKED", "EXPIRED"]}},
                                      {"$set": {"status": "EXPIRED"}})
            doc["status"] = "EXPIRED"
        out.append(_public(doc, names, actor.user_id))
    return out


@router.post("", status_code=201)
def send_message(p: MessageCreate, actor: Actor = Depends(get_actor), db=Depends(get_db),
                 users=Depends(get_user_repository), keyring: Keyring = Depends(get_keyring),
                 audit: AuditLogService = Depends(get_audit_service)):
    if p.recipient_user_id == actor.user_id:
        raise HTTPException(422, "choose another user as the recipient")
    recipient = users.get_by_id(p.recipient_user_id)
    if recipient is None or recipient.disabled:
        raise HTTPException(404, "recipient not found")

    created_ts = int(time.time())
    expires_ts = created_ts + int(p.expires_in_minutes) * 60
    message_id = "msg_" + uuid.uuid4().hex
    if p.kind == "text":
        payload = {"kind": "text", "subject": p.subject.strip(), "text": (p.text or "").strip()}
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        size = len(plain)
        if size > MAX_TEXT_CHARS * 4:
            raise HTTPException(413, "message is too large")
    else:
        try:
            file_bytes = base64.b64decode(p.file_base64 or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(400, "file data is not valid base64") from exc
        if not file_bytes:
            raise HTTPException(400, "empty files cannot be sent")
        if len(file_bytes) > MAX_ATTACHMENT_BYTES:
            raise HTTPException(413, "attachments are limited to 1 MB")
        safe_name = PurePosixPath((p.filename or "attachment.bin").replace("\\", "/")).name
        if not safe_name or safe_name in {".", ".."}:
            raise HTTPException(422, "invalid file name")
        payload = {"kind": "file", "subject": p.subject.strip(), "text": (p.text or "").strip(),
                   "filename": safe_name, "mime_type": (p.mime_type or "application/octet-stream")[:128],
                   "data_base64": base64.b64encode(file_bytes).decode("ascii"), "size": len(file_bytes)}
        plain = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        size = len(file_bytes)

    kid = keyring.active_id
    dek = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(nonce, plain,
        _aad(message_id, actor.user_id, p.recipient_user_id, created_ts, expires_ts, kid))
    sender_nonce, sender_wrapped = _wrap_dek(keyring, kid, message_id, actor.user_id, dek)
    recipient_nonce, recipient_wrapped = _wrap_dek(keyring, kid, message_id, p.recipient_user_id, dek)
    doc = {
        "_id": message_id, "sender_user_id": actor.user_id, "recipient_user_id": p.recipient_user_id,
        "kind": p.kind, "size": size, "created_ts": created_ts, "expires_ts": expires_ts,
        "status": "DELIVERED", "kid": kid, "nonce": nonce, "ciphertext": ciphertext,
        "sender_wrap_nonce": sender_nonce, "sender_wrapped_dek": sender_wrapped,
        "recipient_wrap_nonce": recipient_nonce, "recipient_wrapped_dek": recipient_wrapped,
    }
    db[COLLECTION].insert_one(doc)
    audit.record("DIRECT_MESSAGE_SENT", "success", user_id=actor.user_id, operation="message",
                 resource=f"message:{message_id}", reason=f"recipient={p.recipient_user_id}; kind={p.kind}; bytes={size}")
    return {"message_id": message_id, "status": "DELIVERED", "created_ts": created_ts,
            "expires_ts": expires_ts, "recipient_user_id": p.recipient_user_id}


@router.post("/{message_id}/decrypt")
def decrypt_message(message_id: str, actor: Actor = Depends(get_actor), db=Depends(get_db),
                    keyring: Keyring = Depends(get_keyring), audit: AuditLogService = Depends(get_audit_service)):
    doc = _load_participant(db, message_id, actor)
    now = int(time.time())
    if doc.get("status") == "REVOKED":
        raise HTTPException(410, "message access was revoked by the sender")
    if doc.get("expires_ts", 0) <= now or doc.get("status") == "EXPIRED":
        db[COLLECTION].update_one({"_id": message_id}, {"$set": {"status": "EXPIRED"}})
        raise HTTPException(410, "message has expired")
    dek = _unwrap_dek(keyring, doc, actor.user_id)
    try:
        plain = AESGCM(dek).decrypt(bytes(doc["nonce"]), bytes(doc["ciphertext"]),
            _aad(message_id, doc["sender_user_id"], doc["recipient_user_id"], doc["created_ts"],
                 doc["expires_ts"], int(doc["kid"])))
    except (InvalidTag, KeyError, ValueError) as exc:
        raise HTTPException(422, "message integrity verification failed") from exc
    if actor.user_id == doc["recipient_user_id"]:
        db[COLLECTION].update_one({"_id": message_id, "status": "DELIVERED"},
                                  {"$set": {"status": "READ", "read_ts": now}})
    else:
        db[COLLECTION].update_one({"_id": message_id}, {"$set": {"sender_decrypted_ts": now}})
    audit.record("DIRECT_MESSAGE_DECRYPTED", "success", user_id=actor.user_id, operation="decrypt",
                 resource=f"message:{message_id}", reason="recipient opened message" if actor.user_id == doc["recipient_user_id"] else "sender opened sent copy")
    return {"message_id": message_id, "payload_base64": base64.b64encode(plain).decode("ascii"),
            "kind": doc["kind"], "size": doc["size"], "expires_ts": doc["expires_ts"]}


@router.post("/{message_id}/revoke")
def revoke_message(message_id: str, p: RevokeMessage, actor: Actor = Depends(get_actor),
                   db=Depends(get_db), audit: AuditLogService = Depends(get_audit_service)):
    doc = db[COLLECTION].find_one({"_id": message_id, "sender_user_id": actor.user_id})
    if doc is None:
        raise HTTPException(404, "message not found")
    if doc.get("status") in {"REVOKED", "EXPIRED"} or doc.get("expires_ts", 0) <= int(time.time()):
        raise HTTPException(409, "message is no longer available to revoke")
    now = int(time.time())
    result = db[COLLECTION].update_one({"_id": message_id, "sender_user_id": actor.user_id,
                                        "status": {"$nin": ["REVOKED", "EXPIRED"]}},
                                       {"$set": {"status": "REVOKED", "revoked_ts": now,
                                                 "revocation_reason": p.reason}})
    if not result.matched_count:
        raise HTTPException(409, "message state changed; refresh and retry")
    audit.record("DIRECT_MESSAGE_REVOKED", "success", user_id=actor.user_id, operation="revoke",
                 resource=f"message:{message_id}", reason=p.reason)
    return {"message_id": message_id, "status": "REVOKED"}
