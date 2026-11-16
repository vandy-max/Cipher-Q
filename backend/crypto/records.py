"""Cryptographic record format v3.

Roles of the keys (nothing here is custom cryptography: HKDF-SHA256 + AES-256-GCM):

  qkey   32-byte output of the server-side BB84 *simulation* (key session).  Input keying material only.
  DEK    fresh random 256-bit key per record; encrypts the data.
  RWK    record-wrapping key = HKDF-SHA256(IKM=qkey, salt=wrap_salt, info=frame(tag, wrap_context))
         wraps the DEK.  ``wrap_salt`` is fresh random per wrap, so every wrap uses a distinct key.

What enters each derivation / AAD (all via ``security.canonical`` -- typed, NFC, length-framed):

  static_ctx (immutable for the life of the record; part of the DATA AAD)
      v, record_id, owner_user_id, intent_id, intent_version, intent_body_hash, resource,
      classification, size
  wrap_ctx = static_ctx + key_session_id + key_generation      (RWK derivation `info` and WRAP AAD,
                                                                 plus wrap_salt in the AAD)

  DATA:  AES-256-GCM(DEK, nonce_d, plaintext, AAD = frame("CIPHERQ|REC-DATA|v3", canonical(static_ctx)))
  WRAP:  AES-256-GCM(RWK, nonce_w, DEK,       AAD = frame("CIPHERQ|DEK-WRAP|v3", canonical(wrap_ctx), wrap_salt))

Authorization state (decision id, session version, policy version, ...) is deliberately NOT part of
the record's AAD: it changes over the life of a record.  It controls *release of the qkey*
(``intent_engine.contexts``) instead.  Rewrapping to a new key session leaves the ciphertext
untouched (data AAD is static).
"""
from __future__ import annotations

import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from security.canonical import canonical_bytes, frame

RECORD_VERSION = 3
_TAG_DATA = b"CIPHERQ|REC-DATA|v3"
_TAG_WRAP = b"CIPHERQ|DEK-WRAP|v3"
_TAG_RWK = b"CIPHERQ|RWK|v3"


class RecordError(Exception):
    """Authentication/format failure. Deliberately uninformative."""


def static_context(*, record_id: str, owner_user_id: int, intent_id: int, intent_version: int,
                   intent_body_hash: str, resource: str, classification: str, size: int) -> dict[str, Any]:
    return {"v": RECORD_VERSION, "record_id": record_id, "owner_user_id": owner_user_id,
            "intent_id": intent_id, "intent_version": intent_version, "intent_body_hash": intent_body_hash,
            "resource": resource, "classification": classification, "size": size}


def _wrap_ctx(static_ctx: dict, key_session_id: str, key_generation: int) -> dict:
    return {**static_ctx, "key_session_id": key_session_id, "key_generation": key_generation}


def _rwk(qkey: bytes, wrap_salt: bytes, wrap_ctx: dict) -> bytes:
    if len(qkey) != 32:
        raise RecordError("bad key material")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=wrap_salt,
                info=frame(_TAG_RWK, canonical_bytes(wrap_ctx))).derive(qkey)


def seal(plaintext: bytes, qkey: bytes, static_ctx: dict, key_session_id: str, key_generation: int) -> dict:
    dek, nonce_d, nonce_w, wrap_salt = os.urandom(32), os.urandom(12), os.urandom(12), os.urandom(32)
    ct = AESGCM(dek).encrypt(nonce_d, plaintext, frame(_TAG_DATA, canonical_bytes(static_ctx)))
    wctx = _wrap_ctx(static_ctx, key_session_id, key_generation)
    wrapped = AESGCM(_rwk(qkey, wrap_salt, wctx)).encrypt(nonce_w, dek, frame(_TAG_WRAP, canonical_bytes(wctx), wrap_salt))
    return {"schema": RECORD_VERSION, "static_ctx": static_ctx, "key_session_id": key_session_id,
            "key_generation": key_generation, "data_nonce": nonce_d, "ciphertext": ct,
            "wrap_salt": wrap_salt, "wrap_nonce": nonce_w, "wrapped_dek": wrapped}


def unwrap_dek(rec: dict, qkey: bytes) -> bytes:
    """Authenticate and return the record DEK for an authorized in-process operation only."""
    try:
        if rec.get("schema") != RECORD_VERSION:
            raise RecordError("unsupported record version")
        sctx = rec["static_ctx"]
        wctx = _wrap_ctx(sctx, rec["key_session_id"], int(rec["key_generation"]))
        salt = bytes(rec["wrap_salt"])
        return AESGCM(_rwk(qkey, salt, wctx)).decrypt(
            bytes(rec["wrap_nonce"]), bytes(rec["wrapped_dek"]), frame(_TAG_WRAP, canonical_bytes(wctx), salt))
    except RecordError:
        raise
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise RecordError("record failed authentication") from exc


def open_(rec: dict, qkey: bytes) -> bytes:
    """Authenticate + decrypt. Any tampering with ciphertext, nonce, wrapped DEK, wrap salt, any
    static-context field, the key-session binding or the key itself raises ``RecordError``."""
    try:
        dek = unwrap_dek(rec, qkey)
        sctx = rec["static_ctx"]
        return AESGCM(dek).decrypt(bytes(rec["data_nonce"]), bytes(rec["ciphertext"]),
                                   frame(_TAG_DATA, canonical_bytes(sctx)))
    except RecordError:
        raise
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise RecordError("record failed authentication") from exc


def rewrap(rec: dict, old_qkey: bytes, new_qkey: bytes, new_key_session_id: str, new_generation: int) -> dict:
    """Unwrap the DEK under the old key session, wrap it under the new one. Ciphertext unchanged."""
    sctx = rec["static_ctx"]
    old_ctx = _wrap_ctx(sctx, rec["key_session_id"], int(rec["key_generation"]))
    salt = bytes(rec["wrap_salt"])
    try:
        dek = AESGCM(_rwk(old_qkey, salt, old_ctx)).decrypt(bytes(rec["wrap_nonce"]), bytes(rec["wrapped_dek"]),
                                                            frame(_TAG_WRAP, canonical_bytes(old_ctx), salt))
    except (InvalidTag, KeyError, ValueError, TypeError) as exc:
        raise RecordError("record failed authentication") from exc
    new_salt, new_nonce = os.urandom(32), os.urandom(12)
    new_ctx = _wrap_ctx(sctx, new_key_session_id, new_generation)
    wrapped = AESGCM(_rwk(new_qkey, new_salt, new_ctx)).encrypt(
        new_nonce, dek, frame(_TAG_WRAP, canonical_bytes(new_ctx), new_salt))
    return {**rec, "key_session_id": new_key_session_id, "key_generation": new_generation,
            "wrap_salt": new_salt, "wrap_nonce": new_nonce, "wrapped_dek": wrapped}
