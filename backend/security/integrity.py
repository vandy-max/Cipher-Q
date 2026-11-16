"""Keyed integrity protection (HMAC-SHA256) for immutable security records.

A record's MAC covers its canonical encoding plus a record-type label and the key
id.  Verification is constant-time.  A valid MAC proves the record was produced by
a holder of the server signing key and has not been modified since; it does NOT
prove the record is still *current* -- revocation / status is separate, mutable
state that every consumer must check (see ``intent_engine.decision``).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .canonical import canonical_bytes, frame
from .keyring import AUTHZ_SIGN, Keyring, UnknownKeyError

MAC_FIELD = "mac"


class IntegrityError(Exception):
    pass


def _mac(kr: Keyring, kid: int, record_type: str, body: dict[str, Any], purpose: str = AUTHZ_SIGN) -> str:
    key = kr.subkey(purpose, kid)
    msg = frame(b"CIPHERQ|RECORD-MAC|v1", record_type.encode(), str(kid).encode(), canonical_bytes(body))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def seal(kr: Keyring, record_type: str, body: dict[str, Any], purpose: str = AUTHZ_SIGN) -> dict[str, Any]:
    """Return ``body`` plus ``kid`` and ``mac``."""
    body = {k: v for k, v in body.items() if k not in (MAC_FIELD, "kid")}
    kid = kr.active_id
    return {**body, "kid": kid, MAC_FIELD: _mac(kr, kid, record_type, body, purpose)}


def verify(kr: Keyring, record_type: str, record: dict[str, Any], purpose: str = AUTHZ_SIGN) -> bool:
    try:
        kid = int(record["kid"])
        presented = str(record[MAC_FIELD])
        body = {k: v for k, v in record.items() if k not in (MAC_FIELD, "kid", "_id")}
        body_with_id = {k: v for k, v in record.items() if k not in (MAC_FIELD, "kid")}
        # `_id` is part of the sealed body when the caller sealed it; try both forms.
        for candidate in (body_with_id, body):
            if hmac.compare_digest(_mac(kr, kid, record_type, candidate, purpose), presented):
                return True
        return False
    except (KeyError, ValueError, UnknownKeyError, TypeError):
        return False


def require(kr: Keyring, record_type: str, record: dict[str, Any], purpose: str = AUTHZ_SIGN) -> None:
    if not verify(kr, record_type, record, purpose):
        raise IntegrityError(f"{record_type} failed integrity verification")
