"""Shared encrypted-record metadata and lookup helpers."""
from __future__ import annotations

import time
from typing import Any

SHARES_COLLECTION = "crypto_shares"
RECORD_VALIDITY_SECONDS = 24 * 60 * 60


def record_expires_ts(record: dict[str, Any]) -> int | None:
    """Use stored expiry when present; legacy records keep their original creation window."""
    expires_ts = record.get("expires_ts")
    if isinstance(expires_ts, int) and not isinstance(expires_ts, bool):
        return expires_ts
    created_ts = record.get("created_ts")
    if isinstance(created_ts, int) and not isinstance(created_ts, bool):
        return created_ts + RECORD_VALIDITY_SECONDS
    return None


def record_expired(record: dict[str, Any], now: int | None = None) -> bool:
    expires_ts = record_expires_ts(record)
    return expires_ts is None or expires_ts <= (int(time.time()) if now is None else now)


def find_record(db, record_id: str, *, include_shares: bool = False) -> tuple[dict | None, bool]:
    record = db["crypto_records"].find_one({"_id": record_id})
    if record is not None:
        return record, False
    if include_shares:
        record = db[SHARES_COLLECTION].find_one({"_id": record_id})
        if record is not None:
            return record, True
    return None, False


def authorization_metadata(record: dict[str, Any], *, shared: bool) -> dict[str, Any]:
    static_ctx = record.get("sealed", {}).get("static_ctx", {})
    metadata = {
        "record_id": record["_id"],
        "owner_user_id": record["owner_user_id"],
        "resource": record["resource"],
        "classification": record["classification"],
        "size": record["size"],
        "intent_id": record["intent_id"],
        "intent_version": record.get("intent_version", static_ctx.get("intent_version")),
        "intent_body_hash": static_ctx.get("intent_body_hash"),
        "key_session_id": record["key_session_id"],
        "key_generation": record.get("key_generation", record.get("sealed", {}).get("key_generation")),
        "created_ts": record["created_ts"],
        "expires_ts": record_expires_ts(record),
    }
    if shared:
        metadata.update({
            "recipient_user_id": record["recipient_user_id"],
            "source_record_id": record["source_record_id"],
            "share_status": record["status"],
        })
    return metadata


def sealed_context_matches(record: dict[str, Any], *, shared: bool) -> bool:
    sealed = record.get("sealed")
    if not isinstance(sealed, dict) or sealed.get("schema") != 3:
        return False
    context = sealed.get("static_ctx")
    if not isinstance(context, dict):
        return False
    expected_record_id = record.get("source_record_id") if shared else record.get("_id")
    expected_version = record.get("intent_version", context.get("intent_version"))
    expected = {
        "record_id": expected_record_id,
        "owner_user_id": record.get("owner_user_id"),
        "intent_id": record.get("intent_id"),
        "intent_version": expected_version,
        "resource": record.get("resource"),
        "classification": record.get("classification"),
        "size": record.get("size"),
    }
    return (context.get("v") == 3 and all(context.get(name) == value for name, value in expected.items())
            and sealed.get("key_session_id") == record.get("key_session_id")
            and sealed.get("key_generation") == record.get("key_generation", sealed.get("key_generation")))
