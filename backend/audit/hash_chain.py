"""Keyed, tamper-evident audit chain.

v17 used an UNKEYED SHA-256 chain: anyone with database write access could rewrite
history and recompute every hash, and deleting the newest entries went undetected.

v18:

    mac_n = HMAC-SHA256(audit_mac_subkey(kid),
                        frame("CIPHERQ|AUDIT|v2", seq, prev_mac, canonical(body)))

* the MAC key never leaves the server (HKDF subkey of the keyring), so a database-only
  attacker cannot forge or re-link entries;
* ``seq`` is part of the MAC, so reordering / splicing is detected;
* a sealed **head record** (``seq``, ``mac``) plus an append-only secondary sink make
  tail truncation detectable (see ``audit.service``).

What this does NOT give you: protection against an attacker who holds the application
keyring (they can forge everything), and no protection from the operator deleting the
database *and* the sink.  Ship the sink to storage the application cannot rewrite.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence

from security.canonical import canonical_bytes, frame
from security.keyring import AUDIT_MAC, Keyring, UnknownKeyError

GENESIS_HASH = "0" * 64
DOMAIN = b"CIPHERQ|AUDIT|v2"


@dataclass(frozen=True)
class AuditEntry:
    timestamp: datetime
    user_id: int | None
    action: str
    intent_hash: str | None
    result: str
    prev_log_hash: str
    current_log_hash: str
    session_id: str | None = None
    device_id: str | None = None
    resource: str | None = None
    operation: str | None = None
    risk: str | None = None
    reason: str | None = None
    seq: int = 0
    kid: int = 0


def iso_ms(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _body(seq, timestamp, user_id, action, intent_hash, result, session_id, device_id, resource,
          operation, risk, reason) -> dict:
    return {"seq": int(seq), "ts": iso_ms(timestamp), "user_id": user_id, "action": action,
            "intent_hash": intent_hash, "result": result, "session_id": session_id,
            "device_id": device_id, "resource": resource, "operation": operation,
            "risk": risk, "reason": reason}


def compute_entry_mac(kr: Keyring, kid: int, seq: int, prev: str, timestamp: datetime, user_id, action,
                      intent_hash, result, session_id=None, device_id=None, resource=None, operation=None,
                      risk=None, reason=None) -> str:
    body = _body(seq, timestamp, user_id, action, intent_hash, result, session_id, device_id, resource,
                 operation, risk, reason)
    key = kr.subkey(AUDIT_MAC, kid)
    return hmac.new(key, frame(DOMAIN, str(kid).encode(), prev.encode(), canonical_bytes(body)),
                    hashlib.sha256).hexdigest()


def head_mac(kr: Keyring, kid: int, seq: int, mac: str) -> str:
    key = kr.subkey(AUDIT_MAC, kid)
    return hmac.new(key, frame(b"CIPHERQ|AUDIT-HEAD|v2", str(kid).encode(), str(seq).encode(), mac.encode()),
                    hashlib.sha256).hexdigest()


def build_entry(kr: Keyring, seq: int, prev_log_hash: str, timestamp: datetime, user_id, action, intent_hash,
                result, session_id=None, device_id=None, resource=None, operation=None, risk=None,
                reason=None) -> AuditEntry:
    kid = kr.active_id
    mac = compute_entry_mac(kr, kid, seq, prev_log_hash, timestamp, user_id, action, intent_hash, result,
                            session_id, device_id, resource, operation, risk, reason)
    return AuditEntry(timestamp=timestamp, user_id=user_id, action=action, intent_hash=intent_hash,
                      result=result, prev_log_hash=prev_log_hash, current_log_hash=mac, session_id=session_id,
                      device_id=device_id, resource=resource, operation=operation, risk=risk, reason=reason,
                      seq=seq, kid=kid)


@dataclass(frozen=True)
class ChainVerificationResult:
    valid: bool
    first_invalid_index: int | None = None
    reason: str | None = None
    checks: dict[str, bool] = None
    checked_entries: int = 0

    def __post_init__(self):
        if self.checks is None:
            object.__setattr__(self, "checks", {})


def verify_chain(kr: Keyring, entries: Sequence[AuditEntry], head: dict | None = None,
                 sink_tail: dict | None = None, sink_configured: bool = False) -> ChainVerificationResult:
    """Read-only verification.  Never appends to the chain it is verifying.

    ``head``: the stored sealed head record ``{seq, mac, kid, head_mac}`` (None = absent).
    ``sink_tail``: last record read from the secondary sink ``{seq, mac}`` (None = empty/absent).
    """
    checks = {"genesis": True, "sequence": True, "chain_continuity": True, "mac_verification": True,
              "required_fields": True, "chronological_order": True, "head_anchor": True,
              "secondary_sink": True}

    def fail(i, key, msg):
        checks[key] = False
        return ChainVerificationResult(False, i, msg, checks, len(entries))

    expected_prev, prev_ts = GENESIS_HASH, None
    for i, e in enumerate(entries):
        if not e.action or not e.result or not e.prev_log_hash or not e.current_log_hash or not e.kid:
            return fail(i, "required_fields", f"entry {i}: required audit fields missing (legacy or malformed)")
        if e.seq != i + 1:
            return fail(i, "sequence", f"entry {i}: sequence number {e.seq} is not {i + 1} (gap, reorder or deletion)")
        if i == 0 and e.prev_log_hash != GENESIS_HASH:
            return fail(i, "genesis", f"entry {i}: genesis link invalid")
        if prev_ts is not None and e.timestamp < prev_ts:
            return fail(i, "chronological_order", f"entry {i}: timestamp earlier than previous entry")
        if e.prev_log_hash != expected_prev:
            return fail(i, "chain_continuity", f"entry {i}: prev link does not match previous entry")
        try:
            mac = compute_entry_mac(kr, e.kid, e.seq, e.prev_log_hash, e.timestamp, e.user_id, e.action,
                                    e.intent_hash, e.result, e.session_id, e.device_id, e.resource,
                                    e.operation, e.risk, e.reason)
        except (UnknownKeyError, ValueError, TypeError):
            return fail(i, "mac_verification", f"entry {i}: MAC cannot be verified (unknown key id or bad field)")
        if not hmac.compare_digest(mac, e.current_log_hash):
            return fail(i, "mac_verification", f"entry {i}: MAC mismatch (entry modified or forged)")
        expected_prev, prev_ts = e.current_log_hash, e.timestamp

    n = len(entries)
    last_mac = entries[-1].current_log_hash if entries else GENESIS_HASH
    if head is None:
        if n:
            return fail(None, "head_anchor", "head record missing although entries exist (tail truncation or tampering)")
    else:
        try:
            ok = hmac.compare_digest(head_mac(kr, int(head["kid"]), int(head["seq"]), str(head["mac"])),
                                     str(head["head_mac"]))
        except (KeyError, ValueError, TypeError, UnknownKeyError):
            ok = False
        if not ok:
            return fail(None, "head_anchor", "head record failed MAC verification")
        hs = int(head["seq"])
        if hs > n:
            return fail(None, "head_anchor", f"head records {hs} entries but only {n} exist (tail truncation)")
        if hs == n and head["mac"] != last_mac:
            return fail(None, "head_anchor", "head MAC does not match the newest entry")
        if hs < n - 8:    # head is written right after each insert; a small lag is a benign crash/race window
            return fail(None, "head_anchor", "head is far behind the newest entries")
    if sink_configured:
        if sink_tail is None:
            if n:
                return fail(None, "secondary_sink", "secondary sink is empty/missing although entries exist")
        else:
            ss = int(sink_tail["seq"])
            if ss > n:
                return fail(None, "secondary_sink", f"sink holds seq {ss} but database has only {n} entries")
            if ss <= n and ss > 0 and entries[ss - 1].current_log_hash != sink_tail["mac"]:
                return fail(None, "secondary_sink", f"sink entry {ss} differs from database entry")
            if ss < n - 8:
                return fail(None, "secondary_sink", "sink is far behind the database")
    return ChainVerificationResult(True, checks=checks, checked_entries=n)
