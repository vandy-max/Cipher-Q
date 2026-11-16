"""Server-side quantum-key (simulation) sessions.

A *key session* is one BB84 **simulation** run performed by the backend on behalf of an
authenticated user.  The resulting 32-byte key:

* never leaves the backend (the API returns an opaque ``key_session_id`` and telemetry only);
* is stored wrapped with AES-256-GCM under a purpose-separated key-ring sub-key
  (``QKEY_WRAP``), AAD = (key_session_id, owner, kid), inside a database that is itself
  encrypted -- two independent layers;
* is used only as input keying material for per-record wrapping keys (``crypto.records``) and is
  released to a cryptographic operation only through an authorization-bound crypto context
  (``intent_engine.engine``);
* belongs to exactly one user, has an expiry, and moves through
  ``ACTIVE -> ROTATED | REVOKED | EXPIRED`` -- or is created already ``ABORTED_QBER`` /
  ``INSUFFICIENT_KEY`` / ``NO_SIFTED_BITS`` (no key stored at all).

Lifecycle semantics
  ACTIVE   may encrypt new records and decrypt existing ones.
  ROTATED  decrypt/re-wrap only (grace period while records are migrated to a newer session).
  REVOKED  key material destroyed immediately (crypto-shredding); records wrapped only under it
           become unrecoverable.  This is intentional and documented.
  EXPIRED  as REVOKED, applied lazily when ``expires_ts`` passes.

Because the BB84 run is a simulation the key is generated server-side: re-running the simulation
does NOT reproduce a key, so the wrapped copy here is the only copy.
"""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pymongo.errors import DuplicateKeyError  # noqa: F401

from quantum.bb84 import STATUS_OK
from security.canonical import frame
from security.keyring import QKEY_WRAP, Keyring

COLLECTION = "key_sessions"

ACTIVE, ROTATED, REVOKED, EXPIRED = "ACTIVE", "ROTATED", "REVOKED", "EXPIRED"


class KeyUnavailableError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(detail or code)


@dataclass(frozen=True)
class KeySessionInfo:
    key_session_id: str
    status: str
    qber: float
    sifted_bits: int
    effective_entropy_bits: int
    created_ts: int
    expires_ts: int
    generation: int
    simulation: bool = True

    def as_dict(self) -> dict:
        return {"key_session_id": self.key_session_id, "status": self.status, "qber": self.qber,
                "sifted_bits": self.sifted_bits, "effective_entropy_bits": self.effective_entropy_bits,
                "created_ts": self.created_ts, "expires_ts": self.expires_ts, "generation": self.generation,
                "simulation": self.simulation,
                "notice": "BB84 is simulated on a classical computer; this is not physical QKD."}


def _aad(ks_id: str, user_id: int, kid: int) -> bytes:
    return frame(b"CIPHERQ|QKEY-WRAP|v1", ks_id.encode(), str(user_id).encode(), str(kid).encode())


def _info(d: dict) -> KeySessionInfo:
    return KeySessionInfo(d["_id"], d["status"], d["qber"] / 10000.0, d["sifted_bits"], d["entropy_bits"],
                          d["created_ts"], d["expires_ts"], d["generation"])


class KeySessionService:
    def __init__(self, db, keyring: Keyring, quantum_service, *, ttl_seconds: int, max_qubits: int) -> None:
        self.db, self.kr, self.q, self.ttl, self.max_qubits = db, keyring, quantum_service, ttl_seconds, max_qubits

    # ------------------------------------------------------------------ create
    def create(self, user_id: int, *, n_qubits: int | None = None, eavesdrop_prob: float = 0.0,
               generation: int = 1) -> KeySessionInfo:
        res = self.q.generate_shared_key(eavesdrop_prob=eavesdrop_prob, n_qubits=n_qubits,
                                         max_qubits=self.max_qubits)
        ks_id = "ks_" + secrets.token_urlsafe(18)
        now = int(time.time())
        doc = {"_id": ks_id, "user_id": user_id, "status": res.status if res.status != STATUS_OK else ACTIVE,
               "qber": int(round(res.qber * 10000)), "sifted_bits": res.sifted_bits,
               "final_key_bits": res.final_key_bits, "entropy_bits": res.effective_entropy_bits,
               "created_ts": now, "expires_ts": now + self.ttl, "generation": generation,
               "kid": self.kr.active_id, "wrapped": None, "nonce": None, "use_count": 0}
        if res.status == STATUS_OK:
            nonce = os.urandom(12)
            wrapped = AESGCM(self.kr.subkey(QKEY_WRAP, self.kr.active_id)).encrypt(
                nonce, res.key_bytes, _aad(ks_id, user_id, self.kr.active_id))
            doc["wrapped"], doc["nonce"] = wrapped, nonce
        self.db[COLLECTION].insert_one(doc)
        return _info(doc)

    # ------------------------------------------------------------------ lookup
    def _load(self, ks_id: str) -> dict | None:
        d = self.db[COLLECTION].find_one({"_id": ks_id})
        if d and d["status"] in (ACTIVE, ROTATED) and d["expires_ts"] <= int(time.time()):
            self._destroy(ks_id, EXPIRED)
            d = self.db[COLLECTION].find_one({"_id": ks_id})
        return d

    def get(self, ks_id: str, user_id: int, *, admin: bool = False) -> KeySessionInfo | None:
        d = self._load(ks_id)
        if d is None or (d["user_id"] != user_id and not admin):
            return None                       # indistinguishable: no existence oracle across users
        return _info(d)

    def list_for_user(self, user_id: int) -> list[KeySessionInfo]:
        return [_info(self._load(d["_id"])) for d in self.db[COLLECTION].find({"user_id": user_id}).sort("created_ts", -1)]

    def status_of(self, ks_id: str) -> str | None:
        d = self._load(ks_id)
        return d["status"] if d else None

    # ------------------------------------------------------------------ use (server-internal)
    def unwrap(self, ks_id: str, user_id: int, *, for_encrypt: bool) -> bytes:
        """Return the key. Internal: only the crypto-context layer may call this."""
        d = self._load(ks_id)
        if d is None or d["user_id"] != user_id:
            raise KeyUnavailableError("KEY_SESSION_NOT_FOUND")
        allowed = {ACTIVE} if for_encrypt else {ACTIVE, ROTATED}
        if d["status"] not in allowed or d["wrapped"] is None:
            raise KeyUnavailableError("KEY_SESSION_" + d["status"], f"key session is {d['status']}")
        try:
            key = AESGCM(self.kr.subkey(QKEY_WRAP, int(d["kid"]))).decrypt(
                bytes(d["nonce"]), bytes(d["wrapped"]), _aad(ks_id, user_id, int(d["kid"])))
        except InvalidTag as exc:
            raise KeyUnavailableError("KEY_SESSION_CORRUPT") from exc
        self.db[COLLECTION].update_one({"_id": ks_id}, {"$inc": {"use_count": 1}})
        return key

    def extend_for_record(self, ks_id: str, user_id: int, expires_ts: int) -> bool:
        """Keep a key session recoverable at least as long as its owner's live records.

        The extension is bounded by a record's server-computed expiry. It does not
        reactivate expired/revoked keys and never extends a key past the record's
        permitted access window.
        """
        now = int(time.time())
        if isinstance(expires_ts, bool) or not isinstance(expires_ts, int) or expires_ts <= now:
            return False
        collection = self.db[COLLECTION]
        current = collection.find_one({"_id": ks_id, "user_id": user_id, "status": ACTIVE})
        if current is None:
            return False
        if int(current.get("expires_ts", 0)) >= expires_ts:
            return True
        result = collection.update_one(
            {"_id": ks_id, "user_id": user_id, "status": ACTIVE,
             "expires_ts": {"$lt": expires_ts}},
            {"$set": {"expires_ts": expires_ts}},
        )
        if result.matched_count == 1:
            return True
        # A concurrent extension may already have moved it farther forward.
        current = collection.find_one({"_id": ks_id, "user_id": user_id, "status": ACTIVE})
        return current is not None and int(current.get("expires_ts", 0)) >= expires_ts

    # ------------------------------------------------------------------ lifecycle
    def _destroy(self, ks_id: str, new_status: str) -> bool:
        res = self.db[COLLECTION].update_one(
            {"_id": ks_id, "status": {"$in": [ACTIVE, ROTATED]}},
            {"$set": {"status": new_status, "wrapped": None, "nonce": None, "destroyed_ts": int(time.time())}})
        return res.matched_count == 1

    def revoke(self, ks_id: str, user_id: int, *, admin: bool = False) -> bool:
        d = self.db[COLLECTION].find_one({"_id": ks_id})
        if d is None or (d["user_id"] != user_id and not admin):
            return False
        return self._destroy(ks_id, REVOKED)

    def revoke_all_for_user(self, user_id: int) -> int:
        return sum(1 for d in self.db[COLLECTION].find({"user_id": user_id, "status": {"$in": [ACTIVE, ROTATED]}})
                   if self._destroy(d["_id"], REVOKED))

    def mark_rotated(self, ks_id: str) -> bool:
        res = self.db[COLLECTION].update_one({"_id": ks_id, "status": ACTIVE}, {"$set": {"status": ROTATED}})
        return res.matched_count == 1

    def rotate(self, ks_id: str, user_id: int, **create_kwargs) -> KeySessionInfo:
        """Create a successor session. The old one becomes ROTATED (decrypt/re-wrap only)."""
        old = self._load(ks_id)
        if old is None or old["user_id"] != user_id or old["status"] != ACTIVE:
            raise KeyUnavailableError("KEY_SESSION_NOT_ACTIVE")
        new = self.create(user_id, generation=old["generation"] + 1, **create_kwargs)
        if new.status != ACTIVE:
            return new                         # exchange failed: old session stays ACTIVE
        self.mark_rotated(ks_id)
        return new
