"""Challenge-bound step-up identity verification.

What this DOES provide
  * a server-issued, single-use, short-lived challenge bound to (user, session, purpose);
    a verification response can only be redeemed once, by the user it was issued to, for the
    session it was issued for, within ``challenge_ttl_seconds`` -- stale responses are useless;
  * server-side comparison of the submitted face descriptor with the enrolled one (the client is
    never told the distance/confidence, so the comparison cannot be used as an oracle to
    hill-climb a descriptor);
  * rejection of bit-identical descriptor resubmission (a live capture is never bit-identical);
  * failure counting with temporary lockout;
  * a time-limited grant (``stepup_grants``) that the authorization engine consults.

What this does NOT provide
  * liveness.  The descriptor is computed by client-side code that the server cannot attest.
    A descriptor-similarity match is evidence that *someone submitted a descriptor close to the
    enrolled one*, not that a live person was in front of a camera.  Grants therefore record
    ``liveness="NOT_ESTABLISHED"`` and the documentation says so.
"""
from __future__ import annotations

import hashlib
import math
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pymongo.errors import DuplicateKeyError

CHALLENGES = "identity_challenges"
GRANTS = "stepup_grants"
PROBES = "identity_probe_hashes"      # RAW (unencrypted) collection: SHA-256 of a submitted descriptor, per user.
PROBE_TTL = 24 * 3600                  # kept in the clear on purpose so that expiry can be indexed / purged cheaply
_PURGE_EVERY = 600
FAILS = "identity_failures"

MAX_FAILS = 5
FAIL_WINDOW = 600
LOCK_SECONDS = 300


class StepUpError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(detail or code)


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    nonce: str
    expires_ts: int


def _probe_hash(descriptor: list[float]) -> str:
    return hashlib.sha256(",".join(f"{x:.6f}" for x in descriptor).encode()).hexdigest()


class StepUpService:
    def __init__(self, db, face_auth, *, challenge_ttl: int, stepup_ttl: int) -> None:
        self.db, self.face, self.ctl, self.sttl = db, face_auth, challenge_ttl, stepup_ttl
        self._last_purge = 0.0
        try:                                        # real MongoDB expires these itself; others rely on _purge()
            self.db.raw[PROBES].create_index("expires_at", expireAfterSeconds=0)
        except Exception:  # noqa: BLE001 -- index support varies (e.g. FerretDB); the app-level purge covers it
            pass

    def _claim_probe(self, user_id: int, descriptor: list[float], now: int) -> bool:
        """Atomically record this exact descriptor for the user. False if it was seen before (replay).
        The unique ``_id`` makes concurrent duplicate submissions race-free; old entries are purged."""
        ph = f"{user_id}:{_probe_hash(descriptor)}"
        try:
            self.db.raw[PROBES].insert_one({"_id": ph, "user_id": user_id,
                                            "expires_at": datetime.fromtimestamp(now + PROBE_TTL, tz=timezone.utc)})
        except DuplicateKeyError:
            return False
        if now - self._last_purge > _PURGE_EVERY:
            self._last_purge = now
            try:
                self.db.raw[PROBES].delete_many({"expires_at": {"$lt": datetime.fromtimestamp(now, tz=timezone.utc)}})
            except Exception:  # noqa: BLE001 -- housekeeping must never break verification
                pass
        return True

    # -- challenges ---------------------------------------------------------
    def issue_challenge(self, user_id: int, session_id: str, purpose: str = "STEP_UP") -> Challenge:
        if not self.face.is_enrolled(user_id):
            raise StepUpError("NOT_ENROLLED", "no face enrolment on file")
        self._check_lock(user_id)
        cid, nonce, exp = secrets.token_hex(16), secrets.token_hex(16), int(time.time()) + self.ctl
        self.db[CHALLENGES].insert_one({"_id": cid, "user_id": user_id, "session_id": session_id,
                                        "purpose": purpose, "nonce": nonce, "expires_ts": exp, "used": False})
        return Challenge(cid, nonce, exp)

    def _check_lock(self, user_id: int) -> None:
        d = self.db[FAILS].find_one({"_id": user_id})
        if d and d.get("locked_until", 0) > int(time.time()):
            raise StepUpError("LOCKED", "too many failed verifications; try later")

    def _fail(self, user_id: int) -> None:
        now = int(time.time())
        d = self.db[FAILS].find_one({"_id": user_id})
        if d is None:
            self.db[FAILS].insert_one({"_id": user_id, "first_ts": now, "count": 1, "locked_until": 0})
            return
        if now - d.get("first_ts", 0) > FAIL_WINDOW:
            d = {**d, "first_ts": now, "count": 0}
        count = d["count"] + 1
        upd = {"count": count, "first_ts": d["first_ts"]}
        if count >= MAX_FAILS:
            upd["locked_until"] = now + LOCK_SECONDS
        self.db[FAILS].update_one({"_id": user_id}, {"$set": upd})

    # -- verification ----------------------------------------------------------
    def verify(self, user_id: int, session_id: str, challenge_id: str, descriptor: list[float]) -> dict:
        self._check_lock(user_id)
        now = int(time.time())
        ch = self.db[CHALLENGES].find_one({"_id": challenge_id})
        if (ch is None or ch["user_id"] != user_id or ch["session_id"] != session_id
                or ch["expires_ts"] < now or ch["used"]):
            raise StepUpError("CHALLENGE_INVALID", "challenge missing, expired, used or not yours")
        # single use: consume BEFORE evaluating the descriptor
        won = self.db[CHALLENGES].update_one({"_id": challenge_id, "used": False}, {"$set": {"used": True}})
        if won.matched_count != 1:
            raise StepUpError("CHALLENGE_INVALID", "challenge already used")
        if len(descriptor) != 128 or not all(isinstance(x, (int, float)) and math.isfinite(x) and -5 <= x <= 5
                                             for x in descriptor):
            raise StepUpError("DESCRIPTOR_INVALID", "malformed descriptor")
        if not self._claim_probe(user_id, descriptor, now):
            self._fail(user_id)
            raise StepUpError("DESCRIPTOR_REPLAY", "identical descriptor was already submitted")
        result = self.face.verify(user_id, descriptor)
        if not result.verified:
            self._fail(user_id)
            raise StepUpError("NO_MATCH", "verification failed")
        self.db[FAILS].delete_one({"_id": user_id})
        grant = {"_id": secrets.token_hex(12), "user_id": user_id, "session_id": session_id,
                 "verified_ts": now, "expires_ts": now + self.sttl, "method": "FACE_DESCRIPTOR_SIMILARITY",
                 "liveness": "NOT_ESTABLISHED", "challenge_id": challenge_id, "revoked": False,
                 "confidence": float(result.confidence)}
        self.db[GRANTS].insert_one(grant)
        return {"grant_id": grant["_id"], "expires_ts": grant["expires_ts"], "liveness": grant["liveness"],
                "confidence": grant["confidence"]}

    def probe(self, user_id: int, descriptor: list[float]) -> float | None:
        """Server-side descriptor comparison for continuous monitoring. Returns the server-computed
        confidence, or None if the descriptor is malformed, replayed or not enrolled (counts as a failed tick).
        Descriptor similarity only: no liveness is established."""
        self._check_lock(user_id)
        if len(descriptor) != 128 or not all(isinstance(x, (int, float)) and math.isfinite(x) and -5 <= x <= 5
                                             for x in descriptor):
            return None
        now = int(time.time())
        if not self._claim_probe(user_id, descriptor, now):
            return None
        if not self.face.is_enrolled(user_id):
            return None
        r = self.face.verify(user_id, descriptor)
        return float(r.confidence) if r.verified else 0.0

    def fresh_grant_confidence(self, user_id: int, session_id: str, max_age: int | None = None) -> float | None:
        now = int(time.time())
        max_age = self.sttl if max_age is None else max_age
        best = None
        for g in self.db[GRANTS].find({"user_id": user_id, "session_id": session_id}):
            if not g["revoked"] and g["expires_ts"] > now and now - g["verified_ts"] <= max_age:
                if best is None or g["verified_ts"] > best[0]:
                    best = (g["verified_ts"], g.get("confidence"))
        return None if best is None else best[1]

    def has_fresh_grant(self, user_id: int, session_id: str, max_age: int | None = None) -> bool:
        now = int(time.time())
        max_age = self.sttl if max_age is None else max_age
        for g in self.db[GRANTS].find({"user_id": user_id, "session_id": session_id}):
            if not g["revoked"] and g["expires_ts"] > now and now - g["verified_ts"] <= max_age:
                return True
        return False

    def revoke_grants(self, user_id: int, session_id: str | None = None) -> int:
        q = {"user_id": user_id, "revoked": False}
        if session_id:
            q["session_id"] = session_id
        n = 0
        for g in self.db[GRANTS].find(q):
            n += self.db[GRANTS].update_one({"_id": g["_id"]}, {"$set": {"revoked": True}}).matched_count
        return n
