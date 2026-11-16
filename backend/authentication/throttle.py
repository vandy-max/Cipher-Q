"""
Persistent per-username login throttle (shared across workers/restarts).

Keyed on the *normalised username whether or not the account exists*, so the
response for an unknown user is indistinguishable from a known one (no account
enumeration through lockout behaviour).  Trade-off, accepted and documented:
an attacker can deliberately lock a known username for ``lockout`` seconds
(availability vs. credential-stuffing resistance); admins can unlock.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pymongo.collection import ReturnDocument
from pymongo.errors import PyMongoError

from database.encrypted_store import EncryptedDocumentError
from database.models import LOGIN_THROTTLE_COLLECTION


class AccountLockedError(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__("too many failed attempts")


class LoginThrottleUnavailableError(Exception):
    """The persistent throttle could not be read or updated safely."""


def throttle_key(username: str) -> str:
    return username.strip().lower()


class LoginThrottle:
    RESET_AFTER = timedelta(hours=1)
    MAX_LOCK = 86_400

    def __init__(self, db, max_failures: int, lockout_seconds: int) -> None:
        self._col = db[LOGIN_THROTTLE_COLLECTION]
        self._max, self._lock = max_failures, lockout_seconds

    @staticmethod
    def _storage_call(operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except (EncryptedDocumentError, PyMongoError) as exc:
            raise LoginThrottleUnavailableError("persistent login throttle unavailable") from exc

    def begin_attempt(self, username: str, now: datetime | None = None) -> None:
        """Atomically RESERVE one attempt *before* the (slow) password verification.

        Counting after verification lets N concurrent guesses all pass the "is it locked?" check
        before any of them records a failure (measured: 20/20 concurrent wrong guesses were evaluated
        against a 5-attempt limit).  Pessimistic counting closes that window: attempts beyond
        ``max_failures`` are refused whether or not they are concurrent.  A successful login resets
        the counter.  Raises ``AccountLockedError``.
        """
        now = now or datetime.now(timezone.utc)
        key = throttle_key(username)
        doc = self._storage_call(self._col.find_one, {"_id": key})
        if doc:
            until = doc.get("locked_until")
            if until is not None:
                if until.tzinfo is None:
                    until = until.replace(tzinfo=timezone.utc)
                if until > now:
                    raise AccountLockedError(int((until - now).total_seconds()) + 1)
            last = doc.get("last_fail")
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                if now - last > self.RESET_AFTER:
                    self._storage_call(self._col.update_one, {"_id": key},
                                       {"$set": {"fails": 0}, "$unset": {"locked_until": ""}})
        doc = self._storage_call(
            self._col.find_one_and_update,
            {"_id": key}, {"$inc": {"fails": 1}, "$set": {"last_fail": now}},
            upsert=True, return_document=ReturnDocument.AFTER)
        fails = int(doc["fails"])
        if fails > self._max:                                  # over budget -> (extend) the lock and refuse
            secs = min(self._lock * (2 ** (fails - self._max - 1)), self.MAX_LOCK)
            self._storage_call(self._col.update_one, {"_id": key},
                               {"$set": {"locked_until": now + timedelta(seconds=secs)}})
            raise AccountLockedError(int(secs) + 1)

    check = begin_attempt        # backwards-compatible name

    def record_failure(self, username: str, now: datetime | None = None) -> None:
        """The attempt was already counted by ``begin_attempt``; engage the lock at the limit."""
        now = now or datetime.now(timezone.utc)
        key = throttle_key(username)
        doc = self._storage_call(self._col.find_one, {"_id": key})
        if doc and int(doc.get("fails", 0)) >= self._max:
            secs = min(self._lock * (2 ** max(0, int(doc["fails"]) - self._max)), self.MAX_LOCK)
            self._storage_call(self._col.update_one, {"_id": key},
                               {"$set": {"locked_until": now + timedelta(seconds=secs)}})

    def record_success(self, username: str) -> None:
        self._storage_call(self._col.delete_one, {"_id": throttle_key(username)})

    def unlock(self, username: str) -> None:
        self._storage_call(self._col.delete_one, {"_id": throttle_key(username)})
