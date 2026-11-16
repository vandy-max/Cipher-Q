"""
Password hashing -- scrypt (stdlib, memory-hard) with transparent migration
from the v17 PBKDF2-HMAC-SHA256 (100 000 iterations) records.

Stored format (single self-describing string, ``salt`` column left empty):

    scrypt$<log2 N>$<r>$<p>$<salt b64url>$<hash b64url>

Legacy records (``password_hash`` = 64 hex chars, ``salt`` = 32 hex chars) still
verify; on the next successful login the service re-hashes them to scrypt
(``needs_rehash``).  Verification is constant-time and a dummy hash is computed
for unknown users so response time does not reveal account existence.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128          # bounds KDF work an unauthenticated caller can force
_R = 8
_P = 3
_LEGACY_ITERATIONS = 100_000
_COMMON = frozenset({
    "password", "password1", "passw0rd", "1234567890", "qwertyuiop", "letmein123",
    "admin12345", "welcome123", "iloveyou12", "administrator",
})


_COMMON_STEMS = frozenset({"password", "passw", "qwerty", "qwertyuiop", "letmein", "welcome", "admin",
                           "administrator", "iloveyou", "changeme", "abc", "monkey", "dragon", "cipherq"})


class PasswordPolicyError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _log_n() -> int:
    from config import get_settings
    return get_settings().scrypt_log_n


def validate_password_policy(password: str, username: str = "") -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"password must be at most {MAX_PASSWORD_LENGTH} characters")
    if len(set(password)) < 5:
        raise PasswordPolicyError("password is too repetitive")
    low = password.lower()
    stem = re.sub(r"[^a-z]", "", low)
    if low in _COMMON or stem in _COMMON_STEMS or (stem and any(stem.startswith(w) and len(stem) <= len(w) + 2 for w in _COMMON_STEMS)):
        raise PasswordPolicyError("password is too common")
    if re.fullmatch(r"[0-9]+", password):
        raise PasswordPolicyError("password must not be only digits")
    if username and len(username) >= 3 and username.lower() in low:
        raise PasswordPolicyError("password must not contain the username")


def _scrypt(password: str, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=1 << log_n, r=r, p=p,
                          maxmem=256 * 1024 * 1024, dklen=32)


def hash_password_v2(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError("password too long")
    log_n, salt = _log_n(), secrets.token_bytes(16)
    return f"scrypt${log_n}${_R}${_P}${_b64(salt)}${_b64(_scrypt(password, salt, log_n, _R, _P))}"


# --- legacy API (kept: used by migration tests and old callers) ---------
def generate_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    """LEGACY PBKDF2 hash -- only for verifying/creating v17-format test fixtures."""
    if not password:
        raise ValueError("password must not be empty")
    if not salt:
        raise ValueError("salt must not be empty")
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt),
                               _LEGACY_ITERATIONS).hex()


_V2 = re.compile(r"^scrypt\$(\d{1,2})\$(\d{1,2})\$(\d{1,2})\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$")


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH or not password:
        return False
    m = _V2.match(expected_hash or "")
    if m:
        log_n, r, p = int(m[1]), int(m[2]), int(m[3])
        if not (10 <= log_n <= 20 and 1 <= r <= 16 and 1 <= p <= 16):
            return False
        cand = _scrypt(password, _unb64(m[4]), log_n, r, p)
        return hmac.compare_digest(cand, _unb64(m[5]))
    try:
        return hmac.compare_digest(hash_password(password, salt), expected_hash)
    except ValueError:
        return False


def needs_rehash(expected_hash: str) -> bool:
    m = _V2.match(expected_hash or "")
    return not m or int(m[1]) < _log_n()


_DUMMY: str | None = None


def burn_dummy_verify(password: str) -> None:
    """Equalise timing for unknown usernames."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password_v2(secrets.token_urlsafe(12))
    verify_password(password if isinstance(password, str) else "", "", _DUMMY)
