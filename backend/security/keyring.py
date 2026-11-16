"""
Versioned root-key ring with purpose-separated sub-keys.

Root keys are 32 random bytes held outside the database (environment variable
or a 0600 file; see ``config.py``).  Each *purpose* gets an independent key via
HKDF-SHA256, so compromise of, say, the audit-MAC key does not reveal the
database-encryption key and a key can never be used for two purposes.

Key ids are stored next to ciphertext / MACs (``kid``) so rotation never
requires guessing which key to use: old keys stay in the ring, *decrypt-only*,
until ``scripts/rotate_keys.py`` has re-encrypted everything and the operator
retires them.
"""
from __future__ import annotations

from typing import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DB_ENCRYPTION = "db-encryption"
QKEY_WRAP = "quantum-key-wrap"
CTX_WRAP = "crypto-context-wrap"
AUTHZ_SIGN = "authorization-signing"
AUDIT_MAC = "audit-mac"
DIRECT_MESSAGE_WRAP = "direct-message-wrap"

_PURPOSES = frozenset({DB_ENCRYPTION, QKEY_WRAP, CTX_WRAP, AUTHZ_SIGN, AUDIT_MAC, DIRECT_MESSAGE_WRAP})
_SALT = b"CIPHERQ-KEYRING-v1"


class UnknownKeyError(KeyError):
    pass


class Keyring:
    def __init__(self, keys: Mapping[int, bytes], active_id: int) -> None:
        if active_id not in keys:
            raise UnknownKeyError(f"active key id {active_id} not in keyring")
        for kid, key in keys.items():
            if len(key) != 32:
                raise ValueError(f"key {kid} must be 32 bytes")
        self._keys = dict(keys)
        self.active_id = active_id
        self._cache: dict[tuple[str, int], bytes] = {}

    def __repr__(self) -> str:
        return f"Keyring(ids={sorted(self._keys)}, active={self.active_id}, keys=<redacted>)"

    def ids(self) -> list[int]:
        return sorted(self._keys)

    def has(self, kid: int) -> bool:
        return kid in self._keys

    def subkey(self, purpose: str, kid: int | None = None) -> bytes:
        if purpose not in _PURPOSES:
            raise ValueError(f"unknown key purpose {purpose!r}")
        kid = self.active_id if kid is None else kid
        if kid not in self._keys:
            raise UnknownKeyError(f"key id {kid} is not in the keyring")
        ck = (purpose, kid)
        if ck not in self._cache:
            self._cache[ck] = HKDF(algorithm=hashes.SHA256(), length=32, salt=_SALT,
                                   info=b"purpose:" + purpose.encode()).derive(self._keys[kid])
        return self._cache[ck]


_keyring: Keyring | None = None


def get_keyring() -> Keyring:
    global _keyring
    if _keyring is None:
        from config import get_settings
        s = get_settings()
        _keyring = Keyring(s.keyring, s.active_key_id)
    return _keyring


def reset_keyring() -> None:  # test helper
    global _keyring
    _keyring = None
