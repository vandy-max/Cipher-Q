"""
Registration / login orchestration (hardened).

* username normalisation + atomic uniqueness (``usernames`` index collection);
* scrypt hashing, transparent re-hash of legacy PBKDF2 records on login;
* persistent lockout + uniform failure responses + dummy hash for unknown users;
* every issued JWT is registered (``jti``) so it can be revoked individually, and
  carries the user's ``token_version`` so all tokens can be revoked at once.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .jwt_service import JWTService
from .password import (PasswordPolicyError, burn_dummy_verify, hash_password_v2, needs_rehash,
                       validate_password_policy, verify_password)
from .throttle import AccountLockedError, LoginThrottle  # noqa: F401  (re-exported)

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$")
_MIN_PASSWORD_LENGTH = 10


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    email: str
    password_hash: str
    salt: str
    role: str
    disabled: bool = False
    token_version: int = 0


class UsernameTakenError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class AccountDisabledError(Exception):
    pass


def normalize_username(username: str) -> str:
    return unicodedata.normalize("NFC", username).strip()


class UserRepository(Protocol):
    def get_by_username(self, username: str) -> UserRecord | None: ...
    def get_by_id(self, user_id: int) -> UserRecord | None: ...
    def create(self, username: str, email: str, password_hash: str, salt: str, role: str) -> UserRecord: ...
    def update_password_hash(self, user_id: int, password_hash: str) -> None: ...


class TokenRepository(Protocol):
    def register(self, jti: str, user_id: int, expires_at: datetime) -> None: ...


class InMemoryUserRepository:
    """Reference/test implementation only -- not for production use."""

    def __init__(self) -> None:
        self._by_id: dict[int, UserRecord] = {}
        self._by_username: dict[str, int] = {}
        self._next_id = 1

    def get_by_username(self, username: str) -> UserRecord | None:
        uid = self._by_username.get(username.lower())
        return self._by_id.get(uid) if uid is not None else None

    def get_by_id(self, user_id: int) -> UserRecord | None:
        return self._by_id.get(user_id)

    def create(self, username, email, password_hash, salt, role) -> UserRecord:
        if username.lower() in self._by_username:
            raise UsernameTakenError(username)
        user = UserRecord(self._next_id, username, email, password_hash, salt, role)
        self._by_id[user.id] = user
        self._by_username[username.lower()] = user.id
        self._next_id += 1
        return user

    def update_password_hash(self, user_id: int, password_hash: str) -> None:
        u = self._by_id[user_id]
        self._by_id[user_id] = UserRecord(u.id, u.username, u.email, password_hash, "", u.role,
                                          u.disabled, u.token_version)


@dataclass(frozen=True)
class AuthResult:
    token: str
    user_id: int
    username: str
    role: str
    expires_at: datetime | None = None


class AuthenticationService:
    def __init__(self, repository: UserRepository, jwt_service: JWTService,
                 tokens: TokenRepository | None = None, throttle: LoginThrottle | None = None) -> None:
        self._repository = repository
        self._jwt = jwt_service
        self._tokens = tokens
        self._throttle = throttle

    # ------------------------------------------------------------------
    def _issue(self, user: UserRecord) -> AuthResult:
        now = datetime.now(timezone.utc)
        import secrets
        jti = secrets.token_hex(16)
        token = self._jwt.create_token(user.id, user.username, user.role, user.token_version, jti=jti, now=now)
        expires = now + self._jwt.ttl
        if self._tokens is not None:
            self._tokens.register(jti, user.id, expires)
        return AuthResult(token=token, user_id=user.id, username=user.username, role=user.role, expires_at=expires)

    def register(self, username: str, email: str, password: str, role: str = "USER_LEVEL_1") -> AuthResult:
        username = normalize_username(username or "")
        if not USERNAME_RE.match(username):
            raise ValueError("username must be 3-64 characters: letters, digits and _ . @ -")
        email = (email or "").strip()
        if not EMAIL_RE.match(email):
            raise ValueError("a valid email address is required")
        try:
            validate_password_policy(password, username)
        except PasswordPolicyError as exc:
            raise ValueError(str(exc)) from exc
        user = self._repository.create(username, email, hash_password_v2(password), "", role)
        return self._issue(user)

    def login(self, username: str, password: str) -> AuthResult:
        username = normalize_username(username or "")
        if self._throttle is not None:
            self._throttle.check(username)          # raises AccountLockedError
        user = self._repository.get_by_username(username) if username else None
        ok = False
        if user is None:
            burn_dummy_verify(password)
        else:
            ok = verify_password(password, user.salt, user.password_hash)
        if not ok:
            if self._throttle is not None:
                self._throttle.record_failure(username)
            raise InvalidCredentialsError("invalid username or password")
        assert user is not None
        if user.disabled:
            if self._throttle is not None:
                self._throttle.record_failure(username)
            raise InvalidCredentialsError("invalid username or password")  # uniform: no state leak
        if self._throttle is not None:
            self._throttle.record_success(username)
        if needs_rehash(user.password_hash):
            self._repository.update_password_hash(user.id, hash_password_v2(password))
        return self._issue(user)
