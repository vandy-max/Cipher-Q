"""
JWT issuance and verification (HS256, algorithm pinned, all claims required).

A JWT here is only a *bearer reference*: it proves that the server once issued
``jti`` to ``sub``.  Whether it is still honoured is decided per request by
``api.dependencies.get_current_user`` against the database (account enabled,
role, ``token_version``, per-token revocation).  Claims:

    sub  user id (str)      jti  random 128-bit id (revocation handle)
    iat/nbf/exp             iss/aud  fixed audience
    tv   user.token_version at issuance (bumped on role change / disable /
         password change / "log out everywhere")
    username / role are NOT trusted for authorization; the DB values are used.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt as pyjwt


class TokenExpiredError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


@dataclass(frozen=True)
class TokenPayload:
    user_id: int
    username: str
    role: str
    expires_at: datetime
    jti: str = ""
    token_version: int = 0
    issued_at: datetime | None = None


_REQUIRED = ["exp", "iat", "nbf", "sub", "jti", "iss", "aud", "tv"]


class JWTService:
    ALGORITHM = "HS256"

    def __init__(self, secret: str, ttl_minutes: int = 30, issuer: str = "cipherq",
                 audience: str = "cipherq-api", *, ttl_hours: int | None = None) -> None:
        if not secret or len(secret.encode()) < 32:
            raise ValueError("JWT secret must be at least 32 bytes")
        self._secret = secret
        self._ttl = timedelta(hours=ttl_hours) if ttl_hours is not None else timedelta(minutes=ttl_minutes)
        self._iss, self._aud = issuer, audience

    @property
    def ttl(self) -> timedelta:
        return self._ttl

    def create_token(self, user_id: int, username: str, role: str, token_version: int = 0,
                     jti: str | None = None, now: datetime | None = None) -> str:
        now = now or datetime.now(timezone.utc)
        payload = {
            "sub": str(user_id), "username": username, "role": role,
            "jti": jti or secrets.token_hex(16), "tv": int(token_version),
            "iat": now, "nbf": now, "exp": now + self._ttl, "iss": self._iss, "aud": self._aud,
        }
        return pyjwt.encode(payload, self._secret, algorithm=self.ALGORITHM)

    def decode_token(self, token: str) -> TokenPayload:
        try:
            p = pyjwt.decode(token, self._secret, algorithms=[self.ALGORITHM], audience=self._aud,
                             issuer=self._iss, options={"require": _REQUIRED}, leeway=5)
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except pyjwt.PyJWTError as exc:
            raise InvalidTokenError("token is invalid") from exc
        try:
            return TokenPayload(
                user_id=int(p["sub"]), username=str(p.get("username", "")), role=str(p.get("role", "")),
                expires_at=datetime.fromtimestamp(p["exp"], tz=timezone.utc), jti=str(p["jti"]),
                token_version=int(p["tv"]), issued_at=datetime.fromtimestamp(p["iat"], tz=timezone.utc))
        except (ValueError, TypeError, KeyError) as exc:
            raise InvalidTokenError("token is invalid") from exc
