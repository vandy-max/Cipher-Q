from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.service import (AccountLockedError, AuthenticationService, InvalidCredentialsError,
                                    UsernameTakenError)
from authentication.throttle import LoginThrottleUnavailableError
from config import get_settings
from security.ratelimit import client_ip, limiter

from ..dependencies import (Principal, get_audit_service, get_auth_service, get_current_user,
                            get_token_repository, get_user_repository)
from ..rbac import DEFAULT_SELF_REGISTER_ROLE
from ..schemas import AuthResponse, LoginRequest, RegisterRequest

router = APIRouter(prefix="/api/auth", tags=["authentication"])
log = logging.getLogger("cipherq.auth")


def _ip_limit(request: Request, bucket: str, limit: int, window: float) -> None:
    st = get_settings()
    ok, retry = limiter.check(f"{bucket}:{client_ip(request, st.trusted_proxies)}", limit, window)
    if not ok:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many requests",
                            headers={"Retry-After": str(int(retry) + 1)})


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    request: Request,
    service: AuthenticationService = Depends(get_auth_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> AuthResponse:
    st = get_settings()
    if not st.allow_self_register:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "self-registration is disabled")
    _ip_limit(request, "register", st.register_ip_per_hour, 3600)
    # Whatever role the client sent is ignored: self-registration => USER_LEVEL_1 only.
    try:
        result = service.register(payload.username, payload.email, payload.password,
                                  role=DEFAULT_SELF_REGISTER_ROLE)
    except UsernameTakenError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "username is already taken") from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit.record(AuditEvent.USER_REGISTERED, "success", user_id=result.user_id)
    return AuthResponse(token=result.token, user_id=result.user_id, username=result.username,
                        role=result.role, expires_at=result.expires_at)


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    service: AuthenticationService = Depends(get_auth_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> AuthResponse:
    st = get_settings()
    _ip_limit(request, "login", st.login_ip_per_10min, 600)
    try:
        result = service.login(payload.username, payload.password)
    except LoginThrottleUnavailableError as exc:
        request_id = getattr(request.state, "request_id", "-")
        log.exception("login throttle unavailable request_id=%s", request_id)
        audit.record(AuditEvent.LOGIN_FAILURE, "rejected", reason="login throttle unavailable")
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "login temporarily unavailable; try again later") from exc
    except AccountLockedError as exc:
        audit.record(AuditEvent.ACCOUNT_LOCKED, "rejected", reason="login throttled")
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many failed attempts; try later",
                            headers={"Retry-After": str(max(1, exc.retry_after))}) from exc
    except InvalidCredentialsError as exc:
        audit.record(AuditEvent.LOGIN_FAILURE, "rejected", reason="invalid credentials")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password") from exc
    audit.record(AuditEvent.LOGIN_SUCCESS, "success", user_id=result.user_id)
    return AuthResponse(token=result.token, user_id=result.user_id, username=result.username,
                        role=result.role, expires_at=result.expires_at)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout(user: Principal = Depends(get_current_user),
           tokens=Depends(get_token_repository),
           audit: AuditLogService = Depends(get_audit_service)) -> None:
    tokens.revoke(user.jti)
    audit.record(AuditEvent.LOGOUT, "success", user_id=user.user_id)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def logout_all(user: Principal = Depends(get_current_user),
               users=Depends(get_user_repository),
               audit: AuditLogService = Depends(get_audit_service)) -> None:
    users.bump_token_version(user.user_id)   # every previously issued token dies
    audit.record(AuditEvent.LOGOUT_ALL, "success", user_id=user.user_id)


@router.get("/me")
def me(user: Principal = Depends(get_current_user)) -> dict:
    return {"user_id": user.user_id, "username": user.username, "role": user.role,
            "expires_at": user.expires_at}
