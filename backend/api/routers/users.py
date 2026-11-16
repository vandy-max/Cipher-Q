"""Admin-only user, role and account-state management (server-side gated)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.throttle import LoginThrottle

from ..dependencies import Principal, get_audit_service, get_login_throttle, get_user_repository
from ..rbac import ADMIN, require_roles
from ..repositories import MongoUserRepository
from ..schemas import UpdateUserRoleRequest, UserResponse

router = APIRouter(prefix="/api/users", tags=["users"])


def _to_response(r) -> UserResponse:
    return UserResponse(id=r.id, username=r.username, email=r.email, role=r.role, disabled=r.disabled)


def _target(repo: MongoUserRepository, user_id: int):
    t = repo.get_by_id(user_id)
    if t is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return t


def _guard_last_admin(repo: MongoUserRepository, target) -> None:
    if target.role == ADMIN and not target.disabled and repo.count_enabled_admins() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "refusing to remove the last enabled administrator")


@router.get("", response_model=list[UserResponse])
def list_users(_: Principal = Depends(require_roles(ADMIN)),
               repo: MongoUserRepository = Depends(get_user_repository)) -> list[UserResponse]:
    return [_to_response(u) for u in repo.list_all()]


@router.put("/{user_id}/role", response_model=UserResponse)
def update_user_role(user_id: int, payload: UpdateUserRoleRequest,
                     admin: Principal = Depends(require_roles(ADMIN)),
                     repo: MongoUserRepository = Depends(get_user_repository),
                     audit: AuditLogService = Depends(get_audit_service)) -> UserResponse:
    target = _target(repo, user_id)
    if target.role == payload.role:
        return _to_response(target)
    if target.role == ADMIN:
        _guard_last_admin(repo, target)
    updated = repo.update_role(user_id, payload.role)      # also invalidates the target's tokens
    audit.record(AuditEvent.ROLE_CHANGED, "success", user_id=admin.user_id,
                 reason=f"target={user_id} {target.role}->{payload.role}")
    return _to_response(updated)


@router.post("/{user_id}/disable", response_model=UserResponse)
def disable_user(user_id: int, admin: Principal = Depends(require_roles(ADMIN)),
                 repo: MongoUserRepository = Depends(get_user_repository),
                 audit: AuditLogService = Depends(get_audit_service)) -> UserResponse:
    target = _target(repo, user_id)
    _guard_last_admin(repo, target)
    updated = repo.set_disabled(user_id, True)
    audit.record(AuditEvent.ACCOUNT_DISABLED, "success", user_id=admin.user_id, reason=f"target={user_id}")
    return _to_response(updated)


@router.post("/{user_id}/enable", response_model=UserResponse)
def enable_user(user_id: int, admin: Principal = Depends(require_roles(ADMIN)),
                repo: MongoUserRepository = Depends(get_user_repository),
                audit: AuditLogService = Depends(get_audit_service)) -> UserResponse:
    _target(repo, user_id)
    updated = repo.set_disabled(user_id, False)
    audit.record(AuditEvent.ACCOUNT_ENABLED, "success", user_id=admin.user_id, reason=f"target={user_id}")
    return _to_response(updated)


@router.post("/{user_id}/unlock", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def unlock_user(user_id: int, admin: Principal = Depends(require_roles(ADMIN)),
                repo: MongoUserRepository = Depends(get_user_repository),
                throttle: LoginThrottle = Depends(get_login_throttle),
                audit: AuditLogService = Depends(get_audit_service)) -> None:
    target = _target(repo, user_id)
    throttle.unlock(target.username)
    audit.record(AuditEvent.ACCOUNT_UNLOCKED, "success", user_id=admin.user_id, reason=f"target={user_id}")
