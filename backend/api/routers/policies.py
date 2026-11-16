from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from database.session import get_db

from ..dependencies import get_audit_service
from ..rbac import require_roles
from ..repositories import PolicyRepository
from ..schemas import PolicyRequest, PolicyResponse

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _to_response(row) -> PolicyResponse:
    return PolicyResponse(
        id=row.id,
        name=row.name,
        rule_type=row.rule_type,
        config=row.config_json,
        active=row.active,
    )


@router.get(
    "",
    response_model=list[PolicyResponse],
    dependencies=[Depends(require_roles("ADMIN"))],
)
def list_policies(
    db: Database = Depends(get_db),
) -> list[PolicyResponse]:
    """Policy Engine is ADMIN-only end to end (see section D of the
    fix pass) — reading policy configuration is itself sensitive
    (it reveals the security rules in force), so GET must be exactly
    as restricted as POST/PUT/DELETE, not merely 'any authenticated
    user'."""
    return [_to_response(row) for row in PolicyRepository(db).list_all()]


@router.post(
    "",
    response_model=PolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_policy(
    payload: PolicyRequest,
    db: Database = Depends(get_db),
    admin=Depends(require_roles("ADMIN")),
    audit: AuditLogService = Depends(get_audit_service),
) -> PolicyResponse:
    row = PolicyRepository(db).create(
        payload.name,
        payload.rule_type,
        payload.config,
        payload.active,
    )
    audit.record(AuditEvent.POLICY_CHANGED, "success", user_id=admin.user_id,
                 reason=f"policy={row.id} created rule_type={row.rule_type} active={row.active}")
    return _to_response(row)


@router.put(
    "/{policy_id}",
    response_model=PolicyResponse,
)
def update_policy(
    policy_id: int,
    payload: PolicyRequest,
    db: Database = Depends(get_db),
    admin=Depends(require_roles("ADMIN")),
    audit: AuditLogService = Depends(get_audit_service),
) -> PolicyResponse:
    row = PolicyRepository(db).update(
        policy_id,
        payload.name,
        payload.rule_type,
        payload.config,
        payload.active,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy not found",
        )
    audit.record(AuditEvent.POLICY_CHANGED, "success", user_id=admin.user_id,
                 reason=f"policy={policy_id} updated rule_type={row.rule_type} active={row.active}")
    return _to_response(row)


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
def delete_policy(
    policy_id: int,
    db: Database = Depends(get_db),
    admin=Depends(require_roles("ADMIN")),
    audit: AuditLogService = Depends(get_audit_service),
) -> Response:
    deleted = PolicyRepository(db).delete(policy_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="policy not found",
        )
    audit.record(AuditEvent.POLICY_CHANGED, "success", user_id=admin.user_id, reason=f"policy={policy_id} deleted")
    return Response(status_code=status.HTTP_204_NO_CONTENT)