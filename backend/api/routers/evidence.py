"""Local evidence provider administration (documented stand-in for a case-management system)."""
from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from audit.events import AuditEvent
from audit.service import AuditLogService
from intent_engine.evidence import LocalEvidenceProvider
from intent_engine.schema import REF_RE, RESOURCE_RE

from ..dependencies import Principal, get_audit_service, get_current_user, get_evidence_provider, get_user_repository
from ..rbac import ADMIN, require_roles

router = APIRouter(prefix="/api/evidence", tags=["evidence"])
_REF = Annotated[str, Field(pattern=REF_RE.pattern, max_length=32)]


class CaseUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Annotated[str, Field(min_length=3, max_length=120)]
    classification_cap: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    allowed_resources: Annotated[list[Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]], Field(max_length=50)]
    assigned_user_ids: Annotated[list[Annotated[int, Field(ge=1)]], Field(max_length=100)] = []
    status: Literal["OPEN", "CLOSED"] = "OPEN"


class UserRef(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: Annotated[int, Field(ge=1)]


def _view(c) -> dict:
    return {"ref": c.ref, "status": c.status, "title": c.title, "classification_cap": c.classification_cap,
            "allowed_resources": list(c.allowed_resources), "assigned_user_ids": list(c.assigned_user_ids),
            "updated_at": c.updated_at, "revision": c.revision,
            "provider": "local-case-table (administrator-maintained; not an external system)"}


@router.get("/cases", dependencies=[Depends(require_roles(ADMIN))])
def list_cases(prov: LocalEvidenceProvider = Depends(get_evidence_provider),
               limit: Annotated[int, Query(ge=1, le=100)] = 50,
               offset: Annotated[int, Query(ge=0)] = 0):
    cases = prov.list_cases(limit=limit, offset=offset)
    return {"cases": [_view(case) for case in cases[:limit]], "offset": offset, "limit": limit,
            "has_more": len(cases) > limit}


@router.put("/cases/{ref}")
def upsert(ref: _REF, p: CaseUpsert, admin: Principal = Depends(require_roles(ADMIN)),
           prov: LocalEvidenceProvider = Depends(get_evidence_provider),
           users=Depends(get_user_repository), audit: AuditLogService = Depends(get_audit_service)):
    # Assignments are the authorisation input of evidence validation: an ID that is not a real user can
    # never match a requester, so saving it silently produces USER_NOT_ASSIGNED later. Reject it now.
    unknown = sorted({uid for uid in p.assigned_user_ids if users.get_by_id(uid) is None})
    if unknown:
        raise HTTPException(422, f"assigned user IDs do not exist: {', '.join(map(str, unknown))}")
    c = prov.upsert_case(ref, title=p.title, classification_cap=p.classification_cap,
                         allowed_resources=p.allowed_resources, assigned_user_ids=p.assigned_user_ids,
                         status=p.status)
    audit.record(AuditEvent.EVIDENCE_CASE_CHANGED, "success", user_id=admin.user_id,
                 reason=f"case={ref} rev={c.revision} status={c.status}")
    return _view(c)


def _mutate(ref, admin, prov, audit, fn, note):
    c = prov.get_case(ref)
    if c is None:
        raise HTTPException(404, "case not found")
    new = fn(c)
    c2 = prov.upsert_case(ref, title=c.title, classification_cap=c.classification_cap,
                          allowed_resources=list(c.allowed_resources), assigned_user_ids=new["assigned"],
                          status=new["status"])
    audit.record(AuditEvent.EVIDENCE_CASE_CHANGED, "success", user_id=admin.user_id,
                 reason=f"case={ref} rev={c2.revision} {note}")
    return _view(c2)


@router.post("/cases/{ref}/close")
def close(ref: _REF, admin: Principal = Depends(require_roles(ADMIN)),
          prov: LocalEvidenceProvider = Depends(get_evidence_provider),
          audit: AuditLogService = Depends(get_audit_service)):
    return _mutate(ref, admin, prov, audit, lambda c: {"assigned": list(c.assigned_user_ids), "status": "CLOSED"}, "closed")


@router.post("/cases/{ref}/assign")
def assign(ref: _REF, p: UserRef, admin: Principal = Depends(require_roles(ADMIN)),
           prov: LocalEvidenceProvider = Depends(get_evidence_provider),
           users=Depends(get_user_repository), audit: AuditLogService = Depends(get_audit_service)):
    if users.get_by_id(p.user_id) is None:
        raise HTTPException(404, "user not found")
    return _mutate(ref, admin, prov, audit,
                   lambda c: {"assigned": sorted(set(c.assigned_user_ids) | {p.user_id}), "status": c.status},
                   f"assigned user {p.user_id}")


@router.post("/cases/{ref}/unassign")
def unassign(ref: _REF, p: UserRef, admin: Principal = Depends(require_roles(ADMIN)),
             prov: LocalEvidenceProvider = Depends(get_evidence_provider),
             audit: AuditLogService = Depends(get_audit_service)):
    return _mutate(ref, admin, prov, audit,
                   lambda c: {"assigned": [u for u in c.assigned_user_ids if u != p.user_id], "status": c.status},
                   f"unassigned user {p.user_id}")


@router.get("/cases/{ref}")
def get(ref: _REF, user: Principal = Depends(get_current_user),
        prov: LocalEvidenceProvider = Depends(get_evidence_provider)):
    c = prov.get_case(ref)
    if c is None or (user.role != ADMIN and user.user_id not in c.assigned_user_ids):
        raise HTTPException(404, "case not found")
    return _view(c)
