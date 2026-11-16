"""Identity: face enrolment (re-authenticated) and challenge-bound step-up verification.

The face descriptor is computed in the browser; the server cannot attest liveness. See
identity/stepup.py and INTENT_SECURITY_ARCHITECTURE.md for exactly what is and is not claimed.
"""
from __future__ import annotations

import math
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService
from monitoring.service import MonitoringService
from authentication.password import verify_password
from config import get_settings
from identity.stepup import StepUpError, StepUpService
from security.ratelimit import client_ip, limiter

from ..dependencies import (get_monitoring_service, Principal, get_audit_service, get_current_user, get_face_auth_service,
                            get_stepup_service, get_user_repository)
from ..rbac import ADMIN, require_roles
from ..repositories import MongoUserRepository

router = APIRouter(prefix="/api/face", tags=["face-auth"])
identity_router = APIRouter(prefix="/api/identity", tags=["identity"])

_SID = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{5,127}$", max_length=128)]


def _check_descriptor(v: list[float]) -> list[float]:
    if len(v) != 128:
        raise ValueError("descriptor must have 128 values")
    if not all(isinstance(x, (int, float)) and math.isfinite(x) and -5.0 <= x <= 5.0 for x in v):
        raise ValueError("descriptor values must be finite numbers in [-5, 5]")
    if len({round(x, 6) for x in v}) < 8:
        raise ValueError("descriptor is degenerate")
    return [float(x) for x in v]


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    descriptor: list[float]
    password: Annotated[str, Field(min_length=1, max_length=128)]
    session_id: _SID | None = None

    _v = field_validator("descriptor")(lambda cls, v: _check_descriptor(v))


class ChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    session_id: _SID


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: Annotated[str, Field(min_length=16, max_length=64)]
    session_id: _SID
    descriptor: list[float]

    _v = field_validator("descriptor")(lambda cls, v: _check_descriptor(v))


@router.get("/status")
def enrollment_status(user: Principal = Depends(get_current_user),
                      service: FaceAuthService = Depends(get_face_auth_service)):
    return {"enrolled": service.is_enrolled(user.user_id)}          # never the descriptor


@router.post("/enroll", status_code=204, response_model=None)
def enroll(p: EnrollRequest, request: Request, user: Principal = Depends(get_current_user),
           service: FaceAuthService = Depends(get_face_auth_service),
           users: MongoUserRepository = Depends(get_user_repository),
           stepup: StepUpService = Depends(get_stepup_service),
           audit: AuditLogService = Depends(get_audit_service)):
    st = get_settings()
    ok, _ = limiter.check(f"enroll:{user.user_id}", 5, 600)
    if not ok:
        raise HTTPException(429, "too many attempts")
    rec = users.get_by_id(user.user_id)
    if rec is None or not verify_password(p.password, rec.salt, rec.password_hash):
        audit.record(AuditEvent.FACE_ENROLLMENT_REJECTED, "rejected", user_id=user.user_id, reason="password re-entry failed")
        raise HTTPException(403, "re-authentication failed")
    if service.is_enrolled(user.user_id):
        # replacing a biometric needs the OLD biometric to have been verified recently, in this session
        if not p.session_id or not stepup.has_fresh_grant(user.user_id, p.session_id):
            audit.record(AuditEvent.FACE_ENROLLMENT_REJECTED, "rejected", user_id=user.user_id,
                         reason="replacement requires fresh step-up with the existing enrolment")
            raise HTTPException(403, "replacing an enrolment requires a fresh step-up verification")
    service.enroll(user.user_id, p.descriptor)
    if p.session_id:
        stepup.revoke_grants(user.user_id)
    audit.record(AuditEvent.FACE_ENROLLED, "success", user_id=user.user_id)


@router.delete("/enrollment/{user_id}", status_code=204, response_model=None)
def admin_reset(user_id: int, admin: Principal = Depends(require_roles(ADMIN)),
                users: MongoUserRepository = Depends(get_user_repository),
                stepup: StepUpService = Depends(get_stepup_service),
                audit: AuditLogService = Depends(get_audit_service)):
    if users.get_by_id(user_id) is None:
        raise HTTPException(404, "user not found")
    users._db["users"].update_one({"_id": user_id}, {"$set": {"face_descriptor": None}})
    stepup.revoke_grants(user_id)
    audit.record(AuditEvent.FACE_ENROLLMENT_RESET, "success", user_id=admin.user_id, reason=f"target={user_id}")


@identity_router.post("/challenges", status_code=201)
def challenge(p: ChallengeRequest, user: Principal = Depends(get_current_user),
              stepup: StepUpService = Depends(get_stepup_service),
              audit: AuditLogService = Depends(get_audit_service)):
    ok, _ = limiter.check(f"chal:{user.user_id}", 20, 60)
    if not ok:
        raise HTTPException(429, "too many requests")
    try:
        c = stepup.issue_challenge(user.user_id, p.session_id)
    except StepUpError as exc:
        raise HTTPException(409 if exc.code == "NOT_ENROLLED" else 429, exc.code) from exc
    audit.record(AuditEvent.STEPUP_CHALLENGE_ISSUED, "success", user_id=user.user_id, session_id=p.session_id)
    return {"challenge_id": c.challenge_id, "nonce": c.nonce, "expires_ts": c.expires_ts}


@identity_router.post("/verify")
def verify(p: VerifyRequest, user: Principal = Depends(get_current_user),
           stepup: StepUpService = Depends(get_stepup_service),
           audit: AuditLogService = Depends(get_audit_service),
           monitoring: MonitoringService = Depends(get_monitoring_service)):
    try:
        grant = stepup.verify(user.user_id, p.session_id, p.challenge_id, p.descriptor)
    except StepUpError as exc:
        audit.record(AuditEvent.STEPUP_FAILURE, "rejected", user_id=user.user_id, session_id=p.session_id,
                     reason=exc.code)
        raise HTTPException(429 if exc.code == "LOCKED" else 403, "verification failed") from exc
    monitoring.acknowledge_stepup(p.session_id)
    audit.record(AuditEvent.STEPUP_SUCCESS, "success", user_id=user.user_id, session_id=p.session_id,
                 reason="descriptor similarity only; liveness not established")
    return {"verified": True, **grant}
