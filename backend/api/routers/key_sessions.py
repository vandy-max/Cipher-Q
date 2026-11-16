"""Server-side quantum-key (simulation) sessions. The key itself is never serialised."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from audit.events import AuditEvent
from audit.service import AuditLogService
from config import get_settings
from crypto import records as crec
from keymgmt.key_sessions import ACTIVE, KeySessionService, KeyUnavailableError
from quantum.bb84 import MIN_QUBITS, STATUS_OK
from security.ratelimit import ConcurrencyGate, client_ip, limiter

from ..dependencies import Principal, get_audit_service, get_current_user, get_key_session_service

router = APIRouter(prefix="/api/key-sessions", tags=["key-sessions"])

_gate = ConcurrencyGate(max(1, get_settings().quantum_concurrency))


class CreateKeySession(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n_qubits: Annotated[int, Field(ge=MIN_QUBITS, le=8192)] | None = None
    # Simulation knob (intercept-resend probability). Honoured ONLY when attack simulation is enabled
    # in the deployment (never in production); it never selects key material.
    simulate_eavesdropper_prob: Annotated[float, Field(ge=0.0, le=1.0)] = 0.0


def _throttle(request: Request, user_id: int) -> None:
    st = get_settings()
    ok, retry = limiter.check(f"qks-user:{user_id}", st.quantum_per_user_per_hour, 3600)
    ok2, retry2 = limiter.check(f"heavy-ip:{client_ip(request, st.trusted_proxies)}", st.heavy_ip_per_minute, 60)
    if not (ok and ok2):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "rate limit exceeded",
                            headers={"Retry-After": str(int(max(retry, retry2)) + 1)})


@router.post("", status_code=status.HTTP_201_CREATED)
def create(payload: CreateKeySession, request: Request, user: Principal = Depends(get_current_user),
           svc: KeySessionService = Depends(get_key_session_service),
           audit: AuditLogService = Depends(get_audit_service)):
    st = get_settings()
    if payload.simulate_eavesdropper_prob > 0 and not st.allow_attack_simulation:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "attack simulation is disabled in this deployment")
    _throttle(request, user.user_id)
    if not _gate.try_acquire():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "quantum simulation capacity exhausted",
                            headers={"Retry-After": "5"})
    try:
        info = svc.create(user.user_id, n_qubits=payload.n_qubits,
                          eavesdrop_prob=payload.simulate_eavesdropper_prob)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    finally:
        _gate.release()
    if info.status != ACTIVE:
        audit.record(AuditEvent.KEY_SESSION_ABORTED, "rejected", user_id=user.user_id,
                     reason=f"key_session={info.key_session_id} status={info.status} qber={info.qber}")
        return JSONResponse(status_code=status.HTTP_409_CONFLICT,
                            content={"detail": "key exchange aborted; no key was established", **info.as_dict()})
    audit.record(AuditEvent.KEY_SESSION_CREATED, "success", user_id=user.user_id,
                 reason=f"key_session={info.key_session_id} qber={info.qber} entropy_bits={info.effective_entropy_bits}")
    return info.as_dict()


@router.get("")
def list_mine(user: Principal = Depends(get_current_user), svc: KeySessionService = Depends(get_key_session_service)):
    return [i.as_dict() for i in svc.list_for_user(user.user_id)]


@router.get("/{key_session_id}")
def get_one(key_session_id: str, user: Principal = Depends(get_current_user),
            svc: KeySessionService = Depends(get_key_session_service)):
    info = svc.get(key_session_id, user.user_id)
    if info is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "key session not found")
    return info.as_dict()


@router.post("/{key_session_id}/revoke")
def revoke(key_session_id: str, user: Principal = Depends(get_current_user),
           svc: KeySessionService = Depends(get_key_session_service),
           audit: AuditLogService = Depends(get_audit_service)):
    if not svc.revoke(key_session_id, user.user_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "key session not found or already ended")
    audit.record(AuditEvent.KEY_SESSION_REVOKED, "success", user_id=user.user_id,
                 reason=f"key_session={key_session_id}; key material destroyed")
    return {"key_session_id": key_session_id, "status": "REVOKED"}


@router.post("/{key_session_id}/rotate", status_code=status.HTTP_201_CREATED)
def rotate(key_session_id: str, payload: CreateKeySession, request: Request,
           user: Principal = Depends(get_current_user),
           svc: KeySessionService = Depends(get_key_session_service),
           audit: AuditLogService = Depends(get_audit_service)):
    st = get_settings()
    if payload.simulate_eavesdropper_prob > 0 and not st.allow_attack_simulation:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "attack simulation is disabled in this deployment")
    _throttle(request, user.user_id)
    if not _gate.try_acquire():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "quantum simulation capacity exhausted")
    try:
        new = svc.rotate(key_session_id, user.user_id, n_qubits=payload.n_qubits,
                         eavesdrop_prob=payload.simulate_eavesdropper_prob)
    except KeyUnavailableError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.code) from exc
    finally:
        _gate.release()
    if new.status != ACTIVE:
        audit.record(AuditEvent.KEY_SESSION_ABORTED, "rejected", user_id=user.user_id,
                     reason=f"rotation aborted status={new.status}; previous session unchanged")
        return JSONResponse(status_code=status.HTTP_409_CONFLICT,
                            content={"detail": "rotation aborted; previous key session unchanged", **new.as_dict()})
    audit.record(AuditEvent.KEY_SESSION_ROTATED, "success", user_id=user.user_id,
                 reason=f"{key_session_id} -> {new.key_session_id}")
    return new.as_dict()


class RewrapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to_key_session_id: Annotated[str, Field(min_length=8, max_length=64)]


@router.post("/{key_session_id}/rewrap")
def rewrap_records(key_session_id: str, payload: RewrapRequest, user: Principal = Depends(get_current_user),
                   svc: KeySessionService = Depends(get_key_session_service),
                   audit: AuditLogService = Depends(get_audit_service)):
    """Move this user's records from ``key_session_id`` to a newer ACTIVE session (ciphertext unchanged)."""
    from database.session import db
    try:
        old_key = svc.unwrap(key_session_id, user.user_id, for_encrypt=False)
        new_info = svc.get(payload.to_key_session_id, user.user_id)
        if new_info is None or new_info.status != ACTIVE:
            raise HTTPException(status.HTTP_409_CONFLICT, "target key session is not active")
        new_key = svc.unwrap(payload.to_key_session_id, user.user_id, for_encrypt=True)
    except KeyUnavailableError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, exc.code) from exc
    moved = 0
    records = list(db["crypto_records"].find({"owner_user_id": user.user_id, "key_session_id": key_session_id}))
    for rec in records:
        try:
            new = crec.rewrap(rec["sealed"], old_key, new_key, payload.to_key_session_id, new_info.generation)
        except crec.RecordError:
            continue
        updated = db["crypto_records"].update_one(
            {"_id": rec["_id"], "key_session_id": key_session_id},
            {"$set": {"sealed": new, "key_session_id": payload.to_key_session_id,
                      "key_generation": new_info.generation}})
        moved += updated.matched_count
    shares_moved = 0
    shares = list(db["crypto_shares"].find(
        {"recipient_user_id": user.user_id, "key_session_id": key_session_id,
         "status": {"$in": ["PENDING", "PENDING_ADMIN", "APPROVED"]}}))
    for share in shares:
        if share["status"] == "PENDING":
            update = {"$set": {"key_session_id": payload.to_key_session_id,
                               "key_generation": new_info.generation}}
        else:
            try:
                new = crec.rewrap(share["sealed"], old_key, new_key,
                                  payload.to_key_session_id, new_info.generation)
            except crec.RecordError:
                continue
            update = {"$set": {"sealed": new, "key_session_id": payload.to_key_session_id,
                               "key_generation": new_info.generation}}
        changed = db["crypto_shares"].update_one(
            {"_id": share["_id"], "recipient_user_id": user.user_id,
             "key_session_id": key_session_id, "status": share["status"]}, update)
        shares_moved += changed.matched_count
    old_key = b""
    new_key = b""
    audit.record(AuditEvent.RECORD_REWRAPPED, "success", user_id=user.user_id,
                 reason=f"{key_session_id} -> {payload.to_key_session_id} "
                        f"records={moved} shares={shares_moved}")
    return {"moved": moved + shares_moved, "records_moved": moved, "shares_moved": shares_moved}
