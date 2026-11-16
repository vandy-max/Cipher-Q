"""Authorization decisions. A PERMIT also mints a single-use cryptographic context."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from audit.events import AuditEvent
from audit.service import AuditLogService
from config import get_settings
from crypto.sharing import authorization_metadata, find_record, record_expired
from intent_engine.engine import Actor, EngineError, IntentEngine, OperationRequest
from intent_engine.schema import ID_RE, RESOURCE_RE, Operation, Purpose
from security.ratelimit import client_ip, limiter

from ..dependencies import get_actor, get_audit_service, get_db, get_intent_engine

router = APIRouter(prefix="/api/decisions", tags=["authorization-decisions"])

_ID = Annotated[str, Field(pattern=ID_RE.pattern, max_length=128)]


class DecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intent_id: Annotated[int, Field(ge=1)]
    intent_version: Annotated[int, Field(ge=1)] | None = None
    operation: Operation
    resource: Annotated[str, Field(pattern=RESOURCE_RE.pattern, max_length=128)]
    purpose_code: Purpose
    session_id: _ID
    device_id: _ID
    key_session_id: Annotated[str, Field(min_length=8, max_length=64)] | None = None   # encrypt
    record_id: Annotated[str, Field(min_length=8, max_length=64)] | None = None        # decrypt
    requested_bytes: Annotated[int, Field(ge=0, le=12_582_912)] | None = None           # encrypt


def public_decision(out) -> dict:
    d = out.decision
    return {"decision_id": d["_id"], "outcome": out.outcome, "reasons": [r.as_dict() for r in out.reasons],
            "intent_id": d["intent_id"], "intent_version": d["intent_version"], "operation": d["operation"],
            "resource": d["resource"], "policy_version": d["policy_version"], "issued_ts": d["issued_ts"],
            "expires_ts": d["expires_ts"], "context_id": out.context_id,
            "next": {"REQUIRE_STEP_UP": "complete a step-up (POST /api/identity/challenges then /verify) and request again",
                     "REQUIRE_APPROVAL": "intent needs approval before it can be used"}.get(out.outcome)}


@router.post("")
def decide(payload: DecisionRequest, request: Request, actor: Actor = Depends(get_actor),
           eng: IntentEngine = Depends(get_intent_engine), db=Depends(get_db),
           audit: AuditLogService = Depends(get_audit_service)):
    st = get_settings()
    ok, retry = limiter.check(f"heavy-ip:{client_ip(request, st.trusted_proxies)}", st.heavy_ip_per_minute, 60)
    ok2, _ = limiter.check(f"decide-user:{actor.user_id}", 120, 60)
    if not (ok and ok2):
        raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(int(retry) + 1)})
    record = None
    key_session_id = payload.key_session_id
    if payload.operation in (Operation.DECRYPT, Operation.SHARE):
        if payload.record_id is None:
            raise HTTPException(422, "record_id is required for this operation")
        rec, shared = find_record(db, payload.record_id, include_shares=payload.operation == Operation.DECRYPT)
        if rec is None:
            audit.record(
                AuditEvent.SHARE_ACCESS_REJECTED if payload.operation == Operation.DECRYPT
                else AuditEvent.AUTHZ_DENIED,
                "rejected", user_id=actor.user_id, operation=payload.operation.value,
                reason=f"record={payload.record_id} not found")
            raise HTTPException(404, "record not found")
        if shared and rec.get("recipient_user_id") != actor.user_id:
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={payload.record_id} recipient mismatch")
            raise HTTPException(404, "record not found")
        can_inspect_expiry = (shared and rec.get("recipient_user_id") == actor.user_id) or (
            not shared and rec.get("owner_user_id") == actor.user_id)
        if can_inspect_expiry and record_expired(rec):
            if shared:
                db["crypto_shares"].update_one(
                    {"_id": rec["_id"], "status": {"$in": ["PENDING", "PENDING_ADMIN", "APPROVED"]}},
                    {"$set": {"status": "EXPIRED"}})
                if rec.get("status") in {"PENDING", "PENDING_ADMIN", "APPROVED"}:
                    audit.record(AuditEvent.SHARE_EXPIRED, "success", user_id=actor.user_id,
                                 resource=rec.get("resource"), reason=f"share={payload.record_id}")
            audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), operation="decrypt",
                         reason=f"record={payload.record_id} expired")
            raise HTTPException(410, "record expired")
        if shared and rec.get("status") != "APPROVED":
            audit.record(AuditEvent.SHARE_ACCESS_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), reason=f"share={payload.record_id} unavailable")
            raise HTTPException(404, "record not found")
        sealed_context = rec.get("sealed", {}).get("static_ctx", {})
        if can_inspect_expiry and sealed_context.get("resource") != rec.get("resource"):
            audit.record(AuditEvent.DECRYPT_REJECTED, "rejected", user_id=actor.user_id,
                         resource=rec.get("resource"), operation="decrypt",
                         reason=f"record={payload.record_id} resource metadata mismatch")
            raise HTTPException(422, "record metadata failed authentication")
        record = authorization_metadata(rec, shared=shared)
        key_session_id = rec["key_session_id"]
    else:
        if payload.record_id is not None:
            raise HTTPException(422, "record_id is only valid for decrypt or share")
    req = OperationRequest(intent_id=payload.intent_id, intent_version=payload.intent_version,
                           operation=payload.operation.value, resource=payload.resource,
                           purpose_code=payload.purpose_code.value, session_id=payload.session_id,
                           device_id=payload.device_id, key_session_id=key_session_id,
                           requested_bytes=(record["size"] if payload.operation == Operation.SHARE and record
                                            else payload.requested_bytes), record=record)
    try:
        out = eng.decide(actor, req)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    return public_decision(out)


@router.get("/{decision_id}")
def get(decision_id: str, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    d = eng.store.get_decision(decision_id)
    if d is None or (d["user_id"] != actor.user_id and actor.role != "ADMIN"):
        raise HTTPException(404, "decision not found")
    st = eng.store.decision_status(decision_id) or {}
    return {"decision_id": d["_id"], "outcome": d["outcome"], "reasons": d["reasons"],
            "intent_id": d["intent_id"], "intent_version": d["intent_version"],
            "integrity_ok": eng.store.decision_authentic(d), "status": st.get("status"),
            "issued_ts": d["issued_ts"], "expires_ts": d["expires_ts"], "policy_version": d["policy_version"]}


class RevokeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, Field(min_length=3, max_length=200)]


@router.post("/{decision_id}/revoke")
def revoke(decision_id: str, payload: RevokeDecision, actor: Actor = Depends(get_actor),
           eng: IntentEngine = Depends(get_intent_engine)):
    try:
        ok = eng.revoke_decision(actor, decision_id, payload.reason)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    return {"decision_id": decision_id, "revoked": ok}
