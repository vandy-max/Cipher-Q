"""Intent lifecycle API (v2): create / version / validate / approve / revoke."""
from __future__ import annotations

from typing import Annotated, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from intent_engine.engine import Actor, EngineError, IntentEngine
from intent_engine.schema import ID_RE, IntentRequest

from ..dependencies import get_actor, get_intent_engine

router = APIRouter(prefix="/api/intents", tags=["intents"])


def _call(fn, *a, **k):
    try:
        return fn(*a, **k)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code if not str(exc) or str(exc) == exc.code else f"{exc.code}: {exc}") from exc


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Annotated[int, Field(ge=1)]
    verdict: Literal["APPROVE", "REJECT"]
    comment: Annotated[str, Field(max_length=200)] = ""


class ReasonRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Annotated[str, Field(min_length=3, max_length=200)]


@router.post("", status_code=201)
def create(payload: IntentRequest, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.create_intent, actor, payload)


@router.get("")
def list_(actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    return eng.list_intents(actor)


@router.get("/{intent_id}")
def get(intent_id: int, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.view, actor, intent_id)


@router.get("/{intent_id}/attachment")
def download_attachment(intent_id: int, session_id: Annotated[str, Query(pattern=ID_RE.pattern, max_length=128)],
                        device_id: Annotated[str, Query(pattern=ID_RE.pattern, max_length=128)],
                        key_session_id: Annotated[str, Query(pattern=ID_RE.pattern, max_length=128)],
                        actor: Actor = Depends(get_actor),
                        eng: IntentEngine = Depends(get_intent_engine)):
    try:
        metadata, content = eng.download_attachment(actor, intent_id, session_id, device_id, key_session_id)
    except EngineError as exc:
        raise HTTPException(exc.status, exc.code) from exc
    filename = metadata["filename"]
    disposition = f"attachment; filename*=UTF-8''{quote(filename, safe='')}"
    return Response(content=content, media_type=metadata["content_type"], headers={
        "Content-Disposition": disposition,
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
    })


@router.post("/{intent_id}/versions", status_code=201)
def new_version(intent_id: int, payload: IntentRequest, actor: Actor = Depends(get_actor),
                eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.new_version, actor, intent_id, payload)


@router.post("/{intent_id}/validate")
def validate(intent_id: int, actor: Actor = Depends(get_actor), eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.validate, actor, intent_id)


@router.post("/{intent_id}/approvals")
def approve(intent_id: int, payload: ApprovalRequest, actor: Actor = Depends(get_actor),
            eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.approve, actor, intent_id, payload.version, payload.verdict, payload.comment)


@router.post("/{intent_id}/withdraw-approval")
def withdraw(intent_id: int, payload: ReasonRequest, actor: Actor = Depends(get_actor),
             eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.withdraw_approval, actor, intent_id, payload.reason)


@router.post("/{intent_id}/revoke")
def revoke(intent_id: int, payload: ReasonRequest, actor: Actor = Depends(get_actor),
           eng: IntentEngine = Depends(get_intent_engine)):
    return _call(eng.revoke_intent, actor, intent_id, payload.reason)
