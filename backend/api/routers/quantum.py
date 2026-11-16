from __future__ import annotations

from fastapi import APIRouter, Depends

from quantum.service import QuantumKeyExchangeService

from ..dependencies import get_quantum_service

router = APIRouter(prefix="/api/quantum", tags=["quantum"])


@router.get("/info")
def backend_info(service: QuantumKeyExchangeService = Depends(get_quantum_service)) -> dict:
    """Public diagnostic: simulator identity + sample circuit. Contains no key material.

    Key generation lives at POST /api/key-sessions (authenticated, server-side)."""
    info = service.backend_info()
    return info
