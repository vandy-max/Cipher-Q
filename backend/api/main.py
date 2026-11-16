"""CipherQ API entry point (hardened).

Configuration comes exclusively from ``config.get_settings()`` which fails
closed for production/staging.  Request guards, security headers, CORS, host
validation and error sanitisation are wired here.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from config import get_settings
from database.encrypted_store import encryption_enabled
from security.http import RequestGuardMiddleware, SecurityHeadersMiddleware

from .routers import (
    audit,
    auth,
    authorization,
    crypto_ops,
    direct_messages,
    decisions,
    evidence,
    face,
    intents,
    key_sessions,
    location,
    monitoring,
    policies,
    quantum,
    reauth_requests,
    risk,
    security,
    users,
)

log = logging.getLogger("cipherq")
settings = get_settings()          # raises ConfigurationError (fail closed) on unsafe config

app = FastAPI(
    title="CipherQ API",
    version="0.2.0-hardened",
    description="Privileged-access prototype: intent-bound, server-side quantum-key-simulation sessions.",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# Middleware order: last added = outermost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.allowed_origins),
    allow_credentials=False,                       # bearer tokens in headers, never cookies
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts,
                   docs_paths=("/docs", "/openapi.json") if settings.enable_docs else ())
app.add_middleware(
    RequestGuardMiddleware,
    max_body_bytes=settings.max_body_bytes,
    deadline_seconds=settings.request_timeout_seconds,
)
if settings.allowed_hosts:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    # Field names + messages only: never echo the submitted values (they may be secrets).
    errors = [{"loc": [str(x) for x in e.get("loc", ())], "msg": str(e.get("msg", "invalid"))}
              for e in exc.errors()][:20]
    return JSONResponse({"detail": "validation error", "errors": errors}, status_code=422)


@app.exception_handler(StarletteHTTPException)
async def _http_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code,
                        headers=getattr(exc, "headers", None))


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    rid = getattr(request.state, "request_id", "-")
    log.exception("unhandled error request_id=%s path=%s", rid, request.url.path)
    return JSONResponse({"detail": "internal error", "request_id": rid}, status_code=500)


for r in (auth, intents, decisions, crypto_ops, direct_messages, key_sessions, evidence, audit, policies, quantum, risk, face,
          authorization, location, monitoring, security, users, reauth_requests):
    app.include_router(r.router)
app.include_router(face.identity_router)


@app.get("/api/health", tags=["health"])
def health() -> dict:
    """Liveness only. No database name, no configuration detail."""
    return {"status": "ok"}
