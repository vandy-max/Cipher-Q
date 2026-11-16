"""HTTP hardening middleware (pure ASGI, so body limits apply to streamed bodies too)."""
from __future__ import annotations

import asyncio
import json
import uuid

_JSON_METHODS = {"POST", "PUT", "PATCH"}


async def _send_json(send, status: int, body: dict, headers: list[tuple[bytes, bytes]] | None = None) -> None:
    raw = json.dumps(body).encode()
    hdrs = [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": hdrs + (headers or [])})
    await send({"type": "http.response.body", "body": raw})


class RequestGuardMiddleware:
    """Request id, body-size limit, JSON content-type enforcement, deadline."""

    def __init__(self, app, max_body_bytes: int, deadline_seconds: float = 30.0) -> None:
        self.app, self.max_body, self.deadline = app, max_body_bytes, deadline_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = {k.lower(): v for k, v in scope["headers"]}
        scope.setdefault("state", {})["request_id"] = uuid.uuid4().hex
        method = scope["method"]

        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_body:
                    return await _send_json(send, 413, {"detail": "request body too large"})
            except ValueError:
                return await _send_json(send, 400, {"detail": "invalid content-length"})
        if method in _JSON_METHODS and (cl not in (None, b"0") or b"transfer-encoding" in headers):
            ctype = headers.get(b"content-type", b"").split(b";")[0].strip().lower()
            if ctype != b"application/json":
                return await _send_json(send, 415, {"detail": "Content-Type must be application/json"})

        received = 0

        async def limited_receive():
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_body:
                    raise _TooLarge()
            return msg

        started = False

        async def tracking_send(msg):
            nonlocal started
            if msg["type"] == "http.response.start":
                started = True
            await send(msg)

        try:
            await asyncio.wait_for(self.app(scope, limited_receive, tracking_send), timeout=self.deadline)
        except _TooLarge:
            if not started:
                await _send_json(send, 413, {"detail": "request body too large"})
        except asyncio.TimeoutError:
            if not started:
                await _send_json(send, 504, {"detail": "request timed out"})


class _TooLarge(Exception):
    pass


class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool, docs_paths: tuple[str, ...] = ()) -> None:
        self.app, self.hsts, self.docs_paths = app, hsts, docs_paths

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope["path"]
        is_docs = any(path.startswith(p) for p in self.docs_paths)

        async def send_wrapper(msg):
            if msg["type"] == "http.response.start":
                h = [(k, v) for k, v in msg["headers"]]
                names = {k.lower() for k, _ in h}
                add = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-resource-policy", b"same-site"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                ]
                if not is_docs:
                    add.append((b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"))
                if path.startswith("/api"):
                    add.append((b"cache-control", b"no-store"))
                if self.hsts:
                    add.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                rid = scope.get("state", {}).get("request_id")
                if rid:
                    add.append((b"x-request-id", rid.encode()))
                h += [(k, v) for k, v in add if k not in names]
                msg = {**msg, "headers": h}
            await send(msg)

        await self.app(scope, receive, send_wrapper)
