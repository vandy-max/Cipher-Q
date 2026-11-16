"""
In-process sliding-window limiter + bounded concurrency gate.

Scope / limits (documented in docs/OPERATIONS.md): state lives in this process.
With several workers each enforces its own window, so effective limits are
``limit x workers``; persistent per-account lockout (``authentication.throttle``)
is stored in the database and is shared.  A production deployment should add a
reverse-proxy / API-gateway limiter in front.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = 50_000) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def check(self, key: str, limit: int, window_seconds: float, now: float | None = None) -> tuple[bool, float]:
        """Record an attempt. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) > self._max_keys:
                self._prune(now, window_seconds)
            q = self._hits[key]
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False, max(0.0, window_seconds - (now - q[0]))
            q.append(now)
            return True, 0.0

    def _prune(self, now: float, window: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] > window]:
            del self._hits[k]

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


class ConcurrencyGate:
    """Non-blocking bounded concurrency: refuse instead of queueing unboundedly."""

    def __init__(self, n: int) -> None:
        self._sem = threading.BoundedSemaphore(n)

    def try_acquire(self) -> bool:
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        self._sem.release()


def client_ip(request, trusted_proxies: int = 0) -> str:
    """Peer address, or the Nth-from-right ``X-Forwarded-For`` hop when behind
    a configured number of trusted proxies (never trust the header otherwise)."""
    if trusted_proxies > 0:
        xff = request.headers.get("x-forwarded-for", "")
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if len(hops) >= trusted_proxies:
            return hops[-trusted_proxies]
    return request.client.host if request.client else "unknown"
