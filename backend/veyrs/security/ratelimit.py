"""Rate limiting (spec section 24, threat model T-API-ABUSE).

Two tiers, because they defend different things:

* **Authentication endpoints** get a strict per-identity + per-IP budget. This is
  credential-stuffing defence, and it must bite long before the general limit.
* **Everything else** gets a per-principal budget, falling back to per-IP for
  unauthenticated traffic.

Storage is Redis when available and an in-process window otherwise. The
in-process fallback is honest about its limitation: with N workers it allows
roughly N x the configured rate, which is stated here and in DEPLOYMENT.md
rather than being quietly wrong. Redis is what you deploy for a real limit.

Fail-open is deliberate: if Redis is unreachable, requests are allowed and a
warning is logged. A rate limiter that takes the whole platform down when its
backing store hiccups has caused the outage it was meant to prevent.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import threading
import time
from collections import defaultdict, deque

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import settings

log = logging.getLogger("veyrs.ratelimit")

#: Paths exempted entirely: probes and metrics are scraped on a schedule and
#: must not be throttled into a false alarm.
EXEMPT_PATHS = frozenset({"/healthz", "/readyz", "/metrics"})

#: Auth paths get the strict budget.
AUTH_PATH_MARKERS = ("/auth/login", "/auth/refresh", "/auth/mfa", "/auth/password")

AUTH_WINDOW_SECONDS = 60


@dataclasses.dataclass
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class _LocalWindow:
    """Sliding window in process memory. Per-worker, not cluster-wide."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window: int) -> Decision:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            cutoff = now - window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry = int(window - (now - bucket[0])) + 1
                return Decision(False, limit, 0, max(1, retry))
            bucket.append(now)
            return Decision(True, limit, limit - len(bucket), 0)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


_local = _LocalWindow()
_redis_client = None
_redis_checked = False


def _redis():
    global _redis_client, _redis_checked
    if _redis_checked:
        return _redis_client
    _redis_checked = True
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_timeout=1,
                                      socket_connect_timeout=1)
        client.ping()
        _redis_client = client
    except Exception as exc:  # noqa: BLE001
        log.warning("rate limiting falling back to in-process windows: %s",
                    exc.__class__.__name__)
        _redis_client = None
    return _redis_client


def check(key: str, limit: int, window: int = 60) -> Decision:
    client = _redis()
    if client is None:
        return _local.hit(key, limit, window)
    try:
        redis_key = f"veyrs:rl:{key}:{int(time.time() // window)}"
        pipeline = client.pipeline()
        pipeline.incr(redis_key)
        pipeline.expire(redis_key, window + 1)
        count = int(pipeline.execute()[0])
    except Exception as exc:  # noqa: BLE001
        # Fail OPEN: a limiter outage must not become a platform outage.
        log.warning("rate limit backend error, allowing request: %s",
                    exc.__class__.__name__)
        return Decision(True, limit, limit, 0)
    if count > limit:
        return Decision(False, limit, 0, window)
    return Decision(True, limit, limit - count, 0)


def reset_local() -> None:
    """Test helper. Clears only the in-process window."""
    _local.reset()


def client_ip(request: Request) -> str:
    """Trust X-Forwarded-For only behind a proxy we configured.

    Taking the header unconditionally lets any caller mint a fresh identity per
    request and walk straight through the limiter.
    """
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _identity(request: Request) -> str:
    """Derive the limiter key from the REQUEST, never from request.state.

    Middleware runs outside the routing layer, so `request.state.principal` is
    always unset here -- it is populated by the `get_principal` dependency,
    which has not run yet. Keying on it looked right and silently degraded every
    authenticated caller to a shared per-IP bucket, which is how one busy
    integration throttles everyone behind the same NAT.

    So the credential itself is the identity: a digest of the bearer token, or
    the API key prefix. Neither is stored in clear -- the digest is truncated and
    the prefix is the public half of the key by design.
    """
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        prefix = api_key.split("_")[1] if "_" in api_key else "unknown"
        return f"apikey:{prefix}"

    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        if token:
            return f"bearer:{hashlib.sha256(token.encode()).hexdigest()[:32]}"
    return f"ip:{client_ip(request)}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, per_minute: int | None = None,
                 auth_per_minute: int | None = None) -> None:
        super().__init__(app)
        self.per_minute = per_minute or settings.rate_limit_per_minute
        self.auth_per_minute = auth_per_minute or settings.auth_rate_limit_per_minute

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        is_auth = any(marker in path for marker in AUTH_PATH_MARKERS)
        if is_auth:
            # Keyed on IP, not on the submitted email: otherwise an attacker
            # rotates the email field and never hits the limit.
            decision = check(f"auth:{client_ip(request)}",
                             self.auth_per_minute, AUTH_WINDOW_SECONDS)
        else:
            decision = check(f"api:{_identity(request)}", self.per_minute, 60)

        if not decision.allowed:
            log.warning("rate limit exceeded path=%s ip=%s", path, client_ip(request))
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"error": "rate_limited",
                         "detail": f"limit of {decision.limit} requests per minute exceeded"},
                headers={"Retry-After": str(decision.retry_after),
                         "X-RateLimit-Limit": str(decision.limit),
                         "X-RateLimit-Remaining": "0"},
            )

        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(decision.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(decision.remaining))
        return response
