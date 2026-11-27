"""Rate limiting (spec section 24, threat model T-API-ABUSE).

Two tiers, because they defend different things:

* **Authentication endpoints** get a strict per-identity + per-IP budget. This is
  credential-stuffing defence, and it must bite long before the general limit.
* **Everything else** gets a per-principal budget: the account of a bearer
  token that VERIFIES (signature, audience, expiry), or an API key that this
  process has already verified once. Anything else -- no credential, a junk
  token, an API key not yet verified -- is keyed by the client address. A
  credential the caller merely PRESENTS is never an identity: otherwise every
  random string would be a fresh bucket (risk register R-14).

Storage is Redis when available and an in-process window otherwise. The
in-process fallback is honest about its limitation: with N workers it allows
roughly N x the configured rate, which is stated here and in DEPLOYMENT.md
rather than being quietly wrong. Redis is what you deploy for a real limit.
A worker that lost Redis tries it again every `REDIS_RETRY_SECONDS`, so the
fallback ends when Redis comes back instead of lasting until a restart (R-25).

Never an outage: if Redis is unreachable or errors, the request is counted in
the in-process window and a warning is logged. A rate limiter that takes the
whole platform down when its backing store hiccups has caused the outage it
was meant to prevent.
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
#: monotonic time before which a worker that lost Redis does not ask again
_redis_retry_at = 0.0
REDIS_RETRY_SECONDS = 30


def _redis_down(exc: Exception) -> None:
    global _redis_client, _redis_retry_at
    if _redis_client is not None or _redis_retry_at == 0.0:
        log.warning("rate limiting falling back to in-process windows "
                    "(retrying Redis every %ss): %s", REDIS_RETRY_SECONDS,
                    exc.__class__.__name__)
    _redis_client = None
    _redis_retry_at = time.monotonic() + REDIS_RETRY_SECONDS


def _redis():
    global _redis_client, _redis_retry_at
    if _redis_client is not None:
        return _redis_client
    if time.monotonic() < _redis_retry_at:
        return None
    try:
        import redis

        client = redis.Redis.from_url(settings.redis_url, socket_timeout=1,
                                      socket_connect_timeout=1)
        client.ping()
    except Exception as exc:  # noqa: BLE001
        _redis_down(exc)
        return None
    if _redis_retry_at:
        log.warning("rate limiting back on Redis")
    _redis_client = client
    _redis_retry_at = 0.0
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
        # Never an outage: count it in this process and ask Redis again later.
        _redis_down(exc)
        return _local.hit(key, limit, window)
    if count > limit:
        return Decision(False, limit, 0, window)
    return Decision(True, limit, limit - count, 0)


def reset_local() -> None:
    """Test helper. Clears only the in-process window."""
    _local.reset()


def client_ip(request: Request) -> str:
    """The caller's address: `request.client.host`, and nothing else.

    The ASGI server (uvicorn with `--proxy-headers --forwarded-allow-ips`)
    already resolves the address through its trusted-proxy list, so this is
    the nearest untrusted hop. The first `X-Forwarded-For` entry is whatever
    the caller sent, so reading it here would let anyone mint a fresh
    rate-limit identity per request.
    """
    return request.client.host if request.client else "unknown"


#: sha256(presented API key) -> (api key id, monotonic expiry). Filled by
#: `deps._principal_from_api_key` AFTER the Argon2 check, read by the limiter.
#: Per process and short-lived: it only chooses a bucket, it authorizes nothing.
_verified_api_keys: dict[str, tuple[str, float]] = {}
_VERIFIED_TTL = 600
_VERIFIED_MAX = 4096


def remember_api_key(clear: str, key_id: object) -> None:
    """Record that `clear` verified as API key `key_id` (called after verification)."""
    if len(_verified_api_keys) >= _VERIFIED_MAX:
        _verified_api_keys.clear()
    digest = hashlib.sha256(clear.encode()).hexdigest()
    _verified_api_keys[digest] = (str(key_id), time.monotonic() + _VERIFIED_TTL)


def _identity(request: Request) -> str:
    """The limiter key: a VERIFIED principal, else the client address.

    Middleware runs before the routing layer, so `request.state.principal` is
    not set yet. A bearer token is therefore verified here -- signature,
    audience, issuer, expiry: an HMAC, no database -- and keyed by its
    subject. Revocation is deliberately not checked; it changes who may act,
    not whose budget a request spends.

    An API key costs an Argon2 verification, too expensive to repeat here, so
    it is keyed by its id only once `get_principal` has verified it in this
    process (`remember_api_key`); until then, and for every key that never
    verifies, the client address is the identity. One busy integration still
    gets its own bucket instead of sharing its office's NAT address.
    """
    ip_identity = f"ip:{client_ip(request)}"
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        hit = _verified_api_keys.get(hashlib.sha256(api_key.encode()).hexdigest())
        if hit and hit[1] > time.monotonic():
            return f"apikey:{hit[0]}"
        return ip_identity

    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        if token:
            from .auth import AuthError, decode_access_token  # local: keep import light

            try:
                subject = decode_access_token(token).get("sub")
            except AuthError:
                subject = None
            if subject:
                return f"user:{subject}"
    return ip_identity


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
