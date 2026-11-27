"""Sign-in for model gateways whose bearer token expires.

Some OpenAI-compatible gateways do not take a static API key: a technical user
signs in (or a client authenticates with client credentials) and receives a
token that is valid for a limited time. A provider row can therefore carry an
*authentication mode* instead of a fixed key:

* ``api_key`` (default) -- the stored key is sent as ``Authorization: Bearer``.
* ``session`` -- POST user name and password to a token URL, read the token
  from the JSON answer.
* ``oauth2`` -- OAuth 2.0 client credentials grant (RFC 6749 section 4.4).

The token is cached per worker process and renewed BEFORE it expires. How long
it lives is resolved automatically when the administrator leaves *Session
lifetime* empty, because the person configuring VEYRS often does not know it:

1. ``expires_in`` (seconds) in the sign-in answer, else ``expires_at`` /
   ``expiry`` / ``exp`` (epoch seconds or ISO 8601);
2. the ``exp`` claim of the token when it is a JWT;
3. a conservative default: 240 s for ``session``, 300 s for ``oauth2``.

A typed lifetime is a CEILING: when the server says the token lives less, the
server wins. Renewal happens with a margin of 10 % of the lifetime, at most
60 s. When the gateway still answers 401 (token revoked, clock skew) the
provider drops the cached token, signs in again and retries ONCE.

Nothing here logs or returns the password, the client secret or the token.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import threading
import time
from typing import Any

from .providers import ProviderError

MODES = ("api_key", "session", "oauth2")
TOKEN_MODES = ("session", "oauth2")
#: Provider kinds that speak the OpenAI chat API and can take a bearer token.
KINDS_WITH_TOKEN_AUTH = ("openai", "openai_compatible")

DEFAULT_LIFETIME = {"session": 240, "oauth2": 300}
MIN_LIFETIME = 30            # never cache for less than this (a login storm)
MAX_LIFETIME = 24 * 3600     # never trust a token for more than a day
MAX_MARGIN = 60

#: Where a token usually sits in a sign-in answer, tried in order.
TOKEN_FIELDS = ("access_token", "token", "id_token", "jwt", "data.access_token",
                "data.token", "result.token")

#: Keys of `auth_config` an administrator may set. Anything else is refused.
CONFIG_KEYS = frozenset({
    "token_url", "username", "username_field", "password_field", "body_format",
    "token_field", "client_id", "scope", "lifetime_minutes",
})


@dataclasses.dataclass(frozen=True)
class TokenAuth:
    """Everything needed to obtain a token; built from an `AiProvider` row."""

    mode: str
    token_url: str
    secret: str | None = None            # password (session) or client secret (oauth2)
    username: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    body_format: str = "json"            # json | form (session only)
    token_field: str | None = None       # dotted path; empty = auto
    client_id: str | None = None
    scope: str | None = None
    lifetime_minutes: int | None = None  # ceiling; None = Auto
    timeout_seconds: int = 30
    cache_key: str = ""

    @property
    def ceiling_seconds(self) -> int | None:
        if not self.lifetime_minutes:
            return None
        return max(MIN_LIFETIME, int(self.lifetime_minutes) * 60)


@dataclasses.dataclass(frozen=True)
class Token:
    value: str
    lifetime: int          # seconds the token was considered valid for
    source: str            # where the lifetime came from (shown by Test)
    obtained_at: float     # time.monotonic()

    @property
    def renew_at(self) -> float:
        margin = min(MAX_MARGIN, max(1, self.lifetime // 10))
        return self.obtained_at + self.lifetime - margin


# ---------------------------------------------------------------------------
# Building and validating the configuration
# ---------------------------------------------------------------------------
def validate_config(mode: str, config: dict | None, *, has_secret: bool) -> dict:
    """Return a cleaned copy of ``config`` or raise ``ValueError`` with the reason."""
    if mode not in MODES:
        raise ValueError(f"auth_mode must be one of {list(MODES)}")
    config = dict(config or {})
    unknown = set(config) - CONFIG_KEYS
    if unknown:
        raise ValueError(f"unknown auth_config keys: {sorted(unknown)}")
    if mode == "api_key":
        return {}
    cleaned = {k: (v.strip() if isinstance(v, str) else v) for k, v in config.items()
               if v not in (None, "")}
    if not str(cleaned.get("token_url", "")).startswith(("http://", "https://")):
        raise ValueError("auth_config.token_url must be an http(s) URL")
    if not has_secret:
        what = "password" if mode == "session" else "client secret"
        raise ValueError(f"auth_secret ({what}) is required for auth_mode {mode!r}")
    if mode == "session":
        if not cleaned.get("username"):
            raise ValueError("auth_config.username is required for auth_mode 'session'")
        if cleaned.get("body_format", "json") not in ("json", "form"):
            raise ValueError("auth_config.body_format must be 'json' or 'form'")
    if mode == "oauth2" and not cleaned.get("client_id"):
        raise ValueError("auth_config.client_id is required for auth_mode 'oauth2'")
    if "lifetime_minutes" in cleaned:
        try:
            minutes = int(cleaned["lifetime_minutes"])
        except (TypeError, ValueError):
            raise ValueError("auth_config.lifetime_minutes must be a whole number") from None
        if not 1 <= minutes <= MAX_LIFETIME // 60:
            raise ValueError("auth_config.lifetime_minutes must be between 1 and 1440")
        cleaned["lifetime_minutes"] = minutes
    return cleaned


def from_row(row: Any, secret: str | None) -> TokenAuth | None:
    """`TokenAuth` for a provider row, or None when it uses a static key."""
    mode = getattr(row, "auth_mode", None) or "api_key"
    if mode not in TOKEN_MODES:
        return None
    config = dict(getattr(row, "auth_config", None) or {})
    fingerprint = hashlib.sha256(
        json.dumps([mode, config, secret or ""], sort_keys=True).encode()
    ).hexdigest()[:16]
    return TokenAuth(
        mode=mode,
        token_url=config.get("token_url", ""),
        secret=secret,
        username=config.get("username"),
        username_field=config.get("username_field") or "username",
        password_field=config.get("password_field") or "password",
        body_format=config.get("body_format") or "json",
        token_field=config.get("token_field") or None,
        client_id=config.get("client_id"),
        scope=config.get("scope"),
        lifetime_minutes=config.get("lifetime_minutes") or None,
        timeout_seconds=min(60, max(5, int(getattr(row, "timeout_seconds", 30) or 30))),
        cache_key=f"{getattr(row, 'organization_id', '')}:{getattr(row, 'id', '')}:{fingerprint}",
    )


# ---------------------------------------------------------------------------
# Lifetime resolution
# ---------------------------------------------------------------------------
def _as_epoch(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        # milliseconds since the epoch are common in JS gateways
        return float(value) / 1000.0 if value > 1e11 else float(value)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.isdigit():
            return _as_epoch(int(text))
        try:
            parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.timestamp()
    return None


def jwt_expiry(token: str) -> float | None:
    """`exp` of a JWT (epoch seconds), without verifying it -- we only schedule."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict):
        return None
    return _as_epoch(claims.get("exp"))


def resolve_lifetime(auth: TokenAuth, body: dict, token: str,
                     now: float | None = None) -> tuple[int, str]:
    """(seconds, source) for a freshly obtained token."""
    now = time.time() if now is None else now
    seconds: float | None = None
    source = ""
    raw = body.get("expires_in")
    if raw is not None and not isinstance(raw, bool):
        try:
            seconds, source = float(raw), "expires_in"
        except (TypeError, ValueError):
            seconds = None
    if seconds is None:
        for key in ("expires_at", "expiry", "expires", "exp"):
            epoch = _as_epoch(body.get(key))
            if epoch is not None:
                seconds, source = epoch - now, key
                break
    if seconds is None:
        epoch = jwt_expiry(token)
        if epoch is not None:
            seconds, source = epoch - now, "jwt exp"
    if seconds is None:
        seconds, source = DEFAULT_LIFETIME[auth.mode], "default"
    ceiling = auth.ceiling_seconds
    if ceiling is not None and seconds > ceiling:
        seconds, source = ceiling, "configured ceiling"
    return int(min(MAX_LIFETIME, max(MIN_LIFETIME, seconds))), source


def _pick(body: dict, path: str) -> Any:
    node: Any = body
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def extract_token(auth: TokenAuth, body: dict) -> str:
    paths = (auth.token_field,) if auth.token_field else TOKEN_FIELDS
    for path in paths:
        value = _pick(body, path)
        if isinstance(value, str) and value.strip():
            return value.strip()
    where = auth.token_field or "access_token/token/id_token"
    raise ProviderError(f"sign-in answer has no token in {where}")


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------
def _request_token(auth: TokenAuth) -> dict:
    import httpx  # local import: keeps `import veyrs` free of network libs

    from .. import net_guard, trust_store

    try:
        net_guard.check_url(auth.token_url)
    except net_guard.OutboundBlocked as exc:
        raise ProviderError(f"sign-in refused: {exc}") from None
    headers = {"Accept": "application/json"}
    kwargs: dict[str, Any] = {}
    if auth.mode == "session":
        fields = {auth.username_field: auth.username or "",
                  auth.password_field: auth.secret or ""}
        kwargs["data" if auth.body_format == "form" else "json"] = fields
    else:
        form = {"grant_type": "client_credentials"}
        if auth.scope:
            form["scope"] = auth.scope
        kwargs["data"] = form
        kwargs["auth"] = (auth.client_id or "", auth.secret or "")
    try:
        response = httpx.post(auth.token_url, headers=headers, timeout=auth.timeout_seconds,
                              verify=trust_store.httpx_verify(), **kwargs)
    except Exception as exc:  # noqa: BLE001 - any transport failure is the same to us
        raise ProviderError(f"sign-in transport error: {exc.__class__.__name__}") from exc
    if response.status_code >= 400:
        # The body may echo the user name; it is never propagated.
        raise ProviderError(f"sign-in returned HTTP {response.status_code}",
                            status=response.status_code)
    try:
        body = response.json()
    except ValueError as exc:
        raise ProviderError("sign-in returned a non-JSON body") from exc
    if not isinstance(body, dict):
        raise ProviderError("sign-in returned JSON that is not an object")
    return body


_lock = threading.Lock()
_cache: dict[str, Token] = {}


def sign_in(auth: TokenAuth) -> Token:
    """Always contact the token URL; store and return the new token."""
    body = _request_token(auth)
    value = extract_token(auth, body)
    lifetime, source = resolve_lifetime(auth, body, value)
    token = Token(value=value, lifetime=lifetime, source=source,
                  obtained_at=time.monotonic())
    with _lock:
        _cache[auth.cache_key] = token
    return token


def get_token(auth: TokenAuth, *, fresh: bool = False) -> str:
    """A valid token, renewing it before it expires (or now when ``fresh``)."""
    if not fresh:
        with _lock:
            cached = _cache.get(auth.cache_key)
        if cached is not None and time.monotonic() < cached.renew_at:
            return cached.value
    return sign_in(auth).value


def invalidate(cache_key: str | None = None) -> None:
    with _lock:
        if cache_key is None:
            _cache.clear()
        else:
            _cache.pop(cache_key, None)


def describe(token: Token) -> dict:
    """What the Test button shows: never the token itself."""
    return {"lifetime_seconds": token.lifetime, "lifetime_source": token.source,
            "renews_after_seconds": max(0, int(token.renew_at - token.obtained_at))}
