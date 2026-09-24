"""Password hashing, token issuance and API-key handling.

Choices and why:
  * Argon2id for passwords (OWASP ASVS 2.4.1 first choice), with the
    argon2-cffi defaults which already exceed the ASVS minimum parameters.
  * Short-lived access JWTs + rotating opaque refresh tokens stored as SHA-256
    hashes. Reuse of an already-rotated refresh token revokes the whole family:
    that is the standard detection for a stolen refresh token.
  * API keys are `veyrs_<prefix>_<secret>`; only the Argon2 hash of the secret
    is persisted, and the prefix is the lookup key so verification is O(1)
    instead of hashing against every row.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import uuid
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from jose import JWTError, jwt

from ..config import settings

_hasher = PasswordHasher()

ACCESS_AUDIENCE = "veyrs:access"
REFRESH_AUDIENCE = "veyrs:refresh"


class AuthError(Exception):
    """Raised for any credential problem. Never carries a distinguishing message
    to the client - the API maps it to a single generic 401."""


# --- passwords ------------------------------------------------------------


def hash_password(password: str) -> str:
    if len(password) < settings.password_min_length:
        raise ValueError(f"password must be at least {settings.password_min_length} characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        # Federated-only account. Still burn time so the absence of a local
        # password is not observable through response timing.
        _hasher.hash(secrets.token_urlsafe(16))
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


# --- JWT access tokens ----------------------------------------------------


def create_access_token(
    *,
    user_id: uuid.UUID,
    organization_id: uuid.UUID,
    permissions: list[str],
    is_superuser: bool = False,
    extra: dict[str, Any] | None = None,
    minutes: int | None = None,
) -> tuple[str, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(minutes=minutes or settings.access_token_minutes)
    payload: dict[str, Any] = {
        "sub": str(user_id),
        "org": str(organization_id),
        "perms": permissions,
        "su": is_superuser,
        "aud": ACCESS_AUDIENCE,
        "iss": settings.app_name,
        "iat": int(now.timestamp()),
        "exp": int(expires.timestamp()),
        "jti": secrets.token_urlsafe(12),
        **(extra or {}),
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token, expires


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            audience=ACCESS_AUDIENCE,
            issuer=settings.app_name,
        )
    except JWTError as exc:
        raise AuthError("invalid token") from exc


# --- refresh tokens -------------------------------------------------------


def new_refresh_token() -> tuple[str, str]:
    """Return (clear_token, sha256_hash). Only the hash is stored."""
    clear = secrets.token_urlsafe(48)
    return clear, hash_token(clear)


def hash_token(clear: str) -> str:
    return hashlib.sha256(clear.encode("utf-8")).hexdigest()


def refresh_expiry() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=settings.refresh_token_days)


# --- API keys -------------------------------------------------------------


def new_api_key() -> tuple[str, str, str]:
    """Return (clear_key, prefix, argon2_hash_of_secret)."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    return f"veyrs_{prefix}_{secret}", prefix, _hasher.hash(secret)


def split_api_key(clear: str) -> tuple[str, str]:
    parts = clear.split("_", 2)
    if len(parts) != 3 or parts[0] != "veyrs":
        raise AuthError("malformed api key")
    return parts[1], parts[2]


def verify_api_key_secret(secret: str, key_hash: str) -> bool:
    try:
        return _hasher.verify(key_hash, secret)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# --- execution-agent tokens -----------------------------------------------
# Same construction as an API key, deliberately DIFFERENT scheme word. An agent
# credential must never be accepted where a user credential is expected: with a
# distinct prefix, `split_api_key()` rejects an agent token outright instead of
# looking it up and finding nothing, and a leaked one is greppable in logs.

AGENT_TOKEN_SCHEME = "veyrsagent"


def new_agent_token() -> tuple[str, str, str]:
    """Return (clear_token, prefix, argon2_hash_of_secret)."""
    prefix = secrets.token_hex(5)
    secret = secrets.token_urlsafe(32)
    return f"{AGENT_TOKEN_SCHEME}_{prefix}_{secret}", prefix, _hasher.hash(secret)


def split_agent_token(clear: str) -> tuple[str, str]:
    parts = (clear or "").split("_", 2)
    if len(parts) != 3 or parts[0] != AGENT_TOKEN_SCHEME:
        raise AuthError("malformed agent token")
    return parts[1], parts[2]


# --- misc -----------------------------------------------------------------


def constant_time_equals(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode(), b.encode())
