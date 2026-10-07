"""Envelope encryption for secrets stored in the database (spec section 24).

Which columns: `ai_providers.api_key_enc`, `itsm_connectors.credentials_enc`,
`threat_sources.credentials_enc`, `webhook_endpoints.secret_enc`. These are
credentials for *third-party* systems that VEYRS must be able to replay, so they
cannot be hashed -- they must be reversibly protected instead.

Key material
------------
`VEYRS_ENCRYPTION_KEY` (a urlsafe-base64 32-byte Fernet key) is the intended
production input; generate one with `veyrs keygen`. If it is unset, the key is
derived from `VEYRS_SECRET_KEY` via HKDF-SHA256 with a fixed info string, so a
development instance works out of the box **and** rotating the app secret
rotates the data key -- which is why `assert_production_safe()` refuses to boot
production without an explicit `VEYRS_ENCRYPTION_KEY`.

Format
------
Ciphertext is stored as `v1:<fernet token>`. The version prefix is what makes
key rotation possible later without guessing at the payload: a `v2:` reader can
coexist with `v1:` rows.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac

from cryptography.fernet import Fernet, InvalidToken

from ..config import settings

PREFIX = "v1:"
_HKDF_INFO = b"veyrs.secrets.v1"


class SecretError(RuntimeError):
    """Raised when stored ciphertext cannot be read with the current key."""


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF with an empty salt. Standard library only, no new dep."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@functools.lru_cache(maxsize=1)
def _fernet() -> Fernet:
    configured = getattr(settings, "encryption_key", "") or ""
    if configured:
        try:
            return Fernet(configured.encode())
        except (ValueError, TypeError) as exc:
            raise SecretError("VEYRS_ENCRYPTION_KEY is not a valid Fernet key") from exc
    derived = _hkdf_sha256(settings.secret_key.encode(), _HKDF_INFO)
    return Fernet(base64.urlsafe_b64encode(derived))


def generate_key() -> str:
    """A fresh key for `VEYRS_ENCRYPTION_KEY`."""
    return Fernet.generate_key().decode()


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt, or pass None through. Empty string encrypts to None.

    Passing an empty value through as None rather than as ciphertext keeps
    "no credential configured" distinguishable from "credential is the empty
    string", which callers check with a plain truthiness test.
    """
    if plaintext is None or plaintext == "":
        return None
    return PREFIX + _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    if not ciphertext.startswith(PREFIX):
        # Rows written before this module existed, or a hand-edited value.
        # Refusing loudly beats silently treating ciphertext as a password.
        raise SecretError("stored value is not VEYRS ciphertext")
    try:
        return _fernet().decrypt(ciphertext[len(PREFIX):].encode()).decode()
    except InvalidToken as exc:
        raise SecretError(
            "cannot decrypt: the encryption key changed or the value is corrupt"
        ) from exc


def try_decrypt(ciphertext: str | None) -> str | None:
    """Best-effort read for display paths that must not 500 on a bad row."""
    try:
        return decrypt(ciphertext)
    except SecretError:
        return None


def mask(plaintext: str | None) -> str:
    """`sk-abc...xyz` for UI display. Never returns more than 8 real characters."""
    if not plaintext:
        return ""
    if len(plaintext) <= 8:
        return "*" * len(plaintext)
    return f"{plaintext[:4]}...{plaintext[-4:]}"
