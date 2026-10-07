"""Time-based one-time passwords (RFC 6238) for local password logins.

Why this module exists
----------------------
`users.mfa_enabled` and `users.mfa_secret` shipped with the first schema, and
`/auth/login` accepted an `mfa_code` field -- but nothing ever verified it. The
login path only asserted that the field was *present*, so any six characters
satisfied it and MFA was decorative. Nobody had it enabled, so nothing was
breached; the trap was that the first operator to turn it on would have got a
green padlock and no second factor.

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * The shared secret is stored **encrypted** (`security/secrets.py`, the same
    envelope used for third-party credentials). It cannot be hashed: TOTP needs
    the secret back to recompute the code.
  * `verify()` returns the *time step* that matched, and the caller persists it
    in `users.mfa_last_step`. A code is refused if its step is not strictly
    greater than the last accepted one, so a code captured over the shoulder --
    or replayed off a proxy log -- is single-use.
  * `VALID_WINDOW = 1` accepts the neighbouring 30s steps to survive clock
    skew. That is the standard tolerance; widening it multiplies the guess
    space, so it is a constant and not a setting.
  * Comparison is constant time. A timing oracle on six digits is small but
    real, and this is the code path an attacker gets to call repeatedly.
  * This module NEVER decides lockout. Rate limiting and the failed-login
    counter live in the login endpoint, which is the only place that can see
    password failures and code failures as one budget.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets as _secrets
import struct
import time
import urllib.parse

from . import secrets as vault

DIGITS = 6
PERIOD = 30
VALID_WINDOW = 1  # +/- one step of clock skew
SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommendation


class MfaError(RuntimeError):
    """Raised when enrolment state is unusable (missing or corrupt secret)."""


def generate_secret() -> str:
    """A fresh base32 secret, in the shape authenticator apps expect."""
    return base64.b32encode(_secrets.token_bytes(SECRET_BYTES)).decode().rstrip("=")


def _code_at(secret: str, step: int) -> str:
    """One HOTP value (RFC 4226) for the given counter."""
    padding = "=" * (-len(secret) % 8)
    try:
        key = base64.b32decode(secret.upper() + padding, casefold=True)
    except (ValueError, TypeError) as exc:
        raise MfaError("stored MFA secret is not valid base32") from exc
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** DIGITS)).zfill(DIGITS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def verify(secret: str, code: str | None, *, last_step: int | None = None,
           now: float | None = None) -> int | None:
    """Return the matching time step, or None.

    `last_step` is the step of the most recently accepted code for this user.
    A match at or below it is a replay and is refused even though the digits
    are arithmetically correct.
    """
    if not code:
        return None
    candidate = code.strip().replace(" ", "")
    # `isdigit()` alone is not enough: it is True for Arabic-Indic and other
    # non-ASCII digits, and `hmac.compare_digest` raises TypeError on those --
    # turning a junk login attempt into a 500 from an unauthenticated caller.
    if len(candidate) != DIGITS or not (candidate.isascii() and candidate.isdigit()):
        return None

    centre = current_step(now)
    for offset in range(-VALID_WINDOW, VALID_WINDOW + 1):
        step = centre + offset
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(_code_at(secret, step), candidate):
            return step
    return None


def provisioning_uri(secret: str, *, account: str, issuer: str = "VEYRS") -> str:
    """otpauth:// URI for a QR code. Never log this: it carries the secret."""
    label = urllib.parse.quote(f"{issuer}:{account}", safe="")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"


# ---------------------------------------------------------------------------
# Storage helpers -- the only places that touch the envelope.
# ---------------------------------------------------------------------------
def seal(secret: str) -> str:
    sealed = vault.encrypt(secret)
    if sealed is None:  # pragma: no cover - encrypt only returns None for None
        raise MfaError("could not seal the MFA secret")
    return sealed


def unseal(stored: str | None) -> str:
    """Decrypt an enrolled secret, or fail closed.

    A user flagged `mfa_enabled` whose secret is missing or undecryptable must
    NOT be able to log in: that state means the encryption key rotated without
    re-enrolment, and silently downgrading to password-only would be the exact
    bug this module was written to remove.
    """
    if not stored:
        raise MfaError("MFA is enabled but no secret is enrolled")
    try:
        plain = vault.decrypt(stored)
    except vault.SecretError as exc:
        raise MfaError("enrolled MFA secret cannot be decrypted") from exc
    if not plain:
        raise MfaError("enrolled MFA secret is empty")
    return plain
