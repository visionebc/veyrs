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

Also `users.mfa_secret`, `itsm_connectors.inbound_secret_enc`,
`scanner_connectors.credentials_enc`, `asset_sources.credentials_enc` and the
LDAP bind password inside `organizations.settings` -- the complete, enforced
list is `services/secret_storage.COLUMNS`.

Format
------
What `encrypt()` returns depends on `VEYRS_SECRET_BACKEND`; what `decrypt()`
accepts does NOT. It dispatches on the prefix of the stored value, so a row
written in one mode stays readable after the mode changes:

  * `v1:<fernet token>`          local: the database holds the ciphertext.
  * `vault:<uuid>`               vault: the value is at `<mount>/data/secrets/<uuid>`
                                 in an external KV v2 store (`secret_vault.py`);
                                 the database holds only the reference.
  * `vm1:<uuid>:<fernet token>`  mirror: both. The vault is read first and the
                                 local copy is the fallback -- a migration step
                                 that does NOT yet take the credential off the host.

The version prefix is also what makes key rotation possible later without
guessing at the payload: a `v2:` reader can coexist with `v1:` rows.

Key rotation
------------
`VEYRS_ENCRYPTION_KEY_PREVIOUS` (comma-separated) lists earlier keys that may
DECRYPT but never encrypt. Rotation is: new key in `VEYRS_ENCRYPTION_KEY`, old
key in `..._PREVIOUS`, restart, `veyrs secrets rekey --apply` (re-seals every
local copy under the new key via `reseal()`), then drop `..._PREVIOUS` and
restart again. A `vault:` value has no local copy and is never touched.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from ..config import settings

PREFIX = "v1:"
VAULT_PREFIX = "vault:"
MIRROR_PREFIX = "vm1:"
MODES = ("local", "mirror", "vault")
_HKDF_INFO = b"veyrs.secrets.v1"

log = logging.getLogger("veyrs.secrets")


class SecretError(RuntimeError):
    """Raised when a stored secret cannot be read (or a new one cannot be stored)."""


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


def _previous_fernets() -> list[Fernet]:
    raw = getattr(settings, "encryption_key_previous", "") or ""
    keys = []
    for part in (p.strip() for p in raw.split(",")):
        if not part:
            continue
        try:
            keys.append(Fernet(part.encode()))
        except (ValueError, TypeError) as exc:
            raise SecretError("VEYRS_ENCRYPTION_KEY_PREVIOUS holds an invalid Fernet key") from exc
    return keys


@functools.lru_cache(maxsize=1)
def _keyring() -> MultiFernet:
    """The current key first (the only one that encrypts), then previous keys."""
    return MultiFernet([_fernet(), *_previous_fernets()])


def forget_keys() -> None:
    """Drop the cached keys (after the settings changed, e.g. in tests)."""
    _fernet.cache_clear()
    _keyring.cache_clear()


def _local_part(stored: str) -> tuple[str, str]:
    """(prefix to keep, Fernet token) of a value that carries a local copy."""
    kind = storage_kind(stored)
    if kind == "local":
        return PREFIX, stored[len(PREFIX):]
    if kind == "mirror":
        key, sep, local = stored[len(MIRROR_PREFIX):].partition(":")
        if not sep or not local:
            raise SecretError("stored mirror value is malformed")
        return f"{MIRROR_PREFIX}{key}:", local
    raise SecretError(f"a {kind} value has no local copy to re-seal")


def sealed_with_current_key(stored: str) -> bool:
    """Whether the local copy of `stored` opens with the CURRENT key alone."""
    _keep, token = _local_part(stored)
    try:
        _fernet().decrypt(token.encode())
        return True
    except InvalidToken:
        return False


def reseal(stored: str) -> str:
    """The same value with its local copy re-sealed under the current key.

    Raises SecretError if neither the current nor a previous key opens it --
    the row is then left exactly as it was by the caller.
    """
    keep, token = _local_part(stored)
    try:
        return keep + _keyring().rotate(token.encode()).decode()
    except InvalidToken as exc:
        raise SecretError(
            "cannot re-seal: no configured key (current or previous) opens this value"
        ) from exc


def generate_key() -> str:
    """A fresh key for `VEYRS_ENCRYPTION_KEY`."""
    return Fernet.generate_key().decode()


def mode() -> str:
    """The configured backend: local | mirror | vault."""
    value = (getattr(settings, "secret_backend", "local") or "local").lower()
    if value not in MODES:
        raise SecretError(f"VEYRS_SECRET_BACKEND={value!r} is not one of local, mirror, vault")
    return value


def _seal_local(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def _open_local(token: str) -> str:
    try:
        return _keyring().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise SecretError(
            "cannot decrypt: the encryption key changed or the value is corrupt"
        ) from exc


def storage_kind(stored: str | None) -> str:
    """empty | local | mirror | vault | unknown -- from the prefix alone, no I/O."""
    if not stored:
        return "empty"
    if stored.startswith(PREFIX):
        return "local"
    if stored.startswith(MIRROR_PREFIX):
        return "mirror"
    if stored.startswith(VAULT_PREFIX):
        return "vault"
    return "unknown"


def vault_key(stored: str | None) -> str | None:
    """The vault key a stored value references, or None (local / empty / foreign)."""
    kind = storage_kind(stored)
    if kind == "vault":
        return stored[len(VAULT_PREFIX):]
    if kind == "mirror":
        return stored[len(MIRROR_PREFIX):].split(":", 1)[0]
    return None


def seal_as(plaintext: str, kind: str, *, reuse_key: str | None = None) -> str:
    """Store `plaintext` in the given form, whatever the configured mode.

    `encrypt()` is this with the configured mode; `veyrs secrets migrate` calls
    it with the TARGET mode. `reuse_key` rewrites an existing vault entry in
    place instead of minting a new one (mirror <-> vault conversions), so a
    migration does not leave an orphan behind for every row it touches.
    """
    from . import secret_vault

    if kind == "local":
        return PREFIX + _seal_local(plaintext)
    if kind not in ("vault", "mirror"):
        raise SecretError(f"unknown storage kind {kind!r}")
    key = reuse_key or secret_vault.new_key()
    secret_vault.write(key, plaintext)
    if kind == "vault":
        return VAULT_PREFIX + key
    return f"{MIRROR_PREFIX}{key}:{_seal_local(plaintext)}"


def encrypt(plaintext: str | None) -> str | None:
    """Encrypt, or pass None through. Empty string encrypts to None.

    Passing an empty value through as None rather than as ciphertext keeps
    "no credential configured" distinguishable from "credential is the empty
    string", which callers check with a plain truthiness test.

    In `vault` mode a vault that cannot take the write RAISES: quietly keeping
    the credential on the host instead would defeat the setting without anyone
    knowing. In `mirror` mode it degrades to a local-only `v1:` value with a
    warning -- mirror already keeps a local copy by design, and `secrets status`
    counts the row as local so the gap stays visible.
    """
    if plaintext is None or plaintext == "":
        return None
    current = mode()
    if current == "local":
        return PREFIX + _seal_local(plaintext)
    if current == "vault":
        return seal_as(plaintext, "vault")
    from .secret_vault import VaultError

    try:
        return seal_as(plaintext, "mirror")
    except VaultError as exc:
        log.warning("secret backend mirror: vault write failed, stored locally only: %s", exc)
        return PREFIX + _seal_local(plaintext)


def decrypt(ciphertext: str | None) -> str | None:
    """The plaintext, dispatched on the stored prefix -- never on the mode alone.

    A `vault:` value needs the vault whatever the mode says; there is no other
    copy, so a failure raises. A `vm1:` value reads the vault first in mirror
    and vault mode and falls back to its local copy with a warning; in local
    mode the vault is not contacted at all.
    """
    if not ciphertext:
        return None
    kind = storage_kind(ciphertext)
    if kind == "local":
        return _open_local(ciphertext[len(PREFIX):])
    if kind == "vault":
        from . import secret_vault

        return secret_vault.read(ciphertext[len(VAULT_PREFIX):])
    if kind == "mirror":
        key, sep, local = ciphertext[len(MIRROR_PREFIX):].partition(":")
        if not sep or not local:
            raise SecretError("stored mirror value is malformed")
        if mode() == "local":
            return _open_local(local)
        from . import secret_vault

        try:
            return secret_vault.read(key)
        except secret_vault.VaultError as exc:
            log.warning("secret backend: vault read of %s failed, using the local "
                        "mirror copy: %s", key, exc)
            return _open_local(local)
    # Rows written before this module existed, or a hand-edited value.
    # Refusing loudly beats silently treating ciphertext as a password.
    raise SecretError("stored value is not VEYRS ciphertext")


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
