"""Client for an external secret store: HashiCorp Vault or OpenBao, KV version 2.

Why this exists
---------------
`security/secrets.py` protects third-party credentials with a Fernet key that
lives in `/opt/veyrs/.env` on the same host as the database. Whoever can read
that disk can read every credential. With `VEYRS_SECRET_BACKEND=vault` the
credential itself moves off the node: the database row holds only a reference
(`vault:<uuid>`) and the value is fetched from the vault when it is needed.

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * **Only the vault token is cached** (per process, until two thirds of its
    lease has run). Secret VALUES are fetched every time. A cache of values
    would put the credentials back in this process's memory indefinitely and
    make the vault's audit log lie about who read what, and when.
  * **The vault's own configuration is never in the database.** It comes from
    `config.Settings` (environment). The AppRole secret-id and the token are
    read from files named by the environment, not from the environment itself:
    `/proc/<pid>/environ` and `docker inspect` both print environment values.
    A file other users can read is refused.
  * **Every failure raises.** A credential that exists but cannot be read is
    an error, never `""` or `None`: an empty password sent to a directory or
    an ITSM locks the service account out, and the operator goes hunting for a
    password problem that does not exist.
  * **Keys are UUIDs, validated.** The key comes out of a database row; a
    hand-edited `vault:../../sys/...` must not become a request to some other
    vault path with this process's token.
  * Values live at `<mount>/data/secrets/<uuid>` in the field `value`. One mount
    (or namespace) per VEYRS installation: `veyrs secrets gc` treats every key
    under `secrets/` that no row references as an orphan.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import os
import re
import ssl
import stat
import threading
import time
import uuid
from typing import Any

import httpx

from ..config import settings
from .secrets import SecretError

log = logging.getLogger("veyrs.secrets")

#: Folder under the KV mount that holds every VEYRS value.
FOLDER = "secrets"

_KEY_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

#: Re-read a token FILE at least this often, so a token rotated on disk by a
#: vault agent is picked up without a restart.
TOKEN_FILE_TTL = 300.0


class VaultError(SecretError):
    """The vault is unconfigured, unreachable, sealed, refused us, or lacks the key."""


@dataclasses.dataclass(frozen=True)
class VaultConfig:
    addr: str
    mount: str
    auth: str
    role_id: str
    secret_id_file: str
    token_file: str
    ca_file: str
    namespace: str
    timeout: float


def current_config() -> VaultConfig:
    """Snapshot of the VEYRS_VAULT_* settings, read now (tests flip them)."""
    return VaultConfig(
        addr=(settings.vault_addr or "").strip().rstrip("/"),
        mount=(settings.vault_mount or "").strip().strip("/"),
        auth=settings.vault_auth or "approle",
        role_id=settings.vault_role_id or "",
        secret_id_file=settings.vault_secret_id_file or "",
        token_file=settings.vault_token_file or "",
        ca_file=settings.vault_ca_file or "",
        namespace=settings.vault_namespace or "",
        timeout=float(settings.vault_timeout or 5.0),
    )


def config_problems(cfg: VaultConfig | None = None) -> list[str]:
    """What is missing for this process to talk to the vault at all."""
    cfg = cfg or current_config()
    problems = []
    if not cfg.addr:
        problems.append("VEYRS_VAULT_ADDR is not set")
    elif not cfg.addr.startswith(("https://", "http://")):
        problems.append("VEYRS_VAULT_ADDR must be an http(s) URL")
    if not cfg.mount:
        problems.append("VEYRS_VAULT_MOUNT is empty")
    if cfg.auth == "approle":
        if not cfg.role_id:
            problems.append("VEYRS_VAULT_ROLE_ID is not set")
        if not cfg.secret_id_file:
            problems.append("VEYRS_VAULT_SECRET_ID_FILE is not set")
    elif cfg.auth == "token":
        if not cfg.token_file:
            problems.append("VEYRS_VAULT_TOKEN_FILE is not set")
    else:
        problems.append(f"VEYRS_VAULT_AUTH={cfg.auth!r} is not approle or token")
    return problems


def is_configured(cfg: VaultConfig | None = None) -> bool:
    return not config_problems(cfg)


def _require_config(cfg: VaultConfig) -> None:
    problems = config_problems(cfg)
    if problems:
        raise VaultError(
            "this process has no usable external vault configuration ("
            + "; ".join(problems) + "). Set the VEYRS_VAULT_* settings; a credential "
            "already stored as a vault reference stays unreadable until you do (or "
            "until `veyrs secrets migrate --to local --apply` is run from a host "
            "that has them)"
        )


def valid_key(key: str) -> bool:
    return bool(key) and bool(_KEY_RE.match(key))


def new_key() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# credential files
# ---------------------------------------------------------------------------
def read_credential_file(path: str, what: str) -> str:
    """Read a secret-id / token file, refusing one that other users can read.

    World-readable is refused outright. Group-readable is allowed with a
    warning: `root:veyrs 0640` is a legitimate way to hand a file to the
    service account, but it is one group membership away from a leak.
    """
    try:
        info = os.stat(path)
    except OSError as exc:
        raise VaultError(f"{what} file {path} cannot be read: {exc.strerror}") from exc
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o007:
        raise VaultError(
            f"{what} file {path} is accessible to every user on the host "
            f"(mode {mode:04o}); chmod 600 it"
        )
    if mode & 0o070:
        log.warning("%s file %s is group-accessible (mode %04o); 0600 is expected",
                    what, path, mode)
    try:
        with open(path, encoding="utf-8") as handle:
            value = handle.read().strip()
    except OSError as exc:
        raise VaultError(f"{what} file {path} cannot be read: {exc.strerror}") from exc
    if not value:
        raise VaultError(f"{what} file {path} is empty")
    return value


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------
def _verify(cfg: VaultConfig) -> ssl.SSLContext | bool:
    if cfg.ca_file:
        try:
            return ssl.create_default_context(cafile=cfg.ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise VaultError(f"VEYRS_VAULT_CA_FILE {cfg.ca_file} is unusable: {exc}") from exc
    return True


def _request(cfg: VaultConfig, method: str, path: str, *, token: str | None = None,
             body: dict | None = None) -> httpx.Response:
    headers = {}
    if cfg.namespace:
        headers["X-Vault-Namespace"] = cfg.namespace
    if token:
        headers["X-Vault-Token"] = token
    try:
        with httpx.Client(timeout=cfg.timeout, verify=_verify(cfg)) as client:
            return client.request(method, f"{cfg.addr}/v1/{path}", headers=headers, json=body)
    except httpx.HTTPError as exc:
        # The exception text can carry the URL but never the token (it is a
        # header), so naming the class and the address is safe and enough.
        raise VaultError(f"vault at {cfg.addr} is unreachable ({type(exc).__name__})") from exc


# ---------------------------------------------------------------------------
# authentication: the ONLY thing cached
# ---------------------------------------------------------------------------
_lock = threading.Lock()
_tokens: dict[VaultConfig, tuple[str, float]] = {}


def forget_tokens() -> None:
    """Drop every cached token (tests, and after a 403)."""
    with _lock:
        _tokens.clear()


def _login(cfg: VaultConfig) -> tuple[str, float]:
    """A token and how long this process may keep using it (seconds)."""
    if cfg.auth == "token":
        return read_credential_file(cfg.token_file, "VEYRS_VAULT_TOKEN_FILE"), TOKEN_FILE_TTL
    secret_id = read_credential_file(cfg.secret_id_file, "VEYRS_VAULT_SECRET_ID_FILE")
    response = _request(cfg, "POST", "auth/approle/login",
                        body={"role_id": cfg.role_id, "secret_id": secret_id})
    if response.status_code != 200:
        raise VaultError(f"vault refused the AppRole login (HTTP {response.status_code})")
    try:
        auth = response.json()["auth"]
        token = auth["client_token"]
        lease = float(auth.get("lease_duration") or 0)
    except (ValueError, KeyError, TypeError) as exc:
        raise VaultError("vault answered the AppRole login without a token") from exc
    # Log in again at two thirds of the lease rather than renewing: a fresh
    # login is always valid, and it is the path a lost token needs anyway. A
    # zero lease (a non-expiring token) is still re-checked hourly.
    return token, (lease * 2 / 3) if lease > 0 else 3600.0


def token(cfg: VaultConfig | None = None, *, fresh: bool = False) -> str:
    cfg = cfg or current_config()
    _require_config(cfg)
    now = time.monotonic()
    with _lock:
        cached = _tokens.get(cfg)
        if cached and not fresh and cached[1] > now:
            return cached[0]
    value, ttl = _login(cfg)
    with _lock:
        _tokens[cfg] = (value, time.monotonic() + ttl)
    return value


def _authed(cfg: VaultConfig, method: str, path: str, body: dict | None = None) -> httpx.Response:
    response = _request(cfg, method, path, token=token(cfg), body=body)
    if response.status_code == 403:
        # Expired or revoked under us: one fresh login, then believe the answer.
        response = _request(cfg, method, path, token=token(cfg, fresh=True), body=body)
    if response.status_code == 503:
        raise VaultError(f"vault at {cfg.addr} is sealed or unavailable (HTTP 503)")
    return response


# ---------------------------------------------------------------------------
# KV v2 operations
# ---------------------------------------------------------------------------
def _check_key(key: str) -> None:
    if not valid_key(key):
        raise VaultError("stored vault reference is not a VEYRS key")


def _data_path(cfg: VaultConfig, key: str) -> str:
    return f"{cfg.mount}/data/{FOLDER}/{key}"


def _meta_path(cfg: VaultConfig, key: str | None = None) -> str:
    return f"{cfg.mount}/metadata/{FOLDER}" + (f"/{key}" if key else "")


def write(key: str, value: str, cfg: VaultConfig | None = None) -> None:
    cfg = cfg or current_config()
    _check_key(key)
    response = _authed(cfg, "POST", _data_path(cfg, key), {"data": {"value": value}})
    if response.status_code not in (200, 204):
        raise VaultError(f"vault refused to store {FOLDER}/{key} (HTTP {response.status_code})")


def read(key: str, cfg: VaultConfig | None = None) -> str:
    """The stored value. Fetched every call, never cached."""
    cfg = cfg or current_config()
    _check_key(key)
    response = _authed(cfg, "GET", _data_path(cfg, key))
    if response.status_code == 404:
        raise VaultError(f"vault has no entry {FOLDER}/{key} under mount {cfg.mount}")
    if response.status_code != 200:
        raise VaultError(f"vault refused to read {FOLDER}/{key} (HTTP {response.status_code})")
    try:
        data = (response.json().get("data") or {}).get("data") or {}
    except ValueError as exc:
        raise VaultError(f"vault returned an unreadable body for {FOLDER}/{key}") from exc
    value = data.get("value")
    if not isinstance(value, str) or value == "":
        raise VaultError(f"vault entry {FOLDER}/{key} has no 'value'")
    return value


def delete(key: str, cfg: VaultConfig | None = None) -> None:
    """Destroy every version of one entry (metadata delete)."""
    cfg = cfg or current_config()
    _check_key(key)
    response = _authed(cfg, "DELETE", _meta_path(cfg, key))
    if response.status_code not in (200, 204, 404):
        raise VaultError(f"vault refused to delete {FOLDER}/{key} (HTTP {response.status_code})")


def list_keys(cfg: VaultConfig | None = None) -> list[str]:
    """Every VEYRS key under the mount. Sub-folders are not ours and are skipped."""
    cfg = cfg or current_config()
    response = _authed(cfg, "LIST", _meta_path(cfg))
    if response.status_code == 404:
        return []  # Vault answers an empty folder with 404
    if response.status_code != 200:
        raise VaultError(f"vault refused to list {FOLDER}/ (HTTP {response.status_code})")
    keys = ((response.json().get("data") or {}).get("keys")) or []
    return sorted(k for k in keys if isinstance(k, str) and valid_key(k))


def created_at(key: str, cfg: VaultConfig | None = None) -> dt.datetime | None:
    """When the entry was first written, from its KV metadata."""
    cfg = cfg or current_config()
    _check_key(key)
    response = _authed(cfg, "GET", _meta_path(cfg, key))
    if response.status_code != 200:
        return None
    raw = (response.json().get("data") or {}).get("created_time")
    if not isinstance(raw, str):
        return None
    try:
        # Vault prints nanoseconds; fromisoformat takes at most microseconds.
        trimmed = re.sub(r"(\.\d{6})\d+", r"\1", raw.replace("Z", "+00:00"))
        return dt.datetime.fromisoformat(trimmed)
    except ValueError:
        return None


def probe(cfg: VaultConfig | None = None) -> dict[str, Any]:
    """Reachability, seal state and whether our credentials log in.

    Names no token, no secret-id and no stored value -- only booleans and a
    reason. Safe to hand to the status page.
    """
    cfg = cfg or current_config()
    out: dict[str, Any] = {
        "configured": is_configured(cfg), "problems": config_problems(cfg),
        "reachable": None, "initialized": None, "sealed": None, "auth_ok": None,
        "error": None,
    }
    if not cfg.addr or not cfg.addr.startswith(("https://", "http://")):
        return out
    try:
        health = _request(cfg, "GET", "sys/health")
    except VaultError as exc:
        out["reachable"] = False
        out["error"] = str(exc)
        return out
    out["reachable"] = True
    try:
        body = health.json()
        out["initialized"] = body.get("initialized")
        out["sealed"] = body.get("sealed")
    except ValueError:
        pass
    if out["sealed"] or not out["configured"]:
        out["auth_ok"] = False if out["sealed"] else None
        return out
    try:
        response = _authed(cfg, "GET", "auth/token/lookup-self")
        out["auth_ok"] = response.status_code == 200
        if not out["auth_ok"]:
            out["error"] = f"token lookup refused (HTTP {response.status_code})"
    except VaultError as exc:
        out["auth_ok"] = False
        out["error"] = str(exc)
    return out
