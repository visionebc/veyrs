"""RADIUS authentication (AAA) for one organization, with the server's own second factor.

What it is for
--------------
Many security teams already run their second factor in a RADIUS server:
FortiAuthenticator with FortiToken, Microsoft NPS with the Entra MFA extension,
Duo Authentication Proxy, privacyIDEA, FreeRADIUS with an OTP module. Pointing
VEYRS at that server means the same password and the same token as the VPN and
the firewalls, enforced and logged where the security team already looks.

The exchange (RFC 2865)
-----------------------
1. Access-Request with the account name and the password (PAP).
2. The server answers one of three things:
   * Access-Accept  -- signed in. If it carries a Class / Filter-Id the
     organization mapped to a role, the role grants follow it.
   * Access-Reject  -- wrong password, wrong code, locked account.
   * Access-Challenge -- the server wants a second factor. It carries a State
     and usually a Reply-Message ("Enter your FortiToken code"). VEYRS shows the
     message, keeps the State for two minutes keyed by a random challenge id,
     and sends the code back in a second Access-Request with that State. A
     push-approval server simply holds the first answer until the person taps
     "approve", so the timeout must cover that (60 s is typical).

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * **Message-Authenticator is required on every answer** and sent first in
    every request. An answer without one, or with a wrong one, is discarded as
    if it never arrived. That is the Blast-RADIUS mitigation (CVE-2024-3596,
    RFC 3579 + draft-ietf-radext-deprecating-radius): without it, an attacker
    on the path can forge an Access-Accept for any password. It is not a
    setting. A server too old to send it must be upgraded, not accommodated.
  * The Response Authenticator is verified too, and the answer must come from
    the address and port the request went to, with the same identifier.
  * PAP over UDP hides the password with MD5 and the shared secret: keep the
    RADIUS traffic on a management network, use a long random secret, and
    prefer a server reachable without crossing untrusted links. RadSec (RADIUS
    over TLS) is not implemented.
  * A platform superuser is NEVER delegated (same rule as the directory): the
    account that can repair a broken RADIUS configuration cannot depend on it.
  * No just-in-time accounts: RADIUS says yes or no about a name, it does not
    describe a person. The account must exist in VEYRS first (Administration ->
    Users); its username or e-mail is what is sent as User-Name.
  * The shared secret is stored encrypted (security/secrets.py) and never
    returned by any API.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import re
import secrets as _rand
import socket
import struct
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from ..models.tenancy import Organization
from ..security import secrets

SETTINGS_KEY = "radius"
SECRET_FIELD = "secret_enc"

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT, ACCESS_CHALLENGE = 1, 2, 3, 11
CODES = {ACCESS_ACCEPT: "accept", ACCESS_REJECT: "reject", ACCESS_CHALLENGE: "challenge"}
# attribute types
USER_NAME, USER_PASSWORD, SERVICE_TYPE, FILTER_ID = 1, 2, 6, 11
REPLY_MESSAGE, STATE, CLASS, NAS_IDENTIFIER, MESSAGE_AUTHENTICATOR = 18, 24, 25, 32, 80
SERVICE_TYPE_AUTHENTICATE_ONLY = 8
ROLE_ATTRIBUTES = {"Class": CLASS, "Filter-Id": FILTER_ID}

CHALLENGE_TTL = 180
_HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$|^\[?[0-9A-Fa-f:]{2,45}\]?$")

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    # "host" or "host:port", tried in order; the next one only on a TIMEOUT
    # (a server that answers "reject" has answered).
    "servers": [],
    "timeout_seconds": 10,
    "retries": 1,
    "nas_identifier": "veyrs",
    # Which reply attribute carries the role hint, and value -> role slug.
    "role_attribute": "",
    "value_role_map": {},
    SECRET_FIELD: None,
}


class RadiusError(Exception):
    """No usable answer: unreachable, misconfigured, or every answer forged."""


@dataclass
class RadiusAnswer:
    outcome: str                       # accept | reject | challenge
    reply_message: str | None = None
    state: bytes | None = None
    values: dict[str, list[str]] = field(default_factory=dict)   # Class / Filter-Id
    server: str = ""


# ---------------------------------------------------------------- protocol ---
def _attr(kind: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("RADIUS attribute value longer than 253 bytes")
    return struct.pack("!BB", kind, len(value) + 2) + value


def hide_password(password: str, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 5.2: pad to 16, XOR each block with MD5(secret + previous)."""
    raw = password.encode()
    if len(raw) > 128:
        raise ValueError("password longer than 128 bytes (the RADIUS limit)")
    raw += b"\x00" * ((16 - len(raw) % 16) % 16 or (16 if not raw else 0))
    out, prev = b"", authenticator
    for i in range(0, len(raw), 16):
        key = hashlib.md5(secret + prev).digest()
        block = bytes(a ^ b for a, b in zip(raw[i:i + 16], key))
        out += block
        prev = block
    return out


def build_request(identifier: int, authenticator: bytes, secret: bytes, *,
                  user: str, password: str, nas_identifier: str,
                  state: bytes | None = None) -> bytes:
    attrs = _attr(MESSAGE_AUTHENTICATOR, b"\x00" * 16)          # first: Blast-RADIUS guidance
    attrs += _attr(USER_NAME, user.encode())
    attrs += _attr(USER_PASSWORD, hide_password(password, secret, authenticator))
    attrs += _attr(SERVICE_TYPE, struct.pack("!I", SERVICE_TYPE_AUTHENTICATE_ONLY))
    attrs += _attr(NAS_IDENTIFIER, nas_identifier.encode())
    if state:
        attrs += _attr(STATE, state)
    packet = struct.pack("!BBH", ACCESS_REQUEST, identifier, 20 + len(attrs)) + authenticator + attrs
    mac = hmac.new(secret, packet, hashlib.md5).digest()
    return packet[:22] + mac + packet[38:]                       # MA value sits at bytes 22..38


def parse_attributes(data: bytes) -> list[tuple[int, bytes, int]]:
    """[(type, value, offset of value)], or ValueError on a malformed list."""
    out, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated attribute")
        kind, length = data[i], data[i + 1]
        if length < 2 or i + length > len(data):
            raise ValueError("bad attribute length")
        out.append((kind, data[i + 2:i + length], i + 2))
        i += length
    return out


def verify_response(packet: bytes, request_authenticator: bytes, secret: bytes,
                    identifier: int) -> tuple[int, list[tuple[int, bytes, int]]]:
    """(code, attributes) of an AUTHENTIC answer; ValueError for anything else."""
    if len(packet) < 20:
        raise ValueError("short packet")
    code, ident, length = struct.unpack("!BBH", packet[:4])
    if ident != identifier:
        raise ValueError("identifier mismatch")
    if length > len(packet) or length < 20:
        raise ValueError("bad length")
    packet = packet[:length]
    if code not in CODES:
        raise ValueError(f"unexpected code {code}")
    attrs = parse_attributes(packet[20:])
    expected = hashlib.md5(packet[:4] + request_authenticator + packet[20:] + secret).digest()
    if not hmac.compare_digest(expected, packet[4:20]):
        raise ValueError("bad response authenticator (wrong shared secret, or forged)")
    mas = [(v, off) for kind, v, off in attrs if kind == MESSAGE_AUTHENTICATOR]
    if len(mas) != 1 or len(mas[0][0]) != 16:
        raise ValueError("no Message-Authenticator in the answer: refused (Blast-RADIUS, "
                         "CVE-2024-3596) -- enable it on the server")
    value, off = mas[0]
    pos = 20 + off
    zeroed = packet[:4] + request_authenticator + packet[20:pos] + b"\x00" * 16 + packet[pos + 16:]
    if not hmac.compare_digest(hmac.new(secret, zeroed, hashlib.md5).digest(), value):
        raise ValueError("bad Message-Authenticator (wrong shared secret, or forged)")
    return code, attrs


def _split(server: str) -> tuple[str, int]:
    server = server.strip()
    if server.startswith("["):
        host, _, rest = server[1:].partition("]")
        port = rest.lstrip(":") or "1812"
    elif server.count(":") == 1:
        host, port = server.split(":")
    else:
        host, port = server, "1812"
    return host, int(port)


def exchange(cfg: dict, secret: str, *, user: str, password: str,
             state: bytes | None = None, server_hint: str | None = None) -> RadiusAnswer:
    """One Access-Request, tried on each server in order until one answers."""
    servers = list(cfg.get("servers") or [])
    if server_hint and server_hint in servers:
        # A challenge's State is only meaningful to the server that issued it.
        servers = [server_hint]
    if not servers:
        raise RadiusError("no RADIUS server is configured")
    key = secret.encode()
    timeout = float(cfg.get("timeout_seconds") or 10)
    retries = int(cfg.get("retries") or 0)
    problems = []
    for server in servers:
        host, port = _split(server)
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        except OSError as exc:
            problems.append(f"{server}: cannot resolve ({exc.strerror or exc})")
            continue
        family, _, _, _, addr = infos[0]
        for _attempt in range(retries + 1):
            identifier = _rand.randbelow(256)
            authenticator = _rand.token_bytes(16)
            packet = build_request(identifier, authenticator, key, user=user, password=password,
                                   nas_identifier=str(cfg.get("nas_identifier") or "veyrs"),
                                   state=state)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.connect(addr)               # only answers from that address:port arrive
                    sock.send(packet)
                    deadline = dt.datetime.now().timestamp() + timeout
                    while True:
                        remaining = deadline - dt.datetime.now().timestamp()
                        if remaining <= 0:
                            raise socket.timeout()
                        sock.settimeout(remaining)
                        data = sock.recv(4096)
                        try:
                            code, attrs = verify_response(data, authenticator, key, identifier)
                        except ValueError as exc:
                            # Forged or broken: ignore it and keep listening for the real one.
                            problems.append(f"{server}: answer discarded ({exc})")
                            continue
                        return _answer(code, attrs, server)
                except socket.timeout:
                    problems.append(f"{server}: no answer in {timeout:g}s")
                except OSError as exc:
                    problems.append(f"{server}: {exc.strerror or exc}")
                    break
    raise RadiusError("; ".join(problems[-6:]) or "no RADIUS server answered")


def _answer(code: int, attrs: list, server: str) -> RadiusAnswer:
    reply = b"".join(v for k, v, _ in attrs if k == REPLY_MESSAGE).decode(errors="replace").strip()
    state = next((v for k, v, _ in attrs if k == STATE), None)
    values: dict[str, list[str]] = {}
    for name, kind in ROLE_ATTRIBUTES.items():
        found = [v.decode(errors="replace").strip() for k, v, _ in attrs if k == kind]
        if found:
            values[name] = found
    return RadiusAnswer(outcome=CODES[code], reply_message=reply[:300] or None, state=state,
                        values=values, server=server)


# ------------------------------------------------------------ configuration ---
def _block(organization: Organization | None) -> dict[str, Any]:
    stored = (organization.settings or {}) if organization is not None else {}
    block = stored.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def config(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    merged = dict(DEFAULTS)
    merged.update(_block(session.get(Organization, organization_id)))
    return merged


def is_enabled(session: Session, organization_id: uuid.UUID) -> bool:
    cfg = config(session, organization_id)
    return bool(cfg.get("enabled")) and bool(cfg.get("servers")) and bool(cfg.get(SECRET_FIELD))


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    cfg = config(session, organization_id)
    out = {k: v for k, v in cfg.items() if k != SECRET_FIELD}
    out["secret_set"] = bool(cfg.get(SECRET_FIELD))
    out["message_authenticator"] = "required (not configurable)"
    return out


def validate(cfg: dict[str, Any]) -> list[str]:
    problems = []
    servers = cfg.get("servers") or []
    if not isinstance(servers, list) or len(servers) > 4:
        problems.append("servers is a list of at most four host[:port] entries")
        servers = []
    for s in servers:
        try:
            host, port = _split(str(s))
        except ValueError:
            problems.append(f"{s!r} is not host or host:port")
            continue
        if not _HOST_RE.match(host) or "/" in str(s) or not (1 <= port <= 65535):
            problems.append(f"{s!r} is not host or host:port (no URL)")
    if cfg.get("enabled") and not servers:
        problems.append("at least one RADIUS server is required to enable RADIUS")
    if not (1 <= int(cfg.get("timeout_seconds") or 0) <= 120):
        problems.append("timeout_seconds must be 1-120 (60 covers push approval)")
    if not (0 <= int(cfg.get("retries") or 0) <= 3):
        problems.append("retries must be 0-3")
    nas = str(cfg.get("nas_identifier") or "")
    if not (1 <= len(nas) <= 64) or not nas.isprintable():
        problems.append("nas_identifier must be 1-64 printable characters")
    if cfg.get("role_attribute") not in ("", *ROLE_ATTRIBUTES):
        problems.append("role_attribute must be empty, Class or Filter-Id")
    if not isinstance(cfg.get("value_role_map") or {}, dict):
        problems.append("value_role_map maps attribute values to role slugs")
    return problems


def set_config(session: Session, organization_id: uuid.UUID, payload: dict[str, Any], *,
               secret: str | None = None, actor_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Write the configuration; an absent secret leaves the stored one alone."""
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")
    merged = config(session, organization_id)
    for key in DEFAULTS:
        if key in payload and key != SECRET_FIELD:
            merged[key] = payload[key]
    merged["servers"] = [str(s).strip() for s in (merged.get("servers") or []) if str(s).strip()]
    merged["value_role_map"] = {str(k).strip(): str(v).strip()
                                for k, v in (merged.get("value_role_map") or {}).items()
                                if str(k).strip() and str(v).strip()}
    if secret:
        if len(secret) < 16:
            raise ValueError("the shared secret must be at least 16 characters (use a long random one)")
        merged[SECRET_FIELD] = secrets.encrypt(secret)
    if merged.get("enabled") and not merged.get(SECRET_FIELD):
        raise ValueError("a shared secret is required to enable RADIUS")
    problems = validate(merged)
    if problems:
        raise ValueError("; ".join(problems))
    merged["changed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    merged["changed_by_id"] = str(actor_id) if actor_id else None
    stored = dict(organization.settings or {})
    stored[SETTINGS_KEY] = merged
    organization.settings = stored      # reassign: JSONB in-place changes are not tracked
    session.flush()
    return state(session, organization_id)


def _secret(cfg: dict) -> str:
    try:
        value = secrets.decrypt(cfg.get(SECRET_FIELD))
    except secrets.SecretError as exc:
        raise RadiusError(f"the stored shared secret cannot be read: {exc}") from exc
    if not value:
        raise RadiusError("no shared secret is stored")
    return value


def roles_for(cfg: dict, answer: RadiusAnswer) -> list[str] | None:
    """Role slugs from the reply attribute, or None when no mapping is configured."""
    attr = cfg.get("role_attribute") or ""
    mapping = cfg.get("value_role_map") or {}
    if not attr or not mapping:
        return None
    return sorted({mapping[v] for v in answer.values.get(attr, []) if v in mapping})


# --------------------------------------------------------------- challenges ---
def _store():
    from ..security import mfa_delivery
    return mfa_delivery.store()


def save_challenge(user_id: Any, answer: RadiusAnswer) -> str:
    challenge_id = _rand.token_urlsafe(24)
    _store().set(f"veyrs:radius:ch:{challenge_id}", json.dumps({
        "user_id": str(user_id), "server": answer.server,
        "state": (answer.state or b"").hex(), "message": answer.reply_message}), CHALLENGE_TTL)
    return challenge_id


def take_challenge(challenge_id: str | None, user_id: Any) -> dict | None:
    """The pending challenge of THIS user, removed (single use), or None."""
    if not challenge_id or not re.fullmatch(r"[A-Za-z0-9_\-]{20,64}", challenge_id):
        return None
    key = f"veyrs:radius:ch:{challenge_id}"
    st = _store()
    raw = st.get(key)
    if not raw:
        return None
    st.delete(key)
    data = json.loads(raw)
    return data if data.get("user_id") == str(user_id) else None


# ---------------------------------------------------------------- sign-in ---
def authenticate(session: Session, organization_id: uuid.UUID, user_name: str,
                 password: str) -> RadiusAnswer:
    cfg = config(session, organization_id)
    return exchange(cfg, _secret(cfg), user=user_name, password=password)


def answer_challenge(session: Session, organization_id: uuid.UUID, user_name: str,
                     pending: dict, code: str) -> RadiusAnswer:
    cfg = config(session, organization_id)
    return exchange(cfg, _secret(cfg), user=user_name, password=code or "",
                    state=bytes.fromhex(pending.get("state") or ""), server_hint=pending.get("server"))


def test_connection(session: Session, organization_id: uuid.UUID, user_name: str,
                    password: str, code: str | None = None) -> dict:
    """A real exchange with the SAVED configuration, step by step. Never raises."""
    steps: list[dict] = []
    cfg = config(session, organization_id)
    problems = validate(cfg)
    if not cfg.get("servers") or not cfg.get(SECRET_FIELD):
        problems.append("no server or no shared secret saved")
    steps.append({"step": "configuration", "ok": not problems, "detail": "; ".join(problems) or "saved and valid"})
    if problems:
        return {"ok": False, "steps": steps}
    try:
        answer = exchange(cfg, _secret(cfg), user=user_name, password=password)
    except RadiusError as exc:
        steps.append({"step": "first answer", "ok": False, "detail": str(exc)})
        return {"ok": False, "steps": steps}
    steps.append({"step": "first answer", "ok": answer.outcome != "reject",
                  "detail": f"{answer.outcome} from {answer.server} (Message-Authenticator verified)"
                            + (f": {answer.reply_message}" if answer.reply_message else "")})
    if answer.outcome == "challenge":
        if not code:
            steps.append({"step": "second factor", "ok": True,
                          "detail": "the server asks for a second factor; run the test again with the code"})
            return {"ok": True, "challenge": True, "message": answer.reply_message, "steps": steps}
        try:
            answer = exchange(cfg, _secret(cfg), user=user_name, password=code, state=answer.state,
                              server_hint=answer.server)
        except RadiusError as exc:
            steps.append({"step": "second factor", "ok": False, "detail": str(exc)})
            return {"ok": False, "steps": steps}
        steps.append({"step": "second factor", "ok": answer.outcome == "accept",
                      "detail": f"{answer.outcome}" + (f": {answer.reply_message}" if answer.reply_message else "")})
    roles = roles_for(cfg, answer) if answer.outcome == "accept" else None
    if roles is not None:
        steps.append({"step": "roles", "ok": True,
                      "detail": f"{cfg.get('role_attribute')}={answer.values.get(cfg.get('role_attribute'), [])} -> {roles or 'no mapped role'}"})
    return {"ok": answer.outcome == "accept", "steps": steps}
