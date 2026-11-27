"""One rule for "what is the caller's IP address".

The answer is `request.client.host`. uvicorn runs with `--proxy-headers
--forwarded-allow-ips=...`, so that value is already the nearest hop that is not
a trusted proxy. The first `X-Forwarded-For` entry is whatever the caller sent,
so nothing in the application may read the header.

These tests build a bare `starlette.requests.Request` from a scope dict, so
they need no database and no running app.
"""
from __future__ import annotations

import pathlib
import re
import uuid

from starlette.requests import Request

from veyrs.security import ratelimit
from veyrs.security.deps import Principal, audit_actor

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend" / "veyrs"
UNIT = ROOT / "infrastructure/systemd/veyrs-api.service"

# RFC 5737 documentation addresses.
REAL_PEER = "198.51.100.7"
FORGED = "203.0.113.99"


def _request(client_host: str | None = REAL_PEER, headers: dict[str, str] | None = None) -> Request:
    raw = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/thing",
        "query_string": b"",
        "headers": raw,
        "client": (client_host, 54321) if client_host else None,
        "server": ("testserver", 80),
        "scheme": "http",
    }
    return Request(scope)


def _principal() -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        label="tester",
        permissions=frozenset(),
    )


# ---------------------------------------------------------------------------
# 1. The rate limiter
# ---------------------------------------------------------------------------
def test_client_ip_ignores_x_forwarded_for():
    request = _request(headers={"X-Forwarded-For": f"{FORGED}, 192.0.2.1"})
    assert ratelimit.client_ip(request) == REAL_PEER


def test_client_ip_without_a_peer_is_unknown():
    assert ratelimit.client_ip(_request(client_host=None)) == "unknown"


# ---------------------------------------------------------------------------
# 2. The audit context
# ---------------------------------------------------------------------------
def test_audit_actor_records_the_peer_not_a_forged_header():
    principal = _principal()
    request = _request(headers={"X-Forwarded-For": FORGED, "User-Agent": "unit-test"})
    ctx = audit_actor(request, principal)
    assert ctx["ip_address"] == REAL_PEER
    assert set(ctx) == {
        "organization_id", "actor_id", "actor_label", "correlation_id",
        "ip_address", "user_agent",
    }
    assert ctx["organization_id"] == principal.organization_id
    assert ctx["actor_id"] == principal.user_id
    assert ctx["actor_label"] == "tester"
    assert ctx["user_agent"] == "unit-test"


def test_audit_actor_without_a_peer_records_none():
    assert audit_actor(_request(client_host=None), _principal())["ip_address"] is None


# ---------------------------------------------------------------------------
# 3. Nothing under backend/veyrs reads the header
# ---------------------------------------------------------------------------
def test_no_backend_file_reads_x_forwarded_for():
    offenders = [
        str(path.relative_to(ROOT))
        for path in sorted(BACKEND.rglob("*.py"))
        # A quoted header name is a read (`headers.get("X-Forwarded-For")`);
        # prose in a docstring explaining why is not.
        if re.search(r"""['"]x-forwarded-for['"]""", path.read_text(encoding="utf-8"), re.I)
    ]
    assert not offenders, (
        "the application must use request.client.host and never read "
        "X-Forwarded-For (uvicorn already resolves it through its trusted "
        "proxy list): " + ", ".join(offenders)
    )


# ---------------------------------------------------------------------------
# 4. The systemd unit
# ---------------------------------------------------------------------------
def test_the_unit_passes_the_trusted_proxy_list_from_the_environment():
    lines = [l.strip() for l in UNIT.read_text().splitlines()
             if l.strip() and not l.strip().startswith("#")]
    assert "Environment=VEYRS_FORWARDED_ALLOW_IPS=127.0.0.1" in lines, (
        "the unit must declare a loopback default that .env can override")
    text = "\n".join(lines)
    assert "--forwarded-allow-ips=${VEYRS_FORWARDED_ALLOW_IPS}" in text
    assert "--forwarded-allow-ips=127.0.0.1" not in text
    assert "--proxy-headers" in text


# ---------------------------------------------------------------------------
# 5. Exactly one audit-context helper
# ---------------------------------------------------------------------------
def test_routers_do_not_define_their_own_actor_helper():
    own = [
        str(path.relative_to(ROOT))
        for path in sorted((BACKEND / "api").rglob("*.py"))
        if re.search(r"^def _actor\(", path.read_text(encoding="utf-8"), re.M)
    ]
    assert not own, "routers must import security.deps.audit_actor, not redefine it: " + ", ".join(own)


def test_the_routers_share_the_one_helper():
    users = [p for p in sorted((BACKEND / "api" / "v1").glob("*.py"))
             if "audit_actor as _actor" in p.read_text(encoding="utf-8")]
    assert {p.stem for p in users} == {
        "assets", "admin", "findings", "risk_register",
        "tickets", "fix_plan", "policies", "knowledge",
    }
    defs = [p for p in BACKEND.rglob("*.py")
            if re.search(r"^def audit_actor\(", p.read_text(encoding="utf-8"), re.M)]
    assert [p.name for p in defs] == ["deps.py"]
