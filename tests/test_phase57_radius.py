"""Phase 57 -- RADIUS sign-in (AAA) with the server's own second factor.

A fake RADIUS server runs in-process on 127.0.0.1. What must never regress:
* an answer without a valid Message-Authenticator is NOT believed (Blast-RADIUS);
* an answer signed with another secret is NOT believed;
* Access-Challenge -> mfa_required with the server's message; the challenge id
  is single use and bound to the account;
* a platform superuser is never delegated to RADIUS;
* the shared secret is never returned.
"""
from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import threading
import uuid

import pytest
from sqlalchemy import select

from conftest import _flush_rate_limits, auth_headers
from veyrs.db import SessionLocal, set_tenant
from veyrs.models.audit import AuditLog
from veyrs.models.tenancy import Role, User
from veyrs.security import mfa_delivery
from veyrs.services import radius_auth as ra

SECRET = "a-long-random-shared-secret-0123"


class FakeRadius:
    """alice: password then FortiToken-style challenge; bob: password only."""

    def __init__(self, mode: str = "ok"):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.requests: list[dict] = []
        self.stop = False
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                self.handle(data, addr)
            except Exception:  # noqa: BLE001
                pass

    def handle(self, data, addr):
        code, ident, length = struct.unpack("!BBH", data[:4])
        auth = data[4:20]
        attrs = ra.parse_attributes(data[20:length])
        ma = [(v, off) for k, v, off in attrs if k == ra.MESSAGE_AUTHENTICATOR]
        pos = 20 + ma[0][1]
        zeroed = data[:pos] + b"\x00" * 16 + data[pos + 16:length]
        assert hmac.compare_digest(hmac.new(SECRET.encode(), zeroed, hashlib.md5).digest(), ma[0][0])
        user = next(v for k, v, _ in attrs if k == ra.USER_NAME).decode()
        hidden = next(v for k, v, _ in attrs if k == ra.USER_PASSWORD)
        pw, prev = b"", auth
        for i in range(0, len(hidden), 16):
            key = hashlib.md5(SECRET.encode() + prev).digest()
            pw += bytes(a ^ b for a, b in zip(hidden[i:i + 16], key))
            prev = hidden[i:i + 16]
        pw = pw.rstrip(b"\x00").decode()
        state = next((v for k, v, _ in attrs if k == ra.STATE), None)
        self.requests.append({"user": user, "password": pw, "state": state})
        out = []
        if user == "alice" and state is None and pw == "pw-alice":
            reply, out = ra.ACCESS_CHALLENGE, [(ra.STATE, b"st-1"), (ra.REPLY_MESSAGE, b"Enter FortiToken code")]
        elif user == "alice" and state == b"st-1" and pw == "123456":
            reply, out = ra.ACCESS_ACCEPT, [(ra.CLASS, b"veyrs-admins")]
        elif user == "bob" and pw == "pw-bob":
            reply = ra.ACCESS_ACCEPT
        else:
            reply = ra.ACCESS_REJECT
        secret = b"some-other-secret-entirely" if self.mode == "bad_secret" else SECRET.encode()
        body = b""
        if self.mode != "no_ma":
            body += ra._attr(ra.MESSAGE_AUTHENTICATOR, b"\x00" * 16)
        for k, v in out:
            body += ra._attr(k, v)
        head = struct.pack("!BBH", reply, ident, 20 + len(body))
        if self.mode != "no_ma":
            mac = hmac.new(secret, head + auth + body, hashlib.md5).digest()
            body = body[:2] + mac + body[18:]
        resp_auth = hashlib.md5(head + auth + body + secret).digest()
        if self.mode == "bad_resp_auth":
            resp_auth = bytes(16)        # Message-Authenticator valid, authenticator forged
        self.sock.sendto(head + resp_auth + body, addr)

    def close(self):
        self.stop = True


@pytest.fixture()
def radius():
    servers = []

    def make(mode="ok"):
        s = FakeRadius(mode)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@pytest.fixture(autouse=True)
def _memory_store(monkeypatch):
    monkeypatch.setattr(mfa_delivery, "_store", mfa_delivery.MemoryStore())


def _cfg(server, **extra):
    return {"enabled": True, "servers": [f"127.0.0.1:{server.port}"], "timeout_seconds": 1,
            "retries": 0, "nas_identifier": "veyrs-test", "role_attribute": "", "value_role_map": {},
            ra.SECRET_FIELD: "x", **extra}


# --------------------------------------------------------------- protocol ---
def test_accept_reject_and_challenge(radius):
    s = radius()
    cfg = _cfg(s)
    assert ra.exchange(cfg, SECRET, user="bob", password="pw-bob").outcome == "accept"
    assert ra.exchange(cfg, SECRET, user="bob", password="nope").outcome == "reject"
    ch = ra.exchange(cfg, SECRET, user="alice", password="pw-alice")
    assert ch.outcome == "challenge" and ch.state == b"st-1" and ch.reply_message == "Enter FortiToken code"
    ok = ra.exchange(cfg, SECRET, user="alice", password="123456", state=ch.state, server_hint=ch.server)
    assert ok.outcome == "accept" and ok.values == {"Class": ["veyrs-admins"]}
    assert s.requests[0]["password"] == "pw-bob"          # PAP hiding round-trips


def test_long_password_round_trips(radius):
    s = radius()
    ra.exchange(_cfg(s), SECRET, user="bob", password="x" * 40)
    assert s.requests[-1]["password"] == "x" * 40


def test_an_answer_without_message_authenticator_is_not_believed(radius):
    s = radius("no_ma")
    with pytest.raises(ra.RadiusError) as exc:
        ra.exchange(_cfg(s), SECRET, user="bob", password="pw-bob")
    assert "Message-Authenticator" in str(exc.value)


def test_an_answer_signed_with_another_secret_is_not_believed(radius):
    s = radius("bad_secret")
    with pytest.raises(ra.RadiusError) as exc:
        ra.exchange(_cfg(s), SECRET, user="bob", password="pw-bob")
    assert "authenticator" in str(exc.value).lower()


def test_a_forged_response_authenticator_is_not_believed(radius):
    s = radius("bad_resp_auth")
    with pytest.raises(ra.RadiusError) as exc:
        ra.exchange(_cfg(s), SECRET, user="bob", password="pw-bob")
    assert "response authenticator" in str(exc.value)


def test_failover_to_the_next_server_on_timeout(radius):
    s = radius()
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))              # bound, never answers
    cfg = _cfg(s, servers=[f"127.0.0.1:{dead.getsockname()[1]}", f"127.0.0.1:{s.port}"])
    assert ra.exchange(cfg, SECRET, user="bob", password="pw-bob").outcome == "accept"
    dead.close()


def test_validation():
    base = dict(ra.DEFAULTS, enabled=True, servers=["radius.corp:1812"])
    assert ra.validate(base) == []
    assert ra.validate(dict(base, servers=["https://radius.corp/"]))
    assert ra.validate(dict(base, servers=[]))
    assert ra.validate(dict(base, timeout_seconds=500))
    assert ra.validate(dict(base, role_attribute="Tunnel-Group"))


# -------------------------------------------------------------- sign-in ---
def _setup(org, server, *, role_slug=None):
    org_id, slug, _ = org
    with SessionLocal() as s:
        set_tenant(s, org_id)
        vmap = {"veyrs-admins": role_slug} if role_slug else {}
        ra.set_config(s, org_id, {"enabled": True, "servers": [f"127.0.0.1:{server.port}"],
                                  "timeout_seconds": 1, "retries": 0,
                                  "role_attribute": "Class" if role_slug else "",
                                  "value_role_map": vmap}, secret=SECRET)
        users = {}
        for name in ("alice", "bob"):
            u = User(organization_id=org_id, email=f"{name}-{uuid.uuid4().hex[:6]}@example.org",
                     username=name, full_name=name.title(), password_hash=None)
            s.add(u)
            s.flush()
            users[name] = (u.id, u.email)
        s.commit()
    return slug, users


def _login(client, ident, slug, password, **extra):
    _flush_rate_limits()
    return client.post("/api/v1/auth/login", json={"identifier": ident, "password": password,
                                                    "organization": slug, **extra})


def test_password_only_account(client, org_a, radius):
    s = radius()
    slug, _ = _setup(org_a, s)
    assert _login(client, "bob", slug, "pw-bob").status_code == 200
    assert _login(client, "bob", slug, "wrong").status_code == 401


def test_challenge_flow_single_use_and_roles(client, org_a, radius):
    s = radius()
    with SessionLocal() as db:
        role = db.execute(select(Role).where(Role.organization_id.is_(None), Role.slug != "org-admin")).scalars().first()
    slug, users = _setup(org_a, s, role_slug=role.slug)
    first = _login(client, "alice", slug, "pw-alice")
    assert first.status_code == 401
    d = first.json()["detail"]
    assert d["method"] == "radius" and d["message"] == "Enter FortiToken code" and d["radius_challenge"]
    ok = _login(client, "alice", slug, "pw-alice", mfa_code="123456", radius_challenge=d["radius_challenge"])
    assert ok.status_code == 200, ok.text
    again = _login(client, "alice", slug, "pw-alice", mfa_code="123456", radius_challenge=d["radius_challenge"])
    assert again.status_code == 401                       # single use
    with SessionLocal() as db:
        set_tenant(db, org_a[0])
        reasons = [a.reason for a in db.execute(select(AuditLog).where(AuditLog.action == "auth.login")).scalars()
                   if getattr(a, "reason", None)] if hasattr(AuditLog, "reason") else []
    from veyrs.models.tenancy import UserRole
    with SessionLocal() as db:
        set_tenant(db, org_a[0])
        granted = db.execute(select(UserRole).where(UserRole.user_id == users["alice"][0])).scalars().all()
        assert any(g.role_id == role.id for g in granted)


def test_a_wrong_code_fails_and_spends_the_budget(client, org_a, radius):
    s = radius()
    slug, users = _setup(org_a, s)
    d = _login(client, "alice", slug, "pw-alice").json()["detail"]
    bad = _login(client, "alice", slug, "pw-alice", mfa_code="000000", radius_challenge=d["radius_challenge"])
    assert bad.status_code == 401
    with SessionLocal() as db:
        set_tenant(db, org_a[0])
        assert db.get(User, users["alice"][0]).failed_logins >= 1


def test_a_challenge_belongs_to_one_account(client, org_a, radius):
    s = radius()
    slug, _ = _setup(org_a, s)
    d = _login(client, "alice", slug, "pw-alice").json()["detail"]
    sent = len(s.requests)
    stolen = _login(client, "bob", slug, "anything", mfa_code="123456", radius_challenge=d["radius_challenge"])
    assert stolen.status_code == 401
    assert len(s.requests) == sent, "another account's challenge must be refused before the server is asked"


def test_unreachable_server_is_a_refusal(client, org_a, radius):
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))

    class Dead:
        port = dead.getsockname()[1]
    slug, _ = _setup(org_a, Dead)
    assert _login(client, "bob", slug, "pw-bob").status_code == 401
    dead.close()


def test_a_superuser_is_never_delegated(client, org_a, radius):
    s = radius()
    slug, users = _setup(org_a, s)
    with SessionLocal() as db:
        set_tenant(db, org_a[0])
        db.get(User, users["bob"][0]).is_superuser = True
        db.commit()
    n = len(s.requests)
    assert _login(client, "bob", slug, "pw-bob").status_code == 401
    assert len(s.requests) == n


# ------------------------------------------------------------ admin API ---
def test_admin_api_hides_the_secret_and_tests_for_real(client, org_a, admin_a, radius):
    s = radius()
    body = {"enabled": True, "servers": [f"127.0.0.1:{s.port}"], "timeout_seconds": 1, "retries": 0}
    assert client.put("/api/v1/radius", headers=admin_a, json={**body, "secret": "short"}).status_code == 422
    r = client.put("/api/v1/radius", headers=admin_a, json={**body, "secret": SECRET})
    assert r.status_code == 200, r.text
    st = client.get("/api/v1/radius", headers=admin_a).json()
    assert st["secret_set"] is True and SECRET not in str(st) and "secret_enc" not in st
    t1 = client.post("/api/v1/radius/test", headers=admin_a,
                     json={"user_name": "alice", "password": "pw-alice"}).json()
    assert t1["ok"] and t1.get("challenge") and t1["message"] == "Enter FortiToken code"
    t2 = client.post("/api/v1/radius/test", headers=admin_a,
                     json={"user_name": "alice", "password": "pw-alice", "code": "123456"}).json()
    assert t2["ok"] and any(st["step"] == "second factor" and st["ok"] for st in t2["steps"])


def test_the_radius_challenge_is_the_second_factor(client, org_a, radius):
    """An account with VEYRS's own MFA on is not asked twice after a RADIUS challenge,
    but IS asked when RADIUS accepted on the password alone."""
    s = radius()
    slug, users = _setup(org_a, s)
    with SessionLocal() as db:
        set_tenant(db, org_a[0])
        for name in ("alice", "bob"):
            u = db.get(User, users[name][0])
            u.mfa_enabled, u.mfa_method = True, "email"
        db.commit()
    d = _login(client, "alice", slug, "pw-alice").json()["detail"]
    ok = _login(client, "alice", slug, "pw-alice", mfa_code="123456", radius_challenge=d["radius_challenge"])
    assert ok.status_code == 200, ok.text
    bob = _login(client, "bob", slug, "pw-bob")
    assert bob.status_code in (401, 503) and "access_token" not in bob.text
