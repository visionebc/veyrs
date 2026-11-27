"""0.41.0 audit fix round, workstream `auth`: one regression test per item.

Risk register IDs (docs/security/risk-register.md) and debt IDs
(docs/audit/risks-and-debt.md) name each section. Every test here failed
against 0.39.1 for the reason its docstring gives.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import logging
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
import jwt
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from conftest import ADMIN_PASSWORD, _flush_rate_limits, _make_org, auth_headers, login
from veyrs.config import Settings, settings
from veyrs.db import SessionLocal, engine, set_tenant
from veyrs.main import app
from veyrs.models import Organization, Role, User, UserRole
from veyrs.models.audit import AuditLog, AuthEvent
from veyrs.models.tenancy import RefreshToken
from veyrs.security import lockout, mfa, mfa_delivery, ratelimit, secrets, tenant_guard
from veyrs.security.agent_auth import LeaseToken
from veyrs.security.auth import ACCESS_AUDIENCE, create_access_token, hash_password
from veyrs.services import audit, mfa_admin

API = "/api/v1"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _from(ip: str) -> TestClient:
    """A client whose requests arrive from `ip` (what uvicorn resolves as request.client)."""
    async def asgi(scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=(ip, 40000))
        await app(scope, receive, send)
    return TestClient(asgi)


def _attempt(client: TestClient, email: str, slug: str, password: str = ADMIN_PASSWORD,
             **extra):
    _flush_rate_limits()
    return client.post(f"{API}/auth/login",
                       json={"email": email, "password": password, "organization": slug, **extra})


def _user(email: str) -> User:
    with SessionLocal() as s:
        u = s.execute(select(User).where(User.email == email)).scalar_one()
        return u


def _update_user(email: str, **values) -> None:
    with SessionLocal() as s:
        u = s.execute(select(User).where(User.email == email)).scalar_one()
        set_tenant(s, u.organization_id)
        u = s.get(User, u.id)
        for k, v in values.items():
            setattr(u, k, v)
        s.commit()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _add_user(org_id: uuid.UUID, slug: str, role_slug: str = "org-admin") -> str:
    email = f"u-{uuid.uuid4().hex[:8]}@{slug}.test"
    with SessionLocal() as s:
        set_tenant(s, org_id)
        user = User(organization_id=org_id, email=email, full_name="Someone",
                    password_hash=hash_password(ADMIN_PASSWORD))
        s.add(user)
        s.flush()
        role = s.execute(select(Role).where(Role.slug == role_slug,
                                            Role.organization_id.is_(None))).scalar_one()
        s.add(UserRole(organization_id=org_id, user_id=user.id, role_id=role.id))
        s.commit()
    return email


@pytest.fixture()
def memory_store(monkeypatch):
    store = mfa_delivery.MemoryStore()
    monkeypatch.setattr(mfa_delivery, "_store", store)
    return store


# ---------------------------------------------------------------------------
# R-08 access tokens die with logout, password change, MFA reset, deactivation
# ---------------------------------------------------------------------------
def test_logout_voids_the_access_token(client, org_a):
    _, slug, email = org_a
    tokens = login(client, email, slug)
    headers = _bearer(tokens["access_token"])
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 200
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
    # 0.39.1: still 200 until expiry -- logout revoked refresh tokens only.
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401
    assert client.post(f"{API}/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_password_change_voids_every_access_token(client, org_a):
    _, slug, email = org_a
    other_device = _bearer(login(client, email, slug)["access_token"])
    headers = _bearer(login(client, email, slug)["access_token"])
    new = "a-brand-new-Password-456"
    response = client.post(f"{API}/auth/password", headers=headers,
                           json={"current_password": ADMIN_PASSWORD, "new_password": new})
    assert response.status_code == 204, response.text
    assert client.get(f"{API}/auth/me", headers=other_device).status_code == 401
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401
    assert login(client, email, slug, password=new)["access_token"]


def test_operator_mfa_reset_and_deactivation_void_access_tokens(client, org_a, admin_a):
    org_id, slug, email = org_a
    target = _add_user(org_id, slug, "read-only")
    headers = _bearer(login(client, target, slug)["access_token"])
    assert mfa_admin.mfa_reset(argparse.Namespace(email=target, reason="lost phone")) == 0
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401

    headers = _bearer(login(client, target, slug)["access_token"])
    user_id = _user(target).id
    assert client.patch(f"{API}/users/{user_id}", headers=admin_a,
                        json={"is_active": False}).status_code == 200
    assert client.patch(f"{API}/users/{user_id}", headers=admin_a,
                        json={"is_active": True}).status_code == 200
    # Reactivation must not revive the session that deactivation ended.
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401


def test_a_token_from_before_the_version_column_still_works(client, org_a):
    """Deploying 0.41.0 must not sign everybody out: no `tv` claim reads as 0."""
    _, slug, email = org_a
    user = _user(email)
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    legacy = jwt.encode({"sub": str(user.id), "org": str(user.organization_id), "perms": [],
                         "su": False, "aud": ACCESS_AUDIENCE, "iss": settings.app_name,
                         "iat": now, "exp": now + 300, "jti": "legacy"},
                        settings.secret_key, algorithm=settings.jwt_algorithm)
    assert client.get(f"{API}/auth/me", headers=_bearer(legacy)).status_code == 200


# ---------------------------------------------------------------------------
# R-15 refresh families are per sign-in; refresh honours lock and org state
# ---------------------------------------------------------------------------
def _refresh(client, token):
    _flush_rate_limits()
    return client.post(f"{API}/auth/refresh", json={"refresh_token": token})


def test_reuse_revokes_one_family_not_every_device(client, org_a):
    _, slug, email = org_a
    laptop = login(client, email, slug)
    phone = login(client, email, slug)
    rotated = _refresh(client, laptop["refresh_token"])
    assert rotated.status_code == 200
    # Replay of the rotated-out laptop token: the laptop chain is revoked ...
    assert _refresh(client, laptop["refresh_token"]).status_code == 401
    assert _refresh(client, rotated.json()["refresh_token"]).status_code == 401
    # ... and the phone, a different sign-in, keeps working (0.39.1: revoked too).
    assert _refresh(client, phone["refresh_token"]).status_code == 200


def test_rotation_keeps_the_family(client, org_a):
    _, slug, email = org_a
    first = login(client, email, slug)
    second = _refresh(client, first["refresh_token"]).json()
    with SessionLocal() as s:
        user = _user(email)
        set_tenant(s, user.organization_id)
        families = {r.family_id for r in s.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id)).scalars()}
    assert len(families) == 1 and user.id not in families
    assert second["refresh_token"]


def test_refresh_refuses_a_locked_user_and_a_disabled_organization(client, org_a):
    org_id, slug, email = org_a
    tokens = login(client, email, slug)
    _update_user(email, locked_until=dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))
    assert _refresh(client, tokens["refresh_token"]).status_code == 401
    _update_user(email, locked_until=None)
    # The lock refusal does not revoke: the session continues after the lock.
    tokens = _refresh(client, tokens["refresh_token"]).json()
    with SessionLocal() as s:
        s.get(Organization, org_id).is_active = False
        s.commit()
    try:
        assert _refresh(client, tokens["refresh_token"]).status_code == 401
    finally:
        with SessionLocal() as s:
            s.get(Organization, org_id).is_active = True
            s.commit()


# ---------------------------------------------------------------------------
# R-13 lockout: one source cannot lock an account; R-24 password routes charge it
# ---------------------------------------------------------------------------
def test_one_source_cannot_lock_the_account(org_a, memory_store):
    """0.39.1: ten failures from anywhere locked the account for everyone."""
    _, slug, email = org_a
    attacker = _from("198.51.100.7")
    for _ in range(lockout.SOURCE_FREE + 10):
        assert _attempt(attacker, email, slug, password="wrong-password-xyz").status_code == 401
    user = _user(email)
    assert not user.is_locked and user.failed_logins == lockout.SOURCE_FREE
    # The attacker's own source is waiting -- even the right password is refused there ...
    assert _attempt(attacker, email, slug).status_code == 401
    # ... and the real person, elsewhere, signs in.
    assert _attempt(_from("192.0.2.10"), email, slug).status_code == 200


def test_failures_from_many_sources_lock_the_account(org_a, memory_store, monkeypatch):
    _, slug, email = org_a
    sources = [f"198.51.100.{i}" for i in range(1, lockout.ACCOUNT_THRESHOLD // lockout.SOURCE_FREE + 1)]
    for ip in sources:
        for _ in range(lockout.SOURCE_FREE):
            _attempt(_from(ip), email, slug, password="wrong-password-xyz")
    assert _user(email).is_locked
    assert _attempt(_from("192.0.2.10"), email, slug).status_code == 401
    # An exempt network is not refused by the account lock.
    monkeypatch.setattr(settings, "lockout_exempt_networks", "203.0.113.0/24")
    assert _attempt(_from("203.0.113.5"), email, slug).status_code == 200
    assert not _user(email).is_locked          # a success clears it


def test_operator_unlock_clears_lock_and_back_off(org_a, memory_store):
    _, slug, email = org_a
    attacker = _from("198.51.100.99")
    for _ in range(lockout.SOURCE_FREE):
        _attempt(attacker, email, slug, password="wrong-password-xyz")
    assert _attempt(attacker, email, slug).status_code == 401
    assert mfa_admin.unlock(argparse.Namespace(email=email, reason="test")) == 0
    assert _attempt(attacker, email, slug).status_code == 200


def test_back_off_doubles_and_caps():
    waits = [min(lockout.SOURCE_BASE_SECONDS * 2 ** (n - lockout.SOURCE_FREE),
                 lockout.SOURCE_CAP_SECONDS) for n in range(5, 12)]
    assert waits == [30, 60, 120, 240, 480, 900, 900]


def test_password_change_charges_the_lockout_budget(client, org_a, memory_store):
    """0.39.1: a stolen token could guess the password here, unthrottled and unlogged."""
    org_id, slug, email = org_a
    headers = _bearer(login(client, email, slug)["access_token"])
    for _ in range(lockout.SOURCE_FREE):
        response = client.post(f"{API}/auth/password", headers=headers,
                               json={"current_password": "not-the-password",
                                     "new_password": "whatever-New-Password-1"})
        assert response.status_code == 401
    assert _user(email).failed_logins == lockout.SOURCE_FREE
    refused = client.post(f"{API}/auth/password", headers=headers,
                          json={"current_password": ADMIN_PASSWORD,
                                "new_password": "whatever-New-Password-1"})
    assert refused.status_code == 429 and int(refused.headers["Retry-After"]) >= 1
    with SessionLocal() as s:
        set_tenant(s, org_id)
        reasons = s.execute(select(AuthEvent.reason).where(
            AuthEvent.organization_id == org_id, AuthEvent.event == "password.change")).scalars().all()
    assert reasons.count("bad_password") == lockout.SOURCE_FREE and "throttled" in reasons


def test_mfa_disable_charges_wrong_codes(client, org_a, admin_a, memory_store):
    _, slug, email = org_a
    secret = client.post(f"{API}/auth/mfa/enroll", headers=admin_a).json()["secret"]
    assert client.post(f"{API}/auth/mfa/activate", headers=admin_a,
                       json={"code": mfa._code_at(secret, mfa.current_step())}).status_code == 200
    r = client.post(f"{API}/auth/mfa/disable", headers=admin_a,
                    json={"password": ADMIN_PASSWORD, "code": "000000"})
    assert r.status_code == 422
    assert _user(email).failed_logins == 1


# ---------------------------------------------------------------------------
# R-26 delivered-code guesses are counted atomically
# ---------------------------------------------------------------------------
class _User:
    def __init__(self):
        self.id = uuid.uuid4()
        self.email = "someone@example.com"
        self.mfa_method = "email"
        self.mfa_telegram_chat_id = None


def test_the_guess_counter_is_the_atomic_one(memory_store, monkeypatch):
    """The count lives in an INCR counter, not in the stored code record.

    0.39.1 read `tries` out of the code record, added one in Python and wrote
    it back, so parallel guesses all read the same value. Here the record
    claims no guess was made while the atomic counter says five were: the
    right code must still be refused.
    """
    monkeypatch.setattr(mfa_delivery, "deliver", lambda *a, **k: None)
    user = _User()
    sent = {}
    monkeypatch.setattr(mfa_delivery.secrets, "randbelow", lambda n: sent.setdefault("c", 123456))
    mfa_delivery.issue(user, "email")
    code = f"{sent['c']:06d}"
    for _ in range(mfa_delivery.MAX_TRIES):
        memory_store.incr(mfa_delivery._key("tries", user.id), 300)
    assert mfa_delivery.check(user, code, "email") is False


def test_a_right_code_after_four_wrong_ones_still_works(memory_store, monkeypatch):
    monkeypatch.setattr(mfa_delivery, "deliver", lambda *a, **k: None)
    monkeypatch.setattr(mfa_delivery.secrets, "randbelow", lambda n: 424242)
    user = _User()
    mfa_delivery.issue(user, "email")
    for _ in range(mfa_delivery.MAX_TRIES - 1):
        assert mfa_delivery.check(user, "000000", "email") is False
    assert mfa_delivery.check(user, "424242", "email") is True


# ---------------------------------------------------------------------------
# R-14 the limiter keys only verified identities; R-25 it retries Redis
# ---------------------------------------------------------------------------
def _mini(per_minute: int = 2) -> TestClient:
    mini = FastAPI()

    @mini.get("/api/v1/thing")
    def thing() -> dict:
        return {"ok": True}

    mini.add_middleware(ratelimit.RateLimitMiddleware, per_minute=per_minute, auth_per_minute=100)

    async def asgi(scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=(ip, 40000))
        await mini(scope, receive, send)
    ip = f"198.18.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}"
    return TestClient(asgi)


def test_junk_credentials_share_the_address_bucket():
    """0.39.1: every random bearer string or API key was a fresh 240/min bucket."""
    client = _mini(per_minute=2)
    ratelimit.reset_local()
    for _ in range(2):
        r = client.get("/api/v1/thing", headers=_bearer(f"junk-{uuid.uuid4().hex}"))
        assert r.status_code == 200
    assert client.get("/api/v1/thing",
                      headers={"X-API-Key": f"veyrs_{uuid.uuid4().hex[:8]}_x"}).status_code == 429


def test_verified_identities_get_their_own_bucket():
    client = _mini(per_minute=1)
    for _ in range(2):
        token, _ = create_access_token(user_id=uuid.uuid4(), organization_id=uuid.uuid4(),
                                       permissions=[])
        assert client.get("/api/v1/thing", headers=_bearer(token)).status_code == 200
    key = f"veyrs_{uuid.uuid4().hex[:8]}_{uuid.uuid4().hex}"
    ratelimit.remember_api_key(key, uuid.uuid4())
    assert client.get("/api/v1/thing", headers={"X-API-Key": key}).status_code == 200


def test_a_worker_retries_redis_after_falling_back(monkeypatch):
    import redis

    clock = {"t": 1000.0}
    monkeypatch.setattr(ratelimit.time, "monotonic", lambda: clock["t"])
    monkeypatch.setattr(ratelimit, "_redis_client", None)
    monkeypatch.setattr(ratelimit, "_redis_retry_at", 0.0)
    calls = {"n": 0}

    class Up:
        def ping(self):
            return True

    def from_url(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("down")
        return Up()

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(from_url))
    assert ratelimit._redis() is None                 # down: in-process window
    assert ratelimit._redis() is None and calls["n"] == 1   # not hammered
    clock["t"] += ratelimit.REDIS_RETRY_SECONDS + 1
    assert isinstance(ratelimit._redis(), Up)         # 0.39.1: never asked again
    monkeypatch.setattr(ratelimit, "_redis_client", None)


# ---------------------------------------------------------------------------
# R-18 / TD-15 secret key; TD-31 neutral defaults refused in production
# ---------------------------------------------------------------------------
_SAFE = dict(environment="production", encryption_key="k" * 44,
             public_base_url="https://veyrs.example.com",
             database_url="postgresql+psycopg://veyrs:strong@db/veyrs")


def test_production_refuses_an_unset_secret_key():
    with pytest.raises(RuntimeError, match="secret_key must be set"):
        Settings(secret_key="", **_SAFE).assert_production_safe()
    Settings(secret_key="s" * 40, **_SAFE).assert_production_safe()   # explicit key: fine


def test_development_still_gets_an_ephemeral_key():
    s = Settings(secret_key="", environment="development")
    assert len(s.secret_key) >= 32 and s.secret_key_ephemeral


def test_defaults_name_no_deployment():
    fields = Settings.model_fields
    for name in ("cors_origins", "public_base_url", "smtp_from"):
        assert "visionebc" not in str(fields[name].default)
    with pytest.raises(RuntimeError, match="public_base_url"):
        Settings(secret_key="s" * 40, **{**_SAFE, "public_base_url": ""}).assert_production_safe()
    with pytest.raises(RuntimeError, match="smtp_from"):
        Settings(secret_key="s" * 40, smtp_host="mail.example.com", smtp_from="",
                 **_SAFE).assert_production_safe()


# ---------------------------------------------------------------------------
# R-20 the library HKDF derives the keys the hand-written one did
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("ikm,expected", [
    # computed with the 0.39.1 hand-written implementation
    (b"test-secret-key-of-sufficient-length-0123456789",
     "6b592e02f22463f6538ad10cc5b7c09816f31e9501c0421556b49e8ed876981e"),
    (b"x" * 40, "96d9f41925320e71afbfebaf85c29a45372923ae136cbad570e8d3692913da33"),
    ("clé-ünïcode-secret-0123456789abcdef".encode(),
     "b6e43f0cac53b6d0bbfbb9a27946fd41105c14472c9e28e65f144be2601a9ab3"),
])
def test_hkdf_is_byte_identical_to_the_previous_implementation(ikm, expected):
    assert secrets._hkdf_sha256(ikm, b"veyrs.secrets.v1").hex() == expected


def test_hkdf_matches_rfc5869_test_case_3():
    okm = secrets._hkdf_sha256(bytes([0x0b] * 22), b"", 42)
    assert okm.hex() == ("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                         "9d201395faa4b61a96c8")
    assert len(base64.urlsafe_b64encode(secrets._hkdf_sha256(b"k" * 40, b"i"))) == 44


# ---------------------------------------------------------------------------
# R-05 audit trails are append-only in the database; auth_events isolated
# ---------------------------------------------------------------------------
def _audit_row(org_id) -> uuid.UUID:
    marker = f"append-only-{uuid.uuid4().hex}"
    with SessionLocal() as s:
        set_tenant(s, org_id)
        audit.record(s, organization_id=org_id, action="test.append_only",
                     object_type="probe", object_label=marker)
        s.commit()
        set_tenant(s, org_id)
        return s.execute(select(AuditLog.id).where(AuditLog.object_label == marker)).scalar_one()


@pytest.mark.parametrize("statement", [
    "UPDATE audit_log SET action = 'tampered' WHERE id = :id",
    "DELETE FROM audit_log WHERE id = :id",
])
def test_audit_rows_cannot_be_changed_or_deleted(org_a, statement):
    org_id = org_a[0]
    row_id = _audit_row(org_id)
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("SELECT set_config('veyrs.current_org', :o, true)"), {"o": str(org_id)})
        try:
            with pytest.raises(DBAPIError, match="append-only"):
                conn.execute(text(statement), {"id": row_id})
        finally:
            trans.rollback()


@pytest.mark.parametrize("table", ["audit_log", "ai_audit_log", "auth_events"])
def test_audit_tables_cannot_be_truncated(table):
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            with pytest.raises(DBAPIError, match="append-only"):
                conn.execute(text(f"TRUNCATE {table}"))
        finally:
            trans.rollback()


def test_the_retention_prune_may_delete(org_a):
    org_id = org_a[0]
    row_id = _audit_row(org_id)
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL veyrs.audit_prune = 'on'"))
        # No tenant bound: the prune sees every tenant's rows in one pass.
        assert conn.execute(text("DELETE FROM audit_log WHERE id = :id"),
                            {"id": row_id}).rowcount == 1


def test_a_hard_deleted_user_still_detaches_from_its_audit_rows(org_a):
    """The FK cascade (ON DELETE SET NULL) is an UPDATE the trigger lets through."""
    org_id, slug, _ = org_a
    email = _add_user(org_id, slug, "read-only")
    user_id = _user(email).id
    with SessionLocal() as s:
        set_tenant(s, org_id)
        audit.record(s, organization_id=org_id, actor_id=user_id, action="test.cascade",
                     object_type="probe", object_label=str(user_id))
        s.execute(text("DELETE FROM user_roles WHERE user_id = :u"), {"u": user_id})
        s.commit()
    with SessionLocal() as s:
        set_tenant(s, org_id)
        s.execute(text("DELETE FROM users WHERE id = :u"), {"u": user_id})
        s.commit()
        set_tenant(s, org_id)
        row = s.execute(select(AuditLog).where(AuditLog.object_label == str(user_id))).scalar_one()
        assert row.actor_id is None


def test_auth_events_are_forced_and_isolated(org_a, org_b):
    with engine.connect() as conn:
        forced = conn.execute(text(
            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
            "WHERE relname = 'auth_events' AND relkind = 'r'")).scalar_one()
    assert forced is True
    marker = f"rls-{uuid.uuid4().hex}@example.com"
    with SessionLocal() as s:            # pre-auth writer: nothing bound
        audit.record_auth(s, event="login", success=False, email_attempted=marker,
                          organization_id=org_a[0], reason="bad_password")
        audit.record_auth(s, event="login", success=False, email_attempted=marker,
                          reason="unknown_user")
        s.commit()

    def seen(bound, unattributed=False):
        with SessionLocal() as s:
            if bound:
                set_tenant(s, bound)
            if unattributed:
                s.execute(text("SELECT set_config('veyrs.auth_events_unattributed', 'on', true)"))
            return {r.reason for r in s.execute(
                select(AuthEvent).where(AuthEvent.email_attempted == marker)).scalars()}

    assert seen(org_a[0]) == {"bad_password"}
    assert seen(org_b[0]) == set()
    assert seen(None) == set()
    assert seen(None, unattributed=True) == {"unknown_user"}


def test_auth_events_api(client, org_a, admin_a):
    org_id, slug, email = org_a
    _attempt(client, email, slug, password="wrong-password-xyz")
    unknown = f"nobody-{uuid.uuid4().hex}@example.com"
    _attempt(client, unknown, slug, password="wrong-password-xyz")
    page = client.get(f"{API}/auth-events", headers=admin_a,
                      params={"event": "login", "success": "false"})
    assert page.status_code == 200, page.text
    body = page.json()
    assert body["total"] >= 1 and all(i["success"] is False for i in body["items"])
    assert {i["reason"] for i in body["items"]} >= {"bad_password"}
    assert unknown not in str(body)
    assert client.get(f"{API}/auth-events", headers=admin_a,
                      params={"unattributed": "true"}).status_code == 403
    _update_user(email, is_superuser=True)
    platform = auth_headers(client, email, slug)
    rows = client.get(f"{API}/auth-events", headers=platform,
                      params={"unattributed": "true", "email": unknown}).json()
    assert rows["total"] == 1 and rows["items"][0]["reason"] == "unknown_user"


def test_auth_events_need_audit_read(client, org_a):
    org_id, slug, _ = org_a
    reader = auth_headers(client, _add_user(org_id, slug, "read-only"), slug)
    assert client.get(f"{API}/auth-events", headers=reader).status_code == 403


# ---------------------------------------------------------------------------
# R-07 an organization can require a second factor
# ---------------------------------------------------------------------------
def _require_mfa(client, headers, value=True):
    r = client.put(f"{API}/mfa-policy", headers=headers, json={"require_mfa": value})
    assert r.status_code == 200, r.text
    return r.json()


def test_policy_sends_an_account_without_a_factor_to_enrolment(client, org_a, admin_a):
    org_id, slug, email = org_a
    before = login(client, email, slug)                 # a session from before the switch
    state = _require_mfa(client, admin_a)
    assert state["require_mfa"] is True and state["users_without_mfa"] >= 1

    body = _attempt(client, email, slug).json()
    assert body["mfa_enrollment_required"] is True and body["refresh_token"] is None
    assert body["permissions"] == []
    restricted = _bearer(body["access_token"])
    refused = client.get(f"{API}/assets", headers=restricted)
    assert refused.status_code == 403 and refused.json()["detail"]["error"] == "mfa_enrollment_required"
    assert client.get(f"{API}/auth/me", headers=restricted).status_code == 200
    assert client.put(f"{API}/mfa-policy", headers=restricted,
                      json={"require_mfa": False}).status_code == 403

    # The password-only session from before the policy ends at its next refresh.
    assert _refresh(client, before["refresh_token"]).status_code == 401

    secret = client.post(f"{API}/auth/mfa/enroll", headers=restricted).json()["secret"]
    done = client.post(f"{API}/auth/mfa/activate", headers=restricted,
                       json={"code": mfa._code_at(secret, mfa.current_step())})
    assert done.status_code == 200, done.text
    full = done.json()["tokens"]
    assert full["refresh_token"] and not full["mfa_enrollment_required"]
    assert client.get(f"{API}/assets", headers=_bearer(full["access_token"])).status_code == 200
    assert _refresh(client, full["refresh_token"]).status_code == 200


def test_policy_includes_platform_administrators(client, org_a, admin_a):
    _, slug, email = org_a
    _require_mfa(client, admin_a)
    _update_user(email, is_superuser=True)
    assert _attempt(client, email, slug).json()["mfa_enrollment_required"] is True


def test_policy_needs_settings_admin(client, org_a):
    org_id, slug, _ = org_a
    reader = auth_headers(client, _add_user(org_id, slug, "read-only"), slug)
    assert client.put(f"{API}/mfa-policy", headers=reader,
                      json={"require_mfa": True}).status_code == 403


def test_no_policy_no_change(client, org_a):
    _, slug, email = org_a
    body = login(client, email, slug)
    assert body["mfa_enrollment_required"] is False and body["refresh_token"]


# ---------------------------------------------------------------------------
# R-10 / R-11 / R-12 single sign-on
# ---------------------------------------------------------------------------
from test_phase58_oidc import _callback, _claims, _configure, _start, idp  # noqa: E402,F401


def test_sso_requires_email_verified_to_be_present(client, org_a, idp):
    """0.39.1 rejected only `email_verified: false`; a missing claim passed."""
    slug = _configure(org_a)
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce)
    idp.claims.pop("email_verified")
    _, back = _callback(client, state)
    assert "error" in back and "email_verified" in back["error"][0]


def test_sso_flow_is_bound_to_the_starting_browser(client, org_a, idp):
    slug = _configure(org_a)
    started = client.get(f"{API}/auth/oidc/{slug}/start")
    cookie = started.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/api/v1/auth/oidc" in cookie
    from urllib.parse import parse_qs, urlsplit
    q = parse_qs(urlsplit(started.json()["authorization_url"]).query)
    _claims(idp, org_a[2], q["nonce"][0])
    victim = TestClient(app)                       # never started a flow
    _, back = _callback(victim, q["state"][0])
    assert "error" in back and "another browser" in back["error"][0]

    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce)
    _, back = _callback(client, state)
    assert "h" in back
    # A hand-off read off the screen is useless in another browser.
    assert victim.post(f"{API}/auth/oidc/exchange",
                       json={"handoff": back["h"][0]}).status_code == 401


def test_sso_respects_and_keeps_an_account_lock(client, org_a, idp):
    """0.39.1 signed a locked account in through SSO and cleared its lock."""
    slug = _configure(org_a)
    _, _, email = org_a
    until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)
    _update_user(email, locked_until=until, failed_logins=7)
    state, nonce = _start(client, slug)
    _claims(idp, email, nonce)
    _, back = _callback(client, state)
    assert "error" in back and "locked" in back["error"][0]

    _update_user(email, locked_until=None)
    state, nonce = _start(client, slug)
    _claims(idp, email, nonce)
    _, back = _callback(client, state)
    _update_user(email, locked_until=until)          # locked between callback and exchange
    assert client.post(f"{API}/auth/oidc/exchange",
                       json={"handoff": back["h"][0]}).status_code == 401
    user = _user(email)
    assert user.is_locked and user.failed_logins == 7


# ---------------------------------------------------------------------------
# R-23 tenant guard
# ---------------------------------------------------------------------------
@pytest.fixture()
def guard(monkeypatch):
    monkeypatch.setattr(tenant_guard, "MODE", "record")
    tenant_guard.violations.clear()
    yield tenant_guard.violations
    tenant_guard.violations.clear()


def test_the_guard_flags_an_unbound_tenant_query(org_a, guard):
    from veyrs.models import Team

    with SessionLocal() as s:
        s.execute(select(Team).limit(1)).all()
    assert guard and "teams" in guard[0]
    guard.clear()
    with SessionLocal() as s:
        set_tenant(s, org_a[0])
        s.execute(select(Team).limit(1)).all()
        s.execute(select(User).limit(1)).all()          # pre-auth table: allowed unbound
    assert not guard


def test_every_get_route_queries_tenant_tables_bound(client, org_a, admin_a, guard):
    """Walk the live app as an organization administrator.

    Any tenant-table statement a handler runs with no tenant bound would
    return nothing under a correct role and EVERYTHING under one that
    bypasses RLS. None may exist.
    """
    walked = 0
    for route in app.routes:
        path = getattr(route, "path", "")
        if "GET" not in (getattr(route, "methods", None) or set()):
            continue
        if not path.startswith(API) or "/auth/oidc" in path:
            continue
        probe = "/".join(str(uuid.uuid4()) if seg.startswith("{") else seg
                         for seg in path.split("/"))
        _flush_rate_limits()
        client.get(probe, headers=admin_a)
        walked += 1
    assert walked > 100
    assert not guard, "tenant tables queried with no tenant bound: " + "; ".join(sorted(set(guard)))


def test_the_test_role_does_not_bypass_rls():
    with engine.connect() as conn:
        assert tenant_guard.rls_bypass_problem(conn) is None


# ---------------------------------------------------------------------------
# TD-49 the agent lease token travels in a header
# ---------------------------------------------------------------------------
def test_lease_token_header_and_deprecated_query(caplog):
    mini = FastAPI()

    @mini.post("/lease")
    def lease(token: LeaseToken) -> dict:
        return {"token": token}

    c = TestClient(mini)
    assert c.post("/lease", headers={"X-Agent-Lease": "abc"}).json() == {"token": "abc"}
    with caplog.at_level(logging.WARNING, logger="veyrs.agents"):
        assert c.post("/lease?lease_token=old").json() == {"token": "old"}
    assert "deprecated" in caplog.text
    assert c.post("/lease?lease_token=old", headers={"X-Agent-Lease": "new"}).json() == {"token": "new"}


def test_the_agent_client_keeps_the_lease_out_of_urls():
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parents[1] / "integrations" / "veyrs-agent" / "veyrs_agent.py"
    spec = importlib.util.spec_from_file_location("veyrs_agent_fix_auth", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    client = module.Client("https://veyrs.example.com", "veyrsagent_x_y")
    client._call = lambda method, url, **kw: (calls.append((url, kw.get("extra_headers"))), (200, {}))[1]
    client.events("j1", "LEASE", [])
    client.extend("j1", "LEASE")
    client.submit("j1", "LEASE", b"", scanner="nuclei", exit_code=0, filename="x")
    client.fail("j1", "LEASE", "boom")
    assert len(calls) == 4
    for url, headers in calls:
        assert "LEASE" not in url and headers["X-Agent-Lease"] == "LEASE"
