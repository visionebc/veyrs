"""0.42.2 -- platform administration is a role, not a host-only flag.

Software update, Installed software, Network access, Trust store and Web
certificate answered 403 to every console account of an installation that had
no `is_superuser` account, and nothing in the console could fix it. Now the
organization VEYRS was installed for (`security.platform.home_organization_id`)
grants them through `platform:admin`: its Organization Administrators (wildcard)
and anyone given the built-in Platform Administrator role. Other tenants of a
multi-tenant installation, API keys and enrolment-only sessions still get 403.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tests.conftest import ADMIN_PASSWORD, auth_headers
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Organization, Role, User, UserRole
from veyrs.security import permissions as perms
from veyrs.security import platform
from veyrs.security.auth import SCOPE_MFA_ENROLL, hash_password

PAGES = ("/api/v1/admin/system/network", "/api/v1/admin/trust-store")


@pytest.fixture(autouse=True)
def _fresh():
    platform.reset_cache()
    yield
    platform.reset_cache()


def _home(monkeypatch, org_id) -> None:
    monkeypatch.setattr(platform, "home_organization_id", lambda: org_id)


def _user_with_role(org_id: uuid.UUID, slug: str, role_slug: str) -> str:
    email = f"{role_slug}-{uuid.uuid4().hex[:6]}@{slug}.test"
    with SessionLocal() as s:
        set_tenant(s, org_id)
        user = User(organization_id=org_id, email=email, full_name="Platform Person",
                    password_hash=hash_password(ADMIN_PASSWORD))
        s.add(user)
        s.flush()
        role = s.execute(select(Role).where(Role.slug == role_slug,
                                            Role.organization_id.is_(None))).scalar_one()
        s.add(UserRole(organization_id=org_id, user_id=user.id, role_id=role.id))
        s.commit()
    return email


def test_the_builtin_role_exists_and_carries_only_platform_admin():
    assert perms.BUILTIN_ROLES["platform-admin"]["permissions"] == ["platform:admin"]
    assert "platform:admin" in perms.ALL_PERMISSIONS
    assert "platform:admin" in perms.expand(["*:*"])        # org-admin carries it
    with SessionLocal() as s:
        role = s.execute(select(Role).where(Role.slug == "platform-admin",
                                            Role.organization_id.is_(None))).scalar_one()
        assert role.permissions == ["platform:admin"] and role.is_builtin


def test_the_organization_administrator_of_the_home_organization_opens_the_pages(
        client, org_a, monkeypatch):
    org_id, slug, email = org_a
    headers = auth_headers(client, email, slug)
    for page in PAGES:                                     # not home yet
        r = client.get(page, headers=headers)
        assert r.status_code == 403 and "veyrs platform-admin" in r.json()["detail"]
    _home(monkeypatch, org_id)
    for page in PAGES:
        assert client.get(page, headers=headers).status_code == 200, page


def test_another_tenant_administrator_never_does(client, org_a, org_b, monkeypatch):
    _home(monkeypatch, org_a[0])
    _, slug_b, email_b = org_b
    headers = auth_headers(client, email_b, slug_b)
    for page in PAGES:
        assert client.get(page, headers=headers).status_code == 403, page
    r = client.get("/api/v1/auth-events?unattributed=true", headers=headers)
    assert r.status_code == 403


def test_the_platform_administrator_role_alone_opens_the_pages_and_nothing_else(
        client, org_a, org_b, monkeypatch):
    org_id, slug, _ = org_a
    email = _user_with_role(org_id, slug, "platform-admin")
    _home(monkeypatch, org_id)
    headers = auth_headers(client, email, slug)
    for page in PAGES:
        assert client.get(page, headers=headers).status_code == 200, page
    # It is not an organization administrator: tenant administration stays shut.
    assert client.get("/api/v1/users", headers=headers).status_code == 403
    # The same role in a tenant that is not home is worth nothing.
    org_b_id, slug_b, _ = org_b
    other = _user_with_role(org_b_id, slug_b, "platform-admin")
    headers_b = auth_headers(client, other, slug_b)
    for page in PAGES:
        assert client.get(page, headers=headers_b).status_code == 403, page


def test_an_administrator_can_add_a_platform_administrator_from_the_console(
        client, org_a, monkeypatch):
    org_id, slug, email = org_a
    _home(monkeypatch, org_id)
    admin = auth_headers(client, email, slug)
    new = f"ops-{uuid.uuid4().hex[:6]}@{slug}.test"
    r = client.post("/api/v1/users", headers=admin, json={
        "email": new, "full_name": "Ops Person", "password": ADMIN_PASSWORD,
        "role_slugs": ["platform-admin"]})
    assert r.status_code == 201, r.text
    headers = auth_headers(client, new, slug)        # active at once: no invitation
    assert client.get(PAGES[0], headers=headers).status_code == 200


def test_unattributed_auth_events_follow_the_same_rule(client, org_a, monkeypatch):
    org_id, slug, email = org_a
    headers = auth_headers(client, email, slug)
    url = "/api/v1/auth-events?unattributed=true"
    assert client.get(url, headers=headers).status_code == 403
    _home(monkeypatch, org_id)
    assert client.get(url, headers=headers).status_code == 200


def _principal(**kw):
    base = dict(kind="user", restriction=None, is_superuser=False,
                permissions=frozenset({"platform:admin"}), organization_id=uuid.uuid4())
    base.update(kw)
    return SimpleNamespace(**base)


def test_api_keys_and_enrolment_sessions_are_never_platform_administrators(monkeypatch):
    p = _principal()
    _home(monkeypatch, p.organization_id)
    assert platform.is_platform_admin(p)
    assert not platform.is_platform_admin(_principal(kind="apikey",
                                                     organization_id=p.organization_id))
    assert not platform.is_platform_admin(_principal(restriction=SCOPE_MFA_ENROLL,
                                                     organization_id=p.organization_id))
    assert not platform.is_platform_admin(_principal(kind="apikey", is_superuser=True))
    assert not platform.is_platform_admin(None)
    # The host-granted flag still works from any organization.
    assert platform.is_platform_admin(_principal(is_superuser=True, permissions=frozenset()))


def test_home_is_the_oldest_active_organization(org_a):
    with SessionLocal() as s:
        oldest = s.execute(
            select(Organization.id)
            .where(Organization.is_active.is_(True), Organization.deleted_at.is_(None))
            .order_by(Organization.created_at, Organization.id).limit(1)).scalar_one()
    assert platform.home_organization_id() == oldest
    assert oldest != org_a[0]          # a fixture tenant is never home by accident
