"""The audit trails are tenant-isolated, and nothing that writes them breaks.

0.32.3 made `audit_log` and `ai_audit_log` strictly isolated on a fresh
install (production already was). Three things have to hold together for that
to be safe, and each has a test here:

  * the policy is actually there, forced, and bites across tenants;
  * a write the policy rejects is dropped WITHOUT poisoning the session, so the
    request it was only recording still completes;
  * the pre-auth writers -- first login of a directory-provisioned user, and
    role sync on a directory login -- bind their tenant first. Before 0.32.3
    they wrote `user_roles`/`audit_log` unbound, which fails WITH CHECK.

Runs against the real test database, as the application role: a superuser or
BYPASSRLS role skips every policy, and each assertion below would pass for the
wrong reason. The first test refuses that.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from veyrs.api.v1 import auth as auth_api
from veyrs.cli import RLS_TABLES_STRICT_NULLABLE
from veyrs.db import SessionLocal, engine, set_tenant
from veyrs.models import User, UserRole
from veyrs.models.audit import AiAuditLog, AuditLog
from veyrs.services import audit, ldap_auth


def _ai_row(org_id: uuid.UUID, marker: str) -> dict:
    return dict(organization_id=org_id, capability="explain_cve", provider="test",
                model=marker, external=False, data_classification="internal",
                decision="allowed")


def test_the_suite_is_not_running_as_a_role_that_bypasses_rls():
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )).one()
    assert not row.rolsuper and not row.rolbypassrls, (
        "tests connect as a superuser/BYPASSRLS role: every RLS assertion in "
        "this file would pass vacuously"
    )


@pytest.mark.parametrize("table", sorted(RLS_TABLES_STRICT_NULLABLE))
def test_audit_tables_are_forced_with_the_tenant_policy(table):
    with engine.connect() as conn:
        forced = conn.execute(text(
            "SELECT relrowsecurity AND relforcerowsecurity FROM pg_class "
            "WHERE relname = :t AND relkind = 'r'"), {"t": table}).scalar_one()
        policy = conn.execute(text(
            "SELECT count(*) FROM pg_policies "
            "WHERE tablename = :t AND policyname = 'veyrs_tenant_isolation'"),
            {"t": table}).scalar_one()
    assert forced is True
    assert policy == 1


def test_audit_rows_are_invisible_to_another_tenant(org_a, org_b):
    a_id, b_id = org_a[0], org_b[0]
    marker = f"rls-{uuid.uuid4().hex}"
    with SessionLocal() as s:
        set_tenant(s, a_id)
        audit.record(s, organization_id=a_id, action="test.rls", object_type="probe",
                     object_label=marker)
        audit.record_ai(s, **_ai_row(a_id, marker))
        s.commit()

    def count(bound_to):
        with SessionLocal() as s:
            if bound_to is not None:
                set_tenant(s, bound_to)
            return (
                s.execute(select(AuditLog).where(AuditLog.object_label == marker)).all(),
                s.execute(select(AiAuditLog).where(AiAuditLog.model == marker)).all(),
            )

    own_log, own_ai = count(a_id)
    other_log, other_ai = count(b_id)
    none_log, none_ai = count(None)
    # Paired with the owner's read: zero rows elsewhere only means something
    # if the rows are provably there.
    assert (len(own_log), len(own_ai)) == (1, 1)
    assert (len(other_log), len(other_ai)) == (0, 0)
    assert (len(none_log), len(none_ai)) == (0, 0)


def test_a_rejected_audit_write_does_not_break_the_request(org_a, org_b):
    a_id, b_id = org_a[0], org_b[0]
    marker = f"cross-{uuid.uuid4().hex}"
    with SessionLocal() as s:
        set_tenant(s, a_id)
        # Both fail WITH CHECK: a NULL tenant, and another tenant's id.
        audit.record(s, organization_id=None, action="test.null", object_type="probe",
                     object_label=marker)
        audit.record(s, organization_id=b_id, action="test.cross", object_type="probe",
                     object_label=marker)
        audit.record_ai(s, **_ai_row(b_id, marker))
        # The session is still usable: the next query and the commit succeed.
        assert s.execute(text("SELECT 1")).scalar_one() == 1
        audit.record(s, organization_id=a_id, action="test.after", object_type="probe",
                     object_label=marker)
        s.commit()

    with SessionLocal() as s:
        set_tenant(s, a_id)
        actions = sorted(s.execute(
            select(AuditLog.action).where(AuditLog.object_label == marker)).scalars())
    assert actions == ["test.after"]


def _directory(monkeypatch, org_id, identity, *, roles):
    cfg = {"jit_provisioning": True, "sync_roles_on_login": True}
    monkeypatch.setattr(auth_api, "_jit_target_organization", lambda s, slug: org_id)
    monkeypatch.setattr(ldap_auth, "config", lambda s, oid: dict(cfg))
    monkeypatch.setattr(ldap_auth, "is_enabled", lambda s, oid: True)
    monkeypatch.setattr(ldap_auth, "authenticate", lambda s, oid, ident, pw: identity)
    monkeypatch.setattr(ldap_auth, "roles_for", lambda c, ident: list(roles))


def test_directory_first_login_writes_its_grants_and_audit_row(monkeypatch, org_a):
    org_id = org_a[0]
    name = f"jit-{uuid.uuid4().hex[:8]}"
    identity = ldap_auth.LdapIdentity(dn=f"cn={name},dc=test", username=name,
                                      email=f"{name}@example.test", full_name=name)
    _directory(monkeypatch, org_id, identity, roles=["org-admin"])

    with SessionLocal() as s:                       # unbound: this is pre-auth
        user = auth_api._provision_from_directory(s, name, "pw", None)
        assert user is not None
        user_id = user.id
        s.commit()

    with SessionLocal() as s:
        set_tenant(s, org_id)
        grants = s.execute(select(UserRole).where(UserRole.user_id == user_id)).all()
        trail = s.execute(select(AuditLog).where(
            AuditLog.action == "user.provisioned_from_directory",
            AuditLog.object_id == str(user_id))).scalars().all()
    assert len(grants) == 1
    assert len(trail) == 1 and trail[0].organization_id == org_id


def test_directory_role_sync_on_login_is_idempotent(monkeypatch, org_a):
    """Unbound, the existing grant reads back as zero rows and gets re-inserted
    -- a unique-constraint 500 on the second directory login."""
    org_id = org_a[0]
    name = f"sync-{uuid.uuid4().hex[:8]}"
    identity = ldap_auth.LdapIdentity(dn=f"cn={name},dc=test", username=name,
                                      email=f"{name}@example.test")
    _directory(monkeypatch, org_id, identity, roles=["org-admin"])
    with SessionLocal() as s:
        set_tenant(s, org_id)
        u = User(organization_id=org_id, email=identity.email, username=name,
                 full_name=name, password_hash=None, ldap_dn=identity.dn)
        s.add(u)
        s.commit()
        user_id = u.id

    for _ in range(2):
        with SessionLocal() as s:                   # unbound, as in /login
            user = s.get(User, user_id)
            auth_api._apply_identity(s, user, identity)
            s.commit()

    with SessionLocal() as s:
        set_tenant(s, org_id)
        grants = s.execute(select(UserRole).where(UserRole.user_id == user_id)).all()
    assert len(grants) == 1
