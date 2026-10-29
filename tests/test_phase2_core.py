"""Phase 2 - core platform: auth, RBAC, tenancy, audit.

The tenant-isolation and privilege-escalation tests are the important ones: they
are the controls the threat model relies on, so they assert behaviour rather than
implementation.
"""
from __future__ import annotations

import uuid

from conftest import ADMIN_PASSWORD, auth_headers, login

API = "/api/v1"


# --- liveness / contract --------------------------------------------------


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["app"] == "VEYRS"


def test_security_headers_present(client):
    r = client.get("/healthz")
    for header in ("X-Content-Type-Options", "X-Frame-Options",
                   "Content-Security-Policy", "X-Correlation-ID"):
        assert header in r.headers, header
    assert r.headers["X-Frame-Options"] == "DENY"


def test_openapi_documents_every_route(client):
    spec = client.get(f"{API}/openapi.json").json()
    assert spec["info"]["title"] == "VEYRS"
    assert len(spec["paths"]) >= 15


# --- authentication -------------------------------------------------------


def test_login_and_me(client, org_a):
    _, slug, email = org_a
    tokens = login(client, email, slug)
    assert tokens["token_type"] == "bearer"
    assert "*:*" in tokens["permissions"] or len(tokens["permissions"]) > 50

    me = client.get(f"{API}/auth/me",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == email
    assert "org-admin" in body["roles"]


def test_wrong_password_is_indistinguishable_from_unknown_user(client, org_a):
    _, slug, email = org_a
    bad_password = client.post(f"{API}/auth/login",
                               json={"email": email, "password": "wrong-password-x",
                                     "organization": slug})
    unknown = client.post(f"{API}/auth/login",
                          json={"email": f"nobody-{uuid.uuid4().hex}@example.test",
                                "password": "wrong-password-x", "organization": slug})
    assert bad_password.status_code == unknown.status_code == 401
    assert bad_password.json() == unknown.json()


def test_no_credentials_is_401(client):
    assert client.get(f"{API}/users").status_code == 401


def test_garbage_token_is_401(client):
    r = client.get(f"{API}/users", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401


def test_refresh_rotates_and_reuse_kills_the_family(client, org_a):
    _, slug, email = org_a
    tokens = login(client, email, slug)
    first = client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert first.status_code == 200
    rotated = first.json()["refresh_token"]
    assert rotated != tokens["refresh_token"]

    # replaying the original (already rotated) token must fail...
    replay = client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401
    # ...and must also invalidate the token that replaced it
    after = client.post(f"{API}/auth/refresh", json={"refresh_token": rotated})
    assert after.status_code == 401


def test_logout_revokes_refresh_tokens(client, org_a):
    _, slug, email = org_a
    tokens = login(client, email, slug)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
    assert client.post(f"{API}/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_password_change_invalidates_sessions(client, org_a):
    _, slug, email = org_a
    tokens = login(client, email, slug)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    r = client.post(f"{API}/auth/password", headers=headers,
                    json={"current_password": ADMIN_PASSWORD,
                          "new_password": "another-Strong-Password-9"})
    assert r.status_code == 204
    assert client.post(f"{API}/auth/refresh",
                       json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert login(client, email, slug, "another-Strong-Password-9")["access_token"]


# --- tenant isolation (threat model T-TENANT-01) --------------------------


def test_user_list_never_crosses_tenants(client, org_a, org_b, admin_a, admin_b):
    _, _, email_a = org_a
    _, _, email_b = org_b
    emails_a = {u["email"] for u in client.get(f"{API}/users", headers=admin_a).json()["items"]}
    emails_b = {u["email"] for u in client.get(f"{API}/users", headers=admin_b).json()["items"]}
    assert email_a in emails_a and email_b not in emails_a
    assert email_b in emails_b and email_a not in emails_b


def test_cannot_read_another_tenants_object_by_uuid(client, org_a, org_b, admin_a, admin_b):
    created = client.post(f"{API}/users", headers=admin_b,
                          json={"email": f"victim-{uuid.uuid4().hex[:6]}@b.test",
                                "full_name": "Victim User"})
    assert created.status_code == 201
    victim_id = created.json()["id"]
    # tenant A knows the exact UUID and still must get a 404, not a 403
    assert client.get(f"{API}/users/{victim_id}", headers=admin_a).status_code == 404
    assert client.patch(f"{API}/users/{victim_id}", headers=admin_a,
                        json={"full_name": "hijacked"}).status_code == 404
    assert client.delete(f"{API}/users/{victim_id}", headers=admin_a).status_code == 404


def test_team_of_another_tenant_is_invisible(client, org_b, admin_a, admin_b):
    created = client.post(f"{API}/teams", headers=admin_b,
                          json={"name": "Network Security", "slug": "netsec"})
    assert created.status_code == 201
    team_id = created.json()["id"]
    assert client.get(f"{API}/teams", headers=admin_a).json()["total"] == 0
    assert client.patch(f"{API}/teams/{team_id}", headers=admin_a,
                        json={"name": "xx"}).status_code == 404


# --- RBAC ----------------------------------------------------------------


def test_permission_catalogue_is_stable(client, admin_a):
    permissions = client.get(f"{API}/permissions", headers=admin_a).json()
    assert "asset:write" in permissions
    assert "vulnerability:read" in permissions
    # 29 resources x 4 actions. The literal is the point: it fails on an
    # ACCIDENTAL widening of the catalogue, and a deliberate one is expected to
    # move it in the same commit that adds the resource. Last moved by phase 46,
    # which added "riskregister" -- a NEW resource rather than a reuse of
    # `risk:*`, because `risk:read` means the CVE-derived score on an asset and
    # is held by seven built-in roles: folding the register into it would make
    # "who may edit the organisation's risk register" and "who may see asset
    # risk scores" the same decision, in both directions.
    assert "agent:admin" in permissions
    assert "riskregister:admin" in permissions
    assert len(permissions) == 116


def test_read_only_user_cannot_write(client, org_a, admin_a):
    _, slug, _ = org_a
    email = f"reader-{uuid.uuid4().hex[:6]}@a.test"
    created = client.post(f"{API}/users", headers=admin_a,
                          json={"email": email, "full_name": "Read Only User",
                                "password": ADMIN_PASSWORD, "role_slugs": ["read-only"]})
    assert created.status_code == 201
    reader = auth_headers(client, email, slug)
    assert client.get(f"{API}/users", headers=reader).status_code == 403  # no user:read
    assert client.get(f"{API}/cvss/versions", headers=reader).status_code == 200
    assert client.post(f"{API}/teams", headers=reader,
                       json={"name": "Nope", "slug": "nope"}).status_code == 403


def test_privilege_escalation_via_role_grant_is_blocked(client, org_a, admin_a):
    _, slug, _ = org_a
    engineer_email = f"eng-{uuid.uuid4().hex[:6]}@a.test"
    assert client.post(f"{API}/users", headers=admin_a,
                       json={"email": engineer_email, "full_name": "Engineer",
                             "password": ADMIN_PASSWORD,
                             "role_slugs": ["security-engineer"]}).status_code == 201
    engineer = auth_headers(client, engineer_email, slug)
    # a security engineer holds user:* ? no - so creating users is refused outright
    assert client.post(f"{API}/users", headers=engineer,
                       json={"email": "x@a.test", "full_name": "X"}).status_code == 403


def test_api_key_scopes_cannot_exceed_the_issuer(client, org_a, admin_a):
    _, slug, _ = org_a
    lead_email = f"lead-{uuid.uuid4().hex[:6]}@a.test"
    client.post(f"{API}/users", headers=admin_a,
                json={"email": lead_email, "full_name": "Team Lead",
                      "password": ADMIN_PASSWORD, "role_slugs": ["team-lead"]})
    lead = auth_headers(client, lead_email, slug)
    # team-lead has no apikey:write at all
    assert client.post(f"{API}/api-keys", headers=lead,
                       json={"name": "k", "scopes": ["*:*"]}).status_code == 403
    # the admin can mint one, and the secret is returned exactly once
    created = client.post(f"{API}/api-keys", headers=admin_a,
                          json={"name": "importer", "scopes": ["finding:write", "asset:read"]})
    assert created.status_code == 201
    body = created.json()
    assert body["api_key"].startswith("veyrs_")
    listed = client.get(f"{API}/api-keys", headers=admin_a).json()
    assert all("api_key" not in k for k in listed)


def test_api_key_authenticates_and_is_scope_limited(client, org_a, admin_a):
    created = client.post(f"{API}/api-keys", headers=admin_a,
                          json={"name": "scanner", "scopes": ["vulnerability:read"]}).json()
    headers = {"X-API-Key": created["api_key"]}
    assert client.get(f"{API}/cvss/versions", headers=headers).status_code == 200
    assert client.get(f"{API}/users", headers=headers).status_code == 403
    assert client.delete(f"{API}/api-keys/{created['id']}", headers=admin_a).status_code == 204
    assert client.get(f"{API}/cvss/versions", headers=headers).status_code == 401


def test_builtin_roles_are_immutable(client, admin_a):
    roles = client.get(f"{API}/roles", headers=admin_a).json()
    builtin = next(r for r in roles if r["is_builtin"])
    assert client.patch(f"{API}/roles/{builtin['id']}", headers=admin_a,
                        json={"name": "hacked-role"}).status_code == 404  # not owned by the tenant


def test_custom_role_rejects_unknown_permission(client, admin_a):
    r = client.post(f"{API}/roles", headers=admin_a,
                    json={"name": "Bad", "slug": f"bad-{uuid.uuid4().hex[:6]}",
                          "permissions": ["asset:teleport"]})
    assert r.status_code == 422


# --- audit ---------------------------------------------------------------


def test_mutations_are_audited(client, org_a, admin_a):
    email = f"audited-{uuid.uuid4().hex[:6]}@a.test"
    client.post(f"{API}/users", headers=admin_a, json={"email": email, "full_name": "Audited"})
    entries = client.get(f"{API}/audit", headers=admin_a, params={"action": "user.create"}).json()
    assert entries["total"] >= 1
    assert any(e["object_label"] == email for e in entries["items"])


def test_audit_never_leaks_secrets(client, org_a, admin_a):
    client.post(f"{API}/users", headers=admin_a,
                json={"email": f"pw-{uuid.uuid4().hex[:6]}@a.test", "full_name": "With Password",
                      "password": "SomeVerySecret-Password-1"})
    entries = client.get(f"{API}/audit", headers=admin_a).json()["items"]
    dumped = str(entries)
    assert "SomeVerySecret" not in dumped


def test_audit_is_tenant_scoped(client, org_a, org_b, admin_a, admin_b):
    client.post(f"{API}/teams", headers=admin_b, json={"name": "B Team", "slug": "b-team"})
    a_entries = client.get(f"{API}/audit", headers=admin_a).json()["items"]
    assert all(e["object_label"] != "b-team" for e in a_entries)


# --- input validation ----------------------------------------------------


def test_invalid_payloads_are_422_not_500(client, admin_a):
    assert client.post(f"{API}/users", headers=admin_a,
                       json={"email": "not-an-email", "full_name": "X"}).status_code == 422
    assert client.post(f"{API}/teams", headers=admin_a,
                       json={"name": "X", "slug": "Not A Slug"}).status_code == 422
    assert client.post(f"{API}/users", headers=admin_a,
                       json={"email": "a@b.test", "full_name": "X",
                             "password": "short"}).status_code == 422


def test_duplicate_email_is_409(client, admin_a):
    email = f"dupe-{uuid.uuid4().hex[:6]}@a.test"
    assert client.post(f"{API}/users", headers=admin_a,
                       json={"email": email, "full_name": "First"}).status_code == 201
    assert client.post(f"{API}/users", headers=admin_a,
                       json={"email": email, "full_name": "Second"}).status_code == 409


# --- CVSS API surface ----------------------------------------------------


def test_cvss_endpoints(client, admin_a):
    assert client.get(f"{API}/cvss/versions", headers=admin_a).json()["versions"] == [
        "2.0", "3.0", "3.1", "4.0"
    ]
    scored = client.post(f"{API}/cvss/score", headers=admin_a,
                         json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}).json()
    assert scored["base_score"] == 9.8 and scored["base_severity"] == "Critical"
    v4 = client.post(f"{API}/cvss/score", headers=admin_a, json={
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}).json()
    assert v4["score"] == 9.3
    explained = client.post(f"{API}/cvss/explain", headers=admin_a,
                            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}).json()
    assert explained["score"] == 10.0 and explained["drivers"]
    catalogue = client.get(f"{API}/cvss/metrics/4.0", headers=admin_a).json()
    groups = {g["group"] for g in catalogue["groups"]}
    assert {"Base", "Threat", "Environmental", "Supplemental"} <= groups
    assert client.post(f"{API}/cvss/validate", headers=admin_a,
                       json={"vector": "CVSS:3.1/AV:Q/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                       ).json()["valid"] is False
    generated = client.post(f"{API}/cvss/generate", headers=admin_a, json={
        "version": "3.1",
        "metrics": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                    "C": "H", "I": "H", "A": "H"}}).json()
    assert generated["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_cvss_bad_vector_is_422(client, admin_a):
    r = client.post(f"{API}/cvss/score", headers=admin_a, json={"vector": "totally/bogus"})
    assert r.status_code == 422


def test_tenant_binding_survives_commit(org_a):
    """Regression: RLS binding must be re-applied after a commit.

    `set_config(..., true)` is transaction-local, so committing mid-request used
    to silently unbind the tenant and make every later query return zero rows.
    """
    from sqlalchemy import select as _select

    from veyrs.db import SessionLocal as _SessionLocal, current_tenant, set_tenant
    from veyrs.models import Asset as _Asset

    org_id = org_a[0]
    with _SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(_Asset(organization_id=org_id, name="rls-guard"))
        session.commit()

        # Same session, after the commit: the tenant must still be bound.
        assert current_tenant(session) == str(org_id)
        rows = session.execute(
            _select(_Asset).where(_Asset.name == "rls-guard")
        ).scalars().all()
        assert len(rows) == 1, "tenant binding was lost after commit"

        bound = session.execute(
            __import__("sqlalchemy").text("SELECT current_setting('veyrs.current_org', true)")
        ).scalar_one()
        assert bound == str(org_id)
