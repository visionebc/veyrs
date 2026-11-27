"""Regression tests for the api audit-fix round (TD-03/04/06/20/22/23/24/30/47/48/50/51/53/56/62/63, R-03/04/09/17)."""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import socket
import uuid

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import select, text

from conftest import ADMIN_PASSWORD, _make_org, auth_headers, login
from test_phase26_scope import estate  # noqa: F401  (fixture: scoped identity + 3 teams' rows)
from test_phase58_oidc import idp  # noqa: F401  (fixture: fake identity provider)
from veyrs.config import settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    AuditLog, ComplianceFramework, ControlImplementation, KnowledgeArticle, ThreatArticle, User,
)
from veyrs.models.tenancy import RefreshToken
from veyrs.services import cmdb, compliance as compliance_service, itsm, net_guard


def _platform_admin_headers(client, org):
    org_id, slug, email = org
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        user.is_superuser = True
        session.commit()
    return auth_headers(client, email, slug)


@pytest.fixture()
def seeded():
    with SessionLocal() as session:
        compliance_service.seed_frameworks(session)
        session.commit()


# ---------------------------------------------------------------- TD-03 ----
def _builtin_id():
    with SessionLocal() as session:
        return session.execute(select(ComplianceFramework.id).where(
            ComplianceFramework.organization_id.is_(None)).limit(1)).scalar_one()


def test_tenant_admin_cannot_import_into_a_builtin_framework(client, admin_a, seeded):
    csv = ("ref,title\nZZ.1,Injected\n").encode()
    r = client.post(f"/api/v1/compliance/frameworks/{_builtin_id()}/controls:import",
                    headers=admin_a, files={"file": ("c.csv", csv, "text/csv")})
    assert r.status_code == 403, r.text


def test_platform_admin_may_import_into_a_builtin_framework(client, org_a, seeded):
    headers = _platform_admin_headers(client, org_a)
    with SessionLocal() as session:
        fid = session.execute(select(ComplianceFramework.id).where(
            ComplianceFramework.organization_id.is_(None)).limit(1)).scalar_one()
    r = client.post(f"/api/v1/compliance/frameworks/{fid}/controls:import", headers=headers,
                    files={"file": ("c.csv", b"ref,title\nZZ.99,Okay\n", "text/csv")})
    assert r.status_code == 200, r.text


def test_custom_frameworks_do_not_collide_across_tenants(client, admin_a, admin_b):
    body = {"slug": "internal-std", "name": "Internal", "version": "1", "publisher": "us"}
    assert client.post("/api/v1/compliance/frameworks", headers=admin_a, json=body).status_code == 201
    # another tenant uses the same slug+version: no 409, and no leak
    assert client.post("/api/v1/compliance/frameworks", headers=admin_b, json=body).status_code == 201
    # the same tenant twice is still a conflict
    assert client.post("/api/v1/compliance/frameworks", headers=admin_a, json=body).status_code == 409


def test_custom_framework_cannot_shadow_a_builtin(client, admin_a, seeded):
    with SessionLocal() as session:
        row = session.execute(select(ComplianceFramework).where(
            ComplianceFramework.organization_id.is_(None)).limit(1)).scalar_one()
        body = {"slug": row.slug, "name": "x", "version": row.version, "publisher": "p"}
    assert client.post("/api/v1/compliance/frameworks", headers=admin_a, json=body).status_code == 409


# ---------------------------------------------------------------- TD-04 ----
@pytest.mark.parametrize("path,body", [
    ("nvd", {"vulnerabilities": []}),
    ("epss", {"rows": []}),
    ("kev", {"vulnerabilities": []}),
])
def test_global_feed_ingestion_is_platform_admin_only(client, admin_a, org_b, path, body):
    assert client.post(f"/api/v1/intel/feeds/{path}", headers=admin_a, json=body).status_code == 403
    pa = _platform_admin_headers(client, org_b)
    assert client.post(f"/api/v1/intel/feeds/{path}?correlate=false", headers=pa,
                       json=body).status_code == 200


# ---------------------------------------------------------------- TD-06 ----
def test_risk_simulate_works(client, admin_a):
    r = client.post("/api/v1/risk/simulate", headers=admin_a,
                    json={"cvss_score": 9.8, "kev": True, "exposure": "internet",
                          "age_days": 90, "exposure_days": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["risk_score"] > 0 and body["risk_level"]


# ---------------------------------------------------------------- TD-20 ----
def test_threat_summary_runs_without_a_relevance_column(client, admin_a, org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add_all([
            ThreatArticle(organization_id=org_id, title=f"story {i}", content_hash=uuid.uuid4().hex,
                          published_at=dt.datetime.now(dt.timezone.utc), confidence=0.4 + i / 10,
                          relevant_asset_count=i, cve_ids=["CVE-2026-0001"])
            for i in range(3)])
        session.commit()
    r = client.post("/api/v1/ai/threat-summary", headers=admin_a)   # no provider -> deterministic fallback
    assert r.status_code == 200, r.text
    assert "story 2" in str(r.json())


# ---------------------------------------------------------------- TD-22 ----
def test_knowledge_patch_is_partial(client, admin_a, org_a):
    made = client.post("/api/v1/knowledge", headers=admin_a, json={
        "title": "Runbook", "body": "step 1", "is_published": True,
        "required_permissions": ["finding:read"], "tags": ["a"], "kind": "runbook"})
    assert made.status_code == 201, made.text
    aid = made.json()["id"]
    r = client.patch(f"/api/v1/knowledge/{aid}", headers=admin_a, json={"title": "Runbook v2"})
    assert r.status_code == 200, r.text
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        row = session.execute(select(KnowledgeArticle).where(KnowledgeArticle.id == uuid.UUID(aid))).scalar_one()
        assert row.title == "Runbook v2"
        assert row.is_published is True
        assert row.required_permissions == ["finding:read"]
        assert row.kind == "runbook" and row.tags == ["a"]


# ---------------------------------------------------------------- TD-23 ----
def test_organization_patch_cannot_touch_settings_or_activation(client, admin_a):
    for field in ({"settings": {"ldap_auth": {}}}, {"is_active": False}):
        assert client.patch("/api/v1/organization", headers=admin_a, json=field).status_code == 422
    ok = client.patch("/api/v1/organization", headers=admin_a, json={"timezone": "Europe/Zurich"})
    assert ok.status_code == 200
    assert ok.json()["is_active"] is True


# ---------------------------------------------------------------- TD-24 ----
class _Resp:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _FakeClient:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def get(self, url, params=None, headers=None):
        self.calls.append(url)
        return _Resp(self.pages[len(self.calls) - 1])


def _spec(base="https://cmdb.example.com"):
    return cmdb.SourceSpec(driver="http_json", base_url=base, credentials={"token": "t"},
                           collections=["/api/items"], field_map={"hostname": "host"}, value_maps={})


def test_http_json_follows_next_only_on_the_same_origin():
    evil = _FakeClient([{"results": [{"host": "a"}], "next": "https://evil.example.net/steal"}])
    with pytest.raises(cmdb.CmdbError, match="different origin"):
        cmdb.HttpJsonDriver()._collection(evil, _spec(), "/api/items", {"Authorization": "Bearer t"})
    assert evil.calls == ["/api/items"]
    ok = _FakeClient([{"results": [{"host": "a"}], "next": "https://cmdb.example.com/api/items?p=2"},
                      {"results": [{"host": "b"}]}])
    out = cmdb.HttpJsonDriver()._collection(ok, _spec(), "/api/items", {})
    assert len(out) == 2 and len(ok.calls) == 2


# ---------------------------------------------------------------- R-09 -----
def _resolver(*addrs):
    def fake(host, port, **kw):
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in addrs]
    return fake


@pytest.mark.parametrize("url,addrs", [
    ("http://169.254.169.254/latest", ()),
    ("http://[fd00:ec2::254]/", ()),
    ("http://[::ffff:169.254.169.254]/", ()),
    (f"http://{net_guard._ALIBABA_METADATA.network_address}/", ()),
    ("https://meta.example.com/", ("1.2.3.4", "169.254.169.254")),   # one bad record is enough
    ("http://127.0.0.1:8000/", ()),
    ("https://loop.example.com/", ("::1",)),
    ("ftp://example.com/", ()),
    ("http:///nohost", ()),
])
def test_net_guard_always_refuses_metadata_and_loopback(url, addrs):
    with pytest.raises(net_guard.OutboundBlocked):
        net_guard.check_url(url, resolver=_resolver(*addrs))


def test_net_guard_private_ranges_follow_the_setting(monkeypatch):
    private = _resolver("198.19.2.3")
    net_guard.check_url("https://netbox.example.com", resolver=private)          # default: allowed
    monkeypatch.setattr(settings, "outbound_allow_private", False)
    with pytest.raises(net_guard.OutboundBlocked, match="private"):
        net_guard.check_url("https://netbox.example.com", resolver=private)
    net_guard.check_url("https://api.example.com", resolver=_resolver("1.2.3.4"))
    monkeypatch.setattr(settings, "outbound_allow_private", True)
    with pytest.raises(net_guard.OutboundBlocked):                              # per-call tightening
        net_guard.check_url("https://netbox.example.com", resolver=private, allow_private=False)


def test_net_guard_loopback_opt_in(monkeypatch):
    monkeypatch.setattr(settings, "outbound_allow_loopback", True)
    net_guard.check_url("http://127.0.0.1:9000/", resolver=_resolver())
    with pytest.raises(net_guard.OutboundBlocked):   # metadata stays refused even then
        net_guard.check_url("http://169.254.169.254/", resolver=_resolver())


def test_every_connector_entry_point_applies_the_guard():
    from veyrs.services import scanners
    from veyrs.services.ai import providers
    with pytest.raises(cmdb.CmdbError, match="refused"):
        cmdb._client(_spec("http://169.254.169.254"))
    with pytest.raises(scanners.ScannerError, match="refused"):
        scanners._client(scanners.ScannerSpec(driver="x", base_url="http://169.254.169.254",
                                              credentials={}))
    with pytest.raises(itsm.ItsmError, match="refused"):
        itsm._request("GET", "http://169.254.169.254/x", headers={}, json_body=None, timeout=1)
    with pytest.raises(providers.ProviderError, match="refused"):
        providers._post_json("http://169.254.169.254/x", {}, {}, 1)


# ---------------------------------------------------------------- R-03 -----
def test_global_search_respects_team_scope(client, estate):  # noqa: F811
    scoped, wide = estate["scoped"], None
    body = client.get("/api/v1/search", params={"q": "-"}, headers=scoped).json()
    # asset names are "<label>-<hex>", finding titles "<label> finding"
    r = client.get("/api/v1/search", params={"q": "finding"}, headers=scoped).json()["results"]
    titles = {f["title"] for f in r.get("finding", [])}
    assert titles == {"net finding"}, titles
    assets = {a["name"].split("-")[0] for a in client.get(
        "/api/v1/search", params={"q": "-"}, headers=scoped).json()["results"].get("asset", [])}
    assert assets <= {"net"}
    vulns = {v["title"] for v in client.get(
        "/api/v1/search", params={"q": "vulnerability"}, headers=scoped).json()["results"].get("vulnerability", [])}
    assert vulns == {"net vulnerability"}
    assert body is not None


def test_unrestricted_search_still_sees_everything(client, admin_a, estate):  # noqa: F811
    r = client.get("/api/v1/search", params={"q": "finding"}, headers=admin_a).json()["results"]
    assert {f["title"] for f in r["finding"]} == {"net finding", "app finding", "orphan finding"}


# ---------------------------------------------------------------- R-04 -----
def test_correlation_id_is_sanitised():
    from veyrs.observability import sanitize_correlation_id
    assert sanitize_correlation_id("abc-123.x:y") == "abc-123.x:y"
    assert len(sanitize_correlation_id("a" * 500)) == 64
    for bad in ("has space", "line\nbreak", "semi;colon", "", None, "é" * 10):
        out = sanitize_correlation_id(bad)
        uuid.UUID(out)


def test_oversized_correlation_header_does_not_lose_the_audit_row(client, admin_a, org_a):
    slug = f"t-{uuid.uuid4().hex[:6]}"
    r = client.post("/api/v1/teams", headers={**admin_a, "X-Correlation-ID": "c" * 300},
                    json={"name": "Audit probe", "slug": slug})
    assert r.status_code == 201, r.text
    assert len(r.headers["X-Correlation-ID"]) == 64
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        row = session.execute(select(AuditLog).where(
            AuditLog.action == "team.create", AuditLog.object_label == slug)).scalar_one()
        assert row.correlation_id == "c" * 64


# ---------------------------------------------------------------- TD-30 ----
def test_unique_violation_is_409_with_the_envelope(client, admin_a):
    body = {"name": f"svc-{uuid.uuid4().hex[:6]}", "criticality": "high"}
    assert client.post("/api/v1/assets/services", headers=admin_a, json=body).status_code == 201
    r = client.post("/api/v1/assets/services", headers=admin_a, json=body)
    assert r.status_code == 409, r.text
    assert r.json()["error"] == "conflict" and r.json()["correlation_id"]


def test_unhandled_error_returns_the_envelope_not_a_stack_trace():
    from veyrs.observability import RequestContextMiddleware
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)

    @app.get("/boom")
    def boom():
        raise RuntimeError("secret internal detail")

    r = TestClient(app, raise_server_exceptions=False).get("/boom", headers={"X-Correlation-ID": "cid-1"})
    assert r.status_code == 500
    assert r.json() == {"error": "internal_error", "detail": "internal server error",
                        "correlation_id": "cid-1"}
    assert "secret" not in r.text and r.headers["X-Correlation-ID"] == "cid-1"


# ---------------------------------------------------------------- R-17 -----
def test_openapi_is_off_in_production_unless_exposed(monkeypatch):
    from veyrs import main
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(type(settings), "assert_production_safe", lambda self: None)
    monkeypatch.setattr(settings, "expose_openapi", False)
    hidden = TestClient(main.create_app())
    assert hidden.get("/api/v1/openapi.json").status_code == 404
    assert hidden.get("/docs").status_code == 404
    monkeypatch.setattr(settings, "expose_openapi", True)
    assert TestClient(main.create_app()).get("/api/v1/openapi.json").status_code == 200


def test_openapi_is_served_in_development(client):
    assert client.get("/api/v1/openapi.json").status_code == 200


# ---------------------------------------------------------------- TD-47 ----
def test_page_derives_page_and_size_from_limit_and_offset():
    from veyrs.api.v1.schemas import Page
    p = Page(items=[], total=0, limit=10, offset=20)
    assert (p.page, p.size) == (3, 10)
    assert Page.of([], 0, 2, 25).offset == 25


def test_list_endpoints_report_real_pagination(client, admin_a):
    r = client.get("/api/v1/agents", params={"limit": 10, "offset": 20}, headers=admin_a).json()
    assert (r["page"], r["size"]) == (3, 10)


def test_assessments_total_is_the_real_count(client, admin_a, seeded):
    fid = _builtin_id()
    for i in range(3):
        assert client.post("/api/v1/compliance/assessments", headers=admin_a,
                           json={"framework_id": str(fid), "name": f"A{i}"}).status_code in (200, 201)
    r = client.get("/api/v1/compliance/assessments", params={"limit": 1}, headers=admin_a).json()
    assert len(r["items"]) == 1 and r["total"] == 3


# ---------------------------------------------------------------- TD-48 ----
def test_password_minimum_follows_the_setting(monkeypatch):
    from veyrs.api.v1.schemas import UserCreate
    base = {"email": "a@b.example", "full_name": "Some One"}
    monkeypatch.setattr(settings, "password_min_length", 8)
    UserCreate(**base, password="x" * 8)
    monkeypatch.setattr(settings, "password_min_length", 16)
    with pytest.raises(ValueError):
        UserCreate(**base, password="x" * 15)
    UserCreate(**base, password="x" * 16)


# ---------------------------------------------------------------- TD-50 ----
def test_get_knowledge_does_not_write_and_view_is_explicit(client, admin_a):
    aid = client.post("/api/v1/knowledge", headers=admin_a,
                      json={"title": "T", "body": "b"}).json()["id"]
    for _ in range(2):
        assert client.get(f"/api/v1/knowledge/{aid}", headers=admin_a).json()["view_count"] == 0
    assert client.post(f"/api/v1/knowledge/{aid}/view", headers=admin_a).status_code == 204
    assert client.get(f"/api/v1/knowledge/{aid}", headers=admin_a).json()["view_count"] == 1


def test_coverage_get_reports_stale_without_persisting(client, admin_a, org_a, seeded):
    org_id = org_a[0]
    fid = _builtin_id()
    from veyrs.models import ComplianceControl
    with SessionLocal() as session:
        set_tenant(session, org_id)
        control = session.execute(select(ComplianceControl).where(
            ComplianceControl.framework_id == fid).limit(1)).scalar_one()
        session.add(ControlImplementation(
            organization_id=org_id, control_id=control.id, status="implemented",
            next_review_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)))
        session.commit()
        control_id = control.id
    body = client.get(f"/api/v1/compliance/frameworks/{fid}/coverage", headers=admin_a).json()
    assert body["counts"]["stale"] == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(select(ControlImplementation.status).where(
            ControlImplementation.organization_id == org_id,
            ControlImplementation.control_id == control_id)).scalar_one() == "implemented"
    assert client.post(f"/api/v1/compliance/frameworks/{fid}/refresh-signals",
                       headers=admin_a).status_code == 200
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(select(ControlImplementation.status).where(
            ControlImplementation.organization_id == org_id,
            ControlImplementation.control_id == control_id)).scalar_one() == "stale"


# ---------------------------------------------------------------- TD-51 ----
class _Upload:
    def __init__(self, size):
        self.left, self.read_total = size, 0

    async def read(self, n=-1):
        n = self.left if n is None or n < 0 else min(n, self.left)
        self.left -= n
        self.read_total += n
        return b"x" * n


def test_read_capped_stops_at_the_limit_instead_of_reading_everything():
    from veyrs.api.v1.uploads import read_capped
    big = _Upload(50 * 1024 * 1024)
    with pytest.raises(HTTPException) as err:
        asyncio.run(read_capped(big, 1024 * 1024))
    assert err.value.status_code == 413
    assert big.read_total < 2 * 1024 * 1024
    assert len(asyncio.run(read_capped(_Upload(1000), 2000))) == 1000


# ---------------------------------------------------------------- TD-53 ----
def test_connection_hardening_failure_is_logged_once(caplog):
    from veyrs import db

    class Broken:
        def cursor(self):
            raise RuntimeError("nope")

    db._hardening_warned = False
    with caplog.at_level(logging.WARNING, logger="veyrs.db"):
        db._harden_connection(Broken(), None)
        db._harden_connection(Broken(), None)
    assert len([r for r in caplog.records if "timeouts" in r.getMessage()]) == 1


# ---------------------------------------------------------------- TD-56 ----
def test_servicenow_link_uses_the_configured_table(monkeypatch):
    monkeypatch.setattr(itsm, "_request", lambda *a, **k: {"result": {"sys_id": "abc", "number": "CHG1"}})
    spec = itsm.ConnectorSpec(slug="s", system="servicenow", base_url="https://sn.example.com",
                              credentials={"token": "t"}, field_mapping={"table": "change_request"})
    ticket = itsm.ServiceNowAdapter().create(
        spec, {"summary": "t", "description": "d", "priority": "high"})
    assert "uri=change_request.do?sys_id=abc" in ticket.url


# ---------------------------------------------------------------- TD-62 ----
def test_account_lookup_normalises_case_and_reports_ambiguity():
    from veyrs.services import mfa_admin
    a, b = _make_org("dup-a"), _make_org("dup-b")
    shared = f"shared-{uuid.uuid4().hex[:6]}@example.test"
    for org_id, _slug, _email in (a, b):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            session.add(User(organization_id=org_id, email=shared, full_name="Shared"))
            session.commit()
    with SessionLocal() as session:
        with pytest.raises(mfa_admin.AccountLookupError, match="--org"):
            mfa_admin.find_account(session, shared.upper())
        found = mfa_admin.find_account(session, shared.upper(), a[1])
        assert found is not None and found.organization_id == a[0]
        assert mfa_admin.find_account(session, "nobody@example.test") is None


# ---------------------------------------------------------------- TD-63 ----
def test_delete_user_revokes_refresh_tokens_and_add_member_refuses_deleted(client, admin_a, org_a):
    org_id, slug, _ = org_a
    email = f"gone-{uuid.uuid4().hex[:6]}@{slug}.test"
    made = client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Gone Soon", "password": "Another-Strong-Pass-1",
        "role_slugs": ["security-manager"]})
    assert made.status_code == 201, made.text
    uid = made.json()["id"]
    login(client, email, slug, "Another-Strong-Pass-1")
    team = client.post("/api/v1/teams", headers=admin_a,
                       json={"name": "Team T", "slug": f"t-{uuid.uuid4().hex[:6]}"}).json()["id"]
    assert client.delete(f"/api/v1/users/{uid}", headers=admin_a).status_code == 204
    with SessionLocal() as session:
        set_tenant(session, org_id)
        live = session.execute(select(RefreshToken).where(
            RefreshToken.user_id == uuid.UUID(uid), RefreshToken.revoked_at.is_(None))).scalars().all()
        assert live == []
    assert client.post(f"/api/v1/teams/{team}/members/{uid}", headers=admin_a).status_code == 404


def test_sso_jit_creation_is_audited(client, org_a, idp):
    from test_phase58_oidc import _callback, _claims, _configure, _start
    slug = _configure(org_a, jit_provisioning=True)
    state, nonce = _start(client, slug)
    email = f"jit-{uuid.uuid4().hex[:8]}@example.test"
    _claims(idp, email, nonce)
    r, _back = _callback(client, state)
    assert r.status_code == 303 and "error" not in r.headers["location"], r.headers["location"]
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        row = session.execute(select(AuditLog).where(
            AuditLog.action == "user.sso_provisioned", AuditLog.object_label == email)).scalar_one()
        assert row.actor_label == f"sso:{email}"
