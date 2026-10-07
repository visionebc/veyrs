"""Phase 10: production hardening.

Rate limiting, security headers, authorization matrix and the tenant-isolation
guarantees, asserted end to end rather than assumed from the code.

The authorization matrix is the important part of this file. Spec section 22
says every endpoint authorizes server-side; the only way to keep that true as
routes are added is to assert it mechanically -- so `test_every_route_is_
protected` walks the live app and fails the build if a new route forgets.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from veyrs.config import settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.main import app as veyrs_app
from veyrs.models import Organization, Role, User, UserRole
from veyrs.observability import SECURITY_HEADERS
from veyrs.security import ratelimit
from veyrs.security.auth import hash_password

from conftest import ADMIN_PASSWORD, auth_headers


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _clean_windows():
    ratelimit.reset_local()
    yield
    ratelimit.reset_local()


def _mini_app(per_minute: int = 3, auth_per_minute: int = 2) -> TestClient:
    """A throwaway app so the limiter is exercised at a testable rate.

    The main suite runs with the limit raised; testing the limiter itself needs
    a small budget, and mutating the global app's middleware would leak into
    every other test in the session.
    """
    app = FastAPI()

    @app.get("/api/v1/thing")
    def thing() -> dict:
        return {"ok": True}

    @app.post("/api/v1/auth/login")
    def login() -> dict:
        return {"ok": True}

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    app.add_middleware(ratelimit.RateLimitMiddleware, per_minute=per_minute,
                       auth_per_minute=auth_per_minute)
    return TestClient(app)


def _identity_headers() -> dict[str, str]:
    """A unique credential per test.

    The Redis backend uses a fixed window keyed on the caller identity, and that
    window is shared across the whole test session. Without a distinct token per
    test, the second limiter test inherits the first one's exhausted bucket.
    """
    return {"Authorization": f"Bearer rl-{uuid.uuid4().hex}"}


def test_general_limit_returns_429_with_retry_after():
    client = _mini_app(per_minute=3)
    headers = _identity_headers()
    for _ in range(3):
        assert client.get("/api/v1/thing", headers=headers).status_code == 200
    response = client.get("/api/v1/thing", headers=headers)
    assert response.status_code == 429
    assert response.json()["error"] == "rate_limited"
    assert int(response.headers["Retry-After"]) >= 1
    assert response.headers["X-RateLimit-Remaining"] == "0"


def test_remaining_header_counts_down():
    client = _mini_app(per_minute=3)
    headers = _identity_headers()
    first = client.get("/api/v1/thing", headers=headers)
    second = client.get("/api/v1/thing", headers=headers)
    assert int(first.headers["X-RateLimit-Remaining"]) == 2
    assert int(second.headers["X-RateLimit-Remaining"]) == 1


def test_auth_endpoints_have_a_stricter_budget():
    """Credential stuffing must be stopped long before the general limit."""
    client = _mini_app(per_minute=100, auth_per_minute=2)
    # Auth is keyed on source IP by design, so this test needs the Redis window
    # cleared rather than a fresh credential.
    _clear_backend("auth:testclient")
    assert client.post("/api/v1/auth/login").status_code == 200
    assert client.post("/api/v1/auth/login").status_code == 200
    assert client.post("/api/v1/auth/login").status_code == 429
    # the general budget is untouched
    assert client.get("/api/v1/thing", headers=_identity_headers()).status_code == 200


def test_probes_are_never_rate_limited():
    """A throttled /healthz reads as an outage to every orchestrator."""
    client = _mini_app(per_minute=1)
    for _ in range(10):
        assert client.get("/healthz").status_code == 200


def test_distinct_credentials_get_distinct_buckets():
    client = _mini_app(per_minute=2)
    a = _identity_headers()
    b = _identity_headers()
    assert client.get("/api/v1/thing", headers=a).status_code == 200
    assert client.get("/api/v1/thing", headers=a).status_code == 200
    assert client.get("/api/v1/thing", headers=a).status_code == 429
    # B has its own budget: one noisy integration must not throttle everyone.
    assert client.get("/api/v1/thing", headers=b).status_code == 200


def test_forwarded_for_is_ignored_unless_the_proxy_is_trusted(monkeypatch):
    """Otherwise any caller mints a fresh identity per request."""
    monkeypatch.setattr(settings, "trust_proxy_headers", False)
    client = _mini_app(per_minute=2)
    _clear_backend("api:ip:testclient")
    for index in range(2):
        assert client.get("/api/v1/thing",
                          headers={"X-Forwarded-For": f"1.2.3.{index}"}).status_code == 200
    spoofed = client.get("/api/v1/thing", headers={"X-Forwarded-For": "9.9.9.9"})
    assert spoofed.status_code == 429


def _clear_backend(key: str) -> None:
    """Drop a limiter window from whichever backend is live."""
    ratelimit.reset_local()
    client = ratelimit._redis()
    if client is not None:
        for found in client.scan_iter(f"veyrs:rl:{key}:*"):
            client.delete(found)


def test_limiter_fails_open_when_the_backend_errors(monkeypatch):
    """A limiter outage must not become a platform outage."""
    class Broken:
        def pipeline(self):
            raise RuntimeError("redis is gone")

    monkeypatch.setattr(ratelimit, "_redis", lambda: Broken())
    decision = ratelimit.check("anything", limit=1)
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
def test_security_headers_are_present_on_every_response(client):
    response = client.get("/healthz")
    for header in SECURITY_HEADERS:
        assert header in response.headers, f"{header} missing"


def test_security_header_values_are_restrictive(client):
    headers = client.get("/healthz").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] in ("DENY", "SAMEORIGIN")
    assert "no-referrer" in headers.get("Referrer-Policy", "")


def test_correlation_id_is_echoed_back(client):
    given = str(uuid.uuid4())
    response = client.get("/healthz", headers={"X-Correlation-ID": given})
    assert response.headers["X-Correlation-ID"] == given


def test_correlation_id_is_generated_when_absent(client):
    response = client.get("/healthz")
    uuid.UUID(response.headers["X-Correlation-ID"])  # raises if not a UUID


# ---------------------------------------------------------------------------
# Authorization matrix
# ---------------------------------------------------------------------------
#: Routes that are public BY DESIGN. Anything else must reject anonymous callers.
PUBLIC_PATHS = {
    "/healthz", "/readyz", "/metrics", "/docs", "/redoc", "/openapi.json",
    f"{settings.api_prefix}/openapi.json",
    f"{settings.api_prefix}/auth/login",
    f"{settings.api_prefix}/auth/refresh",
    # FastAPI mounts this alongside /docs; it is a static OAuth2 redirect shim
    # with no data access, and it does not exist in production (docs_url=None).
    "/docs/oauth2-redirect",
}

#: Routes authenticated by something OTHER than a Principal, which therefore
#: answer 404 rather than 401 to an anonymous probe. They are NOT public, and
#: they are listed separately from PUBLIC_PATHS so that distinction stays
#: visible: putting them in the set above would read as "no auth needed".
#:
#: The ITSM inbound webhook is signed with a per-connector HMAC. It answers 404
#: for an unknown org, an unknown connector AND a connector with inbound
#: disabled - identical responses on purpose, so the URL cannot be used to
#: enumerate tenants. Its own suite (test_phase17_itsm_inbound) asserts that an
#: unsigned, wrongly-signed, tampered or replayed request is refused.
SIGNED_PATHS = {
    f"{settings.api_prefix}/integrations/itsm/{{organization_slug}}/{{connector_slug}}/inbound",
}


def test_every_route_is_protected(client):
    """Walk the live app: a new endpoint that forgets auth fails the build.

    This is the mechanical enforcement of spec section 22. Reviewing each new
    route by eye is exactly the control that erodes under delivery pressure.
    """
    # The limiter answers BEFORE authentication, so a route that has already
    # been hit enough times replies 429 and is reported here as "reachable
    # without authentication" -- the exact opposite of what happened.
    #
    # Flushing ONCE before the walk is not enough and was never a fix: this
    # test issues one request per route, so its own traffic is what trips the
    # limiter, and the budget runs out somewhere in the tail. It passed only
    # while the route count stayed under the threshold, and went red again the
    # next time four routes were added -- with the failure pointing at the
    # routes that happened to be last rather than at anything wrong with them.
    #
    # The reason this matters beyond a flaky test: **a 429 can also HIDE a real
    # hole.** A genuinely unauthenticated route answers 200, but if the limiter
    # fires first it answers 429, and the obvious "fix" of adding 429 to the
    # accepted set would turn this guardrail off without anyone noticing.
    # So the counters are dropped before EVERY probe.
    from tests.conftest import _flush_rate_limits

    unprotected: list[str] = []
    throttled: list[str] = []
    for route in veyrs_app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", set()) or set()
        if not path or path in PUBLIC_PATHS:
            continue
        accepted = {401, 403, 405}
        if path in SIGNED_PATHS:
            accepted.add(404)
        if "{" in path:
            probe = path.replace("{", "").replace("}", "")
            for segment in path.split("/"):
                if segment.startswith("{"):
                    probe = probe.replace(segment.strip("{}"), str(uuid.uuid4()))
            path_to_call = probe
        else:
            path_to_call = path
        method = "GET" if "GET" in methods else next(iter(methods - {"HEAD", "OPTIONS"}), None)
        if method is None:
            continue
        _flush_rate_limits()
        response = client.request(method, path_to_call)
        if response.status_code == 429:
            # Reported separately and still a failure: it means the flush above
            # did not work, not that the route is open.
            throttled.append(f"{method} {path}")
        elif response.status_code not in accepted:
            unprotected.append(f"{method} {path} -> {response.status_code}")
    assert not throttled, (
        "the rate limiter answered before authentication, so these routes were "
        "not actually tested: " + "; ".join(throttled))
    assert not unprotected, "routes reachable without authentication: " + \
        "; ".join(unprotected)


def _user_with_role(org_id: uuid.UUID, slug: str, role_slug: str) -> str:
    email = f"{role_slug}-{uuid.uuid4().hex[:6]}@{slug}.test"
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = User(organization_id=org_id, email=email, full_name=role_slug,
                    password_hash=hash_password(ADMIN_PASSWORD))
        session.add(user)
        session.flush()
        role = session.execute(
            select(Role).where(Role.slug == role_slug, Role.organization_id.is_(None))
        ).scalar_one()
        session.add(UserRole(organization_id=org_id, user_id=user.id, role_id=role.id))
        session.commit()
    return email


@pytest.mark.parametrize("role_slug,path,expected", [
    # auditor is read-only everywhere: no write route may accept it
    ("auditor", "/api/v1/ai/policy", 403),          # needs ai:read
    ("read-only", "/api/v1/ai/policy", 403),
    ("read-only", "/api/v1/users", 403),            # needs user:read
    ("executive", "/api/v1/dashboard/executive", 200),
    ("auditor", "/api/v1/compliance/frameworks", 200),
    ("security-engineer", "/api/v1/ai/capabilities", 200),
])
def test_role_permissions_are_enforced_per_route(client, org_a, role_slug, path, expected):
    org_id, slug, _ = org_a
    email = _user_with_role(org_id, slug, role_slug)
    headers = auth_headers(client, email, slug)
    assert client.get(path, headers=headers).status_code == expected


def test_a_token_from_one_tenant_cannot_read_another(client, org_a, org_b):
    _, slug_a, email_a = org_a
    org_b_id, _, _ = org_b
    headers = auth_headers(client, email_a, slug_a)

    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        from veyrs.models import Asset

        asset = Asset(organization_id=org_b_id, name="secret-b", asset_type="server")
        session.add(asset)
        session.commit()
        asset_id = asset.id

    response = client.get(f"/api/v1/assets/{asset_id}", headers=headers)
    assert response.status_code == 404  # not 403: existence itself is not disclosed


def test_expired_or_forged_tokens_are_rejected(client):
    for token in ("not-a-token", "a.b.c", ""):
        response = client.get("/api/v1/assets",
                              headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401


def test_unknown_api_key_is_rejected(client):
    response = client.get("/api/v1/assets", headers={"X-API-Key": "veyrs_abc_def"})
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Configuration safety
# ---------------------------------------------------------------------------
def test_production_refuses_a_derived_encryption_key():
    from veyrs.config import Settings

    unsafe = Settings(
        environment="production", secret_key="x" * 40, encryption_key="",
        public_base_url="https://veyrs.example.com",
        database_url="postgresql+psycopg://veyrs:strong@db/veyrs",
    )
    with pytest.raises(RuntimeError, match="encryption_key"):
        unsafe.assert_production_safe()


def test_production_refuses_the_bootstrap_database_password():
    from veyrs.config import Settings

    unsafe = Settings(
        environment="production", secret_key="x" * 40, encryption_key="k" * 44,
        public_base_url="https://veyrs.example.com",
        database_url="postgresql+psycopg://veyrs:veyrs@db/veyrs",
    )
    with pytest.raises(RuntimeError, match="bootstrap password"):
        unsafe.assert_production_safe()


def test_production_refuses_plain_http():
    from veyrs.config import Settings

    unsafe = Settings(
        environment="production", secret_key="x" * 40, encryption_key="k" * 44,
        public_base_url="http://veyrs.example.com",
        database_url="postgresql+psycopg://veyrs:strong@db/veyrs",
    )
    with pytest.raises(RuntimeError, match="https"):
        unsafe.assert_production_safe()


def test_a_short_secret_key_is_refused():
    from veyrs.config import Settings

    with pytest.raises(ValueError, match="at least 32"):
        Settings(secret_key="too-short")


# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------
def test_healthz_reports_version(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["version"] == settings.version


def test_readyz_checks_the_database(client):
    body = client.get("/readyz").json()
    assert body["checks"]["database"] == "ok"


def test_metrics_are_prometheus_formatted(client):
    """Asserted through the phase-18 token gate, not around it.

    `/metrics` answers 404 to an unauthenticated caller, so this test was
    scraping a 404 body and failing on a contract that was never broken.
    Authenticating keeps the exposition-format assertion honest AND exercises
    the gate's happy path; `test_phase18_hardening` owns the refusal cases.
    """
    client.get("/healthz")
    headers = ({"Authorization": f"Bearer {settings.metrics_token}"}
               if settings.metrics_token else {})
    text = client.get("/metrics", headers=headers).text
    assert "veyrs_build_info" in text
    assert "veyrs_requests_total" in text


def test_validation_errors_never_echo_the_submitted_value(client, admin_a):
    """Request bodies here routinely carry credentials and vulnerability detail."""
    response = client.post("/api/v1/integrations/connectors", headers=admin_a, json={
        "slug": "x", "name": "x", "system": "servicenow", "base_url": "https://x",
        "credentials": {"password": "SuperSecret123!"},
        "ticket_types": "not-a-list",
    })
    assert response.status_code == 422
    assert "SuperSecret123!" not in response.text


# ---------------------------------------------------------------------------
# List endpoints
# ---------------------------------------------------------------------------
#: Every collection route, called with no filters. These were shipped broken --
#: ten of them built `Page(page=..., size=...)`, fields the schema does not
#: declare, so each one raised a ValidationError at response time and nothing
#: caught it because no test called them over HTTP. This walk is the guard.
LIST_ENDPOINTS = [
    "/api/v1/assets",
    "/api/v1/assets/services",
    "/api/v1/vulnerabilities",
    "/api/v1/findings",
    "/api/v1/tickets",
    "/api/v1/tickets-metrics",
    "/api/v1/intel/cve",
    "/api/v1/intel/kev",
    "/api/v1/intel/sources",
    "/api/v1/intel/feeds/runs",
    "/api/v1/documents",
    "/api/v1/knowledge",
    "/api/v1/risk/profiles",
    "/api/v1/policies/sla",
    "/api/v1/policies/escalation",
    "/api/v1/policies/assignment",
    "/api/v1/policies/sla/events",
    "/api/v1/users",
    "/api/v1/teams",
    "/api/v1/departments",
    "/api/v1/roles",
    "/api/v1/api-keys",
    "/api/v1/audit",
    "/api/v1/notifications",
    "/api/v1/workflows",
    "/api/v1/workflows/runs",
    "/api/v1/compliance/frameworks",
    "/api/v1/compliance/evidence",
    "/api/v1/compliance/assessments",
    "/api/v1/integrations/imports",
    "/api/v1/integrations/connectors",
    "/api/v1/ai/providers",
    "/api/v1/ai/conversations",
    "/api/v1/ai/audit",
    "/api/v1/reports",
]


#: Routes that return a domain-shaped payload rather than a page, by design.
NON_PAGINATED = {"/api/v1/tickets-metrics", "/api/v1/reports",
                 "/api/v1/policies/sla/events"}


@pytest.mark.parametrize("path", LIST_ENDPOINTS)
def test_list_endpoints_return_a_valid_page(client, admin_a, path):
    response = client.get(path, headers=admin_a)
    assert response.status_code == 200, f"{path} -> {response.status_code} {response.text[:300]}"
    body = response.json()
    if isinstance(body, dict) and "items" in body:
        # the pagination contract every client depends on
        assert {"items", "total", "limit", "offset", "page", "size"} <= set(body)
        assert body["offset"] == (body["page"] - 1) * body["size"]


def test_page_of_computes_offset_from_a_one_based_page():
    from veyrs.api.v1.schemas import Page

    page = Page.of(items=[], total=120, page=3, size=25)
    assert page.limit == 25
    assert page.offset == 50   # pages 1 and 2 consumed 50 rows
    assert page.has_more is True
