"""Shared test fixtures.

Tests run against a real PostgreSQL database (`veyrs_test`), not SQLite: the
schema depends on JSONB, UUID and Row Level Security, so an in-memory stand-in
would test something VEYRS does not actually deploy.

The database URL is taken from VEYRS_TEST_DATABASE_URL, defaulting to the same
credentials as the app with `_test` appended to the database name.
"""
from __future__ import annotations

import os
import uuid
from urllib.parse import urlsplit

import pytest

# Point the app at the test database BEFORE veyrs.config is imported.
def _test_database_url() -> str:
    """Derive the test DB URL by swapping ONLY the trailing database name.

    `str.replace("/veyrs", "/veyrs_test")` also rewrites the `//veyrs:` in the
    userinfo, producing `veyrs_test` as the *username* and a confusing
    "password authentication failed" instead of "database missing".
    """
    explicit = os.environ.get("VEYRS_TEST_DATABASE_URL")
    if explicit:
        return explicit
    url = os.environ.get("VEYRS_DATABASE_URL") or ""
    if url.endswith("/veyrs"):
        return url[: -len("/veyrs")] + "/veyrs_test"
    return url


def _assert_is_test_database(url: str) -> None:
    """Refuse to run the suite against anything but a `*_test` database.

    This suite creates and destroys tenants by the thousand. Without the guard
    there was a live path to production: run bare `pytest` with no .env loaded,
    VEYRS_DATABASE_URL is unset, `_test_database_url()` returns "", nothing is
    exported, and `veyrs.config` falls back to its own built-in default - which
    is the PRODUCTION database. 1,198 orphan `tenant-*` organisations in the
    production `veyrs` database on 2026-08-10 are what that looks like
    afterwards. Failing loudly here is the only reliable place to stop it: by
    the time a fixture is writing rows, the damage is already committed.
    """
    if not url:
        raise RuntimeError(
            "no test database configured. Run ./scripts/test.sh, which loads "
            ".env and derives VEYRS_TEST_DATABASE_URL - never bare pytest, "
            "which would fall back to the production default."
        )
    name = urlsplit(url).path.lstrip("/").split("?")[0]
    if not name.endswith("_test"):
        raise RuntimeError(
            f"refusing to run tests against database {name!r}: the name must "
            "end in '_test'. Set VEYRS_TEST_DATABASE_URL, or run "
            "./scripts/test.sh which derives it from .env."
        )


_default = _test_database_url()
_assert_is_test_database(_default)
os.environ["VEYRS_DATABASE_URL"] = _default
os.environ.setdefault("VEYRS_ENVIRONMENT", "development")
os.environ.setdefault("VEYRS_SECRET_KEY", "test-secret-key-of-sufficient-length-0123456789")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import select, text  # noqa: E402

from veyrs.cli import init_db  # noqa: E402
from veyrs.db import SessionLocal, engine, set_tenant  # noqa: E402
from veyrs.main import app  # noqa: E402
from veyrs.models import Base, Organization, Role, User, UserRole  # noqa: E402
from veyrs.security.auth import hash_password  # noqa: E402

ADMIN_PASSWORD = "test-Admin-Password-123"


@pytest.fixture(scope="session", autouse=True)
def _schema():
    init_db(None)
    yield


def _flush_rate_limits() -> None:
    """Drop the limiter's counters.

    The rate limiter is a production control and stays enabled, but every test
    login arrives from the same identity (ip=testclient). Across a full suite
    that trips the 10/min auth limit and the *fixture* fails with 429, making
    results depend on execution order. The limiter's own behaviour is asserted
    in test_phase10_hardening against isolated apps.
    """
    from veyrs.security import ratelimit

    ratelimit.reset_local()
    client = ratelimit._redis()
    if client is None:
        return
    try:
        keys = list(client.scan_iter("veyrs:rl:*"))
        if keys:
            client.delete(*keys)
    except Exception:                          # a missing Redis is not a test failure
        pass


@pytest.fixture(scope="session", autouse=True)
def _clear_rate_limits():
    _flush_rate_limits()
    yield
    _flush_rate_limits()


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)


def _make_org(slug_prefix: str) -> tuple[uuid.UUID, str, str]:
    """Create an isolated organization with an org-admin. Returns (id, slug, email)."""
    slug = f"{slug_prefix}-{uuid.uuid4().hex[:8]}"
    email = f"admin@{slug}.test"
    with SessionLocal() as session:
        org = Organization(name=slug.title(), slug=slug)
        session.add(org)
        session.flush()
        set_tenant(session, org.id)
        user = User(organization_id=org.id, email=email, full_name="Test Admin",
                    password_hash=hash_password(ADMIN_PASSWORD))
        session.add(user)
        session.flush()
        role = session.execute(
            select(Role).where(Role.slug == "org-admin", Role.organization_id.is_(None))
        ).scalar_one()
        session.add(UserRole(organization_id=org.id, user_id=user.id, role_id=role.id))
        session.commit()
        return org.id, slug, email


@pytest.fixture()
def org_a():
    return _make_org("tenant-a")


@pytest.fixture()
def org_b():
    return _make_org("tenant-b")


def login(client: TestClient, email: str, slug: str, password: str = ADMIN_PASSWORD) -> dict:
    _flush_rate_limits()      # fixtures must not be throttled by the app's own limiter
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password, "organization": slug},
    )
    assert response.status_code == 200, response.text
    return response.json()


def auth_headers(client: TestClient, email: str, slug: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client, email, slug)['access_token']}"}


@pytest.fixture()
def admin_a(client, org_a):
    _, slug, email = org_a
    return auth_headers(client, email, slug)


@pytest.fixture()
def admin_b(client, org_b):
    _, slug, email = org_b
    return auth_headers(client, email, slug)
