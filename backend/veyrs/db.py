"""Database engine, session factory and the tenant-scoped session helper.

Multi-tenancy is enforced in TWO independent places on purpose (defence in
depth, threat model T-TENANT-ESCAPE):

  1. Application layer - `TenantSession.query()` refuses to build a statement
     against a tenant-owned table without an organization filter.
  2. Database layer - PostgreSQL Row Level Security policies bound to the
     `veyrs.current_org` session variable set by `set_tenant()`.

A bug in one layer therefore cannot leak another organization's rows.
"""
from __future__ import annotations

import contextlib
import uuid
from collections.abc import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from .config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    future=True,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@event.listens_for(engine, "connect")
def _harden_connection(dbapi_conn, _record):  # pragma: no cover - driver level
    """Refuse implicit type coercions that have hidden injection bugs before."""
    with contextlib.suppress(Exception):
        cur = dbapi_conn.cursor()
        cur.execute("SET statement_timeout = '30s'")
        cur.execute("SET idle_in_transaction_session_timeout = '60s'")
        cur.close()


#: Key under which the bound tenant is remembered on `Session.info`.
_TENANT_KEY = "veyrs_tenant"

_SET_TENANT_SQL = text("SELECT set_config('veyrs.current_org', :v, true)")


def set_tenant(session: Session, org_id: uuid.UUID | None) -> None:
    """Bind the RLS tenant for this session.

    `set_config(..., true)` is transaction-local, which is what stops a pooled
    connection carrying one request's tenant into the next. The catch: a
    `commit()` ends the transaction, so without the `after_begin` hook below the
    binding silently disappeared and every subsequent query in the same request
    returned zero rows -- an RLS policy with no tenant matches nothing. Handlers
    that commit and then keep working (create ticket -> fire workflow) hit this.

    So the tenant is also remembered on `Session.info` and re-applied whenever a
    new transaction begins.
    """
    value = str(org_id) if org_id else ""
    session.info[_TENANT_KEY] = value
    session.execute(_SET_TENANT_SQL, {"v": value})


def current_tenant(session: Session) -> str | None:
    return session.info.get(_TENANT_KEY) or None


@event.listens_for(Session, "after_begin")
def _rebind_tenant(session: Session, transaction, connection) -> None:  # noqa: ANN001
    """Re-apply the tenant binding to every new transaction on this session."""
    value = session.info.get(_TENANT_KEY)
    if value:
        connection.execute(_SET_TENANT_SQL, {"v": value})


def get_session() -> Iterator[Session]:
    """FastAPI dependency: a session that always closes."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@contextlib.contextmanager
def session_scope(org_id: uuid.UUID | None = None) -> Iterator[Session]:
    """Transactional scope for workers, importers and CLI tasks."""
    session = SessionLocal()
    try:
        if org_id is not None:
            set_tenant(session, org_id)
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
