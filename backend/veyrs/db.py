"""Database engine, session factory and the tenant-scoped session helper.

Multi-tenancy (threat model T-TENANT-ESCAPE):

  1. Database layer, the control -- PostgreSQL Row Level Security policies
     bound to the `veyrs.current_org` session variable set by `set_tenant()`.
     The production API refuses to start under a role that bypasses RLS
     (superuser or BYPASSRLS), see `security/tenant_guard.py`.
  2. Application layer, a convention -- queries also filter on
     `organization_id`, and `TenantSession` (security/deps.py) is a session
     already bound to the caller's tenant. Nothing refuses a statement that
     forgets the filter; `security/tenant_guard.py` flags a tenant-table
     statement run with NO tenant bound (on with VEYRS_DEBUG, and in tests).
"""
from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker

from .config import settings

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    future=True,
    echo=False,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


_hardening_warned = False


@event.listens_for(engine, "connect")
def _harden_connection(dbapi_conn, _record):  # pragma: no cover - driver level
    """Bound runaway statements and abandoned transactions (best effort)."""
    try:
        cur = dbapi_conn.cursor()
        cur.execute("SET statement_timeout = '30s'")
        cur.execute("SET idle_in_transaction_session_timeout = '60s'")
        cur.close()
    except Exception as exc:  # noqa: BLE001 - never block a connection over a guard rail
        # Without the timeouts a runaway query or a stuck transaction is not
        # bounded; say so once instead of failing silently.
        global _hardening_warned
        if not _hardening_warned:
            _hardening_warned = True
            logging.getLogger("veyrs.db").warning(
                "could not apply the statement/idle-transaction timeouts to a new "
                "connection (%s); queries on this pool are unbounded", exc.__class__.__name__)


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
