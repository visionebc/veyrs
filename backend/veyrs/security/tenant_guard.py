"""Tenant isolation guards that do not depend on remembering a filter (R-23).

What actually isolates tenants is PostgreSQL Row Level Security, bound per
session by `db.set_tenant()`. A query's own `organization_id ==` filter is a
second layer only by convention: nothing refuses a statement without one, and
plenty of correct code relies on RLS alone (`session.get(Team, id)`). RLS in
turn has two ways to fail silently, and this module turns both into errors:

1. **The role bypasses RLS.** A superuser or `BYPASSRLS` database role skips
   every policy, so one missing filter becomes a cross-tenant read with no
   error. `rls_bypass_problem()` reports it; the API refuses to start in
   production when it is true (`main.lifespan`).
2. **The tenant is not bound.** A strictly isolated table queried with no
   tenant bound returns nothing (or fails WITH CHECK) under a correct role --
   and returns EVERY tenant's rows under a bypassing one. `install()` hooks
   every ORM statement: one that touches a strictly isolated table while
   `db.current_tenant(session)` is empty is a violation. `MODE` decides what a
   violation does: `off` (production default: no cost beyond one attribute
   read), `log` (on when VEYRS_DEBUG is true), `raise`, or `record` (tests
   collect them; tests/test_fix_auth.py walks every GET route with it).

What it does NOT guarantee: that a query bound to the RIGHT tenant also
filters correctly inside it (team scope is `security/scope.py`'s job), nor
anything about raw SQL sent with `text()` (no mapper, so not inspected), nor
the credential-keyed tables that are deliberately readable before
authentication (`cli.RLS_TABLES_PREAUTH`).
"""
from __future__ import annotations

import logging
from functools import lru_cache

from sqlalchemy import event, text
from sqlalchemy.orm import Session
from sqlalchemy.sql.util import find_tables

from ..config import settings

log = logging.getLogger("veyrs.tenant_guard")

MODE = "log" if settings.debug else "off"
violations: list[str] = []
_installed = False


class TenantUnbound(RuntimeError):
    """A strictly isolated table was queried with no tenant bound."""


@lru_cache(maxsize=1)
def strict_tables() -> frozenset[str]:
    """Tables whose RLS policy is strict: exactly what `init-db` makes strict."""
    from ..cli import (RLS_TABLES_PREAUTH, RLS_TABLES_SKIP,  # noqa: PLC0415 - avoid a cycle
                       RLS_TABLES_STRICT_NULLABLE)
    from ..models import Base  # noqa: PLC0415

    out = set()
    for name, table in Base.metadata.tables.items():
        if name in RLS_TABLES_SKIP or name in RLS_TABLES_PREAUTH:
            continue
        if "organization_id" not in table.c:
            continue
        if table.c.organization_id.nullable and name not in RLS_TABLES_STRICT_NULLABLE:
            continue
        out.add(name)
    return frozenset(out)


def _tables(statement) -> set[str]:  # noqa: ANN001 - any executable
    try:
        return {t.name for t in find_tables(statement, include_aliases=True,
                                            include_joins=True, include_crud=True)
                if getattr(t, "name", None)}
    except Exception:  # noqa: BLE001 - an exotic construct must not break a query
        return set()


def _check(state) -> None:  # noqa: ANN001 - ORMExecuteState
    if MODE == "off":
        return
    from ..db import current_tenant  # noqa: PLC0415

    if current_tenant(state.session):
        return
    names = _tables(state.statement) | {m.local_table.name for m in state.all_mappers
                                         if getattr(m, "local_table", None) is not None}
    hit = names & strict_tables()
    if not hit:
        return
    kind = ("select" if state.is_select else "update" if state.is_update
            else "delete" if state.is_delete else "statement")
    message = f"{kind} on {', '.join(sorted(hit))} with no tenant bound"
    if MODE == "raise":
        raise TenantUnbound(message)
    if MODE == "record":
        violations.append(message)
        return
    log.warning("tenant guard: %s", message, stack_info=True)


def install() -> None:
    """Hook every ORM statement (idempotent)."""
    global _installed
    if _installed:
        return
    event.listen(Session, "do_orm_execute", _check)
    _installed = True


def rls_bypass_problem(connection) -> str | None:  # noqa: ANN001 - SQLAlchemy Connection
    """Why RLS would not apply to this connection's role, or None."""
    row = connection.execute(text(
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
    )).one()
    if row.rolsuper:
        return "the database role is a superuser, which bypasses row level security"
    if row.rolbypassrls:
        return "the database role has BYPASSRLS, which bypasses row level security"
    return None
