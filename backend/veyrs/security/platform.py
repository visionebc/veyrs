"""Who may open the installation-wide pages (platform administration).

Software update, Installed software, Network access, Trust store, Web
certificate, the global intelligence feeds and the built-in compliance
frameworks concern the whole installation, not one organization. Until 0.42.2
only an account with `users.is_superuser` reached them, and that flag could be
set only on the host (`veyrs platform-admin`). An installation whose first
account was created without it -- or whose operator added another
administrator from the console -- had nobody in the console able to open them.

A platform administrator is now any of:

* an account with `is_superuser` (unchanged; granted on the host);
* an account holding `platform:admin` -- the built-in `platform-admin` role, or
  `org-admin` through its wildcard -- **in the home organization**, the one
  VEYRS was installed for (the oldest active organization; organizations are
  only ever created on the host, with `veyrs bootstrap`).

The home-organization condition keeps a multi-tenant installation safe: the
administrator of a second tenant holds the same wildcard and must not be able
to update, re-certify or re-trust everybody's installation. API keys and
enrolment-only sessions are never platform administrators.
"""
from __future__ import annotations

import time
import uuid

from sqlalchemy import select

PERMISSION = "platform:admin"
_TTL_SECONDS = 60.0
_cache: tuple[float, uuid.UUID | None] | None = None


def home_organization_id() -> uuid.UUID | None:
    """The organization this installation was set up for: the oldest active one.

    `organizations` carries no row level security, so a plain session sees all
    of them. Cached for a minute: it changes only when an operator creates or
    retires an organization on the host.
    """
    global _cache
    now = time.monotonic()
    if _cache is not None and now - _cache[0] < _TTL_SECONDS:
        return _cache[1]
    from ..db import SessionLocal
    from ..models.tenancy import Organization

    with SessionLocal() as session:
        home = session.execute(
            select(Organization.id)
            .where(Organization.is_active.is_(True), Organization.deleted_at.is_(None))
            .order_by(Organization.created_at, Organization.id)
            .limit(1)
        ).scalar_one_or_none()
    _cache = (now, home)
    return home


def reset_cache() -> None:
    global _cache
    _cache = None


def is_platform_admin(principal) -> bool:  # noqa: ANN001 -- security.deps.Principal
    if principal is None or principal.kind != "user" or principal.restriction:
        return False
    if principal.is_superuser:
        return True
    return (PERMISSION in principal.permissions
            and principal.organization_id == home_organization_id())
