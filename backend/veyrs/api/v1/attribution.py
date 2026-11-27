"""Why did this finding change? (see services/attribution.py)

Two read-only routes:

* `GET /findings/{id}/attribution` -- every state transition of one finding
  with its cause, actor and evidence, and a regression assessment on reopens.
  Same visibility as the finding detail: tenant, then team scope, 404 when the
  caller may not see it.
* `GET /findings/changes` -- recent closes and reopens across the estate the
  caller can see, filterable by cause.

The router is registered BEFORE the findings router: `/findings/changes`
would otherwise be captured by `/findings/{finding_id}` and answer 422.
Tagged `vulnerability management`, which `security/scope.py` lists as a
team-scoped tag -- and both routes do narrow by scope.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from ...security.deps import Principal, TenantSession, require
from ...services import attribution
from .findings import _get_finding

router = APIRouter(tags=["vulnerability management"])


@router.get("/findings/changes", summary="Recent closes and reopens, with their cause")
def recent_changes(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
    since: dt.datetime | None = Query(
        default=None, description="ISO timestamp. Default: 30 days ago."),
    cause: str | None = Query(default=None, description="One of the attribution causes."),
    kind: str | None = Query(default=None, pattern="^(closed|reopened)$",
                             description="closed | reopened. Default: both."),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> dict:
    if cause is not None and cause not in attribution.CAUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown cause {cause!r}; expected one of "
                            f"{sorted(attribution.CAUSES)}")
    now = dt.datetime.now(dt.timezone.utc)
    if since is None:
        since = now - dt.timedelta(days=30)
    elif since.tzinfo is None:
        since = since.replace(tzinfo=dt.timezone.utc)
    kinds = frozenset({kind}) if kind else frozenset({"closed", "reopened"})
    result = attribution.recent_changes(
        session, principal.organization_id, principal.scope,
        since=since, kinds=kinds, cause=cause, page=page, size=size,
    )
    result["scope"] = principal.scope.as_dict()
    return result


@router.get("/findings/{finding_id}/attribution",
            summary="Why did this finding change? Every transition with its cause")
def finding_attribution(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict:
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    return attribution.explain(session, finding)
