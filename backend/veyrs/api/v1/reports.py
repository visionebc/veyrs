"""Dashboards and report exports (spec sections 27 and 29).

Authorization note: each report declares its own permission in
`services/reporting.REPORTS`, and the route enforces THAT rather than a blanket
`report:read`. An asset register is asset data; a compliance report is
compliance data. One permission for "reports" would have been a way to read
everything through the export door.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ...security import scope as team_scope
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...services import analytics, audit, reporting

router = APIRouter(tags=["dashboards & reports"])


def _refuse_if_scoped(principal: Principal) -> None:
    """Report exports are estate-wide documents; they are not narrowed.

    A dashboard carries a `scope` block and is read on screen by the person who
    owns the scope. An exported PDF outlives that context: it gets attached to
    an audit, an insurance questionnaire or a board pack, where "asset register"
    means the register. Producing a one-team file under the same title is the
    kind of quiet error nobody catches until it matters, so a team-scoped
    identity is refused instead.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "report exports cover the whole estate and are not narrowed to a team; "
        "use the dashboards, which state their scope",
    )


TEAM_FILTER = Query(default=None, description="Narrow every figure to one owning team")


def _view(session, principal: Principal, team_id: uuid.UUID | None):
    """The scope one dashboard read runs under: the principal's, or one team's.

    `?team_id=` is a *view* filter and reuses `TeamScope` rather than threading
    a `team_id` argument through `analytics`: every existing predicate is
    already scope-aware, so the per-team dashboard is the estate dashboard with
    a smaller set and no second code path to keep in step.

    The body moved to `security.scope.resolve_view` in v0.17.1, when
    `/policies/sla/*` became the second surface offering the filter. Two copies
    of "look up the team, 404 on another tenant's, name it in the response"
    would have been two chances to drop one of the three.
    """
    return team_scope.resolve_view(session, principal.scope,
                                   principal.organization_id, team_id)


# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------
@router.get("/dashboard/executive")
def executive_dashboard(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("report:read"))],
    days: int = Query(default=90, ge=7, le=730),
    team_id: uuid.UUID | None = TEAM_FILTER,
) -> dict[str, Any]:
    return analytics.executive_dashboard(session, principal.organization_id, days=days,
                                     scope=_view(session, principal, team_id))


@router.get("/dashboard/technical")
def technical_dashboard(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("report:read"))],
    team_id: uuid.UUID | None = TEAM_FILTER,
) -> dict[str, Any]:
    return analytics.technical_dashboard(session, principal.organization_id,
                                     scope=_view(session, principal, team_id))


@router.get("/dashboard/sla")
def sla_dashboard(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:read"))],
    days: int = Query(default=90, ge=7, le=730),
    team_id: uuid.UUID | None = TEAM_FILTER,
) -> dict[str, Any]:
    return analytics.sla_report(session, principal.organization_id, days=days,
                                scope=_view(session, principal, team_id))


@router.get("/dashboard/trends")
def trends(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("report:read"))],
    days: int = Query(default=90, ge=7, le=730),
    buckets: int = Query(default=12, ge=2, le=52),
    team_id: uuid.UUID | None = TEAM_FILTER,
) -> dict[str, Any]:
    view = _view(session, principal, team_id)
    return {
        # Was assembled by hand here and so did not carry the team filter the
        # other three dashboards report. One builder, one shape.
        "scope": analytics.scope_block(view),
        "risk": analytics.risk_trend(session, principal.organization_id,
                                     days=days, buckets=buckets, scope=view),
        "findings": analytics.finding_trend(session, principal.organization_id,
                                            days=days, buckets=buckets, scope=view),
    }


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@router.get("/reports")
def list_reports(
    principal: CurrentPrincipal,
) -> dict[str, Any]:
    """The catalogue, annotated with what THIS caller may actually export."""
    return {
        "formats": list(reporting.FORMATS),
        "reports": [
            {**entry, "available": principal.can(entry["permission"])}
            for entry in reporting.catalogue()
        ],
    }


@router.get("/reports/{slug}")
def build_report(
    slug: str,
    session: TenantSession,
    principal: CurrentPrincipal,
    days: int = Query(default=90, ge=7, le=730),
    limit: int = Query(default=1000, ge=1, le=20000),
    framework_id: uuid.UUID | None = Query(default=None),
) -> dict[str, Any]:
    spec = _spec(slug)
    principal.require(spec.permission)
    _refuse_if_scoped(principal)
    try:
        return reporting.build(
            session, principal.organization_id, slug,
            days=days, limit=limit,
            **({"framework_id": framework_id} if framework_id else {}),
        )
    except reporting.ReportError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.get("/reports/{slug}/export")
def export_report(
    slug: str,
    session: TenantSession,
    principal: CurrentPrincipal,
    format: str = Query(default="json"),
    days: int = Query(default=90, ge=7, le=730),
    limit: int = Query(default=1000, ge=1, le=20000),
    framework_id: uuid.UUID | None = Query(default=None),
) -> Response:
    spec = _spec(slug)
    principal.require(spec.permission)
    _refuse_if_scoped(principal)
    try:
        payload, content_type, filename = reporting.render(
            session, principal.organization_id, slug, format,
            days=days, limit=limit,
            **({"framework_id": framework_id} if framework_id else {}),
        )
    except reporting.ReportError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    # Exports leave the platform, so they are audited like any other egress.
    audit.record(
        session, action="report.exported", object_type="report", object_id=slug,
        object_label=spec.title, organization_id=principal.organization_id,
        actor_id=principal.user_id, actor_label=principal.label,
        changes={"format": format, "bytes": len(payload)},
    )
    session.commit()
    return Response(
        content=payload, media_type=content_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _spec(slug: str) -> reporting.ReportSpec:
    spec = reporting.REPORTS.get(slug)
    if spec is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            f"unknown report {slug!r}; known: {sorted(reporting.REPORTS)}",
        )
    return spec
