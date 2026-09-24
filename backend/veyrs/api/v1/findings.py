"""Vulnerability and finding API: the operator's daily work queue.

The distinction the whole product rests on:

* **Vulnerability** = "CVE-2026-0001 matters to this organization" (one row per
  tenant per CVE).
* **Finding** = "CVE-2026-0001 is present on fw-edge-01:443" (one row per
  affected place). Findings carry the risk score, the owner, the SLA and the
  lifecycle; vulnerabilities roll up the worst of them.

Everything is filtered on the principal's organization, and RLS backs it up.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import false as sa_false, func, or_, select

from ...models import (
    Asset, CLOSED_STATES, Cve, Finding, FindingEvent, OPEN_STATES, RiskProfile, Vulnerability,
)
from ...security import scope as team_scope
from ...security.deps import Principal, TenantSession, require
from ...services import audit, correlation, intelligence
from ...services import risk as risk_service
from ...services import teams as teams_service
from ...services import sla as sla_service
from .schemas import Page
from .vuln_schemas import (
    AssetOut, FindingBulkAssign, FindingBulkTransition, FindingDetail, FindingOut,
    FindingTransition, RiskProfileOut, RiskProfileWrite, RiskSimulateRequest,
    VulnerabilityOut,
)

router = APIRouter(tags=["vulnerability management"])


def _actor(request: Request, principal: Principal) -> dict:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": ip,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------


@router.get("/vulnerabilities", response_model=Page[VulnerabilityOut],
            summary="List vulnerabilities affecting this organization")
def list_vulnerabilities(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("vulnerability:read"))],
    q: str | None = None,
    severity: str | None = None,
    kev: bool | None = None,
    state: str | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=100),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[VulnerabilityOut]:
    stmt = select(Vulnerability).where(
        Vulnerability.organization_id == principal.organization_id
    )
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Vulnerability.cve_id.ilike(needle), Vulnerability.title.ilike(needle),
            Vulnerability.description.ilike(needle),
        ))
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev.is_(kev))
    if state:
        stmt = stmt.where(Vulnerability.state == state)
    if min_risk is not None:
        stmt = stmt.where(Vulnerability.risk_score >= min_risk)
    if principal.scope.restricted:
        # A vulnerability is a roll-up across the estate. Under a team scope it
        # is visible when at least one of its findings is -- listing it with an
        # affected-asset count the caller cannot reach would leak the shape of
        # someone else's estate through a summary row.
        visible = team_scope.findings(
            select(Finding.vulnerability_id).where(
                Finding.organization_id == principal.organization_id
            ),
            principal.scope,
        )
        stmt = stmt.where(Vulnerability.id.in_(visible))

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(Vulnerability.risk_score.desc().nullslast())
        .offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page.of([VulnerabilityOut.model_validate(r) for r in rows], total, page, size)


@router.get("/vulnerabilities/{vulnerability_id}", summary="Vulnerability detail")
def get_vulnerability(
    vulnerability_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("vulnerability:read"))],
) -> dict:
    row = session.get(Vulnerability, vulnerability_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    detail_stmt = team_scope.findings(
        select(Finding).where(Finding.vulnerability_id == row.id), principal.scope
    )
    findings = session.execute(
        detail_stmt.order_by(Finding.risk_score.desc().nullslast())
    ).scalars().all()
    if principal.scope.restricted and not findings:
        # Nothing of this vulnerability is in scope. Returning the roll-up with
        # an empty list would still disclose that the tenant is affected.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    payload = VulnerabilityOut.model_validate(row).model_dump()
    payload["findings"] = [FindingOut.model_validate(f).model_dump() for f in findings]
    payload["open_findings"] = len([f for f in findings if f.state in OPEN_STATES])
    if row.cve_id:
        payload["intelligence"] = intelligence.intelligence_snapshot(session, row.cve_id)
    return payload


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


def _get_finding(session, organization_id: uuid.UUID, finding_id: uuid.UUID,
                 scope: team_scope.TeamScope = team_scope.UNRESTRICTED) -> Finding:
    row = session.get(Finding, finding_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if not team_scope.finding_visible(session, row, scope):
        # 404, not 403: see `_get_asset` in assets.py -- a 403 would confirm the
        # finding exists, which is the one thing segregation must not leak.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return row


def _label_findings(session, rows: list[FindingOut], sources: list) -> list[FindingOut]:
    """Resolve assignment labels and the *effective* owning team for a page.

    `owning_team_id` is computed here rather than read from a column because it
    does not exist as one: a finding with no explicit assignment is still owned,
    by whoever owns its asset. Showing an empty owner for those rows is what
    made ownership look unpopulated when it was merely implicit.
    """
    asset_ids = [f.asset_id for f in sources]
    asset_teams = dict(session.execute(
        select(Asset.id, Asset.team_id).where(Asset.id.in_(asset_ids or [uuid.uuid4()]))
    ).all())
    for row, source in zip(rows, sources):
        row.owning_team_id = row.assigned_team_id or asset_teams.get(source.asset_id)
    names = teams_service.resolve_names(
        session,
        team_ids=[r.assigned_team_id for r in rows] + [r.owning_team_id for r in rows],
        user_ids=[r.assigned_user_id for r in rows],
    )
    for row in rows:
        row.assigned_team_name = names["teams"].get(row.assigned_team_id)
        row.owning_team_name = names["teams"].get(row.owning_team_id)
        row.assigned_user_name = names["users"].get(row.assigned_user_id)
    return rows


@router.get("/findings", response_model=Page[FindingOut], summary="The work queue")
def list_findings(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
    q: str | None = None,
    state: str | None = None,
    open_only: bool = True,
    severity: str | None = None,
    risk_level: str | None = None,
    min_risk: float | None = Query(default=None, ge=0, le=100),
    kev: bool | None = None,
    min_epss: float | None = Query(default=None, ge=0, le=1),
    exposure: str | None = None,
    asset_id: uuid.UUID | None = None,
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
    owning_team_id: uuid.UUID | None = Query(
        default=None,
        description="Effective owner: explicit assignment, else the asset's team. "
                    "Prefer this over assigned_team_id for a team queue.",
    ),
    my_teams: bool = Query(default=False, description="Owned by any team I belong to."),
    mine: bool = Query(default=False, description="Assigned to me personally."),
    unowned: bool = Query(default=False, description="No owning team at all."),
    sla_breached: bool | None = None,
    order: str = Query(default="risk", pattern="^(risk|sla|detected|severity)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[FindingOut]:
    stmt = select(Finding).where(Finding.organization_id == principal.organization_id)
    if state:
        stmt = stmt.where(Finding.state == state)
    elif open_only:
        stmt = stmt.where(Finding.state.in_(tuple(OPEN_STATES)))
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q.strip()}%"))
    for column, value in (
        (Finding.severity, severity), (Finding.risk_level, risk_level),
        (Finding.asset_id, asset_id), (Finding.assigned_team_id, assigned_team_id),
        (Finding.assigned_user_id, assigned_user_id),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
    if min_risk is not None:
        stmt = stmt.where(Finding.risk_score >= min_risk)
    if kev is not None:
        stmt = stmt.where(Finding.kev.is_(kev))
    if min_epss is not None:
        stmt = stmt.where(Finding.epss_score >= min_epss)
    if sla_breached is not None:
        stmt = stmt.where(Finding.sla_breached.is_(sla_breached))
    if exposure:
        stmt = stmt.join(Asset, Asset.id == Finding.asset_id).where(Asset.exposure == exposure)

    stmt = team_scope.findings(stmt, principal.scope)
    owner = teams_service.owning_team()
    if owning_team_id is not None:
        stmt = stmt.where(owner == owning_team_id)
    if unowned:
        stmt = stmt.where(owner.is_(None))
    if mine:
        stmt = stmt.where(Finding.assigned_user_id == principal.user_id)
    if my_teams:
        # An API key has no memberships. Rather than quietly returning the whole
        # estate, an empty membership set returns nothing: "my queue" for a
        # machine identity is a question with no answer, not "everything".
        member_of = teams_service.member_team_ids(session, principal.user_id)
        stmt = stmt.where(owner.in_(tuple(member_of)) if member_of else sa_false())

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    ordering = {
        "risk": (Finding.risk_score.desc().nullslast(),),
        "sla": (Finding.sla_breached.desc(), Finding.sla_due_at.asc().nullslast()),
        "detected": (Finding.detected_at.desc(),),
        "severity": (Finding.severity.asc(), Finding.risk_score.desc().nullslast()),
    }[order]
    rows = session.execute(
        stmt.order_by(*ordering).offset((page - 1) * size).limit(size)
    ).scalars().all()
    items = _label_findings(session, [FindingOut.model_validate(r) for r in rows], rows)
    return Page.of(items, total, page, size)


@router.get("/findings/{finding_id}", response_model=FindingDetail, summary="Finding detail")
def get_finding(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> FindingDetail:
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    detail = FindingDetail.model_validate(finding)
    _label_findings(session, [detail], [finding])
    detail.sla = sla_service.sla_status(finding)
    asset = session.get(Asset, finding.asset_id)
    if asset is not None:
        detail.asset = AssetOut.model_validate(asset)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    if vulnerability is not None and vulnerability.cve_id:
        detail.cve = intelligence.intelligence_snapshot(session, vulnerability.cve_id)
    events = session.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.created_at)
    ).scalars().all()
    detail.events = [{
        "at": e.created_at.isoformat(), "event": e.event, "actor": e.actor_label,
        "details": e.details,
    } for e in events]
    return detail


@router.post("/findings/{finding_id}/transition", response_model=FindingOut,
             summary="Move a finding through the lifecycle")
def transition_finding(
    finding_id: uuid.UUID,
    payload: FindingTransition,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:write"))],
) -> FindingOut:
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    before = finding.state
    try:
        correlation.transition(
            session, finding, payload.state,
            actor_id=principal.user_id, actor_label=principal.label, note=payload.note,
        )
    except correlation.TransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    if vulnerability is not None:
        risk_service.rollup_vulnerability(session, vulnerability)
    audit.record(session, action="finding.transition", object_type="finding",
                 object_id=str(finding.id), **_actor(request, principal), changes=audit.diff({"state": before}, {"state": finding.state}))
    session.commit()
    session.refresh(finding)
    return FindingOut.model_validate(finding)


@router.post("/findings/bulk-transition", summary="Bulk lifecycle change")
def bulk_transition(
    payload: FindingBulkTransition,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:write"))],
) -> dict:
    """Partial success is reported per id rather than failing the whole batch.

    An operator closing 200 false positives should not lose 199 successes
    because one of them was already closed.
    """
    results: dict[str, list[str]] = {"changed": [], "rejected": []}
    for finding_id in payload.finding_ids:
        finding = session.get(Finding, finding_id)
        if (finding is None or finding.organization_id != principal.organization_id
                or not team_scope.finding_visible(session, finding, principal.scope)):
            results["rejected"].append(str(finding_id))
            continue
        try:
            correlation.transition(
                session, finding, payload.state,
                actor_id=principal.user_id, actor_label=principal.label, note=payload.note,
            )
            results["changed"].append(str(finding_id))
        except correlation.TransitionError:
            results["rejected"].append(str(finding_id))
    audit.record(session, action="finding.bulk_transition", object_type="finding",
                 object_id=None,
                 **_actor(request, principal), changes=audit.diff(None, {"state": payload.state,
                                          "changed": len(results["changed"])}))
    session.commit()
    return {"state": payload.state, **results,
            "changed_count": len(results["changed"]),
            "rejected_count": len(results["rejected"])}


@router.post("/findings/bulk-assign", summary="Assign many findings to a team or person")
def bulk_assign_findings(
    payload: FindingBulkAssign,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:write"))],
) -> dict:
    """Route up to 500 findings to a team and/or a person.

    Every change writes a `FindingEvent`, not just an audit row: the finding's
    own history is what an auditor reads when asking *why* a breached SLA sat
    with the wrong team for a week, and a reassignment is the most common
    answer. `reason` lands in `assignment_reason`, the same column the
    AssignmentRule engine writes, so manual and automatic ownership are read
    the same way instead of one of them looking unexplained.
    """
    try:
        changes = payload.assignments(("assigned_team_id", "assigned_user_id"))
        teams_service.validate_team(
            session, principal.organization_id, changes.get("assigned_team_id")
        )
        teams_service.validate_user(
            session, principal.organization_id, changes.get("assigned_user_id")
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "nothing to assign: set a field or list it in `clear`")

    target = changes.get("assigned_team_id")
    if (principal.scope.restricted and "assigned_team_id" in changes
            and (target is None or target not in principal.scope.team_ids)):
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "cannot assign work outside your own team scope")

    results: dict[str, list[str]] = {"changed": [], "rejected": []}
    for finding_id in payload.finding_ids:
        finding = session.get(Finding, finding_id)
        if (finding is None or finding.organization_id != principal.organization_id
                or not team_scope.finding_visible(session, finding, principal.scope)):
            results["rejected"].append(str(finding_id))
            continue
        before = {"assigned_team_id": finding.assigned_team_id,
                  "assigned_user_id": finding.assigned_user_id}
        for field, value in changes.items():
            setattr(finding, field, value)
        finding.assignment_reason = payload.reason or f"manual assignment by {principal.label}"
        session.add(FindingEvent(
            organization_id=principal.organization_id, finding_id=finding.id,
            actor_id=principal.user_id, actor_label=principal.label, event="assigned",
            note=payload.reason,
            details={"from": {k: str(v) if v else None for k, v in before.items()},
                     "to": {k: str(v) if v else None for k, v in changes.items()}},
        ))
        results["changed"].append(str(finding_id))

    audit.record(session, action="finding.bulk_assign", object_type="finding", object_id=None,
                 **_actor(request, principal),
                 changes=audit.diff(None, {**{k: str(v) for k, v in changes.items()},
                                           "changed": len(results["changed"])}))
    session.commit()
    return {**results, "changed_count": len(results["changed"]),
            "rejected_count": len(results["rejected"])}


@router.post("/findings/{finding_id}/accept-risk", response_model=FindingOut,
             summary="Formally accept a risk")
def accept_risk(
    finding_id: uuid.UUID,
    reason: Annotated[str, Query(min_length=10, max_length=2000)],
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:admin"))],
    until: dt.date | None = None,
) -> FindingOut:
    """Risk acceptance needs `risk:admin`, not `finding:write`.

    Accepting a risk is a business decision with audit consequences; an analyst
    who can triage findings must not be able to silently make one disappear.
    """
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    try:
        correlation.transition(session, finding, "accepted_risk",
                               actor_id=principal.user_id, actor_label=principal.label,
                               note=reason)
    except correlation.TransitionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    finding.accepted_by_id = principal.user_id
    finding.accepted_reason = reason
    finding.accepted_until = until
    audit.record(session, action="finding.accept_risk", object_type="finding",
                 object_id=str(finding.id),
                 **_actor(request, principal), changes=audit.diff(None, {"reason": reason, "until": until.isoformat() if until else None}))
    session.commit()
    session.refresh(finding)
    return FindingOut.model_validate(finding)


@router.post("/findings/{finding_id}/rescore", response_model=FindingOut,
             summary="Re-run the risk engine for one finding")
def rescore_finding(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
    profile_id: uuid.UUID | None = None,
) -> FindingOut:
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    profile = risk_service.resolve_profile(session, principal.organization_id, profile_id)
    risk_service.score_finding(session, finding, profile=profile, reason="manual rescore")
    session.commit()
    session.refresh(finding)
    return FindingOut.model_validate(finding)


# --------------------------------------------------------------------------
# Risk profiles + simulator
# --------------------------------------------------------------------------


@router.get("/risk/profiles", response_model=list[RiskProfileOut], summary="Risk profiles")
def list_profiles(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskprofile:read"))],
) -> list[RiskProfileOut]:
    rows = session.execute(
        select(RiskProfile).where(RiskProfile.organization_id == principal.organization_id)
        .order_by(RiskProfile.is_default.desc(), RiskProfile.name)
    ).scalars().all()
    return [RiskProfileOut.model_validate(r) for r in rows]


@router.post("/risk/profiles", response_model=RiskProfileOut,
             status_code=status.HTTP_201_CREATED, summary="Create a custom risk profile")
def create_profile(
    payload: RiskProfileWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskprofile:write"))],
) -> RiskProfileOut:
    existing = session.execute(
        select(RiskProfile).where(
            RiskProfile.organization_id == principal.organization_id,
            RiskProfile.slug == payload.slug,
        )
    ).scalars().first()
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "profile slug already exists")
    if payload.is_default:
        for row in session.execute(
            select(RiskProfile).where(
                RiskProfile.organization_id == principal.organization_id,
                RiskProfile.is_default.is_(True),
            )
        ).scalars().all():
            row.is_default = False
    row = RiskProfile(organization_id=principal.organization_id, is_builtin=False,
                      **payload.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return RiskProfileOut.model_validate(row)


@router.post("/risk/simulate", summary="What-if risk calculation (no persistence)")
def simulate_risk(
    payload: RiskSimulateRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:read"))],
) -> dict:
    from ...engines import risk as engine

    profile = None
    if payload.profile:
        profile = session.execute(
            select(RiskProfile).where(
                RiskProfile.organization_id == principal.organization_id,
                RiskProfile.slug == payload.profile,
            )
        ).scalars().first()

    data = engine.RiskInput(
        cvss_score=payload.cvss_score,
        cvss_vector=payload.cvss_vector,
        epss_score=payload.epss_score,
        epss_percentile=payload.epss_percentile,
        kev=payload.kev,
        exploit_known=payload.exploit_known,
        exploit_maturity=payload.exploit_maturity,
        asset_criticality=payload.asset_criticality,
        data_classification=payload.data_classification,
        exposure=payload.exposure,
        environment=payload.environment,
        age_days=payload.age_days,
        exposure_days=payload.exposure_days,
        compensating_controls=payload.compensating_controls,
        revenue_per_hour=payload.revenue_per_hour,
    )
    result = engine.evaluate(
        data,
        weights=(profile.weights if profile else None),
        options=(profile.options if profile else None),
        profile_slug=(profile.slug if profile else "balanced"),
    )
    return result.as_dict()


@router.post("/risk/rescore", summary="Re-score every open finding")
def rescore_all(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:admin"))],
    profile_id: uuid.UUID | None = None,
) -> dict:
    if principal.scope.restricted:
        # A partial rescore followed by a whole-tenant vulnerability roll-up
        # would produce roll-ups computed from a mix of old and new scores.
        # There is no correct narrowed answer here, so there is no answer.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "re-scoring is an estate-wide operation and cannot be "
                            "narrowed to a team")
    profile = risk_service.resolve_profile(session, principal.organization_id, profile_id)
    findings = session.execute(
        select(Finding).where(
            Finding.organization_id == principal.organization_id,
            Finding.state.in_(tuple(OPEN_STATES)),
        )
    ).scalars().all()
    changed = risk_service.rescore_findings(
        session, principal.organization_id, findings,
        profile=profile, reason="bulk rescore",
    )
    for vulnerability in session.execute(
        select(Vulnerability).where(
            Vulnerability.organization_id == principal.organization_id
        )
    ).scalars().all():
        risk_service.rollup_vulnerability(session, vulnerability)
    session.commit()
    return {"findings": len(findings), "changed": changed,
            "profile": profile.slug if profile else "engine-default"}
