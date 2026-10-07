"""Engagements, scan tests, endpoints and risk acceptance (spec section 32).

Permission mapping, and why it is not a new resource:

* engagements and tests -> `importer:*`. They exist to scope an import, and
  anyone who may run one may organise them.
* endpoints -> `asset:*`. An endpoint is a location on an asset; marking one
  mitigated is an assertion about the estate, not about a finding's triage.
* risk acceptance -> `risk:*`. The built-in `executive` role already carries
  `risk:write` for exactly this ("read-only executive view plus formal risk
  acceptance"), so formal acceptance lands on the persona the spec designed for
  it without inventing a permission the role seeder has never heard of.

`permissions.is_valid()` rejects unknown strings at import time, so a new
resource here would be a schema change, a migration of every role, and a
re-seed. Reusing the existing ones is not a shortcut - it is the model working.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from ...models import (
    Endpoint, Engagement, EngagementType, Finding, FindingEndpoint, RiskAcceptance,
    RiskAcceptanceState, ScanTest, TestFinding,
)
from ...security.deps import Principal, TenantSession, require
from ...services import audit, dedupe, endpoints as endpoint_service, engagements
from .schemas import Page

router = APIRouter(prefix="/engagements", tags=["engagements"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    engagement_type: str
    status: str
    business_service_id: uuid.UUID | None
    asset_group_id: uuid.UUID | None
    target_start: dt.date | None
    target_end: dt.date | None
    started_at: dt.datetime | None
    completed_at: dt.datetime | None
    lead_user_id: uuid.UUID | None
    version: str | None
    branch_tag: str | None
    commit_hash: str | None
    build_id: str | None
    dedupe_within_engagement: bool
    tags: list


class EngagementWrite(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    engagement_type: str = Field(default=EngagementType.SCHEDULED.value)
    description: str | None = None
    business_service_id: uuid.UUID | None = None
    asset_group_id: uuid.UUID | None = None
    lead_user_id: uuid.UUID | None = None
    target_start: dt.date | None = None
    target_end: dt.date | None = None
    dedupe_within_engagement: bool = False
    version: str | None = Field(default=None, max_length=80)
    branch_tag: str | None = Field(default=None, max_length=200)
    commit_hash: str | None = Field(default=None, max_length=80)
    build_id: str | None = Field(default=None, max_length=120)
    tags: list[str] = Field(default_factory=list)


class ScanTestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    engagement_id: uuid.UUID
    title: str | None
    scanner: str
    environment: str | None
    target_start: dt.datetime | None
    target_end: dt.datetime | None
    version: str | None
    branch_tag: str | None
    commit_hash: str | None
    build_id: str | None
    last_import_run_id: uuid.UUID | None
    reimport_count: int
    dedupe_config: dict


class ScanTestDetail(ScanTestOut):
    #: How many findings this test has ever reported, and how many the most
    #: recent run did not. The pair is what tells an operator whether a
    #: reimport was a partial export or a genuine wave of remediation.
    scope_size: int
    present: int
    absent: int
    effective_dedupe: dict


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID | None
    protocol: str | None
    host: str
    port: int | None
    path: str | None
    query: str | None
    fragment: str | None
    canonical: str


class FindingEndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    finding_id: uuid.UUID
    endpoint_id: uuid.UUID
    first_seen_at: dt.datetime
    last_seen_at: dt.datetime
    mitigated: bool
    mitigated_at: dt.datetime | None
    false_positive: bool
    risk_accepted: bool
    method: str | None
    params: str | None
    param_location: str | None
    website: str | None


class MitigateEndpoints(BaseModel):
    endpoint_ids: list[uuid.UUID] = Field(min_length=1)


class RiskAcceptanceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    decision: str
    state: str
    reason: str
    compensating_controls: str | None
    requested_by_id: uuid.UUID | None
    approved_by_id: uuid.UUID | None
    approved_at: dt.datetime | None
    decided_note: str | None
    expires_on: dt.date | None
    expired_at: dt.datetime | None
    reactivate_on_expiry: bool
    restart_sla_on_expiry: bool
    proof_document_id: uuid.UUID | None
    created_at: dt.datetime


class RiskAcceptanceWrite(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    #: Not optional and not defaulted. An acceptance with no stated reason is
    #: the finding being silenced, and an auditor will read it that way.
    reason: str = Field(min_length=10, max_length=8000)
    finding_ids: list[uuid.UUID] = Field(min_length=1)
    decision: str = "accepted"
    expires_on: dt.date | None = None
    compensating_controls: str | None = Field(default=None, max_length=8000)
    reactivate_on_expiry: bool = True
    restart_sla_on_expiry: bool = False
    proof_document_id: uuid.UUID | None = None


class Decision(BaseModel):
    note: str | None = Field(default=None, max_length=4000)


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
@router.get("", response_model=Page[EngagementOut])
def list_engagements(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
    status_filter: str | None = Query(default=None, alias="status"),
    engagement_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[EngagementOut]:
    statement = select(Engagement).where(
        Engagement.organization_id == principal.organization_id
    )
    if status_filter:
        statement = statement.where(Engagement.status == status_filter)
    if engagement_type:
        statement = statement.where(Engagement.engagement_type == engagement_type)
    total = session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()
    rows = session.execute(
        statement.order_by(Engagement.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[EngagementOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(
    body: EngagementWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:write"))],
) -> EngagementOut:
    try:
        row = engagements.create_engagement(
            session, principal.organization_id, **body.model_dump()
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="engagement.create", object_type="engagement",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"type": row.engagement_type})
    session.commit()
    return EngagementOut.model_validate(row)


@router.get("/dedupe-registry")
def dedupe_registry(
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> dict[str, Any]:
    """Which deduplication rule each scanner uses, and what the words mean.

    Surfaced because a silent identity change is indistinguishable from a
    scanner behaving differently: when finding counts move, this is the first
    thing to check.
    """
    return {
        "algorithms": {
            dedupe.LEGACY: (
                "sha256 over organization, asset, CVE/plugin reference, port, "
                "protocol and path. The historical VEYRS rule; correct for "
                "network scanners, wrong for code and dependency scanners."
            ),
            dedupe.UNIQUE_ID: (
                "the tool's own per-instance identifier. Only for tools whose "
                "id already encodes the location."
            ),
            dedupe.HASH_CODE: "sha256 over a configured field list.",
            dedupe.UNIQUE_ID_OR_HASH: (
                "the tool's id when present, the field hash otherwise - matched "
                "on either, so a tool that starts emitting ids mid-life does "
                "not fork every finding it has ever reported."
            ),
        },
        "fields": sorted(dedupe.VALID_FIELDS),
        "scanners": dedupe.describe_registry(),
    }


@router.get("/{engagement_id}", response_model=EngagementOut)
def read_engagement(
    engagement_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> EngagementOut:
    return EngagementOut.model_validate(_engagement(session, principal, engagement_id))


@router.get("/{engagement_id}/tests", response_model=list[ScanTestOut])
def list_tests(
    engagement_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> list[ScanTestOut]:
    _engagement(session, principal, engagement_id)
    rows = session.execute(
        select(ScanTest)
        .where(ScanTest.organization_id == principal.organization_id,
               ScanTest.engagement_id == engagement_id)
        .order_by(ScanTest.created_at.desc())
    ).scalars().all()
    return [ScanTestOut.model_validate(r) for r in rows]


@router.get("/tests/{test_id}", response_model=ScanTestDetail)
def read_test(
    test_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> ScanTestDetail:
    test = session.get(ScanTest, test_id)
    if test is None or test.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan test not found")

    sightings = session.execute(
        select(TestFinding).where(
            TestFinding.organization_id == principal.organization_id,
            TestFinding.test_id == test.id,
        )
    ).scalars().all()
    present = len([s for s in sightings if s.status == "present"])
    payload = ScanTestOut.model_validate(test).model_dump()
    return ScanTestDetail(
        **payload,
        scope_size=len(sightings),
        present=present,
        absent=len(sightings) - present,
        effective_dedupe=dedupe.config_for(
            test.scanner, test.dedupe_config or None).as_dict(),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@router.get("/endpoints/search", response_model=Page[EndpointOut])
def search_endpoints(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
    host: str | None = Query(default=None),
    asset_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[EndpointOut]:
    statement = select(Endpoint).where(
        Endpoint.organization_id == principal.organization_id
    )
    if host:
        statement = statement.where(Endpoint.host.ilike(f"%{host.strip().lower()}%"))
    if asset_id:
        statement = statement.where(Endpoint.asset_id == asset_id)
    total = session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()
    rows = session.execute(
        statement.order_by(Endpoint.canonical).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[EndpointOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.get("/findings/{finding_id}/endpoints")
def finding_endpoints(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict[str, Any]:
    _finding(session, principal, finding_id)
    links = session.execute(
        select(FindingEndpoint).where(
            FindingEndpoint.organization_id == principal.organization_id,
            FindingEndpoint.finding_id == finding_id,
        )
    ).scalars().all()
    by_id = {
        e.id: e for e in session.execute(
            select(Endpoint).where(Endpoint.id.in_([l.endpoint_id for l in links]))
        ).scalars().all()
    } if links else {}
    return {
        "items": [
            {**FindingEndpointOut.model_validate(link).model_dump(),
             "endpoint": (EndpointOut.model_validate(by_id[link.endpoint_id]).model_dump()
                          if link.endpoint_id in by_id else None)}
            for link in links
        ],
        "outstanding": endpoint_service.outstanding(
            session, principal.organization_id, finding_id),
        "fully_mitigated": endpoint_service.fully_mitigated(
            session, principal.organization_id, finding_id),
    }


@router.post("/findings/{finding_id}/endpoints/mitigate")
def mitigate_endpoints(
    finding_id: uuid.UUID,
    body: MitigateEndpoints,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict[str, Any]:
    """Mark endpoints of a finding fixed.

    Deliberately does NOT close the finding even when every endpoint is
    mitigated: closure is a lifecycle transition with its own verification
    step, and letting a bulk endpoint update slip a finding past verification
    would be a hole in the state machine.
    """
    _finding(session, principal, finding_id)
    changed = endpoint_service.mitigate(
        session, organization_id=principal.organization_id, finding_id=finding_id,
        endpoint_ids=body.endpoint_ids, actor_id=principal.user_id,
    )
    outstanding = endpoint_service.outstanding(
        session, principal.organization_id, finding_id)
    audit.record(session, action="finding.endpoints.mitigate", object_type="finding",
                 object_id=finding_id, object_label=None,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"mitigated": changed, "outstanding": outstanding})
    session.commit()
    return {
        "mitigated": changed,
        "outstanding": outstanding,
        "fully_mitigated": endpoint_service.fully_mitigated(
            session, principal.organization_id, finding_id),
        "note": (
            "Endpoint status updated. The finding's own state is unchanged: "
            "closing it remains a lifecycle transition with verification."
        ),
    }


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------
@router.get("/risk-acceptances/list", response_model=Page[RiskAcceptanceOut])
def list_acceptances(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:read"))],
    state: str | None = Query(default=None),
    expiring_within_days: int | None = Query(default=None, ge=0, le=365),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[RiskAcceptanceOut]:
    statement = select(RiskAcceptance).where(
        RiskAcceptance.organization_id == principal.organization_id
    )
    if state:
        statement = statement.where(RiskAcceptance.state == state)
    if expiring_within_days is not None:
        horizon = dt.date.today() + dt.timedelta(days=expiring_within_days)
        statement = statement.where(
            RiskAcceptance.expires_on.is_not(None),
            RiskAcceptance.expires_on <= horizon,
            RiskAcceptance.state == RiskAcceptanceState.ACTIVE.value,
        )
    total = session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()
    rows = session.execute(
        statement.order_by(RiskAcceptance.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[RiskAcceptanceOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.post("/risk-acceptances", response_model=RiskAcceptanceOut, status_code=201)
def request_acceptance(
    body: RiskAcceptanceWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
) -> RiskAcceptanceOut:
    try:
        row = engagements.request_acceptance(
            session, principal.organization_id,
            requested_by_id=principal.user_id, **body.model_dump(),
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="risk_acceptance.request", object_type="risk_acceptance",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"findings": len(body.finding_ids),
                          "expires_on": str(body.expires_on)})
    session.commit()
    return RiskAcceptanceOut.model_validate(row)


@router.post("/risk-acceptances/{acceptance_id}/approve", response_model=RiskAcceptanceOut)
def approve_acceptance(
    acceptance_id: uuid.UUID,
    body: Decision,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
) -> RiskAcceptanceOut:
    acceptance = _acceptance(session, principal, acceptance_id)
    if principal.user_id is None:
        # An API key has no human behind it. Approving an exception is a named
        # accountability, so a machine identity must not be able to grant one.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "risk acceptance must be approved by a named user")
    try:
        engagements.approve(session, acceptance, approved_by_id=principal.user_id,
                            note=body.note)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(session, action="risk_acceptance.approve", object_type="risk_acceptance",
                 object_id=acceptance.id, object_label=acceptance.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"expires_on": str(acceptance.expires_on)})
    session.commit()
    return RiskAcceptanceOut.model_validate(acceptance)


@router.post("/risk-acceptances/{acceptance_id}/reject", response_model=RiskAcceptanceOut)
def reject_acceptance(
    acceptance_id: uuid.UUID,
    body: Decision,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
) -> RiskAcceptanceOut:
    acceptance = _acceptance(session, principal, acceptance_id)
    try:
        engagements.reject(session, acceptance, actor_id=principal.user_id,
                           note=body.note)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    session.commit()
    return RiskAcceptanceOut.model_validate(acceptance)


@router.post("/risk-acceptances/{acceptance_id}/revoke")
def revoke_acceptance(
    acceptance_id: uuid.UUID,
    body: Decision,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
) -> dict[str, Any]:
    acceptance = _acceptance(session, principal, acceptance_id)
    try:
        result = engagements.revoke(session, acceptance, actor_id=principal.user_id,
                                    note=body.note)
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(session, action="risk_acceptance.revoke", object_type="risk_acceptance",
                 object_id=acceptance.id, object_label=acceptance.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=result)
    session.commit()
    return {"state": acceptance.state, **result}


@router.post("/risk-acceptances/expire")
def run_expiry(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:write"))],
    warn_days: int = Query(default=14, ge=0, le=365),
) -> dict[str, Any]:
    """Expire what is due and warn about what is nearly due.

    Exposed as an endpoint as well as a scheduled job so an operator can prove
    the control runs, rather than trusting that a cron somewhere does.
    Idempotent: a second call in the same day expires nothing further.
    """
    stats = engagements.expire_due(session, principal.organization_id,
                                   warn_days=warn_days)
    session.commit()
    return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _engagement(session, principal: Principal, engagement_id: uuid.UUID) -> Engagement:
    row = session.get(Engagement, engagement_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "engagement not found")
    return row


def _finding(session, principal: Principal, finding_id: uuid.UUID) -> Finding:
    row = session.get(Finding, finding_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return row


def _acceptance(session, principal: Principal, acceptance_id: uuid.UUID) -> RiskAcceptance:
    row = session.get(RiskAcceptance, acceptance_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "risk acceptance not found")
    return row
