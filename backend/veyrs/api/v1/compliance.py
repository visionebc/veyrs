"""Compliance endpoints (spec sections 16 and 27).

Every response that reports coverage carries the framework's `is_partial` flag
and its disclaimer. That is not decoration: a customer exporting a "92%
implemented" figure from a 24-of-93 catalogue and putting it in front of an
auditor is a foreseeable, damaging misuse, and the API is the last place we can
prevent it.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from ...models import (
    AssessmentGap, AssessmentStatus, ComplianceAssessment, ComplianceControl,
    ComplianceFramework, ControlImplementation, ControlRiskLink, Evidence, EvidenceKind,
    ImplementationStatus,
)
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...services import audit, compliance as service
from .schemas import Page

router = APIRouter(prefix="/compliance", tags=["compliance"])

MAX_IMPORT_BYTES = 8 * 1024 * 1024
LINKABLE = {"asset", "finding", "ticket", "vulnerability", "document"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class FrameworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    version: str
    publisher: str
    description: str | None
    source_url: str | None
    licence_note: str | None
    is_partial: bool
    official_control_count: int | None
    is_builtin: bool


class FrameworkDetail(FrameworkOut):
    controls_shipped: int = 0
    disclaimer: str | None = None


class FrameworkCreate(BaseModel):
    slug: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=1, max_length=200)
    version: str = Field(min_length=1, max_length=40)
    publisher: str = Field(min_length=1, max_length=120)
    description: str | None = None
    source_url: str | None = None


class ControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ref: str
    title: str
    theme: str | None
    parent_ref: str | None
    normative_text: str | None
    veyrs_guidance: str | None
    crosswalk: dict
    automation_signal: str | None


class ImplementationWrite(BaseModel):
    status: str
    statement: str | None = None
    justification: str | None = None
    review_period_days: int | None = Field(default=None, ge=0, le=3650)


class EvidenceWrite(BaseModel):
    kind: str
    title: str = Field(min_length=1, max_length=300)
    summary: str | None = None
    document_id: uuid.UUID | None = None
    ticket_id: uuid.UUID | None = None
    finding_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    external_url: str | None = None
    valid_until: dt.date | None = None
    payload: dict = Field(default_factory=dict)


class LinkWrite(BaseModel):
    object_type: str
    object_id: str
    rationale: str | None = None


class AssessmentWrite(BaseModel):
    framework_id: uuid.UUID
    name: str = Field(min_length=1, max_length=240)
    scope: str | None = None
    assessor: str | None = None
    started_on: dt.date | None = None


# ---------------------------------------------------------------------------
# Frameworks and controls
# ---------------------------------------------------------------------------
@router.get("/frameworks", response_model=list[FrameworkDetail])
def list_frameworks(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> list[FrameworkDetail]:
    rows = session.execute(
        select(ComplianceFramework)
        .where((ComplianceFramework.organization_id.is_(None))
               | (ComplianceFramework.organization_id == principal.organization_id))
        .order_by(ComplianceFramework.slug, ComplianceFramework.version)
    ).scalars().all()
    out = []
    for framework in rows:
        detail = FrameworkDetail.model_validate(framework)
        detail.controls_shipped = session.execute(
            select(func.count(ComplianceControl.id))
            .where(ComplianceControl.framework_id == framework.id)
        ).scalar_one()
        detail.disclaimer = framework.coverage_disclaimer
        out.append(detail)
    return out


@router.post("/frameworks", response_model=FrameworkOut, status_code=201)
def create_framework(
    payload: FrameworkCreate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:admin"))],
) -> FrameworkOut:
    """Create a CUSTOM framework owned by this organization (spec section 16)."""
    exists = session.execute(
        select(ComplianceFramework).where(ComplianceFramework.slug == payload.slug,
                                          ComplianceFramework.version == payload.version)
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{payload.slug} {payload.version} already exists")
    framework = ComplianceFramework(
        **payload.model_dump(), organization_id=principal.organization_id,
        is_builtin=False, is_partial=False,
        licence_note="Custom framework authored by this organization.",
    )
    session.add(framework)
    session.flush()
    audit.record(session, action="compliance.framework.created",
                 object_type="compliance_framework", object_id=framework.id,
                 object_label=framework.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.commit()
    return FrameworkOut.model_validate(framework)


@router.get("/frameworks/{framework_id}/controls", response_model=list[ControlOut])
def list_controls(
    framework_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> list[ControlOut]:
    _framework(session, principal, framework_id)
    rows = session.execute(
        select(ComplianceControl)
        .where(ComplianceControl.framework_id == framework_id)
        .order_by(ComplianceControl.sort_order)
    ).scalars().all()
    return [ControlOut.model_validate(r) for r in rows]


@router.post("/frameworks/{framework_id}/controls:import")
async def import_controls(
    framework_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:admin"))],
    file: UploadFile = File(...),
) -> dict[str, Any]:
    """Import a catalogue the organization licenses (CSV: ref,title,...).

    This is how a partial catalogue becomes complete without VEYRS shipping
    copyrighted text.
    """
    framework = _framework(session, principal, framework_id)
    payload = await file.read()
    if len(payload) > MAX_IMPORT_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
    try:
        result = service.import_controls_csv(session, framework, payload)
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="compliance.controls.imported",
                 object_type="compliance_framework", object_id=framework.id,
                 object_label=framework.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=result)
    session.commit()
    return result


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
@router.get("/frameworks/{framework_id}/coverage")
def framework_coverage(
    framework_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> dict[str, Any]:
    framework = _framework(session, principal, framework_id)
    service.mark_stale_implementations(session, principal.organization_id)
    report = service.coverage(session, principal.organization_id, framework)
    session.commit()
    return report


@router.post("/frameworks/{framework_id}/refresh-signals")
def refresh_signals(
    framework_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:write"))],
) -> dict[str, Any]:
    """Recompute automated evidence from live VEYRS data."""
    framework = _framework(session, principal, framework_id)
    result = service.refresh_automated_evidence(
        session, principal.organization_id, framework_id=framework.id
    )
    audit.record(session, action="compliance.signals.refreshed",
                 object_type="compliance_framework", object_id=framework.id,
                 object_label=framework.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=result)
    session.commit()
    return result


@router.get("/signals")
def list_signals(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> dict[str, Any]:
    """Evaluate every automated signal right now, with its derivation."""
    return {
        "pass_ratio": service.SIGNAL_PASS_RATIO,
        "signals": [
            service.evaluate_signal(session, principal.organization_id, name)
            for name in service.AUTOMATED_SIGNALS
        ],
    }


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------
@router.put("/controls/{control_id}/implementation")
def set_implementation(
    control_id: uuid.UUID,
    payload: ImplementationWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:write"))],
) -> dict[str, Any]:
    control = session.get(ComplianceControl, control_id)
    if control is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")
    implementation = service.get_or_create_implementation(
        session, principal.organization_id, control
    )
    before = implementation.status
    try:
        service.set_status(
            session, implementation, payload.status, statement=payload.statement,
            justification=payload.justification,
            review_period_days=payload.review_period_days,
            actor_id=principal.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    audit.record(session, action="compliance.implementation.updated",
                 object_type="control_implementation", object_id=implementation.id,
                 object_label=control.ref,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"status": {"from": before, "to": implementation.status}})
    session.commit()
    return {
        "control_ref": control.ref, "status": implementation.status,
        "next_review_at": implementation.next_review_at.isoformat()
                          if implementation.next_review_at else None,
    }


@router.get("/controls/{control_id}/chain")
def control_chain(
    control_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> dict[str, Any]:
    """Control -> assets -> findings -> tickets -> evidence, in one call."""
    chain = service.control_chain(session, principal.organization_id, control_id)
    if not chain:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")
    return chain


@router.post("/controls/{control_id}/links", status_code=201)
def link_object(
    control_id: uuid.UUID,
    payload: LinkWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:write"))],
) -> dict[str, Any]:
    control = session.get(ComplianceControl, control_id)
    if control is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")
    if payload.object_type not in LINKABLE:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"object_type must be one of {sorted(LINKABLE)}")
    link = service.link_object(
        session, principal.organization_id, control, payload.object_type,
        payload.object_id, rationale=payload.rationale, actor_id=principal.user_id,
    )
    audit.record(session, action="compliance.control.linked",
                 object_type="control_risk_link", object_id=link.id,
                 object_label=f"{control.ref} -> {payload.object_type}",
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.commit()
    return {"id": str(link.id), "control_ref": control.ref,
            "object_type": link.object_type, "object_id": link.object_id}


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------
@router.post("/controls/{control_id}/evidence", status_code=201)
def add_evidence(
    control_id: uuid.UUID,
    payload: EvidenceWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("evidence:write"))],
) -> dict[str, Any]:
    control = session.get(ComplianceControl, control_id)
    if control is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "control not found")
    if payload.kind not in {k.value for k in EvidenceKind}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {[k.value for k in EvidenceKind]}")
    implementation = service.get_or_create_implementation(
        session, principal.organization_id, control
    )
    evidence = Evidence(
        organization_id=principal.organization_id,
        implementation_id=implementation.id,
        collected_by_id=principal.user_id,
        collected_at=dt.datetime.now(dt.timezone.utc),
        **payload.model_dump(),
    )
    session.add(evidence)
    session.flush()
    audit.record(session, action="compliance.evidence.added",
                 object_type="compliance_evidence", object_id=evidence.id,
                 object_label=evidence.title,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.commit()
    return {"id": str(evidence.id), "control_ref": control.ref, "kind": evidence.kind,
            "collected_at": evidence.collected_at.isoformat()}


@router.get("/evidence", response_model=Page[dict])
def list_evidence(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("evidence:read"))],
    kind: str | None = Query(default=None),
    expired: bool | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[dict]:
    statement = select(Evidence).where(
        Evidence.organization_id == principal.organization_id
    )
    if kind:
        statement = statement.where(Evidence.kind == kind)
    if expired is True:
        statement = statement.where(Evidence.valid_until < dt.date.today())
    elif expired is False:
        statement = statement.where((Evidence.valid_until.is_(None))
                                    | (Evidence.valid_until >= dt.date.today()))
    total = session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()
    rows = session.execute(
        statement.order_by(Evidence.collected_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(
        items=[{**r.as_dict(), "is_expired": r.is_expired} for r in rows],
        total=total, limit=limit, offset=offset,
    )


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------
@router.post("/assessments", status_code=201)
def create_assessment(
    payload: AssessmentWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:write"))],
) -> dict[str, Any]:
    _framework(session, principal, payload.framework_id)
    assessment = ComplianceAssessment(
        organization_id=principal.organization_id,
        status=AssessmentStatus.IN_PROGRESS.value,
        started_on=payload.started_on or dt.date.today(),
        **payload.model_dump(exclude={"started_on"}),
    )
    session.add(assessment)
    session.flush()
    audit.record(session, action="compliance.assessment.created",
                 object_type="compliance_assessment", object_id=assessment.id,
                 object_label=assessment.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.commit()
    return {"id": str(assessment.id), "name": assessment.name,
            "status": assessment.status}


@router.post("/assessments/{assessment_id}/complete")
def complete_assessment(
    assessment_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:write"))],
    summary: str | None = Query(default=None),
) -> dict[str, Any]:
    assessment = session.get(ComplianceAssessment, assessment_id)
    if assessment is None or assessment.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    if assessment.status == AssessmentStatus.COMPLETE.value:
        raise HTTPException(status.HTTP_409_CONFLICT, "assessment is already complete")
    service.complete_assessment(session, assessment, summary=summary)
    gaps = session.execute(
        select(func.count(AssessmentGap.id))
        .where(AssessmentGap.assessment_id == assessment.id)
    ).scalar_one()
    audit.record(session, action="compliance.assessment.completed",
                 object_type="compliance_assessment", object_id=assessment.id,
                 object_label=assessment.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"gaps": gaps})
    session.commit()
    return {"id": str(assessment.id), "status": assessment.status,
            "completed_on": assessment.completed_on.isoformat(),
            "gaps": gaps,
            "snapshot_disclaimer": assessment.snapshot.get("framework", {}).get("disclaimer")}


@router.get("/assessments", response_model=Page[dict])
def list_assessments(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[dict]:
    rows = session.execute(
        select(ComplianceAssessment)
        .where(ComplianceAssessment.organization_id == principal.organization_id)
        .order_by(ComplianceAssessment.created_at.desc())
        .limit(limit).offset(offset)
    ).scalars().all()
    return Page(
        items=[{"id": str(a.id), "name": a.name, "status": a.status,
                "framework_id": str(a.framework_id),
                "started_on": a.started_on.isoformat() if a.started_on else None,
                "completed_on": a.completed_on.isoformat() if a.completed_on else None}
               for a in rows],
        total=len(rows), limit=limit, offset=offset,
    )


@router.get("/assessments/{assessment_id}")
def read_assessment(
    assessment_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("compliance:read"))],
) -> dict[str, Any]:
    assessment = session.get(ComplianceAssessment, assessment_id)
    if assessment is None or assessment.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "assessment not found")
    gaps = session.execute(
        select(AssessmentGap).where(AssessmentGap.assessment_id == assessment.id)
    ).scalars().all()
    return {
        "id": str(assessment.id), "name": assessment.name, "status": assessment.status,
        "scope": assessment.scope, "assessor": assessment.assessor,
        "started_on": assessment.started_on.isoformat() if assessment.started_on else None,
        "completed_on": assessment.completed_on.isoformat()
                        if assessment.completed_on else None,
        "summary": assessment.summary,
        # The snapshot is what was true at completion, never recomputed.
        "snapshot": assessment.snapshot,
        "gaps": [{"id": str(g.id), "title": g.title, "severity": g.severity,
                  "detail": g.detail, "due_date": g.due_date.isoformat()
                  if g.due_date else None,
                  "closed_at": g.closed_at.isoformat() if g.closed_at else None}
                 for g in gaps],
    }


def _framework(session, principal: Principal, framework_id: uuid.UUID) -> ComplianceFramework:
    framework = session.get(ComplianceFramework, framework_id)
    if framework is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "framework not found")
    if framework.organization_id not in (None, principal.organization_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "framework not found")
    return framework
