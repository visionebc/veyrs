"""Ticketing, workflow and notification API (spec sections 13, 14, 15, 30)."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import Response, APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select

from ...models import (
    Finding, Notification, NotificationPreference, OPEN_TICKET_STATES, Ticket,
    TicketComment, TicketEvent, User, WorkflowDefinition, WorkflowRun,
    allowed_ticket_transitions,
)
from ...security import scope as team_scope
from ...services import analytics
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...services import audit, autoticket, digest as digest_service
from ...services import itsm as itsm_service, notifications as notify_service
from ...services import remediation, ticketing, ticketing_mode
from ...services import workflow as workflow_service
from .schemas import Page

router = APIRouter(tags=["ticketing"])


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------


class TicketCreate(BaseModel):
    ticket_type: str = "remediation"
    title: str = Field(min_length=1, max_length=500)
    description: str | None = None
    priority: str = "medium"
    finding_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    business_service_id: uuid.UUID | None = None
    assigned_team_id: uuid.UUID | None = None
    assigned_user_id: uuid.UUID | None = None
    parent_id: uuid.UUID | None = None
    due_at: dt.datetime | None = None
    labels: list[str] = Field(default_factory=list)
    change_type: str | None = None
    implementation_plan: str | None = None
    rollback_plan: str | None = None
    scheduled_start: dt.datetime | None = None
    scheduled_end: dt.datetime | None = None


class TicketOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    reference: str
    ticket_type: str
    state: str
    priority: str
    title: str
    description: str | None
    resolution: str | None
    finding_id: uuid.UUID | None
    vulnerability_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    assigned_team_id: uuid.UUID | None
    assigned_user_id: uuid.UUID | None
    approver_id: uuid.UUID | None
    approved_at: dt.datetime | None
    change_type: str | None
    scheduled_start: dt.datetime | None
    scheduled_end: dt.datetime | None
    due_at: dt.datetime | None
    sla_breached: bool
    resolved_at: dt.datetime | None
    closed_at: dt.datetime | None
    external_system: str | None
    external_key: str | None
    labels: list[str]
    created_at: dt.datetime


class TicketDetail(TicketOut):
    comments: list[dict[str, Any]] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)
    allowed_transitions: list[str] = Field(default_factory=list)


class TicketTransition(BaseModel):
    state: str
    note: str | None = None
    resolution: str | None = None


class CommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    is_internal: bool = False


class WorkflowWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    is_enabled: bool = True
    trigger: str
    conditions: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    stop_on_error: bool = True


class WorkflowOut(WorkflowWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    run_count: int
    last_run_at: dt.datetime | None


def _actor(request: Request, principal: Principal) -> dict:
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": request.client.host if request.client else None,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


def _get_ticket(session, organization_id: uuid.UUID, ticket_id: uuid.UUID,
                scope: team_scope.TeamScope = team_scope.UNRESTRICTED) -> Ticket:
    row = session.get(Ticket, ticket_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ticket not found")
    if not team_scope.ticket_visible(session, row, scope):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ticket not found")
    return row


# --------------------------------------------------------------------------
# Tickets
# --------------------------------------------------------------------------


@router.post("/tickets", response_model=TicketOut, status_code=status.HTTP_201_CREATED,
             summary="Create a ticket")
def create_ticket(
    payload: TicketCreate,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> TicketOut:
    # Enforced HERE, at the single point where an internal ticket is created
    # through the API, rather than by hiding the button. A mode that only the
    # console respects is not a mode: `curl`, the mobile client and any
    # integration would carry on filling a queue the operator believes is
    # closed. See `services/ticketing_mode` for the full table of what the
    # switch does and deliberately does not refuse.
    try:
        ticketing_mode.require_internal(
            session, principal.organization_id, "creating a VEYRS ticket")
    except ticketing_mode.TicketingModeError as exc:
        # 409, not 403: the caller has the permission, the tenant is in a state
        # where the request does not apply. 403 would send an operator to hunt
        # for a missing role that is not missing.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    finding = None
    if payload.finding_id is not None:
        finding = session.get(Finding, payload.finding_id)
        if (finding is None or finding.organization_id != principal.organization_id
                or not team_scope.finding_visible(session, finding, principal.scope)):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
        existing = ticketing.open_ticket_for_finding(session, finding.id)
        if existing is not None and payload.ticket_type == "remediation":
            # Returning the existing ticket beats creating a duplicate queue item.
            return TicketOut.model_validate(existing)

    ticket = ticketing.create_ticket(
        session, principal.organization_id,
        ticket_type=payload.ticket_type,
        title=payload.title,
        description=payload.description,
        finding_id=payload.finding_id,
        vulnerability_id=finding.vulnerability_id if finding is not None else None,
        asset_id=payload.asset_id or (finding.asset_id if finding is not None else None),
        business_service_id=payload.business_service_id,
        assigned_team_id=payload.assigned_team_id,
        assigned_user_id=payload.assigned_user_id,
        requested_by_id=principal.user_id,
        priority=payload.priority,
        due_at=payload.due_at or (finding.sla_due_at if finding is not None else None),
        parent_id=payload.parent_id,
        labels=payload.labels,
        actor_label=principal.label,
    )
    for field in ("change_type", "implementation_plan", "rollback_plan",
                  "scheduled_start", "scheduled_end"):
        value = getattr(payload, field)
        if value is not None:
            setattr(ticket, field, value)
    audit.record(session, action="ticket.create", object_type="ticket",
                 object_id=ticket.reference,
                 **_actor(request, principal), changes=audit.diff(None, {"type": ticket.ticket_type}))
    session.commit()
    session.refresh(ticket)
    workflow_service.trigger(session, principal.organization_id, "ticket.created",
                             ticket=ticket, finding=finding)
    session.commit()
    return TicketOut.model_validate(ticket)


@router.post("/findings/{finding_id}/remediation", status_code=status.HTTP_201_CREATED,
             summary="Raise the remediation work for a finding")
def open_remediation(
    finding_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> dict:
    """One route, both modes. THIS is what the console calls.

    Before phase 45 the console posted to `/tickets` with a `finding_id`, which
    hardcoded the internal queue into the front end. Asking the API "arrange for
    this finding to be fixed" and letting the tenant's own configuration decide
    where that lands is the difference between a mode and a coat of paint.

    The response says which system answered (`kind`), so a caller never has to
    infer it -- and `created: false` means the work already existed, which is
    the same idempotence `ticket_for_finding` always had.
    """
    finding = session.get(Finding, finding_id)
    if (finding is None or finding.organization_id != principal.organization_id
            or not team_scope.finding_visible(session, finding, principal.scope)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    try:
        record, created = remediation.open_for_finding(
            session, finding, actor_label=principal.label,
        )
    except ticketing_mode.TicketingModeError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except itsm_service.ItsmError as exc:
        # 502: VEYRS is fine, the remote system refused or could not be
        # reached. A 500 here would send the operator to read OUR logs.
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    audit.record(
        session,
        action="finding.remediation_opened",
        object_type="finding", object_id=str(finding.id),
        object_label=record.reference,
        changes=audit.diff(None, {"kind": record.kind, "reference": record.reference}),
        **_actor(request, principal),
    )
    session.commit()
    return {**record.as_dict(), "created": created, "finding_id": str(finding.id)}


@router.get("/tickets", response_model=Page[TicketOut], summary="List tickets")
def list_tickets(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
    q: str | None = None,
    ticket_type: str | None = None,
    state: str | None = None,
    open_only: bool = True,
    priority: str | None = None,
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    sla_breached: bool | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[TicketOut]:
    stmt = select(Ticket).where(Ticket.organization_id == principal.organization_id)
    if state:
        stmt = stmt.where(Ticket.state == state)
    elif open_only:
        stmt = stmt.where(Ticket.state.in_(tuple(OPEN_TICKET_STATES)))
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(Ticket.reference.ilike(needle), Ticket.title.ilike(needle)))
    for column, value in (
        (Ticket.ticket_type, ticket_type), (Ticket.priority, priority),
        (Ticket.assigned_team_id, assigned_team_id),
        (Ticket.assigned_user_id, assigned_user_id), (Ticket.finding_id, finding_id),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
    if sla_breached is not None:
        stmt = stmt.where(Ticket.sla_breached.is_(sla_breached))
    stmt = team_scope.tickets(stmt, principal.scope)

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(Ticket.sla_breached.desc(), Ticket.due_at.asc().nullslast(),
                      Ticket.created_at.desc())
        .offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page.of([TicketOut.model_validate(r) for r in rows], total, page, size)


# --------------------------------------------------------------------------
# Automatic ticket creation
#
# Declared BEFORE `/tickets/{ticket_id}`: FastAPI matches routes in declaration
# order, so `/tickets/automation` placed after the UUID parameter would be
# parsed as a ticket id and answer 422 for a path that exists.
# --------------------------------------------------------------------------


class AutoTicketPolicyIn(BaseModel):
    """Every field optional so a client can change one without resetting the rest.

    `exclude_unset` in the handler is what makes that true: a body carrying
    only `enabled` must not silently reset the threshold to a default the
    operator never chose.
    """

    enabled: bool | None = None
    min_risk_score: float | None = Field(default=None, ge=0, le=100)
    severities: list[str] | None = None
    require_kev: bool | None = None
    internet_exposed_only: bool | None = None
    require_owner: bool | None = None
    max_per_run: int | None = Field(default=None, ge=1, le=500)


class AutoTicketBackfillIn(BaseModel):
    #: Defaults True. The destructive direction of a mistake here is hundreds
    #: of tickets and hundreds of notifications, and undoing it is manual.
    dry_run: bool = True
    limit: int = Field(default=200, ge=1, le=2000)


@router.get("/tickets/automation", summary="Automatic ticket creation policy")
def get_ticket_automation(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
) -> dict:
    """Read-open to anyone who can read tickets.

    An operator looking at a queue that grows on its own has to be able to find
    out why without an administrator; making the answer a privileged secret is
    how "who opened these?" becomes an afternoon.
    """
    state = autoticket.state(session, principal.organization_id)
    return {
        **state,
        "recent_created": autoticket.recent_auto_created(
            session, principal.organization_id
        ),
        "budget_window_minutes": autoticket.BUDGET_WINDOW_MINUTES,
    }


@router.put("/tickets/automation", summary="Change the automatic ticket policy")
def put_ticket_automation(
    payload: AutoTicketPolicyIn,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> dict:
    """`ticket:admin`, and never a team-scoped grant.

    The policy governs the whole estate: a team that could raise the threshold
    would stop tickets opening for work that is not theirs, and nobody outside
    that team would see the change. Same refusal SLA policy writes take.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "automatic ticket creation governs the whole estate and cannot be "
        "changed by a team-scoped identity; it requires an estate-wide grant",
    )
    changes = payload.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "nothing to change")
    before = autoticket.state(session, principal.organization_id)
    try:
        after = autoticket.set_policy(
            session, principal.organization_id, changes, actor_id=principal.user_id,
        )
    except autoticket.AutoTicketError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    audit.record(
        session,
        action="organization.auto_ticket_policy_changed",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="automatic ticket creation",
        changes={k: [before.get(k), after.get(k)] for k in changes},
        **_actor(request, principal),
    )
    session.commit()
    return after


@router.post("/tickets/automation/preview",
             summary="How many tickets this policy would open right now")
def preview_ticket_automation(
    payload: AutoTicketPolicyIn | None,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
) -> dict:
    """Dry-run the policy WITHOUT saving it.

    A body lets the console answer "what would happen if I set the threshold to
    50?" before anybody commits to it; an empty body previews the policy as
    stored. Either way it writes nothing.
    """
    policy = autoticket.state(session, principal.organization_id)
    if payload is not None:
        overrides = payload.model_dump(exclude_unset=True)
        policy = {**policy, **{k: v for k, v in overrides.items() if v is not None}}
        # A preview is always evaluated as if the policy were on: previewing a
        # disabled policy and getting zero would answer a question nobody asked.
        policy["enabled"] = True
    return autoticket.preview(session, principal.organization_id, policy=policy)


@router.post("/tickets/automation/backfill",
             summary="Open tickets for the existing backlog, once")
def backfill_ticket_automation(
    payload: AutoTicketBackfillIn,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> dict:
    """A deliberate one-off catch-up, not a side effect of enabling automation.

    It deliberately does NOT require `enabled`: "ticket the backlog now" and
    "keep ticketing from now on" are different decisions, and coupling them
    would force anyone who wants the first to live with the second.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "a backfill opens tickets across the whole estate and cannot be run "
        "from a team-scoped identity; it requires an estate-wide grant",
    )
    result = autoticket.backfill(
        session, principal.organization_id,
        dry_run=payload.dry_run, limit=payload.limit,
    )
    if not payload.dry_run:
        audit.record(
            session,
            action="ticket.auto_backfill",
            object_type="organization",
            object_id=principal.organization_id,
            object_label="automatic ticket backfill",
            changes={"created": [0, result["created"]], "capped": result["capped"]},
            **_actor(request, principal),
        )
        session.commit()
    return result


@router.get("/tickets/{ticket_id}", response_model=TicketDetail, summary="Ticket detail")
def get_ticket(
    ticket_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
) -> TicketDetail:
    ticket = _get_ticket(session, principal.organization_id, ticket_id, principal.scope)
    detail = TicketDetail.model_validate(ticket)
    comments = session.execute(
        select(TicketComment).where(TicketComment.ticket_id == ticket.id)
        .order_by(TicketComment.created_at)
    ).scalars().all()
    detail.comments = [{
        "id": str(c.id), "at": c.created_at.isoformat(), "author": c.author_label,
        "body": c.body, "internal": c.is_internal,
    } for c in comments]
    events = session.execute(
        select(TicketEvent).where(TicketEvent.ticket_id == ticket.id)
        .order_by(TicketEvent.created_at)
    ).scalars().all()
    detail.events = [{
        "at": e.created_at.isoformat(), "event": e.event, "actor": e.actor_label,
        "details": e.details,
    } for e in events]
    detail.allowed_transitions = sorted(
        allowed_ticket_transitions(ticket.ticket_type, ticket.state)
    )
    return detail


@router.post("/tickets/{ticket_id}/transition", response_model=TicketOut,
             summary="Move a ticket through its lifecycle")
def transition_ticket(
    ticket_id: uuid.UUID,
    payload: TicketTransition,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> TicketOut:
    ticket = _get_ticket(session, principal.organization_id, ticket_id, principal.scope)
    # Approving your own change request defeats the purpose of an approval gate.
    if payload.state == "approved" and ticket.requested_by_id == principal.user_id \
            and not principal.can("ticket:admin"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "the requester cannot approve their own change; needs ticket:admin",
        )
    previous = ticket.state
    try:
        ticketing.transition_ticket(
            session, ticket, payload.state, actor_id=principal.user_id,
            actor_label=principal.label, note=payload.note, resolution=payload.resolution,
        )
    except ticketing.TicketError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    audit.record(session, action="ticket.transition", object_type="ticket",
                 object_id=ticket.reference, **_actor(request, principal), changes=audit.diff({"state": previous}, {"state": ticket.state}))
    session.commit()
    workflow_service.trigger(
        session, principal.organization_id, "ticket.state_changed", ticket=ticket,
        extra={"previous_state": previous, "state": ticket.state},
    )
    session.commit()
    session.refresh(ticket)
    return TicketOut.model_validate(ticket)


@router.post("/tickets/{ticket_id}/comments", status_code=status.HTTP_201_CREATED,
             summary="Comment on a ticket")
def comment(
    ticket_id: uuid.UUID,
    payload: CommentCreate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> dict:
    ticket = _get_ticket(session, principal.organization_id, ticket_id, principal.scope)
    row = ticketing.add_comment(
        session, ticket, payload.body, author_id=principal.user_id,
        author_label=principal.label, is_internal=payload.is_internal,
    )
    session.commit()
    return {"id": str(row.id), "at": row.created_at.isoformat()}


@router.get("/tickets-metrics", summary="Ticket queue metrics (MTTR, breaches)")
def ticket_metrics(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
) -> dict:
    if principal.scope.restricted:
        # `ticketing.metrics` aggregates the whole queue. Rather than ship a
        # number that silently means "my team's queue" under a heading that
        # says "the queue", answer with the scoped breakdown and say so.
        return {"scope": {"restricted": True, "teams": len(principal.scope.team_ids)},
                "by_type": analytics.ticket_metrics(session, principal.organization_id,
                                                    scope=principal.scope)}
    return ticketing.metrics(session, principal.organization_id)


# --------------------------------------------------------------------------
# Workflows
# --------------------------------------------------------------------------


@router.get("/workflows", response_model=list[WorkflowOut], summary="List workflows")
def list_workflows(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("workflow:read"))],
) -> list[WorkflowOut]:
    rows = session.execute(
        select(WorkflowDefinition).where(
            WorkflowDefinition.organization_id == principal.organization_id
        ).order_by(WorkflowDefinition.name)
    ).scalars().all()
    return [WorkflowOut.model_validate(r) for r in rows]


@router.get("/workflows/actions", summary="Available workflow actions")
def list_actions(
    principal: Annotated[Principal, Depends(require("workflow:read"))],
) -> dict:
    """The allow-list the visual editor renders. There is no free-form code."""
    return {
        **workflow_service.describe(),
    }


@router.post("/workflows", response_model=WorkflowOut, status_code=status.HTTP_201_CREATED,
             summary="Create a workflow")
def create_workflow(
    payload: WorkflowWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("workflow:write"))],
) -> WorkflowOut:
    try:
        workflow_service.validate_steps(payload.steps)
    except workflow_service.WorkflowError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if session.execute(
        select(WorkflowDefinition).where(
            WorkflowDefinition.organization_id == principal.organization_id,
            WorkflowDefinition.slug == payload.slug,
        )
    ).scalars().first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "slug already exists")
    row = WorkflowDefinition(organization_id=principal.organization_id, **payload.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return WorkflowOut.model_validate(row)


@router.patch("/workflows/{workflow_id}", response_model=WorkflowOut,
              summary="Update a workflow")
def update_workflow(
    workflow_id: uuid.UUID,
    payload: WorkflowWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("workflow:write"))],
) -> WorkflowOut:
    row = session.get(WorkflowDefinition, workflow_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "workflow not found")
    try:
        workflow_service.validate_steps(payload.steps)
    except workflow_service.WorkflowError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    session.commit()
    session.refresh(row)
    return WorkflowOut.model_validate(row)


@router.get("/workflows/runs", summary="Workflow run history")
def workflow_runs(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("workflow:read"))],
    definition_id: uuid.UUID | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> dict:
    stmt = select(WorkflowRun).where(
        WorkflowRun.organization_id == principal.organization_id
    )
    if definition_id:
        stmt = stmt.where(WorkflowRun.definition_id == definition_id)
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(WorkflowRun.started_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return {
        # Same pagination contract as `Page`: hand-built dicts that omit
        # limit/offset force every client to special-case these routes.
        "total": total, "page": page, "size": size,
        "limit": size, "offset": (page - 1) * size,
        "items": [{
            "id": str(r.id), "definition_id": str(r.definition_id), "trigger": r.trigger,
            "status": r.status, "started_at": r.started_at.isoformat(),
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "finding_id": str(r.finding_id) if r.finding_id else None,
            "ticket_id": str(r.ticket_id) if r.ticket_id else None,
            "steps": r.step_results,
        } for r in rows],
    }


@router.post("/workflows/seed", summary="Install the built-in workflow set")
def seed_workflows(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("workflow:admin"))],
) -> dict:
    created = workflow_service.seed_workflows(session, principal.organization_id)
    session.commit()
    return {"created": created}


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


@router.get("/notifications", summary="My in-app notifications")
def my_notifications(
    session: TenantSession,
    principal: CurrentPrincipal,
    unread_only: bool = False,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> dict:
    """Scoped to the caller: there is no "read someone else's inbox" endpoint."""
    stmt = select(Notification).where(
        Notification.organization_id == principal.organization_id,
        Notification.recipient_user_id == principal.user_id,
        Notification.channel == "in_app",
    )
    if unread_only:
        stmt = stmt.where(Notification.read_at.is_(None))
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(Notification.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return {
        # Same pagination contract as `Page`: hand-built dicts that omit
        # limit/offset force every client to special-case these routes.
        "total": total, "page": page, "size": size,
        "limit": size, "offset": (page - 1) * size,
        "unread": notify_service.unread_count(session, principal.user_id)
        if principal.user_id else 0,
        "items": [{
            "id": str(r.id), "event": r.event, "subject": r.subject, "body": r.body,
            "at": r.created_at.isoformat(),
            "read_at": r.read_at.isoformat() if r.read_at else None,
            "finding_id": str(r.finding_id) if r.finding_id else None,
            "ticket_id": str(r.ticket_id) if r.ticket_id else None,
        } for r in rows],
    }


@router.post("/notifications/{notification_id}/read", status_code=204,
             response_model=None, response_class=Response, summary="Mark as read")
def mark_read(
    notification_id: uuid.UUID,
    session: TenantSession,
    principal: CurrentPrincipal,
) -> None:
    row = session.get(Notification, notification_id)
    if row is None or row.recipient_user_id != principal.user_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "notification not found")
    row.read_at = row.read_at or dt.datetime.now(dt.timezone.utc)
    session.commit()


@router.post("/notifications/dispatch", summary="Flush the notification queue")
def dispatch(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("notification:admin"))],
) -> dict:
    stats = notify_service.dispatch(session, principal.organization_id)
    session.commit()
    return stats


# --------------------------------------------------------------------------
# Notification preferences and the daily digest
#
# These live in the `ticketing` router, whose tag is SCOPED, and not in a
# router of their own tagged `operations`. That is deliberate: the digest
# preview reads the caller's findings, so a tag claiming "no finding-level
# rows" would be the same false classification `policies` carried until
# v0.17.1 and `cvss` until v0.21.0. A tag is a claim about every route
# beneath it.
# --------------------------------------------------------------------------


class PreferenceWrite(BaseModel):
    event: str = Field(..., max_length=60)
    email: bool = True
    in_app: bool = True


class DigestPolicyWrite(BaseModel):
    enabled: bool | None = None
    hour: int | None = Field(default=None, ge=0, le=23)
    window_hours: int | None = Field(default=None, ge=1, le=168)
    min_severity: str | None = None
    channels: list[str] | None = None
    include_sla: bool | None = None
    include_unassigned: bool | None = None


def _mutable_events() -> list[str]:
    """Every event a user may switch off, and nothing they may not.

    Built from the template catalogue rather than hand-listed: an event added
    with a template but forgotten here would be undisableable in the console
    while still arriving in the inbox.
    """
    known = set(notify_service.BUILTIN_TEMPLATES) | {digest_service.EVENT}
    return sorted(known - notify_service.UNMUTABLE_EVENTS)


@router.get("/notifications/preferences", summary="My channel opt-outs")
def my_preferences(session: TenantSession, principal: CurrentPrincipal) -> dict:
    rows = session.execute(
        select(NotificationPreference).where(
            NotificationPreference.organization_id == principal.organization_id,
            NotificationPreference.user_id == principal.user_id,
        )
    ).scalars().all()
    by_event = {r.event: r for r in rows}
    return {
        "events": [
            {
                "event": event,
                "email": by_event[event].email if event in by_event else True,
                "in_app": by_event[event].in_app if event in by_event else True,
                "explicit": event in by_event,
            } for event in _mutable_events()
        ],
        # Named so the console can explain the greyed-out rows instead of
        # silently omitting them, which reads as "we forgot these".
        "unmutable": sorted(notify_service.UNMUTABLE_EVENTS),
    }


@router.put("/notifications/preferences", summary="Mute or unmute one event")
def set_preference(payload: PreferenceWrite, session: TenantSession,
                   principal: CurrentPrincipal) -> dict:
    if principal.user_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "notification preferences belong to a user")
    if payload.event in notify_service.UNMUTABLE_EVENTS:
        # 422 rather than a silent no-op: the row would be written, the mute
        # would be ignored by `_muted`, and the console would show a switch
        # that stays on. A control that does nothing is worse than no control.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{payload.event} cannot be muted: SLA breaches and escalations are "
            "delivered regardless of preference",
        )
    if payload.event not in _mutable_events():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown notification event {payload.event!r}")
    row = session.execute(
        select(NotificationPreference).where(
            NotificationPreference.organization_id == principal.organization_id,
            NotificationPreference.user_id == principal.user_id,
            NotificationPreference.event == payload.event,
        )
    ).scalars().first()
    if row is None:
        row = NotificationPreference(
            organization_id=principal.organization_id, user_id=principal.user_id,
            event=payload.event,
        )
        session.add(row)
    row.email, row.in_app = payload.email, payload.in_app
    session.commit()
    return {"event": row.event, "email": row.email, "in_app": row.in_app,
            "explicit": True}


@router.get("/notifications/digest", summary="The daily digest policy")
def digest_policy(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("notification:read"))],
) -> dict:
    policy = digest_service.state(session, principal.organization_id)
    policy["recipients"] = len(digest_service.recipients(session,
                                                         principal.organization_id))
    return policy


@router.put("/notifications/digest", summary="Change the daily digest policy")
def set_digest_policy(
    payload: DigestPolicyWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("notification:admin"))],
) -> dict:
    # Estate-wide by nature: this decides what every eligible user in the
    # organization receives. A team-scoped identity narrowing it would produce
    # a policy that reads as organization-wide and is not.
    team_scope.refuse_if_restricted(
        principal.scope,
        "the daily digest is an organization-wide policy and cannot be set for one team",
    )
    before = digest_service.state(session, principal.organization_id)
    try:
        after = digest_service.set_policy(session, principal.organization_id,
                                          payload.model_dump(exclude_unset=True))
    except digest_service.DigestError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="digest.policy", object_type="organization",
                 object_id=principal.organization_id,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=audit.diff(before, after))
    session.commit()
    return after


@router.post("/notifications/digest/preview", summary="What my digest would say")
def digest_preview(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict:
    """Built by the SAME function that sends it, under the caller's own scope.

    A preview assembled separately is a preview that can be right while the
    message is wrong -- and the operator only finds out by trusting it.
    """
    user = session.get(User, principal.user_id) if principal.user_id else None
    payload = digest_service.build(session, principal.organization_id,
                                   scope=principal.scope, user=user)
    payload["body"] = digest_service.render_body(payload)
    return payload


@router.post("/notifications/digest/send", summary="Send the digest now")
def digest_send(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("notification:admin"))],
    dry_run: bool = Query(default=True,
                          description="Default TRUE: 'send now' is not a button "
                                      "you press to find out what it does."),
) -> dict:
    team_scope.refuse_if_restricted(
        principal.scope, "the digest is sent to the whole organization")
    result = digest_service.run(session, principal.organization_id,
                                dry_run=dry_run, force=True)
    if not dry_run:
        result["dispatch"] = notify_service.dispatch(session, principal.organization_id)
        audit.record(session, action="digest.send", object_type="organization",
                     object_id=principal.organization_id,
                     organization_id=principal.organization_id,
                     actor_id=principal.user_id, actor_label=principal.label,
                     changes={"queued": result["queued"],
                              "recipients": result["recipients"]})
    session.commit()
    return result
