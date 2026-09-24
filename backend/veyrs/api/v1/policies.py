"""Policy administration: SLA, escalation and assignment rules.

These three tables are the automation the spec asks for in sections 10-12, and
they are all *data*. An organization changes who owns Fortinet findings, or how
fast a KEV must be fixed, through this API -- never through a code change.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import Response, APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select

from ...models import (
    AssignmentRule, EscalationPolicy, Finding, OPEN_STATES, SlaEvent, SlaPolicy, Team, User,
)
from ...security import scope as team_scope
from ...security.deps import Principal, TenantSession, require
from ...services import analytics, audit, correlation
from ...services import sla as sla_service
from .schemas import Page
from .vuln_schemas import (
    AssignmentRuleOut, AssignmentRuleWrite, EscalationPolicyOut, EscalationPolicyWrite,
    SlaPolicyOut, SlaPolicyWrite,
)

router = APIRouter(prefix="/policies", tags=["policies"])


def _actor(request: Request, principal: Principal) -> dict:
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": request.client.host if request.client else None,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


#: Offered by the three routes below that read finding-level rows. The policy
#: tables themselves are organization configuration and have no owning team, so
#: they neither take it nor need it.
TEAM_FILTER = Query(default=None, description="Narrow to one owning team")


def _estate_only(principal: Principal) -> None:
    """Editing policy is editing it for everybody -- so it needs everybody's grant.

    Found by the source guardrail in `test_phase28_sla_scope.py` while it was
    hunting read leaks, and it is the worse defect of the two: `PATCH
    /policies/sla/{id}` re-applies the changed deadline to **every open finding
    in the organization** (`reapply=true` by default, `force=True`), so a
    team-scoped identity held a write over rows it cannot even list.

    Narrowing the re-apply was the tempting fix and it is wrong: the policy row
    is organization-wide either way, so a partial re-apply would leave the other
    teams governed by a deadline nobody recomputed -- a silent split between
    what the policy says and what the findings carry. An assignment rule is the
    same shape from the other end: a rule is how work is routed *to* teams, and
    a team that can write one decides its own queue.

    Reading stays open on purpose. An operator has to be able to see the SLA
    they are being judged against.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "policy configuration applies to the whole estate and cannot be changed "
        "by a team-scoped identity; it requires an estate-wide role grant",
    )


def _owned(session, model, organization_id: uuid.UUID, row_id: uuid.UUID):
    row = session.get(model, row_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return row


# --------------------------------------------------------------------------
# SLA policies
# --------------------------------------------------------------------------


@router.get("/sla", response_model=list[SlaPolicyOut], summary="List SLA policies")
def list_sla(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:read"))],
) -> list[SlaPolicyOut]:
    rows = session.execute(
        select(SlaPolicy).where(SlaPolicy.organization_id == principal.organization_id)
        .order_by(SlaPolicy.priority)
    ).scalars().all()
    return [SlaPolicyOut.model_validate(r) for r in rows]


@router.post("/sla", response_model=SlaPolicyOut, status_code=status.HTTP_201_CREATED,
             summary="Create an SLA policy")
def create_sla(
    payload: SlaPolicyWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
) -> SlaPolicyOut:
    _estate_only(principal)
    if session.execute(
        select(SlaPolicy).where(
            SlaPolicy.organization_id == principal.organization_id,
            SlaPolicy.slug == payload.slug,
        )
    ).scalars().first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "slug already exists")
    row = SlaPolicy(organization_id=principal.organization_id, **payload.model_dump())
    session.add(row)
    audit.record(session, action="sla.create", object_type="sla_policy",
                 object_id=payload.slug,
                 **_actor(request, principal), changes=audit.diff(None, payload.model_dump(mode="json")))
    session.commit()
    session.refresh(row)
    return SlaPolicyOut.model_validate(row)


@router.patch("/sla/{policy_id}", response_model=SlaPolicyOut, summary="Update an SLA policy")
def update_sla(
    policy_id: uuid.UUID,
    payload: SlaPolicyWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
    reapply: bool = Query(default=True, description="Recompute deadlines on open findings"),
) -> SlaPolicyOut:
    _estate_only(principal)
    row = _owned(session, SlaPolicy, principal.organization_id, policy_id)
    before = {k: getattr(row, k) for k in payload.model_dump()}
    for key, value in payload.model_dump().items():
        setattr(row, key, value)
    session.flush()

    # A changed deadline that does not apply to work already in the queue is a
    # policy nobody trusts. Re-apply by default; the flag exists for migrations.
    if reapply:
        findings = session.execute(
            select(Finding).where(
                Finding.organization_id == principal.organization_id,
                Finding.state.in_(tuple(OPEN_STATES)),
            )
        ).scalars().all()
        for finding in findings:
            sla_service.apply_sla(session, finding, force=True)

    audit.record(session, action="sla.update", object_type="sla_policy",
                 object_id=str(row.id), **_actor(request, principal), changes=audit.diff(before, payload.model_dump(mode="json")))
    session.commit()
    session.refresh(row)
    return SlaPolicyOut.model_validate(row)


@router.delete("/sla/{policy_id}", status_code=204, response_model=None, response_class=Response,
               summary="Delete an SLA policy")
def delete_sla(
    policy_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:admin"))],
) -> None:
    _estate_only(principal)
    row = _owned(session, SlaPolicy, principal.organization_id, policy_id)
    if row.is_default:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "cannot delete the default policy - promote another first")
    session.delete(row)
    session.commit()


# --------------------------------------------------------------------------
# Escalation policies
# --------------------------------------------------------------------------


@router.get("/escalation", response_model=list[EscalationPolicyOut],
            summary="List escalation policies")
def list_escalation(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("escalation:read"))],
) -> list[EscalationPolicyOut]:
    rows = session.execute(
        select(EscalationPolicy).where(
            EscalationPolicy.organization_id == principal.organization_id
        ).order_by(EscalationPolicy.name)
    ).scalars().all()
    return [EscalationPolicyOut.model_validate(r) for r in rows]


@router.post("/escalation", response_model=EscalationPolicyOut,
             status_code=status.HTTP_201_CREATED, summary="Create an escalation policy")
def create_escalation(
    payload: EscalationPolicyWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("escalation:write"))],
) -> EscalationPolicyOut:
    _estate_only(principal)
    levels = sorted(payload.levels, key=lambda s: s.get("after_hours", 0))
    seen: set[int] = set()
    for step in levels:
        level = step.get("level")
        if level is None or level in seen:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "each escalation step needs a unique 'level'",
            )
        seen.add(level)
    row = EscalationPolicy(
        organization_id=principal.organization_id,
        **{**payload.model_dump(), "levels": levels},
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return EscalationPolicyOut.model_validate(row)


# --------------------------------------------------------------------------
# Assignment rules
# --------------------------------------------------------------------------


@router.get("/assignment", response_model=list[AssignmentRuleOut],
            summary="List assignment rules")
def list_rules(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> list[AssignmentRuleOut]:
    rows = session.execute(
        select(AssignmentRule).where(
            AssignmentRule.organization_id == principal.organization_id
        ).order_by(AssignmentRule.priority)
    ).scalars().all()
    return [AssignmentRuleOut.model_validate(r) for r in rows]


@router.post("/assignment", response_model=AssignmentRuleOut,
             status_code=status.HTTP_201_CREATED, summary="Create an assignment rule")
def create_rule(
    payload: AssignmentRuleWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:write"))],
) -> AssignmentRuleOut:
    _estate_only(principal)
    if payload.team_id is None and payload.user_id is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "a rule must target a team or a user")
    if payload.team_id is not None:
        _owned(session, Team, principal.organization_id, payload.team_id)
    if payload.user_id is not None:
        _owned(session, User, principal.organization_id, payload.user_id)
    row = AssignmentRule(organization_id=principal.organization_id, **payload.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return AssignmentRuleOut.model_validate(row)


@router.post("/assignment/test", summary="Dry-run the rule set against a context")
def test_rules(
    context: dict,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict:
    """Explains *why* a rule matched, so operators can debug routing safely."""
    rows = session.execute(
        select(AssignmentRule).where(
            AssignmentRule.organization_id == principal.organization_id,
            AssignmentRule.is_enabled.is_(True),
        ).order_by(AssignmentRule.priority, AssignmentRule.created_at)
    ).scalars().all()
    evaluated = []
    winner = None
    for rule in rows:
        matched = correlation.rule_matches(rule.conditions, context)
        evaluated.append({"id": str(rule.id), "name": rule.name,
                          "priority": rule.priority, "matched": matched})
        if matched and winner is None:
            winner = {"id": str(rule.id), "name": rule.name,
                      "team_id": str(rule.team_id) if rule.team_id else None,
                      "user_id": str(rule.user_id) if rule.user_id else None}
    return {"winner": winner, "evaluated": evaluated}


# --------------------------------------------------------------------------
# The sweep
# --------------------------------------------------------------------------


@router.post("/sla/evaluate", summary="Run the SLA + escalation sweep now")
def evaluate(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
) -> dict:
    """Sweep the caller's own scope -- deliberately not an arbitrary team.

    The sweep writes: it breaches, escalates and notifies. A `?team_id=` here
    would be a view filter steering a mutation, and "I only meant to look" is
    the wrong sentence to be able to say about a page-out. Authorization scope
    is the only thing that narrows it, and the counters returned say so.
    """
    stats = sla_service.evaluate_findings(session, principal.organization_id,
                                          scope=principal.scope)
    session.commit()
    return {**stats, "scope": analytics.scope_block(principal.scope)}


@router.get("/sla/summary", summary="SLA dashboard counters")
def summary(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:read"))],
    team_id: uuid.UUID | None = TEAM_FILTER,
) -> dict:
    """Breach counters, narrowed like every other figure -- and it says which.

    Two defects in one route until v0.17.1: a team-restricted identity read the
    whole estate here, and the console hid the widget under a team filter
    because the endpoint could not be narrowed. The `scope` block is the same
    one the dashboards carry, so the console renders one banner from one shape
    instead of deciding per widget what a number means.
    """
    view = team_scope.resolve_view(session, principal.scope,
                                   principal.organization_id, team_id)
    payload = sla_service.breach_summary(session, principal.organization_id, scope=view)
    payload["scope"] = analytics.scope_block(view)
    return payload


@router.get("/sla/events", response_model=Page[dict], summary="SLA event log")
def events(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:read"))],
    finding_id: uuid.UUID | None = None,
    event: str | None = None,
    team_id: uuid.UUID | None = TEAM_FILTER,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[dict]:
    """The SLA audit trail, scoped by the finding each event belongs to.

    `sla_events` carries no team of its own; it inherits its finding's owner,
    the same shape as `analytics._scoped_history`. Filtering by a finding
    outside the scope therefore answers an empty page rather than 404 -- the
    subquery simply does not contain it, which is the same non-answer the row
    would get anywhere else.
    """
    view = team_scope.resolve_view(session, principal.scope,
                                   principal.organization_id, team_id)
    stmt = select(SlaEvent).where(SlaEvent.organization_id == principal.organization_id)
    if view.restricted:
        visible = team_scope.findings(
            select(Finding.id).where(Finding.organization_id == principal.organization_id),
            view,
        )
        stmt = stmt.where(SlaEvent.finding_id.in_(visible))
    if finding_id:
        stmt = stmt.where(SlaEvent.finding_id == finding_id)
    if event:
        stmt = stmt.where(SlaEvent.event == event)
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(SlaEvent.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page.of([{
            "id": str(r.id), "finding_id": str(r.finding_id), "event": r.event,
            "at": r.created_at.isoformat(), "escalation_level": r.escalation_level,
            "details": r.details,
        } for r in rows], total, page, size)
