"""Ticket lifecycle and ITIL mapping (spec sections 14 and 15).

A remediation ticket is created *from* a finding and keeps a hard link to it, so
the ITIL chain the spec asks for is a set of joins rather than a convention:

    Vulnerability -> Risk -> Incident -> Change -> Remediation -> Verification -> Closure

Deliberate behaviours:

* One open remediation ticket per finding. Creating a second is a no-op that
  returns the existing one -- duplicated tickets are the classic way a
  vulnerability programme loses the plot.
* Resolving a remediation ticket advances its finding to `remediated`; it does
  not close it. Verification is a separate step and a separate human.
* Change tickets require approval before they can be scheduled, and the graph
  in `models/ticketing.TICKET_TRANSITIONS` enforces it.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    Asset, Finding, OPEN_TICKET_STATES, Ticket, TicketComment, TicketCounter, TicketEvent,
    Vulnerability, can_transition_ticket,
)
from . import correlation

REFERENCE_PREFIX = {
    "incident": "INC",
    "problem": "PRB",
    "change": "CHG",
    "service_request": "REQ",
    "remediation": "REM",
    "exception": "EXC",
}

#: Which finding state a ticket resolution implies. Only remediation tickets
#: move the finding; an incident being closed says nothing about the patch.
RESOLUTION_ADVANCES_FINDING = {"remediation"}

PRIORITY_FROM_RISK = ((90.0, "critical"), (70.0, "high"), (40.0, "medium"), (0.0, "low"))


class TicketError(ValueError):
    """Raised for an illegal ticket operation."""


def priority_for(risk_score: float | None, severity: str | None = None) -> str:
    if risk_score is not None:
        for threshold, label in PRIORITY_FROM_RISK:
            if risk_score >= threshold:
                return label
    return severity or "medium"


def next_reference(session: Session, organization_id: uuid.UUID, ticket_type: str) -> str:
    """Per-tenant sequence, so ticket numbers do not leak other tenants' volume."""
    counter = session.execute(
        select(TicketCounter).where(
            TicketCounter.organization_id == organization_id,
            TicketCounter.ticket_type == ticket_type,
        ).with_for_update()
    ).scalars().first()
    if counter is None:
        counter = TicketCounter(
            organization_id=organization_id, ticket_type=ticket_type, last_value=0
        )
        session.add(counter)
        session.flush()
    counter.last_value += 1
    session.flush()
    prefix = REFERENCE_PREFIX.get(ticket_type, "TCK")
    return f"VEYRS-{prefix}-{counter.last_value:06d}"


def record_event(
    session: Session,
    ticket: Ticket,
    event: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    details: dict | None = None,
) -> TicketEvent:
    row = TicketEvent(
        organization_id=ticket.organization_id, ticket_id=ticket.id, event=event,
        actor_id=actor_id, actor_label=actor_label, details=details or {},
    )
    session.add(row)
    return row


def open_ticket_for_finding(session: Session, finding_id: uuid.UUID) -> Ticket | None:
    return session.execute(
        select(Ticket).where(
            Ticket.finding_id == finding_id,
            Ticket.ticket_type == "remediation",
            Ticket.state.in_(tuple(OPEN_TICKET_STATES)),
        )
    ).scalars().first()


def create_ticket(
    session: Session,
    organization_id: uuid.UUID,
    *,
    ticket_type: str = "remediation",
    title: str,
    description: str | None = None,
    finding_id: uuid.UUID | None = None,
    vulnerability_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    business_service_id: uuid.UUID | None = None,
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
    requested_by_id: uuid.UUID | None = None,
    priority: str | None = None,
    due_at: dt.datetime | None = None,
    parent_id: uuid.UUID | None = None,
    labels: list[str] | None = None,
    attributes: dict | None = None,
    actor_label: str = "system",
) -> Ticket:
    ticket = Ticket(
        organization_id=organization_id,
        reference=next_reference(session, organization_id, ticket_type),
        ticket_type=ticket_type,
        state="open",
        priority=priority or "medium",
        title=title[:500],
        description=description,
        finding_id=finding_id,
        vulnerability_id=vulnerability_id,
        asset_id=asset_id,
        business_service_id=business_service_id,
        assigned_team_id=assigned_team_id,
        assigned_user_id=assigned_user_id,
        requested_by_id=requested_by_id,
        due_at=due_at,
        parent_id=parent_id,
        labels=labels or [],
        attributes=attributes or {},
    )
    session.add(ticket)
    session.flush()
    record_event(session, ticket, "created", actor_label=actor_label,
                 details={"type": ticket_type})
    return ticket


def ticket_for_finding(
    session: Session,
    finding: Finding,
    *,
    ticket_type: str = "remediation",
    actor_label: str = "system",
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
) -> tuple[Ticket, bool]:
    """Create (or return) the remediation ticket for a finding."""
    existing = open_ticket_for_finding(session, finding.id)
    if existing is not None:
        return existing, False

    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    cve = vulnerability.cve_id if vulnerability is not None else None
    where = asset.name if asset is not None else "unknown asset"

    description_parts = [
        finding.detail or (vulnerability.description if vulnerability else "") or "",
    ]
    if finding.recommendation:
        description_parts.append(f"\nRecommended action:\n{finding.recommendation}")
    if finding.risk_explanation:
        summary = (finding.risk_explanation or {}).get("summary")
        if summary:
            description_parts.append(f"\nWhy this matters:\n{summary}")

    ticket = create_ticket(
        session, finding.organization_id,
        ticket_type=ticket_type,
        title=f"Remediate {cve or finding.title} on {where}",
        description="\n".join(p for p in description_parts if p).strip() or None,
        finding_id=finding.id,
        vulnerability_id=finding.vulnerability_id,
        asset_id=finding.asset_id,
        business_service_id=asset.business_service_id if asset is not None else None,
        assigned_team_id=assigned_team_id or finding.assigned_team_id,
        assigned_user_id=assigned_user_id or finding.assigned_user_id,
        priority=priority_for(finding.risk_score, finding.severity),
        due_at=finding.sla_due_at,
        labels=[x for x in [cve, "kev" if finding.kev else None] if x],
        attributes={
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "cvss_score": finding.cvss_score,
            "epss_score": finding.epss_score,
        },
        actor_label=actor_label,
    )
    correlation.record_event(
        session, finding, "ticket_created",
        actor_label=actor_label, details={"ticket": ticket.reference},
    )
    session.flush()
    return ticket, True


def transition_ticket(
    session: Session,
    ticket: Ticket,
    target: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    note: str | None = None,
    resolution: str | None = None,
) -> Ticket:
    current = ticket.state
    if current == target:
        return ticket
    if not can_transition_ticket(ticket.ticket_type, current, target):
        raise TicketError(
            f"{ticket.ticket_type}: {current} -> {target} is not an allowed transition"
        )

    now = dt.datetime.now(dt.timezone.utc)
    ticket.state = target
    if target == "resolved":
        ticket.resolved_at = ticket.resolved_at or now
        if resolution:
            ticket.resolution = resolution
    if target in ("closed", "cancelled", "rejected"):
        ticket.closed_at = ticket.closed_at or now
    if target == "approved":
        ticket.approver_id = actor_id
        ticket.approved_at = now
        ticket.approval_note = note

    record_event(session, ticket, "state_changed", actor_id=actor_id,
                 actor_label=actor_label,
                 details={"from": current, "to": target, "note": note})

    # Close the loop back onto the finding.
    if target == "resolved" and ticket.ticket_type in RESOLUTION_ADVANCES_FINDING \
            and ticket.finding_id:
        finding = session.get(Finding, ticket.finding_id)
        if finding is not None and finding.state not in ("remediated", "verified", "closed"):
            try:
                correlation.advance(
                    session, finding, "remediated",
                    actor_id=actor_id, actor_label=actor_label,
                    note=f"ticket {ticket.reference} resolved",
                )
            except correlation.TransitionError:
                # The finding may sit in a terminal state (accepted risk); the
                # ticket still resolves, but we record that the link did not move.
                record_event(session, ticket, "finding_not_advanced",
                             actor_label=actor_label,
                             details={"finding_state": finding.state})
    session.flush()
    return ticket


def add_comment(
    session: Session,
    ticket: Ticket,
    body: str,
    *,
    author_id: uuid.UUID | None = None,
    author_label: str = "system",
    is_internal: bool = False,
) -> TicketComment:
    row = TicketComment(
        organization_id=ticket.organization_id, ticket_id=ticket.id, body=body,
        author_id=author_id, author_label=author_label, is_internal=is_internal,
    )
    session.add(row)
    record_event(session, ticket, "commented", actor_id=author_id, actor_label=author_label,
                 details={"internal": is_internal})
    session.flush()
    return row


def sync_due_dates(session: Session, organization_id: uuid.UUID) -> int:
    """Mirror the finding's authoritative SLA clock onto its open tickets."""
    rows = session.execute(
        select(Ticket, Finding)
        .join(Finding, Finding.id == Ticket.finding_id)
        .where(
            Ticket.organization_id == organization_id,
            Ticket.state.in_(tuple(OPEN_TICKET_STATES)),
        )
    ).all()
    changed = 0
    for ticket, finding in rows:
        if ticket.due_at != finding.sla_due_at or ticket.sla_breached != finding.sla_breached:
            ticket.due_at = finding.sla_due_at
            ticket.sla_breached = finding.sla_breached
            changed += 1
    session.flush()
    return changed


def metrics(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """MTTR and queue shape for the dashboard (spec section 27)."""
    rows = session.execute(
        select(Ticket).where(Ticket.organization_id == organization_id)
    ).scalars().all()
    open_rows = [t for t in rows if t.is_open]
    resolved = [t for t in rows if t.resolved_at is not None]
    mttr = None
    if resolved:
        mttr = round(
            sum((t.resolved_at - t.created_at).total_seconds() for t in resolved)
            / len(resolved) / 3600.0, 2,
        )
    by_type: dict[str, int] = {}
    for ticket in open_rows:
        by_type[ticket.ticket_type] = by_type.get(ticket.ticket_type, 0) + 1
    return {
        "total": len(rows),
        "open": len(open_rows),
        "resolved": len(resolved),
        "breached": len([t for t in open_rows if t.sla_breached]),
        "mttr_hours": mttr,
        "open_by_type": by_type,
        "open_by_priority": {
            p: len([t for t in open_rows if t.priority == p])
            for p in ("critical", "high", "medium", "low")
        },
    }


__all__ = [
    "TicketError", "priority_for", "next_reference", "create_ticket", "ticket_for_finding",
    "transition_ticket", "add_comment", "record_event", "open_ticket_for_finding",
    "sync_due_dates", "metrics",
]
