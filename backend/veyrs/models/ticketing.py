"""Ticketing and ITIL record types (spec sections 14 and 15).

VEYRS ships its own ticket store rather than *only* integrating with ServiceNow
or Jira, for one reason: the relationship graph. A ticket here keeps hard
foreign keys to the finding, asset, product, SLA and evidence, so "show every
change that remediated a KEV on an internet-facing asset last quarter" is a
join, not an export-and-hope exercise. External ITSM systems are mirrored via
`external_system` / `external_key`, and the sync direction is explicit.

ITIL mapping (section 15) is expressed as `ticket_type`, with the canonical
lifecycle for each type enforced in `services/ticketing.py`.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class TicketType(str, enum.Enum):
    INCIDENT = "incident"
    PROBLEM = "problem"
    CHANGE = "change"
    SERVICE_REQUEST = "service_request"
    REMEDIATION = "remediation"          # vulnerability remediation task
    EXCEPTION = "exception"              # formal risk exception request


class TicketState(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    ON_HOLD = "on_hold"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    SCHEDULED = "scheduled"
    IMPLEMENTED = "implemented"
    VERIFYING = "verifying"
    RESOLVED = "resolved"
    CLOSED = "closed"
    CANCELLED = "cancelled"


OPEN_TICKET_STATES = {
    "open", "in_progress", "on_hold", "awaiting_approval", "approved",
    "scheduled", "implemented", "verifying",
}

# Per-type transition graph. Changes need approval; incidents do not. Encoding
# this as data (rather than "any state to any state") is what makes the audit
# trail defensible to an ISO 27001 auditor.
TICKET_TRANSITIONS: dict[str, dict[str, set[str]]] = {
    "default": {
        "open": {"in_progress", "on_hold", "cancelled", "resolved"},
        "in_progress": {"on_hold", "resolved", "cancelled", "verifying"},
        "on_hold": {"in_progress", "cancelled"},
        "verifying": {"resolved", "in_progress"},
        "resolved": {"closed", "in_progress"},
        "closed": set(),
        "cancelled": set(),
    },
    "change": {
        "open": {"awaiting_approval", "cancelled"},
        "awaiting_approval": {"approved", "rejected", "cancelled"},
        "approved": {"scheduled", "cancelled"},
        "rejected": {"open", "cancelled"},
        "scheduled": {"implemented", "cancelled", "on_hold"},
        "on_hold": {"scheduled", "cancelled"},
        "implemented": {"verifying", "cancelled"},
        "verifying": {"resolved", "implemented"},
        "resolved": {"closed"},
        "closed": set(),
        "cancelled": set(),
    },
}


def allowed_ticket_transitions(ticket_type: str, current: str) -> set[str]:
    graph = TICKET_TRANSITIONS.get(ticket_type, TICKET_TRANSITIONS["default"])
    return graph.get(current, set())


def can_transition_ticket(ticket_type: str, current: str, target: str) -> bool:
    return target in allowed_ticket_transitions(ticket_type, current)


class Ticket(Base, TenantMixin, TimestampMixin):
    __tablename__ = "tickets"
    __table_args__ = (
        UniqueConstraint("organization_id", "reference"),
        Index("ix_tickets_org_state", "organization_id", "state"),
        Index("ix_tickets_org_type", "organization_id", "ticket_type"),
        Index("ix_tickets_external", "external_system", "external_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    # Human-facing key, e.g. VEYRS-INC-000123. Operators quote this in email.
    reference: Mapped[str] = mapped_column(String(40), nullable=False)
    ticket_type: Mapped[str] = mapped_column(String(30), default="remediation", nullable=False)
    state: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    priority: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    resolution: Mapped[str | None] = mapped_column(Text, default=None)

    # Ownership
    assigned_team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), default=None
    )
    assigned_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    approver_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    approval_note: Mapped[str | None] = mapped_column(Text, default=None)

    # The graph: what this ticket is about
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"),
        default=None, index=True,
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="SET NULL"), default=None
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), default=None
    )
    business_service_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="SET NULL"), default=None
    )
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), default=None
    )

    # Change-management specifics (ITIL)
    change_type: Mapped[str | None] = mapped_column(String(20), default=None)  # std|normal|emerg
    risk_of_change: Mapped[str | None] = mapped_column(String(20), default=None)
    scheduled_start: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    scheduled_end: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    implementation_plan: Mapped[str | None] = mapped_column(Text, default=None)
    rollback_plan: Mapped[str | None] = mapped_column(Text, default=None)

    # SLA mirror (the authoritative clock stays on the finding)
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    sla_breached: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # External ITSM mirror
    external_system: Mapped[str | None] = mapped_column(String(40), default=None)
    external_key: Mapped[str | None] = mapped_column(String(120), default=None)
    external_url: Mapped[str | None] = mapped_column(String(600), default=None)
    external_state: Mapped[str | None] = mapped_column(String(60), default=None)
    external_synced_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    sync_direction: Mapped[str] = mapped_column(String(20), default="push", nullable=False)

    labels: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    comments: Mapped[list["TicketComment"]] = relationship(
        back_populates="ticket", cascade="all, delete-orphan"
    )

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_TICKET_STATES

    @property
    def time_to_resolve_hours(self) -> float | None:
        if self.resolved_at is None:
            return None
        return (self.resolved_at - self.created_at).total_seconds() / 3600.0


class TicketComment(Base, TenantMixin):
    __tablename__ = "ticket_comments"
    __table_args__ = (Index("ix_ticket_comments_ticket", "ticket_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False,
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    author_label: Mapped[str] = mapped_column(String(200), default="system", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # Internal notes must never be mirrored to a customer-visible ITSM comment.
    is_internal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    external_key: Mapped[str | None] = mapped_column(String(120), default=None)

    ticket: Mapped[Ticket] = relationship(back_populates="comments")


class TicketEvent(Base, TenantMixin):
    """Append-only ticket history, mirroring FindingEvent."""

    __tablename__ = "ticket_events"
    __table_args__ = (Index("ix_ticket_events_ticket", "ticket_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tickets.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False,
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    actor_label: Mapped[str] = mapped_column(String(200), default="system", nullable=False)
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class TicketCounter(Base, TenantMixin):
    """Per-tenant, per-type reference sequence.

    A shared global sequence would leak how many tickets other tenants create,
    which is a real (if minor) multi-tenant information leak.
    """

    __tablename__ = "ticket_counters"
    __table_args__ = (UniqueConstraint("organization_id", "ticket_type"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    ticket_type: Mapped[str] = mapped_column(String(30), nullable=False)
    last_value: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ItsmConnector(Base, TenantMixin, TimestampMixin):
    """Configuration for an external ITSM (ServiceNow / Jira / webhook / email)."""

    __tablename__ = "itsm_connectors"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    system: Mapped[str] = mapped_column(String(40), nullable=False)  # servicenow|jira|webhook
    base_url: Mapped[str | None] = mapped_column(String(600), default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Credentials are stored encrypted at rest by services/secrets.py; the model
    # only ever sees ciphertext, and no API response serialises this column.
    credentials_enc: Mapped[str | None] = mapped_column(Text, default=None)
    # Which VEYRS ticket types sync, and the field mapping.
    ticket_types: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    field_mapping: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_error: Mapped[str | None] = mapped_column(Text, default=None)

    # --- inbound (the remote system pushing back; see services/itsm_inbound)
    #: Off by default. A webhook endpoint that exists before anyone meant it to
    #: is an unauthenticated write path waiting to be found.
    inbound_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: HMAC shared secret, Fernet-encrypted like the credentials. It signs, it
    #: does not authorise: possession proves the sender, and grants nothing else.
    inbound_secret_enc: Mapped[str | None] = mapped_column(Text, default=None)
    #: {"Done": "resolved", "Closed": "closed"} - remote status -> VEYRS ticket
    #: state. EMPTY MEANS ADVISORY ONLY, which is the default and the safe
    #: reading: an unmapped remote closure is recorded, never acted on. This is
    #: the operator's explicit opt-in to letting an external system move a
    #: ticket, and by extension (through RESOLUTION_ADVANCES_FINDING) a finding.
    inbound_transitions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    last_inbound_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
