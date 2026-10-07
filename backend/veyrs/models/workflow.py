"""Workflow and notification models (spec sections 13 and 30).

The workflow engine is deliberately a *small* piece of machinery: a definition
is an ordered list of steps, each step is a named action with a JSON config, and
a run records what each step did. It is not a general-purpose scripting engine,
because a rules system that can run arbitrary code inside a multi-tenant
security product is an attack surface, not a feature. Every action a workflow
can take is an entry in `services/workflow.ACTIONS`, reviewed like any code.
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


class TriggerType(str, enum.Enum):
    FINDING_CREATED = "finding.created"
    FINDING_STATE_CHANGED = "finding.state_changed"
    FINDING_RISK_CHANGED = "finding.risk_changed"
    SLA_WARNED = "sla.warned"
    SLA_BREACHED = "sla.breached"
    SLA_ESCALATED = "sla.escalated"
    KEV_ADDED = "intel.kev_added"
    TICKET_STATE_CHANGED = "ticket.state_changed"
    MANUAL = "manual"
    SCHEDULE = "schedule"


class WorkflowDefinition(Base, TenantMixin, TimestampMixin):
    __tablename__ = "workflow_definitions"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        Index("ix_workflows_org_trigger", "organization_id", "trigger"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    # Same flat AND-map grammar as assignment/SLA conditions, so operators learn
    # one filter language for the whole product.
    conditions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # [{"action":"create_ticket","config":{...}}, {"action":"notify","config":{...}}]
    steps: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # Stop after the first failing step vs continue. Notification workflows
    # usually continue; ticket-then-notify chains must not.
    stop_on_error: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_run_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    runs: Mapped[list["WorkflowRun"]] = relationship(
        back_populates="definition", cascade="all, delete-orphan"
    )


class WorkflowRun(Base, TenantMixin):
    __tablename__ = "workflow_runs"
    __table_args__ = (Index("ix_workflow_runs_org_time", "organization_id", "started_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    definition_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("workflow_definitions.id", ondelete="CASCADE"),
        nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False,
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    # What the run was about, so a run is traceable back into the graph.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    context: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # [{"action":..,"status":"ok|error|skipped","detail":..}]
    step_results: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, default=None)

    definition: Mapped[WorkflowDefinition] = relationship(back_populates="runs")


class NotificationTemplate(Base, TenantMixin, TimestampMixin):
    """Localised message bodies (spec section 23: EN/ES/DE/FR/IT)."""

    __tablename__ = "notification_templates"
    __table_args__ = (UniqueConstraint("organization_id", "slug", "locale"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    subject: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    body_html: Mapped[str | None] = mapped_column(Text, default=None)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Notification(Base, TenantMixin):
    """One delivery attempt on one channel.

    Stored rather than fire-and-forget so "was the CISO actually told?" is
    answerable during an incident review, and so retries are bounded and visible.
    """

    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_org_status", "organization_id", "status"),
        Index("ix_notifications_recipient", "recipient_user_id", "read_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False,
    )
    channel: Mapped[str] = mapped_column(String(20), default="in_app", nullable=False)
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    subject: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)

    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), default=None
    )
    recipient_team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), default=None
    )
    recipient_address: Mapped[str | None] = mapped_column(String(320), default=None)

    finding_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)

    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    read_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class WebhookEndpoint(Base, TenantMixin, TimestampMixin):
    __tablename__ = "webhook_endpoints"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    events: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # HMAC-SHA256 signing secret, encrypted at rest; never serialised.
    secret_enc: Mapped[str | None] = mapped_column(Text, default=None)
    last_status: Mapped[int | None] = mapped_column(Integer, default=None)
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    last_sent_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class NotificationPreference(Base, TenantMixin):
    """Per-user channel opt-outs. Escalation notices are not opt-out-able."""

    __tablename__ = "notification_preferences"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", "event"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    event: Mapped[str] = mapped_column(String(60), nullable=False)
    email: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    in_app: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
