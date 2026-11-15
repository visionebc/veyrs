"""SLA and escalation policies (spec sections 11 and 12).

Both are data, not code: an organization changes its remediation deadlines and
escalation ladder through the API, and the engines read the rows. The matching
rules are ordered by `priority`, first match wins, and every policy carries an
explicit fallback so a finding can never end up with no deadline at all.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class SlaPolicy(Base, TenantMixin, TimestampMixin):
    __tablename__ = "sla_policies"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        Index("ix_sla_policies_org_priority", "organization_id", "priority"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Match conditions, all optional and ANDed:
    # {"severity":["critical"],"kev":true,"exposure":["internet"],
    #  "min_cvss":9.0,"min_epss":0.5,"asset_criticality":["critical"],
    #  "environment":["production"],"min_risk":80}
    conditions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    remediate_within_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    # optional intermediate deadlines; None disables that gate
    triage_within_hours: Mapped[int | None] = mapped_column(Integer, default=None)
    verify_within_hours: Mapped[int | None] = mapped_column(Integer, default=None)
    # warn before the deadline (notification, not a breach)
    warn_at_percent: Mapped[int] = mapped_column(Integer, default=75, nullable=False)
    # business hours only vs wall clock. Critical work should not pause overnight.
    business_hours_only: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    escalation_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("escalation_policies.id", ondelete="SET NULL"),
        default=None,
    )


class EscalationPolicy(Base, TenantMixin, TimestampMixin):
    __tablename__ = "escalation_policies"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Ordered ladder. `after_hours` is measured from finding detection, so the
    # levels are absolute rather than relative to the previous step - a stalled
    # escalation cannot silently skip a level.
    # [{"level":1,"after_hours":4,"notify":"team"},
    #  {"level":2,"after_hours":8,"notify":"team_manager"},
    #  {"level":3,"after_hours":24,"notify":"security_manager"},
    #  {"level":4,"after_hours":48,"notify":"ciso"}]
    levels: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # role slug -> list of user ids / emails resolved at notification time
    targets: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class SlaEvent(Base, TenantMixin):
    """Every SLA state change, so breach reporting is reconstructible."""

    __tablename__ = "sla_events"
    __table_args__ = (Index("ix_sla_events_org_time", "organization_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc),
        nullable=False,
    )
    event: Mapped[str] = mapped_column(String(40), nullable=False)  # set|warned|breached|met
    sla_policy_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    escalation_level: Mapped[int | None] = mapped_column(Integer, default=None)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
