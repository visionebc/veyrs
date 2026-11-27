"""Append-only audit trail.

Three separate logs, because they answer three different questions and have
different retention needs:
  * `audit_log`      - who changed what business object (ITIL/ISO evidence)
  * `auth_events`    - authentication and authorization outcomes (SOC use)
  * `ai_audit_log`   - every AI call: provider, model, data classification,
                       whether content left the perimeter (spec section 20)

Append-only is enforced in the database, not only by the absence of an UPDATE
or DELETE path in the application: `schema_steps/step_auth.py` puts a trigger
on all three tables that refuses UPDATE, DELETE and TRUNCATE. The one exception
is retention: a DELETE is allowed inside a transaction that ran
`SET LOCAL veyrs.audit_prune = 'on'` (the prune command does that, and nothing
else should), plus the cascades of the foreign keys below when an organization
or user row is hard-deleted. The application role owns these tables, so an
owner can still disable the trigger; separating that power needs a non-owner
application role (docs/security/hardening.md).

Tenant isolation: `audit_log` and `ai_audit_log` carry the strict RLS policy
(`cli.RLS_TABLES_STRICT_NULLABLE`); `auth_events` has its own policies in
`step_auth.py` because most of its rows are written before anybody is
authenticated: any session may INSERT, a session reads only its bound
organization's rows.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, uuid_pk


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_org_time", "organization_id", "created_at"),
        Index("ix_audit_object", "object_type", "object_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        default=None, index=True,
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    actor_label: Mapped[str] = mapped_column(String(255), default="system", nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(80), nullable=False)
    object_id: Mapped[str | None] = mapped_column(String(80), default=None)
    object_label: Mapped[str | None] = mapped_column(String(255), default=None)
    # {"field": {"from": ..., "to": ...}} - never store secrets here
    changes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), default=None)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)


class AuthEvent(Base):
    __tablename__ = "auth_events"
    __table_args__ = (Index("ix_auth_events_time", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    # Set in Python as well as by the server so the INSERT needs no RETURNING:
    # under RLS a RETURNING row must pass the SELECT policy, and a pre-auth
    # session (unbound) may write an event it is not allowed to read back.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    # NULL when the attempt names nobody this installation knows (unknown
    # e-mail, unknown refresh token): such a row belongs to no tenant.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    email_attempted: Mapped[str | None] = mapped_column(String(255), default=None, index=True)
    event: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str | None] = mapped_column(String(160), default=None)
    ip_address: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(255), default=None)
    correlation_id: Mapped[str | None] = mapped_column(String(64), default=None)


class AiAuditLog(Base):
    __tablename__ = "ai_audit_log"
    __table_args__ = (Index("ix_ai_audit_org_time", "organization_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    organization_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    user_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    capability: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(40), nullable=False)
    model: Mapped[str] = mapped_column(String(120), nullable=False)
    external: Mapped[bool] = mapped_column(Boolean, nullable=False)
    data_classification: Mapped[str] = mapped_column(String(20), nullable=False)
    decision: Mapped[str] = mapped_column(String(20), nullable=False)  # allowed|blocked|degraded
    block_reason: Mapped[str | None] = mapped_column(String(200), default=None)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, default=None)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, default=None)
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)
    # redaction report: what the sanitiser stripped before the call
    redactions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    prompt_digest: Mapped[str | None] = mapped_column(String(64), default=None)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
