"""Saved views: the filter set an operator opens every morning.

A console list in VEYRS is a query with a dozen dimensions -- severity, state,
exposure, owning team, KEV, exploit maturity, SLA breach. The nav ships a
handful of those combinations as fixed sub-items, which covers the questions the
product anticipated and nothing else. Everything an operator actually works
from ("critical, internet-facing, my team, not yet ticketed") had to be rebuilt
by hand every session, and a filter you rebuild every morning is a filter you
stop using by Thursday.

Three decisions worth keeping:

* **`owner_id` is NOT NULL and cascades.** Sharing is a flag on somebody's
  view, not an ownerless org object. The cost is real -- deleting a user
  deletes the views they shared -- and it is the cheaper failure: an orphan
  shared view that nobody can edit or delete is a row the administrator has to
  reach into the database to remove.
* **`filters` is validated against an allow-list, not stored raw.** A saved
  view is replayed by the console as query parameters against `/findings`,
  `/assets`, `/tickets`. Persisting arbitrary keys would make this table a
  place to smuggle parameters a future release happens to start honouring.
* **It carries no finding rows.** A saved view names a query; it does not
  answer one. That is why the router is exempt from team scope -- see
  `security/scope.py`. Applying the saved filters goes through `/findings`,
  which IS scoped, so a restricted operator opening a shared estate-wide view
  sees their own slice of it rather than a 403 or somebody else's estate.
"""
from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, TimestampMixin, uuid_pk

#: Which console list a saved view belongs to. A view is not portable between
#: entities: `severity=critical` means something different to an asset than to
#: a finding, and a view that silently changed meaning when reused would be
#: worse than one that refuses.
VIEW_ENTITIES: tuple[str, ...] = (
    "findings", "tickets", "assets", "vulnerabilities", "issues",
)


class SavedView(Base, TenantMixin, TimestampMixin):
    __tablename__ = "saved_views"
    __table_args__ = (
        UniqueConstraint("organization_id", "owner_id", "entity", "name",
                         name="uq_saved_views_owner_name"),
        Index("ix_saved_views_org_entity", "organization_id", "entity"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    owner_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    entity: Mapped[str] = mapped_column(String(30), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(400), default=None)
    #: Query parameters, already validated. Values are strings because that is
    #: what they become in a URL; typing them here would only move the coercion.
    filters: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Visible to the rest of the organization. Still only editable by its owner.
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Shown in the sidebar rail rather than only in the "Views" picker.
    is_pinned: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
