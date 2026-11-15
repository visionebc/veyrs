"""Saved report-builder queries: a question an operator asks more than once.

A row is a *specification*, never a result. It holds the JSON spec the report
builder (`services/report_builder.py`) compiles against its curated catalog --
no SQL, no column names, nothing the server did not offer. Three decisions:

* **The spec is re-validated on every run, not only on save.** The catalog is
  code and changes between releases. A spec saved yesterday that names a field
  removed today must fail with a 422 that names the field, not with a 500 from
  deep inside the compiler -- and must never be "repaired" by silently dropping
  the field, which would answer a different question under the same name.
* **Running one applies the RUNNER's authorization, not the owner's.** A shared
  report opened by a team-scoped operator covers that operator's slice. The row
  grants nothing; that is why sharing it is safe at all.
* **`owner_id` is NOT NULL and cascades**, for the reason `saved_views` gives:
  an orphan shared report that nobody can edit is a row only a DBA can remove.
"""
from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class ReportQuery(Base, TenantMixin, TimestampMixin):
    __tablename__ = "report_queries"
    __table_args__ = (
        UniqueConstraint("organization_id", "owner_id", "name",
                         name="uq_report_queries_owner_name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    owner_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(400), default=None)
    #: The normalised builder spec. Validated against the catalog on save AND
    #: on every run -- see the module docstring.
    spec: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Visible to the rest of the organization. Still only editable by its owner,
    #: and still run under each reader's own permissions and team scope.
    is_shared: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
