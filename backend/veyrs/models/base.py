"""Declarative base plus the mixins every VEYRS table is built from."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Explicit naming convention so Alembic autogenerate produces stable, reviewable
# migrations instead of database-assigned constraint names.
NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)

    type_annotation_map = {dict[str, Any]: JSONB, list[str]: JSONB}

    def as_dict(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        exclude = exclude or set()
        out: dict[str, Any] = {}
        for column in self.__table__.columns:
            if column.name in exclude:
                continue
            value = getattr(self, column.name)
            if isinstance(value, uuid.UUID):
                value = str(value)
            elif isinstance(value, dt.datetime):
                value = value.isoformat()
            elif isinstance(value, dt.date):
                value = value.isoformat()
            out[column.name] = value
        return out


def uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class TenantMixin:
    """Every row that belongs to a customer carries its organization_id.

    The column is NOT NULL and indexed: it is the RLS predicate and the first
    key of nearly every composite index in the schema.
    """

    @property
    def _tenant_key(self) -> uuid.UUID:  # pragma: no cover - accessor
        return self.organization_id

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )


class SoftDeleteMixin:
    deleted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None


class SlugMixin:
    slug: Mapped[str] = mapped_column(String(120), nullable=False, index=True)


# Tables that are deliberately GLOBAL (shared reference intelligence, not
# customer data): CVE, CWE, CPE, EPSS, KEV, vendor/product catalogue and the
# compliance framework library. Everything else must carry TenantMixin.
GLOBAL_TABLES = {
    "cve", "cwe", "cpe", "epss_scores", "epss_history", "kev_entries",
    "vendors", "products", "product_versions", "compliance_frameworks",
    "compliance_controls", "cve_references", "cve_cpe_match",
}
