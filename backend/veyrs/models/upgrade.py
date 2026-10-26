"""Operator-maintained vendor upgrade-path rules, read by the fix plan.

"Upgrade to 8.0.2" is only half an answer when the vendor will not let you get
there in one step: some products refuse to skip a major, some need a minimum
intermediate build, some need a database or licence migration first. None of
that is in NVD, and VEYRS ships **no** such facts of its own -- a seeded
"vendor X requires hop Y" is a claim about somebody else's product that nobody
here can keep true. The operator who read the vendor's upgrade guide records
it, with the URL they read it at, and the fix plan applies it.

A rule says: *when the installed version is inside `from_*` and the target is
past `via_version`, you must stop at `via_version` first* -- optionally with a
free-text prerequisite ("export the config", "migrate the database"). A rule
with no `via_version` attaches its prerequisite to any hop that leaves the
range.
"""
from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class UpgradePathRule(Base, TenantMixin, TimestampMixin):
    __tablename__ = "upgrade_path_rules"
    __table_args__ = (
        Index("ix_upgrade_path_rules_product", "organization_id", "vendor_key", "product_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: As the operator typed them, for display.
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(300), nullable=False)
    #: `versions.normalize_name` of the above: what the plan actually matches on,
    #: so "Acme, Inc." and "acme" are the same vendor here as everywhere else.
    vendor_key: Mapped[str] = mapped_column(String(200), nullable=False)
    product_key: Mapped[str] = mapped_column(String(300), nullable=False)

    # The installed-version range the rule applies FROM. Same four bounds as
    # `CveCpeMatch`, compared with the same `versions.in_range`; all empty means
    # "any version of this product".
    from_start_including: Mapped[str | None] = mapped_column(String(120), default=None)
    from_start_excluding: Mapped[str | None] = mapped_column(String(120), default=None)
    from_end_including: Mapped[str | None] = mapped_column(String(120), default=None)
    from_end_excluding: Mapped[str | None] = mapped_column(String(120), default=None)

    #: The mandatory intermediate stop. NULL = a prerequisite-only rule.
    via_version: Mapped[str | None] = mapped_column(String(120), default=None)
    prerequisite: Mapped[str | None] = mapped_column(Text, default=None)
    #: Where the operator read it. A rule with no source is a rumour.
    source_url: Mapped[str | None] = mapped_column(String(1000), default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
