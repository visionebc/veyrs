"""TLS trust store: the certificate authorities this installation ACCEPTS
when it connects out (CMDB, scanners, ITSM, directory, single sign-on, SMTP,
AI endpoints, vault, intelligence feeds).

Why it exists: an enterprise estate signs its internal services with its own
CA, and every outbound client in VEYRS verified against the PUBLIC roots only.
The operator had two choices per connector -- "verify" (fails against every
internal CA) or "do not verify" -- and nothing in between. This table is the
place to put the company root.

Design notes that matter:

* **Installation-wide, not per tenant** (listed in ``GLOBAL_TABLES``). TLS
  verification happens in the process; one organization cannot trust a CA
  "only for itself" without a per-tenant client stack nobody would audit.
  Managing it is a platform-administrator action, like software updates.
* **The database is the source of truth; nothing is written to disk.** Each
  node builds its verification context in memory from these rows, so the
  standby database carries the store and both app nodes agree without a copy
  step. The API runs under ``ProtectSystem=strict`` and needs no new
  writable path.
* **Public certificates only.** A CA certificate is public by definition: no
  Fernet. The CA's private key never comes near this table.
* **The fingerprint is the identity.** Re-importing a CA updates its row in
  place instead of stacking duplicates.
* **Disabled is not deleted.** ``is_enabled=False`` takes a CA out of every
  verification while keeping the record of what was trusted and when.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, uuid_pk

#: A self-signed CA (trust anchor) or a CA signed by another CA. Shown because
#: they behave differently: an intermediate whose issuer is absent imports
#: cleanly and then fails every handshake with "unable to get issuer".
ROLE_ROOT = "root"
ROLE_INTERMEDIATE = "intermediate"
TRUST_ROLES = (ROLE_ROOT, ROLE_INTERMEDIATE)


class TrustedCa(Base, TimestampMixin):
    __tablename__ = "trusted_cas"

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Operator-facing label; defaults to the certificate's common name.
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    pem: Mapped[str] = mapped_column(Text, nullable=False)
    #: Lowercase hex SHA-256 of the DER: the real identity of the row.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    issuer: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    serial: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    role: Mapped[str] = mapped_column(String(16), nullable=False, default=ROLE_INTERMEDIATE)
    not_before: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    not_after: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    added_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    added_by_label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
