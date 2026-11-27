"""The certificate VEYRS PRESENTS to browsers (the mirror image of the trust
store, which holds the CAs it ACCEPTS when it connects out).

Life of a certificate here:

    pending  -- a key + CSR generated on this installation; the CSR went to a CA
    ready    -- the signed certificate came back, matched its key and passed
                every check; not served yet
    active   -- the one certificate every app node serves (at most one row)
    retired  -- was active; kept so it can be reinstalled (rollback)

Design notes that matter:

* **The private key is generated here and never leaves sealed storage.** It is
  stored through `security.secrets.encrypt` (Fernet, or the vault when the
  installation uses one), exactly like connector credentials. No API response
  ever carries it; only the root installer on each node decrypts it, to write
  the file nginx reads.
* **Installation-wide** (`GLOBAL_TABLES`): one installation serves one
  certificate. Platform administrators only.
* **The database is the source of truth for every node.** Each app node runs
  `veyrs-tls-sync.timer` (root) which reads the active row and installs it on
  that node, then reports back in `web_tls_nodes`. Installing on one node is
  therefore installing on all, and a failover node never serves a different
  certificate for long.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, uuid_pk

CERT_PENDING = "pending"
CERT_READY = "ready"
CERT_ACTIVE = "active"
CERT_RETIRED = "retired"
CERT_STATES = (CERT_PENDING, CERT_READY, CERT_ACTIVE, CERT_RETIRED)


class WebCertificate(Base, TimestampMixin):
    __tablename__ = "web_certificates"

    id: Mapped[uuid.UUID] = uuid_pk()
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=CERT_PENDING, index=True)
    #: "csr" = key generated here; "imported" = certificate + key brought in.
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="csr")
    common_name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Names requested (CSR) -- ["veyrs.example.com", "198.19.2.3"].
    requested_names: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    #: Subject fields requested besides CN (O, OU, L, ST, C).
    requested_subject: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    key_type: Mapped[str] = mapped_column(String(16), nullable=False)
    #: `security.secrets.encrypt` of the PEM private key. Never returned.
    key_sealed: Mapped[str] = mapped_column(Text, nullable=False)
    #: SHA-256 of the DER SubjectPublicKeyInfo: how a returned certificate is
    #: matched to the key that requested it.
    key_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    csr_pem: Mapped[str | None] = mapped_column(Text, default=None)

    cert_pem: Mapped[str | None] = mapped_column(Text, default=None)
    #: Intermediates to serve after the leaf (never the root), PEM.
    chain_pem: Mapped[str | None] = mapped_column(Text, default=None)
    cert_fingerprint: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    subject: Mapped[str | None] = mapped_column(String(1000), default=None)
    issuer: Mapped[str | None] = mapped_column(String(1000), default=None)
    serial: Mapped[str | None] = mapped_column(String(80), default=None)
    #: Names the certificate actually covers (its SAN), as issued.
    names: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    not_before: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    not_after: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    #: The checks run when the certificate was attached: [{check, result, detail}].
    checks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    note: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None)
    created_by_label: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    activated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    activated_by_label: Mapped[str | None] = mapped_column(String(255), default=None)


class WebTlsNode(Base):
    """What one app node actually serves, written by its root installer."""

    __tablename__ = "web_tls_nodes"

    node: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: applied | error | not_configured (no `include` in its nginx) | off (no active certificate)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="off")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    desired_fingerprint: Mapped[str | None] = mapped_column(String(64), default=None)
    #: Fingerprint of the certificate the node's :443 returned in the last check.
    served_fingerprint: Mapped[str | None] = mapped_column(String(64), default=None)
    redirect_http: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    nginx_version: Mapped[str | None] = mapped_column(String(64), default=None)
    checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    applied_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)


class InstallationSetting(Base):
    """Installation-wide switches that belong to no organization (key -> JSON)."""

    __tablename__ = "installation_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    updated_by_label: Mapped[str | None] = mapped_column(String(255), default=None)
