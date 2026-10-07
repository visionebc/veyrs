"""Threat intelligence feeds, document intelligence and the knowledge base.

Spec sections 17, 18, 21 and 28. The chain the spec asks for is modelled with
real foreign keys so it can be traversed in both directions:

    Source -> Feed -> Article -> Intelligence -> CVE -> Product -> Asset -> Risk

Documents (vendor advisories, PDFs, scanner exports) are first-class citizens
rather than attachments: an uploaded Fortinet PSIRT advisory becomes text, then
extracted entities, then correlated findings.

Search is intentionally two-layered. Postgres full-text handles exact/lexical
matching and is always available; the vector index (Qdrant) is optional and
degrades to lexical-only, because an on-premise install must not lose search
because an embedding service is unreachable.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class SourceKind(str, enum.Enum):
    RSS = "rss"
    ATOM = "atom"
    JSON = "json"
    MISP = "misp"
    OPENCTI = "opencti"
    VENDOR_ADVISORY = "vendor_advisory"
    CERT = "cert"
    MANUAL = "manual"


class ThreatSource(Base, TenantMixin, TimestampMixin):
    """A configured intelligence source (per tenant: sources are a choice)."""

    __tablename__ = "threat_sources"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), default="rss", nullable=False)
    url: Mapped[str | None] = mapped_column(String(1000), default=None)
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vendors.id", ondelete="SET NULL"), default=None
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # 0.0-1.0. Feeds a confidence score onto derived intelligence rather than
    # treating a random blog and a vendor PSIRT as equally authoritative.
    trust: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    credentials_enc: Mapped[str | None] = mapped_column(Text, default=None)
    poll_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_polled_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    articles: Mapped[list["ThreatArticle"]] = relationship(
        back_populates="source", cascade="all, delete-orphan"
    )


class ThreatArticle(Base, TenantMixin, TimestampMixin):
    __tablename__ = "threat_articles"
    __table_args__ = (
        # Same story published twice must not become two articles.
        UniqueConstraint("organization_id", "content_hash"),
        Index("ix_threat_articles_org_published", "organization_id", "published_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    source_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("threat_sources.id", ondelete="CASCADE"), default=None
    )
    external_id: Mapped[str | None] = mapped_column(String(400), default=None)
    url: Mapped[str | None] = mapped_column(String(1000), default=None)
    title: Mapped[str] = mapped_column(String(600), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    body: Mapped[str | None] = mapped_column(Text, default=None)
    author: Mapped[str | None] = mapped_column(String(200), default=None)
    language: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    published_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Extracted intelligence
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    product_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    vendors: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20), default=None)
    confidence: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    # Does anything in this tenant's inventory match? Computed at ingest.
    relevant_asset_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_relevant: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    read_by: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    source: Mapped[ThreatSource | None] = relationship(back_populates="articles")


class Document(Base, TenantMixin, TimestampMixin):
    """An uploaded file or fetched URL, plus its extraction state."""

    __tablename__ = "documents"
    __table_args__ = (
        UniqueConstraint("organization_id", "content_hash"),
        Index("ix_documents_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    filename: Mapped[str] = mapped_column(String(400), nullable=False)
    #: A human title, separate from the filename on purpose. `filename` is
    #: evidence -- it is what the uploader's disk called the bytes, and the
    #: content hash is taken over those same bytes -- while `title` is how a
    #: person finds the document again six months later. Overwriting the
    #: filename with a nicer name loses the only record of what was received.
    title: Mapped[str | None] = mapped_column(String(400), default=None)
    #: Free-text operator notes: why this was uploaded, what was decided.
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    content_type: Mapped[str] = mapped_column(String(120), default="text/plain", nullable=False)
    source_url: Mapped[str | None] = mapped_column(String(1000), default=None)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Object storage key; the bytes are never kept in the database.
    storage_key: Mapped[str | None] = mapped_column(String(600), default=None)

    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    text_content: Mapped[str | None] = mapped_column(Text, default=None)
    page_count: Mapped[int | None] = mapped_column(Integer, default=None)
    ocr_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    doc_class: Mapped[str | None] = mapped_column(String(40), default=None)
    extracted: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: CVEs the EXTRACTOR found in the text. Machine-derived: re-running
    #: extraction may legitimately rewrite it.
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: CVEs a PERSON attached. Kept in its own column rather than appended to
    #: `cve_ids` because the two have different lifetimes and different
    #: authority: an analyst who links an advisory to a CVE the text never
    #: names has made a judgement, and a re-extraction must not silently
    #: discard it. Every read that wants "all of them" unions the two.
    manual_cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Which team owns this document. Ownership, not authorization: documents
    #: are organization-wide, and making a team's advisories invisible to the
    #: rest of the estate is how the same CVE gets triaged twice.
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), default=None
    )
    #: The vendor whose advisory this is, pointing at the SAME `vendors` rows
    #: the CPE dictionary uses -- so "every Fortinet advisory" and "every
    #: Fortinet product in the estate" are answerable from one identifier
    #: rather than from a free-text field that drifts one spelling per upload.
    vendor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vendors.id", ondelete="SET NULL"), default=None
    )
    uploaded_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    # Governs whether the AI layer may send this content to an external provider.
    data_classification: Mapped[str] = mapped_column(
        String(20), default="internal", nullable=False
    )

    chunks: Mapped[list["DocumentChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class DocumentChunk(Base, TenantMixin):
    """Retrieval unit for vector search. Embeddings live in Qdrant, not here."""

    __tablename__ = "document_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "ordinal"),
        Index("ix_document_chunks_org", "organization_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    document_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("documents.id", ondelete="CASCADE"), nullable=False
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    embedded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    vector_id: Mapped[str | None] = mapped_column(String(80), default=None)

    document: Mapped[Document] = relationship(back_populates="chunks")


class KnowledgeArticle(Base, TenantMixin, TimestampMixin):
    """Runbooks, remediation guides, policies (spec section 21)."""

    __tablename__ = "knowledge_articles"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        Index("ix_knowledge_org_kind", "organization_id", "kind"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), default="guide", nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Least-privilege by default: an empty list means "anyone in the tenant",
    # a populated one restricts to those permission strings.
    required_permissions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # Relationship to the graph
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    product_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    cwe_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    view_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    revisions: Mapped[list["KnowledgeRevision"]] = relationship(
        back_populates="article", cascade="all, delete-orphan"
    )


class KnowledgeRevision(Base, TenantMixin):
    """Immutable history. Editing a runbook must never lose the prior text."""

    __tablename__ = "knowledge_revisions"
    __table_args__ = (
        UniqueConstraint("article_id", "version"),
        Index("ix_knowledge_revisions_article", "article_id", "version"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    article_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("knowledge_articles.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False,
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    change_note: Mapped[str | None] = mapped_column(Text, default=None)

    article: Mapped[KnowledgeArticle] = relationship(back_populates="revisions")
