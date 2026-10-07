"""Global security intelligence: CVE, CWE, CPE, EPSS, CISA KEV, vendor/product.

These tables are deliberately NOT tenant-scoped. A CVE is the same fact for
every customer; duplicating it per tenant would multiply storage by the tenant
count and make correlation impossible. Tenant-specific judgement about a CVE
lives in `Finding` (models/vulnerability.py), which references these rows.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TimestampMixin, uuid_pk


class Cwe(Base, TimestampMixin):
    """Common Weakness Enumeration entry (the *class* of flaw)."""

    __tablename__ = "cwe"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g. "CWE-79"
    name: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    abstraction: Mapped[str | None] = mapped_column(String(40), default=None)
    status: Mapped[str | None] = mapped_column(String(40), default=None)
    # OWASP Top 10 / CIS mapping hints used by the compliance engine
    categories: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    @property
    def resolved(self) -> bool:
        """True once the MITRE dictionary has supplied a real name.

        A row is created the moment an NVD record *mentions* an identifier,
        long before the dictionary is loaded — and `name` is NOT NULL, so the
        placeholder carries the id. Anything that renders a name has to know
        the difference or the UI prints `CWE-79` in a column headed "Name",
        which is what the dashboard did from its first day until `sync-cwe`
        existed.
        """
        return bool(self.name) and self.name.strip().upper() != self.id.strip().upper()

    @property
    def display_name(self) -> str | None:
        return self.name if self.resolved else None


class Vendor(Base, TimestampMixin):
    __tablename__ = "vendors"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    normalized_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    homepage: Mapped[str | None] = mapped_column(String(400), default=None)
    advisory_url: Mapped[str | None] = mapped_column(String(400), default=None)
    # default assignment hint, e.g. Fortinet -> Network Security
    default_team_hint: Mapped[str | None] = mapped_column(String(80), default=None)

    products: Mapped[list["Product"]] = relationship(back_populates="vendor")


class Product(Base, TimestampMixin):
    __tablename__ = "products"
    __table_args__ = (UniqueConstraint("vendor_id", "normalized_name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    normalized_name: Mapped[str] = mapped_column(String(300), nullable=False)
    # server | firewall | database | application | os | library | appliance | saas
    product_type: Mapped[str] = mapped_column(String(40), default="application", nullable=False)
    cpe_part: Mapped[str] = mapped_column(String(2), default="a", nullable=False)  # a|o|h
    eol_date: Mapped[dt.date | None] = mapped_column(Date, default=None)
    default_team_hint: Mapped[str | None] = mapped_column(String(80), default=None)

    vendor: Mapped[Vendor] = relationship(back_populates="products")
    versions: Mapped[list["ProductVersion"]] = relationship(back_populates="product")


class ProductVersion(Base, TimestampMixin):
    __tablename__ = "product_versions"
    __table_args__ = (
        UniqueConstraint("product_id", "version"),
        Index("ix_product_versions_lookup", "product_id", "version"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    product_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    # sortable form: 7.4.3 -> 00007.00004.00003 so range queries work in SQL
    version_key: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    release_date: Mapped[dt.date | None] = mapped_column(Date, default=None)
    eol_date: Mapped[dt.date | None] = mapped_column(Date, default=None)

    product: Mapped[Product] = relationship(back_populates="versions")


class Cpe(Base, TimestampMixin):
    """A CPE 2.3 formatted string, parsed into its 13 components."""

    __tablename__ = "cpe"

    id: Mapped[uuid.UUID] = uuid_pk()
    cpe23: Mapped[str] = mapped_column(String(600), nullable=False, unique=True, index=True)
    part: Mapped[str] = mapped_column(String(2), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    product: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    update_field: Mapped[str] = mapped_column("update", String(120), default="*", nullable=False)
    edition: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    language: Mapped[str] = mapped_column(String(40), default="*", nullable=False)
    sw_edition: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    target_sw: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    target_hw: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    other: Mapped[str] = mapped_column(String(120), default="*", nullable=False)
    title: Mapped[str | None] = mapped_column(String(500), default=None)
    deprecated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    product_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("products.id", ondelete="SET NULL"), default=None,
        index=True,
    )


class Cve(Base, TimestampMixin):
    """Normalized CVE record merged from CVE.org, NVD and vendor advisories."""

    __tablename__ = "cve"
    __table_args__ = (
        Index("ix_cve_published", "published_at"),
        Index("ix_cve_cvss3", "cvss3_base_score"),
        Index("ix_cve_cvss4", "cvss4_score"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)  # CVE-2021-44228
    source: Mapped[str] = mapped_column(String(40), default="nvd", nullable=False)
    state: Mapped[str] = mapped_column(String(20), default="PUBLISHED", nullable=False)
    title: Mapped[str | None] = mapped_column(String(500), default=None)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    modified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    # every CVSS revision the sources published, kept side by side rather than
    # collapsed - the risk engine and the UI both want to show the difference
    cvss2_vector: Mapped[str | None] = mapped_column(String(200), default=None)
    cvss2_base_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss3_vector: Mapped[str | None] = mapped_column(String(200), default=None)
    cvss3_base_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss3_severity: Mapped[str | None] = mapped_column(String(20), default=None)
    cvss3_version: Mapped[str | None] = mapped_column(String(5), default=None)
    cvss4_vector: Mapped[str | None] = mapped_column(String(400), default=None)
    cvss4_score: Mapped[float | None] = mapped_column(Float, default=None)
    cvss4_severity: Mapped[str | None] = mapped_column(String(20), default=None)
    cvss4_nomenclature: Mapped[str | None] = mapped_column(String(10), default=None)

    cwe_ids: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    # [{"vendor":..,"product":..,"versions":[..],"fixed":[..],"cpe23":..}]
    affected: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    fixed_versions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    exploit_known: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_maturity: Mapped[str | None] = mapped_column(String(20), default=None)
    exploit_references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # denormalized for fast filtering; authoritative rows live in their own tables
    epss_score: Mapped[float | None] = mapped_column(Float, default=None, index=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, default=None)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    kev_due_date: Mapped[dt.date | None] = mapped_column(Date, default=None)

    raw: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    @property
    def best_cvss_score(self) -> float | None:
        """Most recent CVSS revision available. v4 > v3.x > v2."""
        for value in (self.cvss4_score, self.cvss3_base_score, self.cvss2_base_score):
            if value is not None:
                return value
        return None

    @property
    def age_days(self) -> int | None:
        if self.published_at is None:
            return None
        return (dt.datetime.now(dt.timezone.utc) - self.published_at).days


class CveReference(Base):
    __tablename__ = "cve_references"
    __table_args__ = (Index("ix_cve_references_cve", "cve_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cve.id", ondelete="CASCADE"), nullable=False
    )
    url: Mapped[str] = mapped_column(String(1000), nullable=False)
    source: Mapped[str | None] = mapped_column(String(120), default=None)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)


class CveCpeMatch(Base):
    """Resolved CVE <-> CPE applicability, including version ranges."""

    __tablename__ = "cve_cpe_match"
    __table_args__ = (
        Index("ix_cve_cpe_cve", "cve_id"),
        Index("ix_cve_cpe_product", "product_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cve.id", ondelete="CASCADE"), nullable=False
    )
    cpe23: Mapped[str] = mapped_column(String(600), nullable=False)
    product_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("products.id", ondelete="SET NULL"), default=None
    )
    vulnerable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version_start_including: Mapped[str | None] = mapped_column(String(120), default=None)
    version_start_excluding: Mapped[str | None] = mapped_column(String(120), default=None)
    version_end_including: Mapped[str | None] = mapped_column(String(120), default=None)
    version_end_excluding: Mapped[str | None] = mapped_column(String(120), default=None)


class EpssScore(Base):
    """Current EPSS probability + percentile for a CVE (one row per CVE)."""

    __tablename__ = "epss_scores"

    cve_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cve.id", ondelete="CASCADE"), primary_key=True
    )
    score: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    model_version: Mapped[str | None] = mapped_column(String(40), default=None)
    scored_on: Mapped[dt.date] = mapped_column(Date, nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False
    )


class EpssHistory(Base):
    """Daily EPSS snapshots, so the UI can plot the trend the spec asks for."""

    __tablename__ = "epss_history"
    __table_args__ = (
        UniqueConstraint("cve_id", "scored_on"),
        Index("ix_epss_history_cve_date", "cve_id", "scored_on"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    cve_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cve.id", ondelete="CASCADE"), nullable=False
    )
    score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    scored_on: Mapped[dt.date] = mapped_column(Date, nullable=False)


class KevEntry(Base):
    """CISA Known Exploited Vulnerabilities catalogue entry."""

    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("cve.id", ondelete="CASCADE"), primary_key=True
    )
    vendor_project: Mapped[str | None] = mapped_column(String(200), default=None)
    product: Mapped[str | None] = mapped_column(String(300), default=None)
    vulnerability_name: Mapped[str | None] = mapped_column(String(500), default=None)
    short_description: Mapped[str | None] = mapped_column(Text, default=None)
    required_action: Mapped[str | None] = mapped_column(Text, default=None)
    date_added: Mapped[dt.date | None] = mapped_column(Date, default=None, index=True)
    due_date: Mapped[dt.date | None] = mapped_column(Date, default=None, index=True)
    known_ransomware: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, default=None)
    imported_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False
    )

    @property
    def days_until_due(self) -> int | None:
        if self.due_date is None:
            return None
        return (self.due_date - dt.date.today()).days


class FeedRun(Base):
    """One execution of an intelligence feed - the importer's watermark + audit."""

    __tablename__ = "feed_runs"
    __table_args__ = (Index("ix_feed_runs_feed_time", "feed", "started_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    feed: Mapped[str] = mapped_column(String(40), nullable=False)  # nvd | epss | kev | rss | misp
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc), nullable=False
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    status: Mapped[str] = mapped_column(String(20), default="running", nullable=False)
    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    watermark: Mapped[str | None] = mapped_column(String(120), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
