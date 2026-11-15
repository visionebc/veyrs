"""Compliance framework, control, evidence and assessment model (spec 16/27).

The spec's instruction -- *"Never invent regulatory requirements. Use
authoritative sources"* -- is a schema constraint here, not just a writing
guideline:

* `ComplianceFramework.is_partial` and `.source_url` are NOT NULL-able
  conveniences, they are the honesty flags. A seeded catalogue that carries only
  the publicly enumerable control identifiers is marked partial, and the API
  surfaces that flag, so nobody mistakes a subset for the standard.
* `ComplianceControl.normative_text` stays empty for standards whose text is
  copyrighted (ISO/IEC). VEYRS stores the identifier and the short title -- what
  you need to *map* to -- and points at the licensed source for the wording. An
  organization that owns the standard can import the text.
* `ControlImplementation.status` is a tenant's own claim, evidenced and dated.
  VEYRS never asserts "you are ISO 27001 compliant"; it reports what is mapped,
  what is evidenced, and what is stale.

Frameworks and controls are GLOBAL (shared reference data, see
`models/base.GLOBAL_TABLES`); implementations, evidence and assessments are
tenant-owned.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, Date, DateTime, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class ImplementationStatus(str, enum.Enum):
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"
    PLANNED = "planned"
    PARTIAL = "partial"
    IMPLEMENTED = "implemented"
    #: Implemented but the supporting evidence has aged past its review period.
    STALE = "stale"


class EvidenceKind(str, enum.Enum):
    DOCUMENT = "document"
    SCREENSHOT = "screenshot"
    CONFIGURATION = "configuration"
    TICKET = "ticket"
    SCAN_RESULT = "scan_result"
    METRIC = "metric"
    ATTESTATION = "attestation"
    #: Produced by VEYRS itself from live data (e.g. "0 KEV findings open").
    AUTOMATED = "automated"


class AssessmentStatus(str, enum.Enum):
    DRAFT = "draft"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    ARCHIVED = "archived"


class ComplianceFramework(Base):
    """A control catalogue. Global: ISO 27001 is the same document for everyone."""

    __tablename__ = "compliance_frameworks"
    __table_args__ = (UniqueConstraint("slug", "version"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    publisher: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    #: Where the authoritative text lives. Shown next to every control.
    source_url: Mapped[str | None] = mapped_column(String(500), default=None)
    #: Copyright/licence position of the catalogue as shipped.
    licence_note: Mapped[str | None] = mapped_column(Text, default=None)
    #: TRUE when VEYRS ships only a subset (or identifiers without normative
    #: text). Surfaced by the API so a partial catalogue can never be mistaken
    #: for the full standard.
    is_partial: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Number of controls the published standard actually contains, when known.
    official_control_count: Mapped[int | None] = mapped_column(Integer, default=None)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Custom frameworks belong to the tenant that created them.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"),
        default=None, index=True,
    )

    controls: Mapped[list["ComplianceControl"]] = relationship(
        back_populates="framework", cascade="all, delete-orphan"
    )

    @property
    def coverage_disclaimer(self) -> str | None:
        if not self.is_partial:
            return None
        return (
            f"VEYRS ships a partial catalogue for {self.name} {self.version}: "
            "control identifiers and short titles only. The normative text is "
            f"published by {self.publisher} and must be obtained from them. "
            "Mappings below are VEYRS' own and are not endorsed by the publisher."
        )


class ComplianceControl(Base):
    """One control/safeguard/subcategory within a framework."""

    __tablename__ = "compliance_controls"
    __table_args__ = (
        UniqueConstraint("framework_id", "ref"),
        Index("ix_controls_framework_ref", "framework_id", "ref"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    framework_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: The publisher's own identifier: "A.8.8", "ID.RA-01", "7.1".
    ref: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    #: Empty for copyrighted catalogues -- deliberately, see module docstring.
    normative_text: Mapped[str | None] = mapped_column(Text, default=None)
    #: VEYRS' own explanation of how this control relates to vulnerability
    #: management. Clearly ours, never presented as the standard's words.
    veyrs_guidance: Mapped[str | None] = mapped_column(Text, default=None)
    theme: Mapped[str | None] = mapped_column(String(120), default=None)
    parent_ref: Mapped[str | None] = mapped_column(String(40), default=None)
    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Cross-framework equivalences, e.g. {"nist-csf-2.0": ["ID.RA-01"]}.
    #: Editorial, and labelled as such in the UI.
    crosswalk: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    #: How VEYRS can evidence this control automatically, if at all.
    #: One of the keys in services/compliance.AUTOMATED_SIGNALS.
    automation_signal: Mapped[str | None] = mapped_column(String(60), default=None)

    framework: Mapped[ComplianceFramework] = relationship(back_populates="controls")


class ControlImplementation(Base, TenantMixin, TimestampMixin):
    """A tenant's position on one control."""

    __tablename__ = "control_implementations"
    __table_args__ = (
        UniqueConstraint("organization_id", "control_id"),
        Index("ix_ctrl_impl_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=ImplementationStatus.NOT_ASSESSED.value, nullable=False
    )
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), default=None
    )
    statement: Mapped[str | None] = mapped_column(Text, default=None)
    justification: Mapped[str | None] = mapped_column(Text, default=None)  # for not_applicable
    #: How often the evidence must be refreshed. 0 == no review requirement.
    review_period_days: Mapped[int] = mapped_column(Integer, default=365, nullable=False)
    last_reviewed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    next_review_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None, index=True
    )
    #: Cached result of the automated signal, recomputed on demand.
    automated_result: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="implementation", cascade="all, delete-orphan"
    )

    @property
    def is_stale(self) -> bool:
        if self.next_review_at is None:
            return False
        return self.next_review_at < dt.datetime.now(dt.timezone.utc)


class Evidence(Base, TenantMixin, TimestampMixin):
    """A dated artefact supporting a control claim.

    Evidence is immutable once created (there is no update route): a changed
    control position produces NEW evidence. An auditor asking "what did you have
    on 2026-03-01?" must get an answer that later edits cannot rewrite.
    """

    __tablename__ = "compliance_evidence"
    __table_args__ = (
        Index("ix_evidence_org_control", "organization_id", "implementation_id"),
        Index("ix_evidence_collected", "organization_id", "collected_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    implementation_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("control_implementations.id", ondelete="CASCADE"),
        default=None,
    )
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, default=None)

    #: Links into the VEYRS graph -- this is what makes evidence traceable
    #: rather than a folder of screenshots.
    document_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("documents.id", ondelete="SET NULL"), default=None
    )
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), default=None
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"), default=None
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), default=None
    )
    external_url: Mapped[str | None] = mapped_column(String(1000), default=None)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    collected_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc), index=True,
    )
    collected_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    #: Evidence goes out of date. NULL means "does not expire".
    valid_until: Mapped[dt.date | None] = mapped_column(Date, default=None)
    #: sha256 of the artefact, so a stored file can be proven unmodified.
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    implementation: Mapped[ControlImplementation | None] = relationship(
        back_populates="evidence"
    )

    @property
    def is_expired(self) -> bool:
        return self.valid_until is not None and self.valid_until < dt.date.today()


class ComplianceAssessment(Base, TenantMixin, TimestampMixin):
    """A point-in-time audit run against one framework."""

    __tablename__ = "compliance_assessments"
    __table_args__ = (Index("ix_assessments_org_framework", "organization_id", "framework_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    framework_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_frameworks.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=AssessmentStatus.DRAFT.value, nullable=False
    )
    scope: Mapped[str | None] = mapped_column(Text, default=None)
    assessor: Mapped[str | None] = mapped_column(String(200), default=None)
    started_on: Mapped[dt.date | None] = mapped_column(Date, default=None)
    completed_on: Mapped[dt.date | None] = mapped_column(Date, default=None)

    #: Frozen snapshot of every control's status at completion. An assessment
    #: that recomputed itself later would be worthless as an audit record.
    snapshot: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, default=None)

    gaps: Mapped[list["AssessmentGap"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )


class AssessmentGap(Base, TenantMixin, TimestampMixin):
    """A non-conformity raised by an assessment, tracked to closure."""

    __tablename__ = "assessment_gaps"

    id: Mapped[uuid.UUID] = uuid_pk()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_assessments.id", ondelete="CASCADE"),
        nullable=False,
    )
    control_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="SET NULL"),
        default=None,
    )
    severity: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, default=None)
    remediation_plan: Mapped[str | None] = mapped_column(Text, default=None)
    due_date: Mapped[dt.date | None] = mapped_column(Date, default=None)
    #: Gaps close through the normal ITSM path, not by editing a spreadsheet.
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("tickets.id", ondelete="SET NULL"), default=None
    )
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    assessment: Mapped[ComplianceAssessment] = relationship(back_populates="gaps")


class ControlRiskLink(Base, TenantMixin, TimestampMixin):
    """Framework -> Control -> Asset/Risk/Vulnerability, the spec's chain.

    Kept as an explicit table rather than derived on the fly because auditors
    ask "who decided this finding evidences A.8.8, and when?".
    """

    __tablename__ = "control_risk_links"
    __table_args__ = (
        Index("ix_ctrl_link_org_control", "organization_id", "control_id"),
        UniqueConstraint("organization_id", "control_id", "object_type", "object_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    control_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("compliance_controls.id", ondelete="CASCADE"),
        nullable=False,
    )
    object_type: Mapped[str] = mapped_column(String(30), nullable=False)  # asset|finding|...
    object_id: Mapped[str] = mapped_column(String(80), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, default=None)
    linked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    #: TRUE when VEYRS created the link from a rule rather than a human.
    is_automatic: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
