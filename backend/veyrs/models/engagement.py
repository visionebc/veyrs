"""Engagement / test scoping, endpoints and risk acceptance (spec section 32).

This module is where three lineages of vulnerability tooling are reconciled:

* **DefectDojo** contributes the *scoping* hierarchy. Its insight is that a
  finding without a bounded scan scope cannot be reimported safely: "close what
  the scanner no longer reports" is only sound if you know exactly which hosts,
  paths and plugins that scanner actually looked at. `Engagement` -> `ScanTest`
  is that boundary. It also contributes `RiskAcceptance` as a first-class,
  expiring, approved artefact rather than a status flag.
* **Faraday** contributes the *web* dimension. Its `vuln_web` model records the
  request/response pair that proves a web finding, which a host+port model
  cannot express. Here that lives on `FindingEndpoint` rather than as a second
  finding class, so one query still answers "everything affecting this asset".
* **VEYRS** keeps the asset-centric core. A `Finding` remains "one flaw on one
  asset" and is NOT owned by a test - a real estate is scanned by several tools
  on different cadences, and re-parenting a finding to whichever tool saw it
  last destroys its history. `TestFinding` records the sightings instead.

The deliberate divergence from DefectDojo: it makes `Finding.test` a required
FK, so the same flaw found by Nessus and by Qualys is two findings that its
deduplication layer then has to reconcile. VEYRS inverts that - one finding,
many sightings - which makes the reconciliation unnecessary rather than clever.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, Date, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class EngagementStatus(str, enum.Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EngagementType(str, enum.Enum):
    #: Automated pipeline scan. Short-lived, high frequency, one test per build.
    CI_CD = "ci_cd"
    #: Human-driven assessment: pentest, red team, code review.
    INTERACTIVE = "interactive"
    #: Recurring infrastructure sweep (the Nessus/Qualys cadence).
    SCHEDULED = "scheduled"


class TestFindingStatus(str, enum.Enum):
    #: pytest collects any class named Test*; without this it emits a warning
    #: for these two and would try to instantiate them as test classes.
    __test__ = False

    #: The most recent run of this test reported the finding.
    PRESENT = "present"
    #: The test ran and did NOT report it. Candidate for closure - never
    #: closure itself, because a host that was merely offline also looks absent.
    ABSENT = "absent"


class RiskAcceptanceDecision(str, enum.Enum):
    ACCEPTED = "accepted"
    TRANSFERRED = "transferred"
    AVOIDED = "avoided"
    MITIGATED_BY_CONTROL = "mitigated_by_control"


class RiskAcceptanceState(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    REJECTED = "rejected"


class Engagement(Base, TenantMixin, TimestampMixin):
    """A bounded body of assessment work: a pentest, a release, a sweep."""

    __tablename__ = "engagements"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        Index("ix_engagements_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    engagement_type: Mapped[str] = mapped_column(
        String(20), default=EngagementType.SCHEDULED.value, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default=EngagementStatus.NOT_STARTED.value, nullable=False
    )

    #: What this engagement covers. Both optional: a first CI/CD engagement
    #: legitimately predates the asset register catching up.
    business_service_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="SET NULL"), default=None
    )
    asset_group_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("asset_groups.id", ondelete="SET NULL"), default=None
    )

    target_start: Mapped[dt.date | None] = mapped_column(Date, default=None)
    target_end: Mapped[dt.date | None] = mapped_column(Date, default=None)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    lead_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    #: CI provenance, copied down onto every test so a finding can always answer
    #: "which build introduced me?" without walking back up the tree.
    version: Mapped[str | None] = mapped_column(String(80), default=None)
    branch_tag: Mapped[str | None] = mapped_column(String(200), default=None)
    commit_hash: Mapped[str | None] = mapped_column(String(80), default=None)
    build_id: Mapped[str | None] = mapped_column(String(120), default=None)

    #: DefectDojo's `deduplication_on_engagement`. When true, deduplication is
    #: confined to this engagement: two pentests of the same app in the same
    #: year are allowed to each carry their own copy of a finding, because the
    #: report for each must stand alone. Off by default - estate-wide dedupe is
    #: the right answer for infrastructure scanning, which is most traffic.
    dedupe_within_engagement: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    tests: Mapped[list["ScanTest"]] = relationship(
        back_populates="engagement", cascade="all, delete-orphan"
    )

    @property
    def is_open(self) -> bool:
        return self.status in (
            EngagementStatus.NOT_STARTED.value,
            EngagementStatus.IN_PROGRESS.value,
            EngagementStatus.PAUSED.value,
        )


class ScanTest(Base, TenantMixin, TimestampMixin):
    """One tool's pass over an engagement's scope. The unit of reimport.

    Named `ScanTest` and not `Test` on purpose: pytest collects any class whose
    name starts with `Test`, and a SQLAlchemy model with an `__init__` it cannot
    call turns the whole suite into collection errors.
    """

    __tablename__ = "scan_tests"
    __table_args__ = (
        Index("ix_scan_tests_org_engagement", "organization_id", "engagement_id"),
        Index("ix_scan_tests_org_scanner", "organization_id", "scanner"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    engagement_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str | None] = mapped_column(String(300), default=None)
    #: Parser key: nessus | qualys | nuclei | trivy | sarif | ...
    scanner: Mapped[str] = mapped_column(String(60), nullable=False)
    environment: Mapped[str | None] = mapped_column(String(30), default=None)

    target_start: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    target_end: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    version: Mapped[str | None] = mapped_column(String(80), default=None)
    branch_tag: Mapped[str | None] = mapped_column(String(200), default=None)
    commit_hash: Mapped[str | None] = mapped_column(String(80), default=None)
    build_id: Mapped[str | None] = mapped_column(String(120), default=None)

    #: The run that most recently populated this test.
    last_import_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("import_runs.id", ondelete="SET NULL"), default=None
    )
    reimport_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Overrides the scanner's registered deduplication settings for this test.
    #: Empty = use the registry in services/dedupe.py.
    dedupe_config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    engagement: Mapped[Engagement] = relationship(back_populates="tests")


class TestFinding(Base, TenantMixin):
    """A sighting: this test saw this finding. The reimport scope, materialised.

    Without this table, "close everything this scanner stopped reporting" has to
    guess its own scope from `Finding.scanner`, which closes findings on hosts
    the run never even touched. That was a real defect: a Nessus export covering
    three hosts would mark an entire estate's Nessus findings remediated.
    """

    __test__ = False   # see TestFindingStatus: keep pytest out of the model layer

    __tablename__ = "test_findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "test_id", "finding_id"),
        Index("ix_test_findings_test_status", "test_id", "status"),
        Index("ix_test_findings_finding", "finding_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    test_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_tests.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default=TestFindingStatus.PRESENT.value, nullable=False
    )
    first_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    last_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    #: The run in which this sighting was last confirmed present.
    last_import_run_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), default=None)
    #: How many consecutive runs of this test have NOT reported it. A single
    #: absence is noise; three in a row is evidence.
    consecutive_absences: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class Endpoint(Base, TenantMixin, TimestampMixin):
    """A network or web location. DefectDojo's Endpoint, with Faraday's URL depth.

    `canonical` is the deduplication identity and is built by
    `services/endpoints.canonicalise()`. It is stored rather than computed on
    read because it is the unique constraint - a normalisation that lives only
    in Python drifts the moment a second code path builds an endpoint.
    """

    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("organization_id", "canonical"),
        Index("ix_endpoints_org_host", "organization_id", "host"),
        Index("ix_endpoints_asset", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), default=None
    )
    #: http | https | tcp | udp | ssh | ... Lowercased.
    protocol: Mapped[str | None] = mapped_column(String(20), default=None)
    userinfo: Mapped[str | None] = mapped_column(String(120), default=None)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, default=None)
    path: Mapped[str | None] = mapped_column(String(1000), default=None)
    query: Mapped[str | None] = mapped_column(String(1000), default=None)
    fragment: Mapped[str | None] = mapped_column(String(500), default=None)
    canonical: Mapped[str] = mapped_column(String(2000), nullable=False)

    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    def __str__(self) -> str:  # pragma: no cover - display helper
        return self.canonical


class FindingEndpoint(Base, TenantMixin):
    """Per-endpoint status of a finding, plus the web evidence that proves it.

    DefectDojo tracks mitigation per endpoint (a header fixed on /admin but not
    on /api is genuinely half-fixed). Faraday stores the HTTP request/response
    pair. Both belong on the same row: the proof and the status of one
    observation are the same fact.
    """

    __tablename__ = "finding_endpoints"
    __table_args__ = (
        UniqueConstraint("organization_id", "finding_id", "endpoint_id"),
        Index("ix_finding_endpoints_endpoint", "endpoint_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False
    )

    first_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    last_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )

    mitigated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mitigated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    mitigated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    risk_accepted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # --- Faraday `vuln_web`: the evidence a host+port row cannot carry.
    method: Mapped[str | None] = mapped_column(String(10), default=None)
    request: Mapped[str | None] = mapped_column(Text, default=None)
    response: Mapped[str | None] = mapped_column(Text, default=None)
    params: Mapped[str | None] = mapped_column(Text, default=None)
    #: Where the payload landed: query | body | header | cookie | path | json
    param_location: Mapped[str | None] = mapped_column(String(20), default=None)
    website: Mapped[str | None] = mapped_column(String(500), default=None)


class RiskAcceptance(Base, TenantMixin, TimestampMixin):
    """An approved, expiring decision not to fix. DefectDojo's model, hardened.

    VEYRS already had `Finding.accepted_until`, which is a date with no
    approver, no proof and no expiry job - i.e. an auditor-visible hole. This
    table is what an ISO 27001 or SOC 2 auditor actually asks to see: who asked,
    who approved, on what evidence, until when, and what happens on expiry.
    """

    __tablename__ = "risk_acceptances"
    __table_args__ = (
        Index("ix_risk_acceptances_org_state", "organization_id", "state"),
        Index("ix_risk_acceptances_expiry", "organization_id", "expires_on"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    decision: Mapped[str] = mapped_column(
        String(30), default=RiskAcceptanceDecision.ACCEPTED.value, nullable=False
    )
    state: Mapped[str] = mapped_column(
        String(20), default=RiskAcceptanceState.PENDING.value, nullable=False
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[str | None] = mapped_column(Text, default=None)

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    #: NULL while pending. An acceptance with no approver never becomes ACTIVE.
    approved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    approved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    decided_note: Mapped[str | None] = mapped_column(Text, default=None)

    expires_on: Mapped[dt.date | None] = mapped_column(Date, default=None)
    expiration_warned_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    expired_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    #: On expiry, put the findings back in the queue (default) or leave them
    #: closed and merely raise an event.
    reactivate_on_expiry: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Reactivation normally keeps the original SLA clock, so an acceptance
    #: cannot be used to launder an overdue finding into a fresh deadline.
    restart_sla_on_expiry: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    #: Signed memo, exception form, board minute - whatever the auditor wants.
    proof_document_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("documents.id", ondelete="SET NULL"), default=None
    )

    findings: Mapped[list["RiskAcceptanceFinding"]] = relationship(
        back_populates="acceptance", cascade="all, delete-orphan"
    )

    @property
    def is_active(self) -> bool:
        return self.state == RiskAcceptanceState.ACTIVE.value

    def days_until_expiry(self, today: dt.date | None = None) -> int | None:
        if self.expires_on is None:
            return None
        return (self.expires_on - (today or dt.date.today())).days


class RiskAcceptanceFinding(Base, TenantMixin):
    __tablename__ = "risk_acceptance_findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "acceptance_id", "finding_id"),
        Index("ix_ra_findings_finding", "finding_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    acceptance_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_acceptances.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    added_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    #: The state the finding was in before acceptance, so expiry can restore it
    #: instead of guessing "new".
    previous_state: Mapped[str | None] = mapped_column(String(30), default=None)

    acceptance: Mapped[RiskAcceptance] = relationship(back_populates="findings")
