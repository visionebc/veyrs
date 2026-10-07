"""Importer runs and external-system links (spec sections 14 and 31).

`ImportRun` is the audit record for every ingestion: which file, which parser,
how many records, how many were new, how many were rejected and WHY. A scanner
import that silently drops 4,000 rows because a hostname column moved is the
classic way a vulnerability programme develops a blind spot, so rejects are
counted, sampled and surfaced -- never swallowed.

`ExternalLink` is the correspondence table between a VEYRS object and its twin
in ServiceNow/Jira. Keeping it separate from `Ticket` means one VEYRS ticket can
be mirrored into several systems (a change record in ServiceNow, an engineering
task in Jira) without either being "the" external id.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class ImportStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    #: Parsed, but the caller asked for a preview instead of a commit.
    PREVIEW = "preview"


class ImportRun(Base, TenantMixin, TimestampMixin):
    __tablename__ = "import_runs"
    __table_args__ = (Index("ix_import_runs_org_started", "organization_id", "started_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    #: nessus | qualys | greenbone | csv | json | api
    source: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    filename: Mapped[str | None] = mapped_column(String(400), default=None)
    #: sha256 of the uploaded payload -- re-uploading the same export is
    #: detectable, which is how "why did my counts double?" gets answered.
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=ImportStatus.RUNNING.value, nullable=False
    )

    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: {"reason": count} plus a bounded sample of the offending rows.
    reject_reasons: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    reject_samples: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    #: Findings this run's test had previously reported and did not this time.
    #: Reported first, closed only within the test's own scope and only past the
    #: consecutive-absence threshold: absence from one export is not proof of
    #: remediation. See services/engagements.reconcile_test().
    stale_candidates: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_marked_absent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_closed_absent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    endpoints_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Host inventory read from the same report. Separate from the finding
    #: counters on purpose: an import that created no findings and 900
    #: inventory rows did useful work, and one number reported for both would
    #: hide that in either direction.
    inventory_hosts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    inventory_added: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    inventory_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Recorded but not resolvable to a CPE-anchored product -- a name to fix,
    #: not a host that is safe. Surfaced by `assets/inventory/coverage`.
    inventory_unmatched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: The scope this import landed in. Nullable because runs recorded before
    #: engagement scoping existed have none, and back-filling a scope they never
    #: had would be an invented audit trail.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="SET NULL"), default=None
    )
    test_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_tests.id", ondelete="SET NULL"), default=None
    )
    #: Which deduplication algorithm this run used, so a counts anomaly can be
    #: traced to a config change instead of being blamed on the scanner.
    dedupe_algorithm: Mapped[str | None] = mapped_column(String(40), default=None)

    options: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    started_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    @property
    def duration_ms(self) -> int | None:
        if self.finished_at is None:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)


class ExternalLink(Base, TenantMixin, TimestampMixin):
    """A VEYRS object mirrored into an external system."""

    __tablename__ = "external_links"
    __table_args__ = (
        UniqueConstraint("organization_id", "connector_id", "object_type", "object_id"),
        Index("ix_external_links_remote", "organization_id", "remote_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    connector_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("itsm_connectors.id", ondelete="CASCADE"),
        nullable=False,
    )
    object_type: Mapped[str] = mapped_column(String(30), nullable=False)  # ticket|finding
    object_id: Mapped[str] = mapped_column(String(80), nullable=False)
    remote_id: Mapped[str] = mapped_column(String(120), nullable=False)
    remote_key: Mapped[str | None] = mapped_column(String(120), default=None)  # e.g. SEC-42
    remote_url: Mapped[str | None] = mapped_column(String(1000), default=None)
    remote_status: Mapped[str | None] = mapped_column(String(60), default=None)

    last_pushed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_pulled_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    #: Hash of the last payload pushed, so an unchanged ticket is not re-sent.
    payload_digest: Mapped[str | None] = mapped_column(String(64), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # --- the relation (phase 45) -----------------------------------------
    # When an organization hands remediation to Jira/ServiceNow
    # (`services/ticketing_mode`), THIS ROW is what replaces the internal
    # ticket: it is the only place VEYRS records that CVE-2023-44487 on
    # dmz-edge became SEC-4412 on the 7th. Those columns are denormalised on
    # purpose. A relation that can only be read by joining four tables and
    # then calling Jira is not a relation an operator can put in a report --
    # and a snapshot is also the honest thing to keep: `severity` here is what
    # the issue was raised for, which stays true after the finding is
    # re-scored.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("findings.id", ondelete="SET NULL"),
        default=None, index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"),
        default=None, index=True,
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="SET NULL"),
        default=None,
    )
    #: Kept beside the FK rather than only behind it: a CVE id is what an
    #: operator searches for, and it survives the vulnerability row being
    #: superseded by a merge.
    cve_id: Mapped[str | None] = mapped_column(String(40), default=None, index=True)
    summary: Mapped[str | None] = mapped_column(String(500), default=None)
    severity: Mapped[str | None] = mapped_column(String(20), default=None)
    risk_score: Mapped[float | None] = mapped_column(Float, default=None)
    #: The SLA clock VEYRS handed over. The authoritative one stays on the
    #: finding -- this is the date the remote system was TOLD about, so a
    #: mismatch is visible instead of being resolved in the remote's favour.
    due_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    remote_created_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    remote_updated_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    remote_priority: Mapped[str | None] = mapped_column(String(40), default=None)
    remote_type: Mapped[str | None] = mapped_column(String(60), default=None)
    remote_assignee: Mapped[str | None] = mapped_column(String(200), default=None)


class ScannerConnector(Base, TenantMixin, TimestampMixin):
    """A scanner VEYRS pulls from, rather than one that uploads to VEYRS.

    The inbound counterpart to `ItsmConnector`, and deliberately a separate
    table: an ITSM connector is an *outbound* ticket sink, this is an *inbound*
    evidence source, and merging them would put a ServiceNow password and a
    Tenable key under one row whose meaning depends on a discriminator column.

    Four properties this table exists to enforce, none of them cosmetic:

    * **`is_enabled` defaults to False.** A configured connector that starts
      polling the moment it is saved is an outbound connection nobody decided
      to make. Same discipline as `ExecAgent`.
    * **`allowed_scans` empty means INERT, not "everything".** The blast radius
      of a sync is the set of remote scans it pulls; defaulting that to the
      whole console is how an operator wiring up one test import ingests a
      neighbouring team's entire estate.
    * **Credentials live in `credentials_enc`**, the same Fernet envelope as
      `itsm_connectors.credentials_enc` and `users.mfa_secret`. No API response
      carries the column, because no schema has a field for it.
    * **`close_absent` requires `engagement_id`.** Absence-based closure is only
      correct inside the scope that actually ran -- a pull covering three hosts
      cannot answer for the rest of the estate. Enforced in
      `services.scanners.sync()`, not merely documented; see the deleted
      `_close_missing()` note in `services/importers/base.py`.
    """

    __tablename__ = "scanner_connectors"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: nessus | tenable_io | tenable_sc -- see services.scanners.DRIVERS.
    driver: Mapped[str] = mapped_column(String(40), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(600), default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Off only for an appliance with a self-signed certificate on a trusted
    #: segment. It is a column and not a global so that turning it off for the
    #: lab appliance does not turn it off for the cloud tenant.
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    credentials_enc: Mapped[str | None] = mapped_column(Text, default=None)

    #: Remote scan ids this connector may pull. Empty = inert.
    allowed_scans: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # --- ingestion options, mirroring services.importers.ImportOptions
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="SET NULL"),
        default=None,
    )
    create_assets: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    close_absent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    absence_threshold: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    min_severity: Mapped[str | None] = mapped_column(String(20), default=None)
    #: Also record what each host HAS, from the same export. **Defaults True**,
    #: unlike its `ImportOptions` counterpart, and the asymmetry is deliberate:
    #: a hand upload is somebody triaging one file, while a connector exists to
    #: keep VEYRS fed from a scanner it does not control -- harvesting the
    #: inventory sitting in the same bytes is the point of pointing at it. The
    #: connector is created disabled either way, so nothing happens until an
    #: operator turns it on.
    import_inventory: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Mine the software-enumeration plugins' free-text output as well. Off by
    #: default: see `ImportOptions.inventory_from_plugin_output` for why a
    #: parsed CPE and a parsed sentence are not the same kind of evidence.
    inventory_from_plugin_output: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    # --- state
    #: {remote_scan_id: sha256 of the last payload ingested}. A scan whose
    #: export is byte-identical to the last one is skipped, so a sync run twice
    #: in an hour does not re-ingest and inflate `findings_updated`.
    sync_state: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("import_runs.id", ondelete="SET NULL"),
        default=None,
    )
