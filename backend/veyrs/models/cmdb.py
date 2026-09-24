"""External asset sources: a CMDB export, an arbitrary JSON API, or NetBox.

    AssetSource -> ASSET_DRIVERS[driver] -> SourceRecord[] -> services.cmdb.sync()
       (a row)      file | http_json | netbox     (no DB)      (the only writer)

The same shape as `services/scanners.py`, and for the same reason: a driver
speaks HTTP (or parses one uploaded file), returns records, and never touches
the session. Everything that writes is in `sync()`, in one place.

Why a staging table exists at all
---------------------------------
`services.inventory.upsert_asset()` finds an asset by its most stable
identifier and then **overwrites** its columns with whatever the caller
brought. That is correct for one authoritative feed and destructive for two:
the second import silently erases the first, and afterwards there is a single
row with a single value per field -- nothing left to compare. A comparative
between two sources is only possible if what EACH source said is still on
disk. That is `asset_source_records`.

Identity is per source, and `assets.external_id` is left alone
--------------------------------------------------------------
`assets` carries `UNIQUE(organization_id, external_id)`. NetBox device 42 and
CMDB record 42 are both "42": one namespace cannot hold both without either a
collision or a migration of live data. External identity therefore lives here,
as `UNIQUE(organization_id, source_id, external_key)`, where the two rows are
both legitimate and may resolve to the same `Asset`.

Invariants copied from `ScannerConnector`, for the same reasons
---------------------------------------------------------------
* **`is_enabled` defaults to False.** A source that starts polling the moment
  it is saved is an outbound connection nobody decided to make.
* **An empty `collections` on a pull driver is INERT, not "everything".** The
  blast radius of a sync is the set of remote collections it reads.
* **Credentials live in `credentials_enc`**, the same Fernet envelope as
  `itsm_connectors` and `users.mfa_secret`. No schema carries the column.

And two that are new here, because this module writes inventory rather than
findings:

* **A sync NEVER writes to `assets`.** It writes staging rows and, at most,
  links them to an asset it matched. Promotion -- copying values into the
  asset register -- is a separate, explicit act, which is what makes an import
  reversible and a comparative meaningful.
* **A record the source stops reporting is marked absent; the ASSET is never
  deleted, deactivated or emptied by an import.** A CMDB export truncated at
  500 rows is not a statement that the estate shrank. Same doctrine as
  `close_absent` in the finding importers, minus the escape hatch: there is no
  option to turn absence into deletion.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class SourceRunStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    #: Parsed and compared, but the caller asked for a preview.
    PREVIEW = "preview"


class MatchStatus(str, enum.Enum):
    #: Resolved to an `Asset` that already existed.
    MATCHED = "matched"
    #: Nothing in the asset register answers to any of this record's keys. NOT
    #: an error: it is the queue of things the estate does not know about, and
    #: it is the single most useful output of a first import.
    UNMATCHED = "unmatched"
    #: An operator decided this row is not an asset (a rack, a spare part, a
    #: decommissioned entry the CMDB never cleaned up).
    IGNORED = "ignored"


#: The fields two sources are compared on. Deliberately a short list of facts
#: with an agreed meaning: comparing free-text descriptions produces a
#: disagreement on every row and teaches operators to ignore the report.
COMPARABLE_FIELDS: tuple[str, ...] = (
    "name", "hostname", "fqdn", "serial", "asset_type", "operating_system",
    "os_version", "environment", "criticality", "exposure",
    "data_classification", "location", "owner_label", "team_label",
    "status_label", "ip_addresses", "mac_addresses",
)

#: Fields whose value is a set, not a string: compared as sets, so
#: ["10.0.0.1", "10.0.0.2"] and ["10.0.0.2", "10.0.0.1"] do not read as a
#: conflict on every single host.
SET_FIELDS: frozenset[str] = frozenset({"ip_addresses", "mac_addresses", "tags"})

#: Fields promotion is allowed to copy into `assets`. `name` is included, the
#: primary key and the ownership FKs are not: an import may describe a host, it
#: may not re-parent it in the tenant hierarchy.
PROMOTABLE_FIELDS: tuple[str, ...] = (
    "name", "hostname", "fqdn", "asset_type", "operating_system", "os_version",
    "environment", "criticality", "exposure", "data_classification",
    "location", "ip_addresses", "mac_addresses",
)


class AssetSource(Base, TenantMixin, TimestampMixin):
    """One external inventory VEYRS reads from."""

    __tablename__ = "asset_sources"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: file | http_json | netbox -- see services.cmdb.ASSET_DRIVERS.
    driver: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    base_url: Mapped[str | None] = mapped_column(String(600), default=None)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    credentials_enc: Mapped[str | None] = mapped_column(Text, default=None)

    #: Which remote collections a pull driver may read. NetBox:
    #: ["dcim.devices", "virtualization.virtual-machines"]. http_json: the
    #: paths appended to `base_url`. **Empty means inert.**
    collections: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Where the array of records lives in a JSON response ("data.items"). None
    #: = the body is the array, or NetBox's own "results".
    record_path: Mapped[str | None] = mapped_column(String(200), default=None)
    #: {veyrs_field: source path or column header}. Ignored by the netbox
    #: driver, which knows its own schema; required by file and http_json,
    #: because guessing which column is the hostname is how an import files 900
    #: hosts under a serial number.
    field_map: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: {veyrs_field: {source value: veyrs value}}. Declarative on purpose: a
    #: tenant whose CMDB says "PRD" needs "production", and a hardcoded table
    #: of everybody's abbreviations is a maintenance debt.
    value_maps: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: Which normalised fields this source is allowed to report at all.
    #: **Empty means every field.**
    #:
    #: A separate column rather than a sentinel value inside `field_map`:
    #: "map this field to nothing" and "do not collect this field" would then
    #: share one key, and the next person to read the column has to guess which
    #: was meant. Two questions, two columns.
    #:
    #: It is an allowlist and not a denylist because the interesting direction
    #: is "only the four things we agreed to hold about a host" -- a denylist
    #: silently starts collecting whatever the next NetBox upgrade adds.
    include_fields: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    #: The ladder used to resolve a record to an existing asset, first hit
    #: wins. Configurable because CMDBs and network sources disagree about
    #: which identifier is trustworthy: NetBox almost always has an IP and
    #: rarely a serial, most CMDBs the reverse.
    match_order: Mapped[list] = mapped_column(
        JSONB, default=lambda: ["external_id", "serial", "fqdn", "hostname", "ip", "name"],
        nullable=False,
    )
    #: Write matched records straight into the asset register at sync time.
    #: **Off by default.** With two sources enabled, on means the last sync of
    #: the day decides what the estate looks like -- exactly the overwrite this
    #: table exists to prevent.
    auto_promote: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Whether promotion may CREATE assets this source describes and VEYRS does
    #: not know. Off by default, same reason as `ImportOptions.create_assets`.
    promote_creates_assets: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    #: Lower wins when two sources disagree on a field during promotion. A
    #: number rather than an ordered list on the org, so adding a source does
    #: not require rewriting somebody else's precedence.
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    # --- state
    sync_state: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    last_sync_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    #: `use_alter` because `asset_source_runs` points back at this table: two
    #: tables with FKs into each other cannot be ordered, and `create_all`
    #: raises rather than guessing. The constraint is added afterwards.
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("asset_source_runs.id", ondelete="SET NULL",
                   use_alter=True, name="fk_asset_sources_last_run"),
        default=None,
    )

    records: Mapped[list["AssetSourceRecord"]] = relationship(
        back_populates="source", cascade="all, delete-orphan",
        foreign_keys="AssetSourceRecord.source_id",
    )


class AssetSourceRun(Base, TenantMixin, TimestampMixin):
    """One pass over one source.

    Not an `ImportRun`. That table's counters are statements about findings --
    `records_rejected`, `findings_created`, `stale_candidates` -- and folding
    an inventory pass into them makes an import look like it dropped
    vulnerability data it never carried. Phase 34 already refused that fold
    once, for the inventory riding inside a Nessus export; this is the same
    refusal with its own table.
    """

    __tablename__ = "asset_source_runs"
    __table_args__ = (
        Index("ix_asset_source_runs_org_started", "organization_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    source_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("asset_sources.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20), default=SourceRunStatus.RUNNING.value, nullable=False
    )
    #: manual | scheduled | upload
    trigger: Mapped[str] = mapped_column(String(20), default="manual", nullable=False)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    filename: Mapped[str | None] = mapped_column(String(400), default=None)
    content_hash: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
    finished_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Byte-identical to what this source said last time. Reported separately
    #: from "updated" so a nightly sync that changes nothing says so, instead
    #: of reporting 4000 updates and hiding the twelve that matter.
    records_unchanged: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    assets_matched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_unmatched: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Only ever non-zero when the source has `auto_promote`, or when an
    #: operator promoted from the comparative screen.
    assets_promoted: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    assets_created: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Records this source used to report and did not this time. A number, and
    #: nothing else: see the module docstring.
    records_absent: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    reject_reasons: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    reject_samples: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    error: Mapped[str | None] = mapped_column(Text, default=None)
    started_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    @property
    def duration_ms(self) -> int | None:
        if self.finished_at is None:
            return None
        return int((self.finished_at - self.started_at).total_seconds() * 1000)


class AssetSourceRecord(Base, TenantMixin, TimestampMixin):
    """What one source says about one thing, kept as the source said it.

    `asset_id` is nullable and stays nullable: a record VEYRS cannot resolve is
    still worth having. Two sources are compared through `asset_id` when both
    resolved, and through `identity_key` when neither has -- otherwise a first
    import of two feeds into an empty estate would produce two lists and no
    comparison, which is the case an operator most wants to see.
    """

    __tablename__ = "asset_source_records"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_id", "external_key"),
        Index("ix_asset_source_records_identity", "organization_id", "identity_key"),
        Index("ix_asset_source_records_asset", "organization_id", "asset_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    source_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("asset_sources.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: The source's own id, namespaced by collection where the source has more
    #: than one ("dcim.device:42"). Unique per source, never across sources.
    external_key: Mapped[str] = mapped_column(String(300), nullable=False)
    #: The normalised key two records are grouped by when neither resolved to
    #: an asset. Derived, never supplied.
    identity_key: Mapped[str | None] = mapped_column(String(300), default=None)
    #: Every key this record could be recognised by, in ladder order. Used to
    #: adopt a sibling record's group so a serial-keyed CMDB row and an
    #: IP-keyed NetBox row still land together.
    match_keys: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), default=None
    )
    match_status: Mapped[str] = mapped_column(
        String(20), default=MatchStatus.UNMATCHED.value, nullable=False
    )
    #: Which rung of the ladder matched, so "why is this the same host?" has an
    #: answer that is not "the algorithm said so".
    matched_by: Mapped[str | None] = mapped_column(String(40), default=None)

    # --- normalised facts
    name: Mapped[str | None] = mapped_column(String(255), default=None)
    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    fqdn: Mapped[str | None] = mapped_column(String(400), default=None)
    serial: Mapped[str | None] = mapped_column(String(200), default=None)
    asset_type: Mapped[str | None] = mapped_column(String(30), default=None)
    operating_system: Mapped[str | None] = mapped_column(String(200), default=None)
    os_version: Mapped[str | None] = mapped_column(String(120), default=None)
    environment: Mapped[str | None] = mapped_column(String(20), default=None)
    criticality: Mapped[str | None] = mapped_column(String(20), default=None)
    exposure: Mapped[str | None] = mapped_column(String(20), default=None)
    data_classification: Mapped[str | None] = mapped_column(String(20), default=None)
    location: Mapped[str | None] = mapped_column(String(200), default=None)
    #: Owner and team as the SOURCE names them, as text. Not FKs: a CMDB's
    #: "owner" is a string in somebody else's directory, and resolving it to a
    #: VEYRS user without being asked would reassign accountability on import.
    owner_label: Mapped[str | None] = mapped_column(String(200), default=None)
    team_label: Mapped[str | None] = mapped_column(String(200), default=None)
    status_label: Mapped[str | None] = mapped_column(String(80), default=None)
    ip_addresses: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    mac_addresses: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Normalised fields with no column of their own, from a tenant's own
    #: field_map. Kept apart from `raw` so a mapped field is never mistaken for
    #: an unread one.
    extra: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    #: The record exactly as the source returned it. This is what makes a
    #: mapping mistake recoverable without re-importing.
    raw: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    content_hash: Mapped[str | None] = mapped_column(String(64), default=None)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("asset_source_runs.id", ondelete="SET NULL"),
        default=None,
    )
    #: The source stopped reporting it. Reported, never acted on.
    is_absent: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    absent_since: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    promoted_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    promoted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    source: Mapped[AssetSource] = relationship(
        back_populates="records", foreign_keys=[source_id]
    )

    def facts(self) -> dict:
        """The comparable view of this record."""
        return {field: getattr(self, field, None) for field in COMPARABLE_FIELDS}
