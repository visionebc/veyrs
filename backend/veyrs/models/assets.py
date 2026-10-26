"""Tenant asset inventory, business services and asset<->product installation.

The asset record is where technical facts (hostname, OS) meet business facts
(owner, criticality, data classification, internet exposure). The risk engine
reads BOTH sides, which is the whole point of the platform: a CVSS 9.8 on a
lab VM is not the same risk as a CVSS 7.5 on an internet-facing payment API.
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

from .base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin, uuid_pk


class AssetType(str, enum.Enum):
    SERVER = "server"
    VM = "vm"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    WEBSITE = "website"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"
    SAAS = "saas"
    IOT = "iot"
    OTHER = "other"


class Criticality(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataClassification(str, enum.Enum):
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"


class Exposure(str, enum.Enum):
    INTERNET = "internet"
    PARTNER = "partner"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class Environment(str, enum.Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    TEST = "test"
    DEVELOPMENT = "development"
    DR = "dr"


# Numeric weights consumed by the risk engine. Kept next to the enums so a new
# enum member cannot be added without deciding what it means for risk.
CRITICALITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}
CLASSIFICATION_WEIGHT = {"restricted": 1.0, "confidential": 0.8, "internal": 0.5, "public": 0.2}
EXPOSURE_WEIGHT = {"internet": 1.0, "partner": 0.7, "internal": 0.4, "isolated": 0.1}
ENVIRONMENT_WEIGHT = {"production": 1.0, "dr": 0.8, "staging": 0.5, "test": 0.3,
                      "development": 0.3}


class BusinessService(Base, TenantMixin, TimestampMixin):
    """A service the business actually sells or depends on (ITIL CMDB concept)."""

    __tablename__ = "business_services"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), default=None
    )
    # monetary impact per hour of outage, used by the Executive risk profile
    revenue_per_hour: Mapped[int | None] = mapped_column(Integer, default=None)
    currency: Mapped[str] = mapped_column(String(3), default="CHF", nullable=False)
    sla_tier: Mapped[str | None] = mapped_column(String(40), default=None)


class Asset(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "external_id"),
        Index("ix_assets_org_type", "organization_id", "asset_type"),
        Index("ix_assets_org_criticality", "organization_id", "criticality"),
        Index("ix_assets_org_exposure", "organization_id", "exposure"),
        Index("ix_assets_hostname", "organization_id", "hostname"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    # stable identity from the source of truth (CMDB, Proxmox, cloud tag...)
    external_id: Mapped[str | None] = mapped_column(String(200), default=None)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(30), default="server", nullable=False)

    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    fqdn: Mapped[str | None] = mapped_column(String(400), default=None)
    ip_addresses: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    mac_addresses: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    operating_system: Mapped[str | None] = mapped_column(String(200), default=None)
    os_version: Mapped[str | None] = mapped_column(String(120), default=None)

    # --- business context (drives risk, ownership and SLA)
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None, index=True
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="SET NULL"), default=None, index=True
    )
    department_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("departments.id", ondelete="SET NULL"), default=None
    )
    business_service_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="SET NULL"), default=None
    )
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    data_classification: Mapped[str] = mapped_column(String(20), default="internal", nullable=False)
    exposure: Mapped[str] = mapped_column(String(20), default="internal", nullable=False)
    environment: Mapped[str] = mapped_column(String(20), default="production", nullable=False)
    location: Mapped[str | None] = mapped_column(String(200), default=None)

    # compensating controls present on this asset (WAF, EDR, network isolation).
    # Each entry reduces exposure risk; see engines/risk.py CONTROL_CREDIT.
    compensating_controls: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    source: Mapped[str] = mapped_column(String(40), default="manual", nullable=False)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    decommissioned_at: Mapped[dt.date | None] = mapped_column(Date, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    installations: Mapped[list["AssetProduct"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    @property
    def is_internet_facing(self) -> bool:
        return self.exposure == "internet"


class AssetProduct(Base, TenantMixin, TimestampMixin):
    """"This product, at this version, is installed on this asset."

    This is the join that turns a CVE into a finding: match CVE -> product ->
    version range -> every AssetProduct row -> the assets that are affected.
    """

    __tablename__ = "asset_products"
    __table_args__ = (
        UniqueConstraint("asset_id", "product_id", "version"),
        Index("ix_asset_products_product", "product_id", "version_key"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    product_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    #: Upstream version, the only form CVE ranges are expressed in.
    version: Mapped[str | None] = mapped_column(String(120), default=None)
    version_key: Mapped[str | None] = mapped_column(String(200), default=None)
    #: What the package manager actually said, e.g. `1:1.24.0-2ubuntu7.1`.
    #:
    #: Kept because it is the difference between a real finding and a false one.
    #: Distributions backport security fixes without moving the upstream
    #: version, so an asset running Ubuntu's `1.24.0-2ubuntu7.1` can already be
    #: patched for a CVE whose range says "<= 1.24.0". Matching has to use the
    #: upstream form or it never fires at all; keeping the distro form is what
    #: lets an analyst see why a finding may already be remediated by the vendor.
    raw_version: Mapped[str | None] = mapped_column(String(200), default=None)
    cpe23: Mapped[str | None] = mapped_column(String(600), default=None)
    install_path: Mapped[str | None] = mapped_column(String(500), default=None)
    detected_by: Mapped[str] = mapped_column(String(40), default="manual", nullable=False)
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    asset: Mapped[Asset] = relationship(back_populates="installations")


class AssetGroup(Base, TenantMixin, TimestampMixin):
    """Saved dynamic selection of assets (a filter, not a static list)."""

    __tablename__ = "asset_groups"
    __table_args__ = (UniqueConstraint("organization_id", "name"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    # {"asset_type":["server"],"exposure":["internet"],"tags":["pci"]}
    criteria: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
