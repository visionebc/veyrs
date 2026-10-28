"""Request/response models for assets, intelligence, vulnerabilities and SLA.

Kept separate from `schemas.py` (tenancy/admin) purely for file size; the same
rules apply: no internal identifiers leak, every list uses the `Page` envelope,
and write models never accept `organization_id` -- tenancy comes from the token.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ...models.assets import AssetType, Criticality, DataClassification, Environment, Exposure
from ...models.vulnerability import FindingState

# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------


class BusinessServiceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    criticality: str = "medium"
    owner_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    revenue_per_hour: int | None = Field(default=None, ge=0)
    currency: str = Field(default="CHF", min_length=3, max_length=3)
    sla_tier: str | None = None


class BusinessServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    criticality: str
    revenue_per_hour: int | None
    currency: str
    sla_tier: str | None


class AssetProductIn(BaseModel):
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=300)
    version: str | None = Field(default=None, max_length=120)
    install_path: str | None = None
    detected_by: str = "manual"


class InventoryItemIn(BaseModel):
    """One piece of installed software.

    Supply `cpe` whenever the collector knows it: it is the only form that
    carries identity with no inference. `vendor`/`product` is accepted because
    package managers do not emit CPE, but it is resolved against the CPE
    dictionary and may be rewritten -- the response says so per row.
    """

    cpe: str | None = Field(default=None, max_length=600,
                            description="CPE 2.3 string, e.g. cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*")
    vendor: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=300)
    version: str | None = Field(default=None, max_length=120,
                                description="Upstream version. CVE ranges are "
                                            "expressed in upstream terms only.")
    raw_version: str | None = Field(
        default=None, max_length=200,
        description="What the package manager reported verbatim, e.g. "
                    "1:1.24.0-2ubuntu7.1. Kept for the analyst: a distro that "
                    "backports a fix leaves the upstream version unchanged, so a "
                    "match on `version` alone can be already-remediated.",
    )
    install_path: str | None = None
    detected_by: str | None = None

    @model_validator(mode="after")
    def _needs_identity(self) -> "InventoryItemIn":
        if not self.cpe and not self.product:
            raise ValueError("each item needs either cpe or product")
        return self


class InventoryBulkIn(BaseModel):
    items: list[InventoryItemIn] = Field(min_length=1, max_length=5000)
    detected_by: str = Field(default="manual", max_length=60)
    replace: bool = Field(
        default=False,
        description="Treat this as the complete inventory from `detected_by` and "
                    "drop what it no longer reports. Only correct for a full sweep.",
    )
    correlate: bool = Field(default=True)


class InventoryHostIn(BaseModel):
    """An asset plus its software, for onboarding an existing estate in one call."""

    name: str | None = Field(default=None, max_length=255)
    external_id: str | None = Field(default=None, max_length=200)
    hostname: str | None = Field(default=None, max_length=255)
    fqdn: str | None = Field(default=None, max_length=400)
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    asset_type: str | None = None
    operating_system: str | None = None
    os_version: str | None = None
    environment: str | None = None
    criticality: str | None = None
    data_classification: str | None = None
    exposure: str | None = None
    location: str | None = None
    items: list[InventoryItemIn] = Field(default_factory=list)

    @model_validator(mode="after")
    def _needs_a_handle(self) -> "InventoryHostIn":
        if not any((self.name, self.hostname, self.fqdn, self.external_id)):
            raise ValueError("a host needs one of name/hostname/fqdn/external_id")
        return self


class InventoryImportIn(BaseModel):
    hosts: list[InventoryHostIn] = Field(min_length=1, max_length=2000)
    detected_by: str = Field(default="cmdb", max_length=60)
    replace: bool = False
    correlate: bool = True


class AssetProductOut(BaseModel):
    id: uuid.UUID
    product_id: uuid.UUID
    vendor: str | None = None
    product: str | None = None
    version: str | None
    detected_by: str
    last_seen_at: dt.datetime | None = None


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str = "server"
    external_id: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    operating_system: str | None = None
    os_version: str | None = None
    owner_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    department_id: uuid.UUID | None = None
    business_service_id: uuid.UUID | None = None
    criticality: str = "medium"
    data_classification: str = "internal"
    exposure: str = "internal"
    environment: str = "production"
    location: str | None = None
    compensating_controls: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    source: str = "manual"
    products: list[AssetProductIn] = Field(default_factory=list)

    @field_validator("asset_type")
    @classmethod
    def _asset_type(cls, value: str) -> str:
        allowed = {member.value for member in AssetType}
        if value not in allowed:
            raise ValueError(f"asset_type must be one of {sorted(allowed)}")
        return value

    @field_validator("criticality")
    @classmethod
    def _criticality(cls, value: str) -> str:
        return _one_of(value, Criticality, "criticality")

    @field_validator("data_classification")
    @classmethod
    def _classification(cls, value: str) -> str:
        return _one_of(value, DataClassification, "data_classification")

    @field_validator("exposure")
    @classmethod
    def _exposure(cls, value: str) -> str:
        return _one_of(value, Exposure, "exposure")

    @field_validator("environment")
    @classmethod
    def _environment(cls, value: str) -> str:
        return _one_of(value, Environment, "environment")


def _one_of(value: str, enum_cls, label: str) -> str:
    allowed = {member.value for member in enum_cls}
    if value not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}")
    return value


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: str | None = None
    hostname: str | None = None
    fqdn: str | None = None
    ip_addresses: list[str] | None = None
    operating_system: str | None = None
    os_version: str | None = None
    owner_id: uuid.UUID | None = None
    team_id: uuid.UUID | None = None
    department_id: uuid.UUID | None = None
    business_service_id: uuid.UUID | None = None
    criticality: str | None = None
    data_classification: str | None = None
    exposure: str | None = None
    environment: str | None = None
    location: str | None = None
    compensating_controls: list[str] | None = None
    tags: list[str] | None = None
    attributes: dict[str, Any] | None = None
    is_active: bool | None = None


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    asset_type: str
    external_id: str | None
    hostname: str | None
    fqdn: str | None
    ip_addresses: list[str]
    operating_system: str | None
    os_version: str | None
    owner_id: uuid.UUID | None
    team_id: uuid.UUID | None
    department_id: uuid.UUID | None
    business_service_id: uuid.UUID | None
    criticality: str
    data_classification: str
    exposure: str
    environment: str
    location: str | None
    tags: list[str]
    compensating_controls: list[str]
    source: str
    is_active: bool
    first_seen_at: dt.datetime | None
    last_seen_at: dt.datetime | None
    created_at: dt.datetime

    # Resolved labels, filled in by the route from one batched lookup per page.
    # The console rendered raw UUIDs for ownership until these existed, which
    # made every ownership column unreadable and the feature effectively unused.
    team_name: str | None = None
    owner_name: str | None = None
    department_name: str | None = None


class AssetDetail(AssetOut):
    products: list[AssetProductOut] = Field(default_factory=list)
    open_findings: int = 0
    max_risk_score: float | None = None


# --------------------------------------------------------------------------
# Intelligence
# --------------------------------------------------------------------------


class CveSummary(BaseModel):
    cve_id: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    kev_due_date: dt.date | None
    published_at: dt.datetime | None
    age_days: int | None
    affected_assets: int | None = None


class NvdIngestRequest(BaseModel):
    """NVD 2.0 payload, either the whole envelope or a bare list."""

    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)


class EpssRow(BaseModel):
    cve: str
    epss: float
    percentile: float


class EpssIngestRequest(BaseModel):
    scored_on: dt.date | None = None
    model_version: str | None = None
    rows: list[EpssRow]


class KevIngestRequest(BaseModel):
    catalogVersion: str | None = None  # noqa: N815 - CISA's own field name
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)


class FeedRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    feed: str
    status: str
    started_at: dt.datetime
    finished_at: dt.datetime | None
    records_seen: int
    records_created: int
    records_updated: int
    watermark: str | None
    error: str | None


# --------------------------------------------------------------------------
# Vulnerabilities and findings
# --------------------------------------------------------------------------


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str | None
    internal_ref: str | None
    title: str
    description: str | None
    state: str
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_version: str | None
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    risk_score: float | None
    risk_level: str | None
    created_at: dt.datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vulnerability_id: uuid.UUID
    asset_id: uuid.UUID
    state: str
    severity: str | None
    title: str
    port: int | None
    protocol: str | None
    path: str | None
    cvss_score: float | None
    epss_score: float | None
    kev: bool
    risk_score: float | None
    risk_level: str | None
    technical_risk: float | None
    exploitability_risk: float | None
    business_risk: float | None
    exposure_risk: float | None
    assigned_team_id: uuid.UUID | None
    assigned_user_id: uuid.UUID | None
    assignment_reason: str | None
    sla_due_at: dt.datetime | None
    sla_breached: bool
    escalation_level: int
    detected_at: dt.datetime
    remediated_at: dt.datetime | None
    age_days: int

    # Resolved labels (see AssetOut). `owning_team_id` is the effective owner:
    # the explicit assignment when there is one, otherwise the team that owns
    # the asset -- which is what the team queue and every scope check use.
    assigned_team_name: str | None = None
    assigned_user_name: str | None = None
    owning_team_id: uuid.UUID | None = None
    owning_team_name: str | None = None


class FindingDetail(FindingOut):
    detail: str | None = None
    recommendation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    risk_explanation: dict[str, Any] = Field(default_factory=dict)
    sla: dict[str, Any] = Field(default_factory=dict)
    asset: AssetOut | None = None
    cve: dict[str, Any] | None = None
    events: list[dict[str, Any]] = Field(default_factory=list)


class FindingTransition(BaseModel):
    state: str
    note: str | None = None

    @field_validator("state")
    @classmethod
    def _state(cls, value: str) -> str:
        allowed = {member.value for member in FindingState}
        if value not in allowed:
            raise ValueError(f"state must be one of {sorted(allowed)}")
        return value


class FindingBulkTransition(BaseModel):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    state: str
    note: str | None = None


class _BulkAssign(BaseModel):
    """Shared shape for the two bulk-ownership endpoints.

    `None` and "absent" mean different things here and the distinction is the
    whole reason for `clear`: `team_id=None` cannot express "unassign", because
    an unset optional field is also None. Sending `clear: ["team_id"]` is the
    only way to null a column, so a client that forgets a field can never
    silently orphan 500 rows.
    """

    clear: list[str] = Field(default_factory=list)

    def assignments(self, allowed: tuple[str, ...]) -> dict[str, uuid.UUID | None]:
        out: dict[str, uuid.UUID | None] = {}
        for field in allowed:
            value = getattr(self, field, None)
            if value is not None:
                out[field] = value
        for field in self.clear:
            if field not in allowed:
                raise ValueError(f"cannot clear {field!r}; allowed: {sorted(allowed)}")
            out[field] = None
        return out


class AssetBulkAssign(_BulkAssign):
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    team_id: uuid.UUID | None = None
    owner_id: uuid.UUID | None = None
    department_id: uuid.UUID | None = None


class FindingBulkAssign(_BulkAssign):
    finding_ids: list[uuid.UUID] = Field(min_length=1, max_length=500)
    assigned_team_id: uuid.UUID | None = None
    assigned_user_id: uuid.UUID | None = None
    reason: str | None = Field(default=None, max_length=300)


class RiskSimulateRequest(BaseModel):
    """What-if input for the risk simulator: no persistence, no side effects."""

    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    kev: bool = False
    exploit_known: bool = False
    exploit_maturity: str | None = None
    asset_criticality: str = "medium"
    data_classification: str = "internal"
    exposure: str = "internal"
    environment: str = "production"
    age_days: int = 0
    exposure_days: int = 0
    compensating_controls: list[str] = Field(default_factory=list)
    revenue_per_hour: int | None = None
    profile: str | None = None


class RiskProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    weights: dict[str, Any]
    options: dict[str, Any]
    is_builtin: bool
    is_default: bool


class RiskProfileWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    weights: dict[str, float] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    is_default: bool = False


# --------------------------------------------------------------------------
# SLA
# --------------------------------------------------------------------------


class SlaPolicyWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    priority: int = 100
    is_enabled: bool = True
    is_default: bool = False
    conditions: dict[str, Any] = Field(default_factory=dict)
    remediate_within_hours: int = Field(ge=1)
    triage_within_hours: int | None = Field(default=None, ge=1)
    verify_within_hours: int | None = Field(default=None, ge=1)
    warn_at_percent: int = Field(default=75, ge=1, le=100)
    business_hours_only: bool = False
    escalation_policy_id: uuid.UUID | None = None


class SlaPolicyOut(SlaPolicyWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID


class EscalationPolicyWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    is_enabled: bool = True
    is_default: bool = False
    levels: list[dict[str, Any]] = Field(default_factory=list)
    targets: dict[str, Any] = Field(default_factory=dict)


class EscalationPolicyOut(EscalationPolicyWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID


class AssignmentRuleWrite(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    priority: int = 100
    is_enabled: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)
    team_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None


class AssignmentRuleOut(AssignmentRuleWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    match_count: int
    last_matched_at: dt.datetime | None


# --------------------------------------------------------------------------
# Intelligence refresh schedule
# --------------------------------------------------------------------------


class IntelFeedScheduleIn(BaseModel):
    """One feed's cadence. Both fields optional so a client can change one.

    `exclude_unset` in the router is what makes that work: a body carrying only
    `enabled` must not reset the interval to a default the operator never
    chose, which is the same trap `clear: []` guards in the bulk-assign paths.
    """

    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=60, le=43200)


class IntelScheduleUpdate(BaseModel):
    feeds: dict[str, IntelFeedScheduleIn] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _not_empty(self) -> "IntelScheduleUpdate":
        if not self.feeds:
            raise ValueError("nothing to change: name at least one feed")
        return self
