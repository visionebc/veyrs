"""Asset sources: importing an external inventory and comparing two of them.

The router is deliberately thin. Every rule that matters -- what is inert, what
a sync may write, what a comparative means -- lives in `services/cmdb.py`, so
there is one answer rather than one per entry point.

The `asset sources` tag is in `security.scope.REFUSED_TAGS`, next to
`integrations` and `engagements`: configuring where the estate's inventory
comes from, and comparing two whole inventories, are estate-wide acts. A
team-scoped identity is a triage identity, and a comparative narrowed to one
team's slice would look like a complete answer while covering a third of the
estate.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Annotated, Any

from fastapi import (
    APIRouter, Depends, File, HTTPException, Query, Response, UploadFile, status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...models.cmdb import (
    AssetSource, AssetSourceRecord, AssetSourceRun, COMPARABLE_FIELDS, MatchStatus,
)
from ...security.deps import Principal, TenantSession, require
from ...security.secrets import encrypt
from ...services import audit, cmdb

router = APIRouter(prefix="/asset-sources", tags=["asset sources"])

#: How a field VEYRS has no column for is kept anyway: `extra.vmid`. This is
#: the only way to hold a NetBox custom field -- `vmid`, `pve_node`, `pve_tags`
#: exist in this NetBox and in nobody's published schema, and they are half the
#: reason to connect a CMDB at all.
#:
#: The `extra.` prefix is REQUIRED and that is the whole point. Accepting any
#: unknown target would mean a typo (`hostnmae` for `hostname`) is silently
#: filed under `extra` and the operator sees an import that runs cleanly and
#: reports no hostnames. Namespacing makes "I know VEYRS has no such field" an
#: explicit statement instead of the default outcome of getting it wrong.
EXTRA_TARGET_RE = re.compile(r"^extra\.[a-z][a-z0-9_]{0,49}$")

DEFAULT_MATCH_ORDER = ("external_id", "serial", "fqdn", "hostname", "ip", "name")

#: Which normalised field each match rung actually reads. Used to refuse an
#: `include_fields` that would make the ladder unreachable.
MATCH_RUNG_FIELDS = {
    "external_id": "external_id", "serial": "serial", "fqdn": "fqdn",
    "hostname": "hostname", "ip": "ip_addresses", "name": "name",
}

MAX_UPLOAD_BYTES = cmdb.MAX_UPLOAD_BYTES


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class AssetSourceWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    driver: str
    description: str | None = None
    base_url: str = ""
    is_enabled: bool = False
    verify_tls: bool = True
    collections: list[str] = Field(default_factory=list)
    record_path: str | None = None
    field_map: dict[str, str] = Field(default_factory=dict)
    value_maps: dict[str, dict[str, str]] = Field(default_factory=dict)
    #: Empty = every field, which is what a source that says nothing gets.
    include_fields: list[str] = Field(default_factory=list)
    match_order: list[str] = Field(
        default_factory=lambda: ["external_id", "serial", "fqdn", "hostname", "ip", "name"]
    )
    auto_promote: bool = False
    promote_creates_assets: bool = False
    priority: int = 100
    #: Never echoed back by any response: there is no field for it in `Out`.
    credentials: dict[str, Any] | None = None


class AssetSourcePatch(BaseModel):
    name: str | None = None
    description: str | None = None
    base_url: str | None = None
    is_enabled: bool | None = None
    verify_tls: bool | None = None
    collections: list[str] | None = None
    record_path: str | None = None
    field_map: dict[str, str] | None = None
    value_maps: dict[str, dict[str, str]] | None = None
    include_fields: list[str] | None = None
    match_order: list[str] | None = None
    auto_promote: bool | None = None
    promote_creates_assets: bool | None = None
    priority: int | None = None
    credentials: dict[str, Any] | None = None


class AssetSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    driver: str
    description: str | None
    base_url: str | None
    is_enabled: bool
    verify_tls: bool
    collections: list
    record_path: str | None
    field_map: dict
    value_maps: dict
    include_fields: list
    match_order: list
    auto_promote: bool
    promote_creates_assets: bool
    priority: int
    last_sync_at: Any = None
    last_error: str | None = None
    credentials_set: bool = False
    #: True when nothing would happen if it ran: no collections on a pull
    #: driver, or no field map where one is required.
    is_inert: bool = False


class AssetSourceRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    status: str
    trigger: str
    dry_run: bool
    filename: str | None
    size_bytes: int
    started_at: Any
    finished_at: Any = None
    records_seen: int
    records_created: int
    records_updated: int
    records_unchanged: int
    records_rejected: int
    assets_matched: int
    assets_unmatched: int
    assets_promoted: int
    assets_created: int
    records_absent: int
    reject_reasons: dict
    reject_samples: list
    error: str | None = None


class RecordOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_id: uuid.UUID
    external_key: str
    identity_key: str | None
    asset_id: uuid.UUID | None
    match_status: str
    matched_by: str | None
    name: str | None
    hostname: str | None
    fqdn: str | None
    serial: str | None
    asset_type: str | None
    operating_system: str | None
    os_version: str | None
    environment: str | None
    criticality: str | None
    exposure: str | None
    data_classification: str | None
    location: str | None
    owner_label: str | None
    team_label: str | None
    status_label: str | None
    ip_addresses: list
    mac_addresses: list
    tags: list
    extra: dict
    is_absent: bool
    promoted_at: Any = None
    last_seen_at: Any = None


class RecordPatch(BaseModel):
    #: `ignored` takes a row out of every comparative and out of promotion --
    #: for the rack, the spare part, the decommissioned entry nobody cleaned
    #: up. It does not delete it: the next sync would recreate it, and the
    #: operator's judgement would be lost every night.
    match_status: str | None = None
    #: Link this record to an asset by hand when the ladder could not.
    asset_id: uuid.UUID | None = None


class PromoteRequest(BaseModel):
    record_ids: list[uuid.UUID] = Field(min_length=1)
    #: Create assets for records that matched nothing. Off by default: see
    #: `services.cmdb.promote_record`.
    create_assets: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _out(source: AssetSource) -> AssetSourceOut:
    out = AssetSourceOut.model_validate(source)
    out.credentials_set = bool(source.credentials_enc)
    driver = cmdb.ASSET_DRIVERS.get(source.driver)
    needs_map = bool(getattr(driver, "needs_field_map", False))
    out.is_inert = (
        (source.driver != "file" and not source.collections)
        or (needs_map and not source.field_map)
    )
    return out


def _source(session, principal: Principal, source_id: uuid.UUID) -> AssetSource:
    source = session.get(AssetSource, source_id)
    if source is None or source.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset source not found")
    return source


def _validate(payload: dict[str, Any], driver: str) -> None:
    if driver not in cmdb.ASSET_DRIVERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"driver must be one of {sorted(cmdb.ASSET_DRIVERS)}")
    for key in payload.get("field_map") or {}:
        if key not in cmdb.KNOWN_FIELDS and not EXTRA_TARGET_RE.match(key):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"field_map targets {key!r}, which is not a VEYRS asset field. "
                f"To keep a field VEYRS has no column for (a NetBox custom "
                f"field, say), name it {'extra.' + key.lower()!r}. Known "
                f"fields: {list(cmdb.KNOWN_FIELDS)}",
            )
    # An enum field mapped to a value VEYRS does not have is refused HERE,
    # while somebody is looking at the form. The same mistake discovered at
    # sync time is a complaint on every row of a run that already happened.
    for target, mapping in (payload.get("value_maps") or {}).items():
        allowed = cmdb.ENUM_FIELDS.get(target)
        if not allowed:
            continue
        bad = sorted({v for v in mapping.values() if v not in allowed})
        if bad:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"value_maps[{target!r}] maps to {bad}, which {'are' if len(bad) > 1 else 'is'} "
                f"not {'values' if len(bad) > 1 else 'a value'} VEYRS accepts for {target}. "
                f"Allowed: {sorted(allowed)}",
            )
    include = payload.get("include_fields")
    if include:
        unknown = [f for f in include if f not in cmdb.KNOWN_FIELDS]
        if unknown:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"include_fields names {unknown}, which are not VEYRS asset "
                f"fields. Known fields: {list(cmdb.KNOWN_FIELDS)}")
        # A source that collects nothing the match ladder can read still
        # produces rows -- staged rows matching no asset, on every host, for
        # ever. That reads as "the CMDB disagrees with the estate" rather than
        # as a filter set too tight, so it is refused at the point of writing.
        rungs = payload.get("match_order") or list(DEFAULT_MATCH_ORDER)
        reachable = {MATCH_RUNG_FIELDS[r] for r in rungs if r in MATCH_RUNG_FIELDS}
        if not (reachable & set(include)):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"include_fields keeps none of the fields this source matches "
                f"on ({sorted(reachable)}), so every record would stage as "
                f"unmatched. Keep at least one, or shorten match_order.")
    for rung in payload.get("match_order") or []:
        if rung not in ("external_id", "serial", "fqdn", "hostname", "ip", "name"):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"unknown match_order rung {rung!r}")
    if driver == "netbox":
        unknown = [c for c in (payload.get("collections") or [])
                   if c not in cmdb.NETBOX_COLLECTIONS]
        if unknown:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"unknown NetBox collections {unknown}; expected any of "
                f"{sorted(cmdb.NETBOX_COLLECTIONS)}")


# ---------------------------------------------------------------------------
# Drivers and sources
# ---------------------------------------------------------------------------
@router.get("/drivers", summary="What kinds of asset source exist")
def list_drivers(
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> dict[str, Any]:
    return {
        "drivers": cmdb.describe_drivers(),
        "fields": list(cmdb.KNOWN_FIELDS),
        "comparable_fields": list(COMPARABLE_FIELDS),
        "notes": (
            "A sync writes staging rows and never writes to the asset "
            "register: promotion is a separate act, which is what makes two "
            "sources comparable at all. A source with no collections is "
            "inert, and a record a source stops reporting is marked absent -- "
            "an import never deletes an asset."
        ),
    }


@router.get("", response_model=list[AssetSourceOut], summary="List asset sources")
def list_sources(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> list[AssetSourceOut]:
    rows = session.execute(
        select(AssetSource)
        .where(AssetSource.organization_id == principal.organization_id)
        .order_by(AssetSource.priority, AssetSource.slug)
    ).scalars().all()
    return [_out(row) for row in rows]


@router.post("", response_model=AssetSourceOut, status_code=201,
             summary="Register an asset source")
def create_source(
    payload: AssetSourceWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> AssetSourceOut:
    fields = payload.model_dump(exclude={"credentials"})
    _validate(fields, payload.driver)
    if payload.driver != "file" and not payload.base_url.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "base_url is required for a source VEYRS fetches from")
    exists = session.execute(
        select(AssetSource).where(
            AssetSource.organization_id == principal.organization_id,
            AssetSource.slug == payload.slug)
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"asset source {payload.slug!r} already exists")

    source = AssetSource(
        organization_id=principal.organization_id,
        credentials_enc=encrypt(json.dumps(payload.credentials))
                        if payload.credentials else None,
        **fields,
    )
    session.add(source)
    session.flush()
    audit.record(session, action="cmdb.source.created", object_type="asset_source",
                 object_id=source.id, object_label=source.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"driver": source.driver, "base_url": source.base_url,
                          "is_enabled": source.is_enabled,
                          "collections": source.collections,
                          "auto_promote": source.auto_promote})
    session.commit()
    return _out(source)


# --- static paths come before /{source_id} ---------------------------------
@router.get("/summary", summary="What each source holds")
def sources_summary(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
) -> dict[str, Any]:
    return cmdb.summary(session, principal.organization_id)


@router.get("/compare", summary="What two sources say about the same thing")
def compare_sources(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
    source_id: Annotated[list[uuid.UUID] | None, Query()] = None,
    mode: str = Query("conflicts", pattern="^(conflicts|gaps|all)$"),
    include_absent: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return cmdb.compare(
        session, principal.organization_id, source_ids=source_id, mode=mode,
        include_absent=include_absent, limit=limit, offset=offset,
    )


@router.get("/records", response_model=list[RecordOut], summary="Staged records")
def list_records(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
    source_id: uuid.UUID | None = None,
    match_status: str | None = None,
    is_absent: bool | None = None,
    promoted: bool | None = None,
    q: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[AssetSourceRecord]:
    query = select(AssetSourceRecord).where(
        AssetSourceRecord.organization_id == principal.organization_id)
    if source_id:
        query = query.where(AssetSourceRecord.source_id == source_id)
    if match_status:
        query = query.where(AssetSourceRecord.match_status == match_status)
    if is_absent is not None:
        query = query.where(AssetSourceRecord.is_absent.is_(is_absent))
    if promoted is not None:
        query = query.where(AssetSourceRecord.promoted_at.is_(None) != promoted)
    if q:
        like = f"%{q.lower()}%"
        query = query.where(
            AssetSourceRecord.name.ilike(like)
            | AssetSourceRecord.hostname.ilike(like)
            | AssetSourceRecord.fqdn.ilike(like)
            | AssetSourceRecord.serial.ilike(like)
            | AssetSourceRecord.external_key.ilike(like)
        )
    query = query.order_by(AssetSourceRecord.name).limit(limit).offset(offset)
    return list(session.execute(query).scalars().all())


@router.patch("/records/{record_id}", response_model=RecordOut,
              summary="Ignore a record, or link it to an asset by hand")
def patch_record(
    record_id: uuid.UUID,
    payload: RecordPatch,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> AssetSourceRecord:
    row = session.get(AssetSourceRecord, record_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "record not found")
    fields = payload.model_dump(exclude_unset=True)
    if "match_status" in fields:
        allowed = {m.value for m in MatchStatus}
        if fields["match_status"] not in allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"match_status must be one of {sorted(allowed)}")
        row.match_status = fields["match_status"]
    if "asset_id" in fields:
        from ...models import Asset

        if fields["asset_id"] is None:
            row.asset_id = None
            row.matched_by = None
            if row.match_status != MatchStatus.IGNORED.value:
                row.match_status = MatchStatus.UNMATCHED.value
        else:
            asset = session.get(Asset, fields["asset_id"])
            if asset is None or asset.organization_id != principal.organization_id:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
            row.asset_id = asset.id
            row.matched_by = "manual"
            row.match_status = MatchStatus.MATCHED.value
    audit.record(session, action="cmdb.record.updated",
                 object_type="asset_source_record", object_id=row.id,
                 object_label=row.external_key,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={k: str(v) for k, v in fields.items()})
    session.commit()
    return row


@router.post("/promote", summary="Copy staged records into the asset register")
def promote_records(
    payload: PromoteRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict[str, Any]:
    result = cmdb.promote(
        session, principal.organization_id, payload.record_ids,
        actor_id=principal.user_id, create_assets=payload.create_assets,
    )
    session.commit()
    return result


# --- one source ------------------------------------------------------------
@router.get("/{source_id}", response_model=AssetSourceOut, summary="One asset source")
def read_source(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> AssetSourceOut:
    return _out(_source(session, principal, source_id))


@router.patch("/{source_id}", response_model=AssetSourceOut, summary="Update a source")
def update_source(
    source_id: uuid.UUID,
    payload: AssetSourcePatch,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> AssetSourceOut:
    source = _source(session, principal, source_id)
    fields = payload.model_dump(exclude_unset=True)
    credentials = fields.pop("credentials", None)
    _validate({**{"field_map": source.field_map, "match_order": source.match_order,
                  "collections": source.collections}, **fields}, source.driver)
    for field, value in fields.items():
        setattr(source, field, value)
    # Validated against the RESULTING row, as the scanner connectors are:
    # enabling in one request and clearing the base URL in the next would
    # otherwise slip past a check that only reads what changed.
    if source.driver != "file" and source.is_enabled and not (source.base_url or "").strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "an enabled fetching source needs a base URL")
    if credentials is not None:
        source.credentials_enc = (encrypt(json.dumps(credentials))
                                  if credentials else None)
    session.flush()
    audit.record(session, action="cmdb.source.updated", object_type="asset_source",
                 object_id=source.id, object_label=source.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={**{k: str(v) for k, v in fields.items()},
                          "credentials": "rotated" if credentials is not None else None})
    session.commit()
    return _out(source)


@router.delete("/{source_id}", status_code=204, response_model=None,
               response_class=Response, summary="Delete a source and its staging rows")
def delete_source(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> Response:
    source = _source(session, principal, source_id)
    audit.record(session, action="cmdb.source.deleted", object_type="asset_source",
                 object_id=source.id, object_label=source.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"driver": source.driver})
    # Assets that were promoted from it are NOT touched. Removing a source is a
    # statement about a feed, not about the estate it described.
    session.delete(source)
    session.commit()
    return Response(status_code=204)


@router.post("/{source_id}/test", summary="Reach the source, write nothing")
def test_source(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> dict[str, Any]:
    source = _source(session, principal, source_id)
    try:
        return cmdb.test_connection(source)
    except cmdb.CmdbError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


@router.post("/{source_id}/sync", response_model=AssetSourceRunOut,
             summary="Read the source into staging")
def sync_source(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:write"))],
    dry_run: bool = False,
) -> AssetSourceRun:
    source = _source(session, principal, source_id)
    if source.driver == "file":
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "this source is fed by upload; POST the export to "
            f"/asset-sources/{source_id}/upload",
        )
    try:
        run = cmdb.sync(session, source, actor_id=principal.user_id, dry_run=dry_run)
    except cmdb.CmdbError as exc:
        session.commit()   # keep the failure recorded on the source
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    session.commit()
    return run


@router.post("/{source_id}/upload", response_model=AssetSourceRunOut,
             summary="Upload a CMDB export into staging")
async def upload_export(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:write"))],
    file: Annotated[UploadFile, File()],
    dry_run: bool = False,
    mark_absent: bool = False,
) -> AssetSourceRun:
    source = _source(session, principal, source_id)
    blob = await file.read()
    if len(blob) > MAX_UPLOAD_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"export exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
    if not blob:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "the export is empty")
    try:
        run = cmdb.sync(session, source, blob=blob, filename=file.filename,
                        actor_id=principal.user_id, dry_run=dry_run,
                        mark_absent=mark_absent, trigger="upload")
    except cmdb.CmdbError as exc:
        session.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    session.commit()
    return run


@router.get("/{source_id}/runs", response_model=list[AssetSourceRunOut],
            summary="This source's import history")
def list_runs(
    source_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
    limit: int = Query(25, ge=1, le=200),
) -> list[AssetSourceRun]:
    _source(session, principal, source_id)
    return list(session.execute(
        select(AssetSourceRun)
        .where(AssetSourceRun.organization_id == principal.organization_id,
               AssetSourceRun.source_id == source_id)
        .order_by(AssetSourceRun.started_at.desc())
        .limit(limit)
    ).scalars().all())
