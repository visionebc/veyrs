"""Asset inventory API (spec sections 7 and 8).

Assets are where business context enters the risk equation: criticality, data
classification, internet exposure, environment and owning team. Everything the
risk engine multiplies CVSS by comes from these rows, which is why creating an
asset without them is allowed but visibly defaulted rather than silently null.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import Response, APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select

from ...models import (
    Asset, AssetProduct, BusinessService, Finding, OPEN_STATES, Product, Vendor,
)
from ...security import scope as team_scope
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...services import audit, correlation, intelligence, inventory, teams as teams_service
from ...services.versions import version_key
from .schemas import Page
from .vuln_schemas import (
    AssetBulkAssign, AssetCreate, AssetDetail, AssetOut, AssetProductIn, AssetProductOut,
    AssetUpdate, BusinessServiceCreate, BusinessServiceOut, InventoryBulkIn, InventoryImportIn,
)

router = APIRouter(prefix="/assets", tags=["assets"])


def _actor(request: Request, principal: Principal) -> dict:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": ip,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


def _get_asset(session, organization_id: uuid.UUID, asset_id: uuid.UUID,
               scope: team_scope.TeamScope = team_scope.UNRESTRICTED) -> Asset:
    """Fetch one asset, or 404.

    Out of scope answers 404 rather than 403: a 403 confirms the row exists,
    which is exactly the fact a segregated tenant is not supposed to learn.
    Every single-asset path (read, update, delete, products, inventory) funnels
    through here, so the check cannot be forgotten on one of them.
    """
    asset = session.get(Asset, asset_id)
    if asset is None or asset.organization_id != organization_id or asset.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if not team_scope.asset_visible(asset, scope):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return asset


def _label(session, rows: list[AssetOut]) -> list[AssetOut]:
    """Fill team/owner/department names with one batched lookup per page.

    Done after serialisation rather than as a join so the ownership filters and
    the ordering keep the query plan they had; a page is at most 200 rows, so
    this is three `IN` lookups over a handful of ids.
    """
    names = teams_service.resolve_names(
        session,
        team_ids=[r.team_id for r in rows],
        user_ids=[r.owner_id for r in rows],
        department_ids=[r.department_id for r in rows],
    )
    for row in rows:
        row.team_name = names["teams"].get(row.team_id)
        row.owner_name = names["users"].get(row.owner_id)
        row.department_name = names["departments"].get(row.department_id)
    return rows


def _install_products(session, asset: Asset, products: list[AssetProductIn]) -> int:
    added = 0
    for spec in products:
        product = intelligence.upsert_product(session, spec.vendor, spec.product)
        existing = session.execute(
            select(AssetProduct).where(
                AssetProduct.organization_id == asset.organization_id,
                AssetProduct.asset_id == asset.id,
                AssetProduct.product_id == product.id,
            )
        ).scalars().first()
        now = dt.datetime.now(dt.timezone.utc)
        if existing is None:
            session.add(AssetProduct(
                organization_id=asset.organization_id, asset_id=asset.id,
                product_id=product.id, version=spec.version,
                version_key=version_key(spec.version), install_path=spec.install_path,
                detected_by=spec.detected_by, last_seen_at=now,
            ))
            added += 1
        else:
            existing.version = spec.version
            existing.version_key = version_key(spec.version)
            existing.install_path = spec.install_path or existing.install_path
            existing.detected_by = spec.detected_by
            existing.last_seen_at = now
        if spec.version:
            intelligence.upsert_product_version(session, product, spec.version)
    session.flush()
    return added


# --------------------------------------------------------------------------
# Business services
# --------------------------------------------------------------------------


@router.post("/services", response_model=BusinessServiceOut,
             status_code=status.HTTP_201_CREATED, summary="Create a business service")
def create_service(
    payload: BusinessServiceCreate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> BusinessServiceOut:
    row = BusinessService(organization_id=principal.organization_id, **payload.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return BusinessServiceOut.model_validate(row)


@router.get("/services", response_model=Page[BusinessServiceOut],
            summary="List business services")
def list_services(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[BusinessServiceOut]:
    stmt = select(BusinessService).where(
        BusinessService.organization_id == principal.organization_id
    )
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(BusinessService.name).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page.of([BusinessServiceOut.model_validate(r) for r in rows], total, page, size)


# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------


@router.post("", response_model=AssetDetail, status_code=status.HTTP_201_CREATED,
             summary="Create an asset")
def create_asset(
    payload: AssetCreate,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> AssetDetail:
    data = payload.model_dump(exclude={"products"})
    now = dt.datetime.now(dt.timezone.utc)
    asset = Asset(
        organization_id=principal.organization_id,
        first_seen_at=now, last_seen_at=now, **data,
    )
    session.add(asset)
    session.flush()
    _install_products(session, asset, payload.products)

    # A newly-inventoried asset is correlated immediately: waiting for the next
    # feed cycle would leave a known-vulnerable host invisible for up to a day.
    correlation.correlate_asset(session, principal.organization_id, asset)

    audit.record(session, action="asset.create", object_type="asset",
                 object_id=str(asset.id), **_actor(request, principal), changes=audit.diff(None, {"name": asset.name}))
    session.commit()
    session.refresh(asset)
    return _detail(session, asset)


def _csv(value: str | None) -> list[str]:
    """Split a comma-separated filter into its members, dropping blanks.

    A single value is just a one-member list, so `exposure=internet` and
    `exposure=internet,partner` go through the same code path. Blanks are
    dropped rather than matched: `exposure=internet,` asking for assets whose
    exposure is the empty string would return nothing and look like a bug in
    the estate rather than a stray comma.
    """
    if value is None:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


@router.get("", response_model=Page[AssetOut], summary="List/search assets")
def list_assets(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
    q: str | None = None,
    asset_type: str | None = None,
    criticality: str | None = None,
    exposure: str | None = Query(
        default=None,
        description="Comma-separated; `internet,partner` means either.",
    ),
    environment: str | None = Query(
        default=None,
        description="Comma-separated; `staging,test` means either.",
    ),
    exclude_exposure: str | None = Query(
        default=None,
        description="Comma-separated exposures to EXCLUDE. `internet` is how "
                    "you ask for the estate that is not reachable from the "
                    "internet without having to enumerate the other three.",
    ),
    exclude_environment: str | None = Query(
        default=None,
        description="Comma-separated environments to EXCLUDE. `production` is "
                    "how you ask for the non-production estate.",
    ),
    tag: str | None = None,
    business_service_id: uuid.UUID | None = None,
    team_id: uuid.UUID | None = None,
    owner_id: uuid.UUID | None = None,
    department_id: uuid.UUID | None = None,
    unowned: bool = Query(
        default=False,
        description="Only assets with no owning team. These are invisible to "
                    "team-scoped users, so they need a way to be found.",
    ),
    is_active: bool | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[AssetOut]:
    """List the estate.

    Negation exists as its own parameter rather than as a magic prefix on the
    positive one because the two are not opposites in practice: "not
    production" has to keep meaning "not production" when a sixth environment
    is added to the enum, and a client that spells out the five it knows about
    would silently stop covering the estate the day a sixth appears. The
    columns are NOT NULL with defaults, so a `!=` predicate cannot drop rows
    through the usual SQL NULL hole -- if that ever changes, these two filters
    are the first things to revisit.
    """
    stmt = select(Asset).where(
        Asset.organization_id == principal.organization_id, Asset.deleted_at.is_(None)
    )
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Asset.name.ilike(needle), Asset.hostname.ilike(needle), Asset.fqdn.ilike(needle)
        ))
    for column, value in (
        (Asset.asset_type, asset_type), (Asset.criticality, criticality),
        (Asset.business_service_id, business_service_id),
        (Asset.team_id, team_id), (Asset.owner_id, owner_id),
        (Asset.department_id, department_id),
    ):
        if value is not None:
            stmt = stmt.where(column == value)
    for column, raw in ((Asset.exposure, exposure), (Asset.environment, environment)):
        members = _csv(raw)
        if members:
            stmt = stmt.where(column.in_(members))
    for column, raw in (
        (Asset.exposure, exclude_exposure), (Asset.environment, exclude_environment),
    ):
        members = _csv(raw)
        if members:
            stmt = stmt.where(column.notin_(members))
    if unowned:
        stmt = stmt.where(Asset.team_id.is_(None))
    stmt = team_scope.assets(stmt, principal.scope)
    if tag:
        stmt = stmt.where(Asset.tags.contains([tag]))
    if is_active is not None:
        stmt = stmt.where(Asset.is_active.is_(is_active))

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(Asset.name).offset((page - 1) * size).limit(size)
    ).scalars().all()
    items = _label(session, [AssetOut.model_validate(r) for r in rows])
    return Page.of(items, total, page, size)


@router.post("/bulk-assign", summary="Assign ownership to many assets at once")
def bulk_assign_assets(
    payload: AssetBulkAssign,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict:
    """Set team / owner / department on up to 500 assets.

    Ownership is validated ONCE, before the loop: an unknown team is an operator
    error about the whole request, not a per-row outcome, and half-applying it
    would leave the estate in a state nobody asked for. Unknown *assets*, by
    contrast, are reported per id -- same rationale as `findings/bulk-transition`.
    """
    try:
        changes = payload.assignments(("team_id", "owner_id", "department_id"))
        teams_service.validate_team(session, principal.organization_id, changes.get("team_id"))
        teams_service.validate_user(session, principal.organization_id, changes.get("owner_id"))
        teams_service.validate_department(
            session, principal.organization_id, changes.get("department_id")
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    if not changes:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "nothing to assign: set a field or list it in `clear`")

    target = changes.get("team_id")
    if (principal.scope.restricted and "team_id" in changes
            and (target is None or target not in principal.scope.team_ids)):
        # Handing an asset to a team you cannot see is a one-way door: you lose
        # the asset and cannot undo it. Refused rather than silently allowed.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "cannot assign ownership outside your own team scope")

    results: dict[str, list[str]] = {"changed": [], "rejected": []}
    for asset_id in payload.asset_ids:
        asset = session.get(Asset, asset_id)
        if (asset is None or asset.organization_id != principal.organization_id
                or asset.deleted_at is not None
                or not team_scope.asset_visible(asset, principal.scope)):
            results["rejected"].append(str(asset_id))
            continue
        for field, value in changes.items():
            setattr(asset, field, value)
        results["changed"].append(str(asset_id))

    audit.record(session, action="asset.bulk_assign", object_type="asset", object_id=None,
                 **_actor(request, principal),
                 changes=audit.diff(None, {**{k: str(v) for k, v in changes.items()},
                                           "changed": len(results["changed"])}))
    session.commit()
    return {**results, "changed_count": len(results["changed"]),
            "rejected_count": len(results["rejected"])}


def _detail(session, asset: Asset) -> AssetDetail:
    installs = session.execute(
        select(AssetProduct, Product, Vendor)
        .join(Product, Product.id == AssetProduct.product_id)
        .join(Vendor, Vendor.id == Product.vendor_id)
        .where(AssetProduct.asset_id == asset.id)
    ).all()
    open_count, max_risk = session.execute(
        select(func.count(Finding.id), func.max(Finding.risk_score))
        .where(Finding.asset_id == asset.id, Finding.state.in_(tuple(OPEN_STATES)))
    ).one()
    detail = AssetDetail.model_validate(asset)
    detail.products = [
        AssetProductOut(
            id=ap.id, product_id=ap.product_id, vendor=vendor.name, product=product.name,
            version=ap.version, detected_by=ap.detected_by, last_seen_at=ap.last_seen_at,
        )
        for ap, product, vendor in installs
    ]
    detail.open_findings = open_count or 0
    detail.max_risk_score = max_risk
    _label(session, [detail])
    return detail


# --------------------------------------------------------------------------
# Inventory
#
# Declared above `/{asset_id}` on purpose: FastAPI matches in declaration order,
# so a later `/inventory/coverage` would be swallowed by `/{asset_id}` and fail
# as a malformed UUID.
# --------------------------------------------------------------------------


@router.get("/inventory/coverage", summary="Which inventory can never match a CVE")
def inventory_coverage(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
) -> dict:
    """Separate "nothing is vulnerable" from "nothing is matchable".

    Both render as an empty findings list everywhere else in the product, and
    only one of them is good news.
    """
    return inventory.coverage(session, principal.organization_id)


@router.get("/inventory/aliases", summary="Verify the curated CPE aliases")
def inventory_aliases(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
) -> dict:
    """A hardcoded alias is a claim about NVD's dictionary; this checks it."""
    return inventory.verify_aliases(session)


@router.post("/inventory/resolve", summary="Dry-run identity resolution")
def inventory_resolve(
    payload: InventoryBulkIn,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
) -> dict:
    """Resolve identities and roll the transaction back.

    Lets an operator see how a CMDB export will be interpreted -- which vendor
    strings get rewritten, which rows will never match -- before committing the
    estate to it.
    """
    out = []
    for item in payload.items:
        try:
            resolution = inventory.resolve_identity(
                session, cpe=item.cpe, vendor=item.vendor,
                product=item.product, version=item.version,
            )
        except ValueError as exc:
            out.append({"input": item.cpe or item.product, "error": str(exc),
                        "matched": False})
        else:
            out.append({"input": item.cpe or item.product, **resolution.as_dict()})
    session.rollback()
    return {"items": len(out), "matched": sum(1 for r in out if r.get("matched")),
            "results": out}


@router.post("/inventory/import", summary="Bulk-onboard hosts with their software")
def inventory_import(
    payload: InventoryImportIn,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict:
    """Create/update many assets and their installed software in one call.

    Built for the initial load from an existing CMDB. Correlation runs per asset
    after its software is recorded, so findings appear in the same request
    rather than at some later unrelated edit.
    """
    summary = {"hosts": 0, "assets_created": 0, "added": 0, "updated": 0,
               "removed": 0, "anchored": 0, "matched": 0, "unmatched": 0,
               "findings_created": 0, "hosts_detail": []}
    for host in payload.hosts:
        asset, created = inventory.upsert_asset(
            session, principal.organization_id, host.model_dump(exclude={"items"})
        )
        result = inventory.install(
            session, asset, host.items,
            detected_by=payload.detected_by, replace=payload.replace,
        )
        correlated = {}
        if payload.correlate and host.items:
            correlated = correlation.correlate_asset(
                session, principal.organization_id, asset
            )
        summary["hosts"] += 1
        summary["assets_created"] += int(created)
        for key in ("added", "updated", "removed", "anchored", "matched",
                    "unmatched"):
            summary[key] += result[key]
        summary["findings_created"] += correlated.get("created", 0)
        summary["hosts_detail"].append({
            "asset": asset.name, "created": created,
            "added": result["added"], "unmatched": result["unmatched"],
            "findings": correlated.get("created", 0),
        })
        audit.record(session, action="asset.inventory.import", object_type="asset",
                     object_id=str(asset.id), **_actor(request, principal),
                     changes={"items": len(host.items), "source": payload.detected_by})
    session.commit()
    return summary


@router.get("/{asset_id}", response_model=AssetDetail, summary="Asset detail")
def get_asset(
    asset_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read"))],
) -> AssetDetail:
    return _detail(session, _get_asset(session, principal.organization_id, asset_id, principal.scope))


@router.patch("/{asset_id}", response_model=AssetDetail, summary="Update an asset")
def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> AssetDetail:
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    changes = payload.model_dump(exclude_unset=True)
    before = {k: getattr(asset, k) for k in changes}
    risk_relevant = {"criticality", "data_classification", "exposure", "environment",
                     "business_service_id", "compensating_controls"}
    for key, value in changes.items():
        setattr(asset, key, value)
    session.flush()

    # Business context is an input to every risk score on this asset: changing it
    # without re-scoring would leave the queue ordered by stale assumptions.
    if risk_relevant & set(changes):
        from ...services import risk as risk_service
        findings = session.execute(
            select(Finding).where(
                Finding.asset_id == asset.id, Finding.state.in_(tuple(OPEN_STATES))
            )
        ).scalars().all()
        risk_service.rescore_findings(
            session, principal.organization_id, findings, reason="asset context changed"
        )

    audit.record(session, action="asset.update", object_type="asset",
                 object_id=str(asset.id),
                 **_actor(request, principal), changes=audit.diff(before, changes))
    session.commit()
    session.refresh(asset)
    return _detail(session, asset)


@router.delete("/{asset_id}", status_code=204, response_model=None, response_class=Response,
               summary="Soft-delete an asset")
def delete_asset(
    asset_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:delete"))],
) -> None:
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    asset.deleted_at = dt.datetime.now(dt.timezone.utc)
    asset.is_active = False
    audit.record(session, action="asset.delete", object_type="asset",
                 object_id=str(asset.id),
                 **_actor(request, principal), changes=audit.diff({"name": asset.name}, None))
    session.commit()


@router.post("/{asset_id}/products", response_model=AssetDetail,
             summary="Record installed software on an asset")
def add_products(
    asset_id: uuid.UUID,
    payload: list[AssetProductIn],
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> AssetDetail:
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    _install_products(session, asset, payload)
    correlation.correlate_asset(session, principal.organization_id, asset)
    session.commit()
    session.refresh(asset)
    return _detail(session, asset)


@router.delete("/{asset_id}/products/{install_id}", status_code=204, response_model=None, response_class=Response,
               summary="Remove installed software")
def remove_product(
    asset_id: uuid.UUID,
    install_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> None:
    _get_asset(session, principal.organization_id, asset_id, principal.scope)
    row = session.get(AssetProduct, install_id)
    if row is None or row.asset_id != asset_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "installation not found")
    session.delete(row)
    session.commit()


@router.post("/{asset_id}/products/bulk", summary="Record installed software in bulk")
def add_products_bulk(
    asset_id: uuid.UUID,
    payload: InventoryBulkIn,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict:
    """Like POST /products, but CPE-aware and honest about what it could not match.

    The older endpoint takes the operator's vendor string at face value, which
    is how an inventory ends up pointing at product rows no CVE will ever
    reference. This one resolves every row against the CPE dictionary and
    returns the per-row verdict.
    """
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    result = inventory.install(
        session, asset, payload.items,
        detected_by=payload.detected_by, replace=payload.replace,
    )
    if payload.correlate:
        result["correlation"] = correlation.correlate_asset(
            session, principal.organization_id, asset
        )
    audit.record(session, action="asset.products.bulk", object_type="asset",
                 object_id=str(asset.id), **_actor(request, principal),
                 changes={"items": len(payload.items), "source": payload.detected_by,
                          "replace": payload.replace})
    session.commit()
    return result


@router.post("/{asset_id}/rescan", summary="Re-correlate this asset against known CVEs")
def rescan_asset(
    asset_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:write"))],
) -> dict:
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    stats = correlation.correlate_asset(session, principal.organization_id, asset)
    session.commit()
    return stats
