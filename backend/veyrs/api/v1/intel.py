"""Threat-intelligence API: CVE, CWE, CPE, EPSS, CISA KEV and feed ingestion.

The read side is deliberately open to any authenticated user with `cve:read`:
CVE data is public knowledge and hiding it behind an elevated role only makes
analysts work around the tool. The *write* side (feed ingestion) needs
`intel:write`, because a poisoned feed would corrupt every tenant's prioritisation.
"""
from __future__ import annotations

import datetime as dt
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...db import get_session
from ...models import (
    AssetProduct, Cve, Cwe, EpssScore, FeedRun, Finding, KevEntry, OPEN_STATES, Product,
    Vendor, Vulnerability,
)
from ...security import scope as team_scope
from ...security.deps import CurrentPrincipal, TenantSession, require
from ...services import audit, intel_pipeline, intel_schedule, intelligence
from .schemas import Page
from .vuln_schemas import (
    CveSummary, EpssIngestRequest, FeedRunOut, IntelScheduleUpdate, KevIngestRequest,
    NvdIngestRequest,
)

router = APIRouter(prefix="/intel", tags=["threat intelligence"])


def _summary(cve: Cve, affected: int | None = None) -> CveSummary:
    return CveSummary(
        affected_assets=affected,
        cve_id=cve.id,
        title=cve.title or (cve.description or "")[:120] or None,
        severity=(
            cve.cvss4_severity or cve.cvss3_severity
            or intelligence.severity_for_score(cve.best_cvss_score)
        ),
        cvss_score=cve.best_cvss_score,
        cvss_vector=cve.cvss4_vector or cve.cvss3_vector or cve.cvss2_vector,
        epss_score=cve.epss_score,
        epss_percentile=cve.epss_percentile,
        kev=cve.kev,
        kev_due_date=cve.kev_due_date,
        published_at=cve.published_at,
        age_days=cve.age_days,
    )


@router.get("/cve", response_model=Page[CveSummary], summary="Search CVEs")
def search_cve(
    session: TenantSession,
    principal: Annotated[Any, Depends(require("cve:read"))],
    q: str | None = Query(default=None, description="Free text over id/title/description"),
    affects_estate: bool = Query(
        default=True,
        description="Only CVEs whose applicability names software this organization "
                    "actually runs. ON by default: the catalogue is the index, not "
                    "the worklist. Turn it off to research a CVE for software you "
                    "are considering, or to check a bulletin against the full corpus.",
    ),
    kev: bool | None = None,
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    min_epss: float | None = Query(default=None, ge=0, le=1),
    cwe: str | None = None,
    published_after: dt.date | None = None,
    order: str = Query(default="risk", pattern="^(risk|published|epss|cvss|id)$"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[CveSummary]:
    stmt = select(Cve)
    # The estate lens goes on FIRST so it also narrows `total`. A filter applied
    # after the count produces a list that says "2 578 of 359 353" and paginates
    # through the 359 353 -- the exact shape of lie the vendor list carried until
    # v0.21.0.
    if affects_estate:
        stmt = stmt.where(Cve.id.in_(
            intelligence.estate_cve_ids(principal.organization_id)
        ))
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Cve.id.ilike(needle), Cve.title.ilike(needle), Cve.description.ilike(needle)
        ))
    if kev is not None:
        stmt = stmt.where(Cve.kev.is_(kev))
    if min_cvss is not None:
        stmt = stmt.where(or_(
            Cve.cvss4_score >= min_cvss,
            Cve.cvss3_base_score >= min_cvss,
            Cve.cvss2_base_score >= min_cvss,
        ))
    if min_epss is not None:
        stmt = stmt.where(Cve.epss_score >= min_epss)
    if cwe:
        stmt = stmt.where(Cve.cwe_ids.contains([cwe]))
    if published_after:
        stmt = stmt.where(Cve.published_at >= dt.datetime.combine(
            published_after, dt.time.min, tzinfo=dt.timezone.utc
        ))

    total = session.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()

    ordering = {
        "risk": (Cve.kev.desc(), Cve.epss_score.desc().nullslast(),
                 Cve.cvss3_base_score.desc().nullslast()),
        "published": (Cve.published_at.desc().nullslast(),),
        "epss": (Cve.epss_score.desc().nullslast(),),
        "cvss": (Cve.cvss3_base_score.desc().nullslast(),),
        "id": (Cve.id.desc(),),
    }[order]
    rows = session.execute(
        stmt.order_by(*ordering).offset((page - 1) * size).limit(size)
    ).scalars().all()
    # `affected_assets` is a declared field of CveSummary that nothing ever
    # populated, so the console's "Your assets" column rendered 0 on every row
    # of a catalogue that genuinely had open findings behind it. Same class of
    # defect as the five columns the Integrations page showed blank in v0.19.0:
    # a surface that renders perfectly while stating something false.
    counts = intelligence.affected_asset_counts(
        session, principal.organization_id, [c.id for c in rows]
    )
    return Page.of(
        [_summary(c, counts.get(c.id, 0)) for c in rows], total, page, size
    )


@router.get("/cve/{cve_id}", summary="CVE detail with CVSS/EPSS/KEV breakdown")
def cve_detail(
    cve_id: str,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("cve:read"))],
) -> dict:
    snapshot = intelligence.intelligence_snapshot(session, cve_id.upper())
    if snapshot is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CVE not found")
    return snapshot


@router.get("/cve/{cve_id}/exposure", summary="This tenant's exposure to a CVE")
def cve_exposure(
    cve_id: str,
    session: TenantSession,
    principal: Annotated[Any, Depends(require("finding:read"))],
) -> dict:
    """The bridge between global intelligence and tenant reality."""
    vulnerability = session.execute(
        select(Vulnerability).where(
            Vulnerability.organization_id == principal.organization_id,
            Vulnerability.cve_id == cve_id.upper(),
        )
    ).scalars().first()
    if vulnerability is None:
        return {"cve_id": cve_id.upper(), "affected_assets": 0, "findings": [],
                "risk_score": None}
    findings = session.execute(
        select(Finding).where(Finding.vulnerability_id == vulnerability.id)
    ).scalars().all()
    return {
        "cve_id": cve_id.upper(),
        "vulnerability_id": str(vulnerability.id),
        "risk_score": vulnerability.risk_score,
        "risk_level": vulnerability.risk_level,
        "affected_assets": len([f for f in findings if f.state in OPEN_STATES]),
        "findings": [
            {"id": str(f.id), "asset_id": str(f.asset_id), "state": f.state,
             "risk_score": f.risk_score, "sla_due_at":
                 f.sla_due_at.isoformat() if f.sla_due_at else None}
            for f in findings
        ],
    }


@router.get("/cve/{cve_id}/epss-history", summary="EPSS trend")
def epss_history(
    cve_id: str,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("cve:read"))],
    days: int = Query(default=90, ge=1, le=3650),
) -> dict:
    return {"cve_id": cve_id.upper(),
            "points": intelligence.epss_trend(session, cve_id.upper(), days)}


@router.get("/kev", summary="CISA KEV catalogue")
def kev_list(
    session: TenantSession,
    principal: Annotated[Any, Depends(require("cve:read"))],
    affects_estate: bool = Query(
        default=True,
        description="Only KEV entries for software this organization runs. "
                    "Same lens, same default and same helper as /intel/cve.",
    ),
    due_within_days: int | None = Query(default=None, ge=0, le=3650),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> dict:
    stmt = select(KevEntry)
    if affects_estate:
        stmt = stmt.where(KevEntry.cve_id.in_(
            intelligence.estate_cve_ids(principal.organization_id)
        ))
    if due_within_days is not None:
        cutoff = dt.date.today() + dt.timedelta(days=due_within_days)
        stmt = stmt.where(KevEntry.due_date.is_not(None), KevEntry.due_date <= cutoff)
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(KevEntry.due_date.asc().nullslast())
        .offset((page - 1) * size).limit(size)
    ).scalars().all()
    return {
        # Same pagination contract as `Page`: hand-built dicts that omit
        # limit/offset force every client to special-case these routes.
        "total": total, "page": page, "size": size,
        "limit": size, "offset": (page - 1) * size,
        "items": [{
            "cve_id": r.cve_id, "vendor_project": r.vendor_project, "product": r.product,
            "vulnerability_name": r.vulnerability_name, "required_action": r.required_action,
            "date_added": r.date_added.isoformat() if r.date_added else None,
            "due_date": r.due_date.isoformat() if r.due_date else None,
            "days_until_due": r.days_until_due, "known_ransomware": r.known_ransomware,
        } for r in rows],
    }


@router.get("/cwe/{cwe_id}", summary="CWE detail")
def cwe_detail(
    cwe_id: str,
    session: TenantSession,
    principal: Annotated[Any, Depends(require("cve:read"))],
) -> dict:
    """The weakness class, plus how much of it this tenant is carrying.

    `name` is null while the row is still the placeholder an NVD identifier
    created — reporting the id as its own name would make an un-ingested
    dictionary look like an ingested one.
    """
    row = session.get(Cwe, cwe_id.upper())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "CWE not found")
    open_findings = session.execute(
        select(func.count(Finding.id))
        .select_from(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .join(Cve, Vulnerability.cve_id == Cve.id)
        .where(Finding.organization_id == principal.organization_id,
               Finding.state.in_(list(OPEN_STATES)),
               Cve.cwe_ids.contains([row.id]))
    ).scalar_one()
    number = row.id.rsplit("-", 1)[-1]
    return {"id": row.id, "name": row.display_name, "resolved": row.resolved,
            "description": row.description,
            "abstraction": row.abstraction, "status": row.status,
            "categories": row.categories, "open_findings": open_findings,
            "reference": f"https://cwe.mitre.org/data/definitions/{number}.html"
                         if number.isdigit() else None}


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------


@router.post("/feeds/nvd", status_code=status.HTTP_202_ACCEPTED, summary="Ingest NVD 2.0 records")
def ingest_nvd(
    payload: NvdIngestRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("intel:write"))],
    correlate: bool = Query(
        default=True,
        description="Run the ingested CVEs against every tenant's inventory. "
                    "Turn off only for a bulk backfill you intend to correlate "
                    "afterwards in one pass.",
    ),
) -> dict:
    """Ingest CVE records and, by default, tell the tenants they are affected.

    Ingestion without correlation was the original behaviour and it was a trap:
    the CVE landed, no finding was raised, and the estate only discovered it the
    next time somebody happened to edit an asset.
    """
    touched: list[str] = []
    stats: dict = dict(intelligence.ingest_nvd(
        session, payload.vulnerabilities, collect=touched
    ))
    session.commit()
    if correlate:
        stats["refresh"] = intel_pipeline.refresh_after_feed(session, "nvd", touched)
    return stats


@router.post("/feeds/epss", status_code=status.HTTP_202_ACCEPTED, summary="Ingest EPSS scores")
def ingest_epss(
    payload: EpssIngestRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("intel:write"))],
    correlate: bool = Query(default=True, description="Rescore affected findings"),
) -> dict:
    """EPSS changes urgency, never applicability, so this rescores; it does not
    correlate. See `services.intel_pipeline` for why that distinction matters."""
    touched: list[str] = []
    stats: dict = dict(intelligence.ingest_epss(
        session, [row.model_dump() for row in payload.rows],
        scored_on=payload.scored_on, model_version=payload.model_version,
        collect=touched,
    ))
    session.commit()
    if correlate:
        stats["refresh"] = intel_pipeline.refresh_after_feed(session, "epss", touched)
    return stats


@router.post("/feeds/kev", status_code=status.HTTP_202_ACCEPTED, summary="Ingest CISA KEV")
def ingest_kev(
    payload: KevIngestRequest,
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("intel:write"))],
    correlate: bool = Query(default=True, description="Rescore affected findings"),
) -> dict:
    """Known exploitation is the single biggest urgency signal in the model, so
    a KEV import rescores every open finding for the CVEs it touched."""
    touched: list[str] = []
    stats: dict = dict(intelligence.ingest_kev(
        session, payload.model_dump(by_alias=True), collect=touched
    ))
    session.commit()
    if correlate:
        stats["refresh"] = intel_pipeline.refresh_after_feed(session, "kev", touched)
    return stats


@router.get("/feeds/runs", response_model=Page[FeedRunOut], summary="Feed run history")
def feed_runs(
    session: Annotated[Session, Depends(get_session)],
    principal: Annotated[Any, Depends(require("intel:read"))],
    feed: str | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=25, ge=1, le=200),
) -> Page[FeedRunOut]:
    stmt = select(FeedRun)
    if feed:
        stmt = stmt.where(FeedRun.feed == feed)
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(FeedRun.started_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    return Page.of([FeedRunOut.model_validate(r) for r in rows], total, page, size)


@router.get("/vendors", summary="Search the shared vendor dictionary")
def list_vendors(
    session: TenantSession,
    principal: Annotated[Any, Depends(require("cve:read"))],
    q: str | None = Query(default=None, description="Substring of the vendor name."),
    in_use: bool = Query(
        default=False,
        description="Only vendors whose products this organization actually runs.",
    ),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[dict]:
    """The `vendors` table, made reachable.

    Worth being blunt about what this is, because the name invites the wrong
    reading: **this is not third-party risk management.** `vendors` and
    `products` are the global CPE dictionary that arrives with NVD -- the rows
    that let "nginx 1.24 on this host" and "this CVE applies to nginx < 1.25"
    join. They are shared by every tenant and nobody's supplier register.

    What IS tenant-specific is `installations`: how many of *your* asset
    products point at that vendor. Returning both in one row is the whole
    point -- a dictionary of 30 000 vendors is noise until you can see which
    twelve of them you actually run.
    """
    # The usage count joins in SQL rather than being applied to the page after
    # the fact. Sorting a page of 50 rows by a column the query did not order
    # by produces a list that looks ranked and is not: the first attempt here
    # returned the alphabetically-first 50 of 37 345 vendors, all with zero
    # installations, tidily sorted among themselves.
    usage = (
        select(
            Product.vendor_id.label("vendor_id"),
            func.count(AssetProduct.id).label("installations"),
        )
        .join(AssetProduct, AssetProduct.product_id == Product.id)
        .where(AssetProduct.organization_id == principal.organization_id)
        .group_by(Product.vendor_id)
        .subquery()
    )
    installs = func.coalesce(usage.c.installations, 0)

    stmt = select(Vendor, installs).join(
        usage, usage.c.vendor_id == Vendor.id, isouter=True
    )
    if q:
        stmt = stmt.where(Vendor.name.ilike(f"%{q.strip()}%"))
    if in_use:
        stmt = stmt.where(installs > 0)

    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    # Vendors you actually run first: the dictionary is 37 000 rows long and the
    # useful part of it is the couple of hundred that describe your estate.
    rows = session.execute(
        stmt.order_by(installs.desc(), Vendor.name)
        .offset((page - 1) * size).limit(size)
    ).all()
    items = [{
        "id": str(vendor.id),
        "name": vendor.name,
        "slug": getattr(vendor, "slug", None),
        "installations": int(count or 0),
    } for vendor, count in rows]
    return Page.of(items, total, page, size)


@router.get("/schedule", summary="How often each intelligence feed refreshes")
def get_schedule(
    session: TenantSession,
    principal: Annotated[Any, Depends(require("intel:read"))],
) -> dict:
    """This tenant's requested cadence next to the one actually in force.

    Read is open to anyone who can read intelligence: an analyst looking at a
    two-day-old EPSS score needs to be able to tell "the feed is configured
    weekly" from "the feed is broken" without asking an administrator.
    """
    return intel_schedule.state(session, principal.organization_id)


@router.put("/schedule", summary="Change how often the intelligence feeds refresh")
def put_schedule(
    payload: IntelScheduleUpdate,
    request: Request,
    session: TenantSession,
    principal: Annotated[Any, Depends(require("intel:write"))],
) -> dict:
    """Set the cadence per feed.

    Refused to a team-scoped identity: the corpus is shared by the whole
    deployment, so this is not a decision that can be narrowed to one team's
    slice of the estate -- it can only be made for everybody or not at all.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "the intelligence corpus is shared by the whole deployment, so its "
        "refresh cadence cannot be set from a team-scoped identity",
    )
    before = intel_schedule.state(session, principal.organization_id)
    try:
        after = intel_schedule.set_schedule(
            session,
            principal.organization_id,
            {feed: spec.model_dump(exclude_unset=True) for feed, spec in payload.feeds.items()},
            actor_id=principal.user_id,
        )
    except intel_schedule.ScheduleError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

    def _digest(state: dict) -> dict:
        return {f["feed"]: [f["enabled"], f["interval_minutes"]] for f in state["feeds"]}

    audit.record(
        session,
        action="organization.intel_schedule_changed",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="intelligence refresh schedule",
        changes={"feeds": [_digest(before), _digest(after)]},
        organization_id=principal.organization_id,
        actor_id=principal.user_id,
        actor_label=principal.label,
        correlation_id=getattr(request.state, "correlation_id", None),
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("User-Agent") or "")[:255] or None,
    )
    session.commit()
    return after


@router.get("/health", summary="Freshness of every intelligence feed")
def intel_health(
    session: TenantSession,
    principal: Annotated[Any, Depends(require("intel:read"))],
) -> dict:
    """Stale intelligence is silently wrong prioritisation, so surface it."""
    out = {}
    now = dt.datetime.now(dt.timezone.utc)
    for feed in ("nvd", "epss", "kev"):
        run = intelligence.last_successful_run(session, feed)
        if run is None:
            out[feed] = {"status": "never_run", "age_hours": None}
            continue
        finished = run.finished_at or run.started_at
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=dt.timezone.utc)
        age = (now - finished).total_seconds() / 3600.0
        # EPSS and KEV publish daily; NVD is continuous but a 48h gap is a problem.
        limit = {"nvd": 48, "epss": 48, "kev": 72}[feed]
        out[feed] = {
            "status": "ok" if age <= limit else "stale",
            "age_hours": round(age, 1),
            "records_seen": run.records_seen,
            "watermark": run.watermark,
        }
    org_id = principal.organization_id
    out["counts"] = {
        "cve": session.execute(select(func.count()).select_from(Cve)).scalar_one(),
        "kev": session.execute(select(func.count()).select_from(KevEntry)).scalar_one(),
        "epss": session.execute(select(func.count()).select_from(EpssScore)).scalar_one(),
        # Both numbers, always, and never the estate one alone. "17 CVEs affect
        # you" is reassuring and meaningless without "out of 359 353 known and
        # 978 products we could resolve" next to it -- an estate that shrank
        # because the inventory broke looks identical to one that got patched.
        "cve_affecting_estate": intelligence.estate_cve_count(session, org_id),
        "kev_affecting_estate": intelligence.estate_kev_count(session, org_id),
    }
    out["inventory"] = intelligence.estate_inventory_health(session, org_id)
    return out
