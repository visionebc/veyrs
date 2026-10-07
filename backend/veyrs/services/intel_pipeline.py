"""Turns freshly ingested intelligence into tenant findings.

`services.intelligence` writes global knowledge and deliberately knows nothing
about tenants. `services.correlation` writes tenant findings and deliberately
knows nothing about feeds. Nothing joined the two, so a CVE could land in the
database and no tenant was ever told: the estate only learned about it if
somebody happened to touch an asset afterwards. This module is that missing
join, and it is the only place allowed to walk every tenant in one pass.

Two different reactions, on purpose:

* **New or revised CVE records** (NVD) can create findings that did not exist,
  so they get the full correlation. A daily NVD delta is a few hundred records,
  which is a few hundred bounded inventory queries.
* **EPSS and KEV** never change *what* is affected, only *how urgent* it is. A
  full correlation over EPSS would be ~250k CVEs x one inventory query each,
  every day, to discover nothing new. Those feeds rescore the findings that
  already exist instead: one indexed query to find them, then the risk engine.

RLS note: every call here rebinds the session's tenant. The binding in force on
entry is captured and restored on exit, because a caller that keeps working
after this returns (the ingest endpoints do) would otherwise be reading a
different tenant's data without ever asking to.
"""
from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import current_tenant, set_tenant
from ..models import Finding, OPEN_STATES, Organization, Vulnerability
from . import correlation, risk as risk_service


def active_organizations(session: Session) -> list[Organization]:
    """Every tenant that should receive intelligence updates.

    Read with whatever tenant is currently bound -- `organizations` is not an
    RLS-scoped table, so this works from a background job with no tenant set.
    """
    return list(session.execute(
        select(Organization).where(Organization.is_active.is_(True))
        .order_by(Organization.slug)
    ).scalars().all())


def correlate_new_cves(
    session: Session,
    cve_ids: Sequence[str],
    *,
    organizations: Sequence[Organization] | None = None,
) -> dict[str, Any]:
    """Run every given CVE against every tenant's inventory.

    Idempotent by construction: `correlate_cve` upserts findings on a dedupe
    key, so re-running a feed does not duplicate the estate.
    """
    ids = _unique(cve_ids)
    result: dict[str, Any] = {"cve_ids": len(ids), "organizations": 0, "created": 0,
                              "updated": 0, "assets": 0, "by_org": {}}
    if not ids:
        return result

    previous = current_tenant(session)
    try:
        for org in (organizations if organizations is not None
                    else active_organizations(session)):
            set_tenant(session, org.id)
            totals = correlation.correlate_batch(session, org.id, ids)
            session.commit()
            result["organizations"] += 1
            result["created"] += totals["created"]
            result["updated"] += totals["updated"]
            result["assets"] += totals["assets"]
            if totals["cves"]:
                result["by_org"][org.slug] = totals
    finally:
        _restore(session, previous)
    return result


#: Ids per window when looking up findings by CVE. EPSS touches every CVE
#: it has ever scored, so this list is not a delta -- it is the corpus.
RESCORE_ID_WINDOW = 5000


def rescore_for_cves(
    session: Session,
    cve_ids: Sequence[str],
    *,
    reason: str,
    organizations: Sequence[Organization] | None = None,
) -> dict[str, Any]:
    """Re-score open findings whose CVE just changed urgency.

    Used by EPSS and KEV. Deliberately does NOT correlate: a probability score
    or an exploitation flag cannot make an asset newly affected, and pretending
    otherwise would turn a cheap daily refresh into a full estate rescan.
    """
    ids = _unique(cve_ids)
    result: dict[str, Any] = {"cve_ids": len(ids), "organizations": 0,
                              "findings": 0, "changed": 0, "by_org": {}}
    if not ids:
        return result

    previous = current_tenant(session)
    try:
        for org in (organizations if organizations is not None
                    else active_organizations(session)):
            set_tenant(session, org.id)
            # Windowed, because for EPSS `ids` IS the corpus: a quarter of a
            # million bind parameters is a statement psycopg has to render and
            # Postgres has to plan before a single row comes back.
            matched: dict[Any, Finding] = {}
            for start in range(0, len(ids), RESCORE_ID_WINDOW):
                for finding in session.execute(
                    select(Finding)
                    .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
                    .where(
                        Finding.organization_id == org.id,
                        Finding.state.in_(tuple(OPEN_STATES)),
                        Vulnerability.cve_id.in_(ids[start:start + RESCORE_ID_WINDOW]),
                    )
                ).scalars():
                    matched[finding.id] = finding
            findings = list(matched.values())
            if not findings:
                continue
            changed = risk_service.rescore_findings(
                session, org.id, findings, reason=reason
            )
            session.commit()
            result["organizations"] += 1
            result["findings"] += len(findings)
            result["changed"] += changed
            result["by_org"][org.slug] = {"findings": len(findings), "changed": changed}
    finally:
        _restore(session, previous)
    return result


def refresh_after_feed(
    session: Session, feed: str, cve_ids: Sequence[str]
) -> dict[str, Any]:
    """Dispatch the right reaction for the feed that just ran."""
    if feed == "nvd":
        return correlate_new_cves(session, cve_ids)
    if feed in ("epss", "kev"):
        return rescore_for_cves(session, cve_ids, reason=f"{feed} refresh")
    raise ValueError(f"unknown feed {feed!r}")


def _unique(values: Sequence[str]) -> list[str]:
    """Preserve order, drop repeats and blanks. A feed page can repeat an id."""
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        key = (value or "").strip().upper()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _restore(session: Session, previous: str | None) -> None:
    set_tenant(session, uuid.UUID(previous) if previous else None)


__all__ = [
    "active_organizations", "correlate_new_cves", "rescore_for_cves",
    "refresh_after_feed",
]
