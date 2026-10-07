"""Dashboard and analytics queries (spec section 27).

Every number here is computed in SQL against the tenant's own rows. Two rules
that shape the module:

* **Report the denominator.** "12 critical findings" is a number; "12 critical
  of 430 open, on 38 of 512 assets" is information. Every ratio ships with the
  counts it came from, because a dashboard that hides its denominator is how a
  programme convinces itself it is fine.
* **Say when a metric is not meaningful yet.** MTTR over three closed findings
  is noise. Metrics carry a `sample` so the UI can grey them out instead of
  drawing a confident line through two points.

Nothing here writes. Analytics that mutates state is a debugging nightmare and
an audit problem.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import Float, and_, case, cast, func, select
from sqlalchemy.orm import Session

from ..models import (
    Asset, AssetProduct, CLOSED_STATES, Cve, Cwe, Finding, OPEN_STATES, Product,
    RiskScoreHistory, Team, Ticket, Vendor, Vulnerability,
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
RISK_LEVELS = ("critical", "high", "medium", "low", "informational")

#: Below this many samples a rate/average is labelled unreliable rather than
#: rendered as a headline figure.
MIN_MEANINGFUL_SAMPLE = 10


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _open(statement):
    return statement.where(Finding.state.in_(list(OPEN_STATES)))


# --- team scope ------------------------------------------------------------
# Every tenant predicate in this module goes through one of the three helpers
# below. That is the point: a dashboard is where a partial view is most
# dangerous, because "3 critical findings" reads as a fact about the estate
# rather than a fact about what the caller may see. If a new query filters on
# `organization_id` directly it will be unscoped, and
# `test_phase26_scope.py::test_no_analytics_query_bypasses_the_scope_helpers`
# fails on the source rather than on a leak in production.


def _scoped(org_id: uuid.UUID, scope=None):
    """Tenant predicate for a `Finding` query, narrowed to the caller's teams."""
    from ..security import scope as team_scope

    clause = Finding.organization_id == org_id
    if scope is not None and scope.restricted:
        clause = and_(clause, team_scope.finding_clause(scope))
    return clause


def _scoped_asset(org_id: uuid.UUID, scope=None):
    from ..security import scope as team_scope

    clause = Asset.organization_id == org_id
    if scope is not None and scope.restricted:
        clause = and_(clause, team_scope.asset_clause(scope))
    return clause


def _scoped_ticket(org_id: uuid.UUID, scope=None):
    from ..security import scope as team_scope

    clause = Ticket.organization_id == org_id
    if scope is not None and scope.restricted:
        clause = and_(clause, team_scope.ticket_clause(scope))
    return clause


def _scoped_history(org_id: uuid.UUID, scope=None):
    """Risk history has no team of its own; it inherits its finding's."""
    clause = RiskScoreHistory.organization_id == org_id
    if scope is not None and scope.restricted:
        visible = select(Finding.id).where(_scoped(org_id, scope))
        clause = and_(clause, RiskScoreHistory.finding_id.in_(visible))
    return clause


def _scope_block(scope=None) -> dict:
    """Ships with every dashboard so a partial view can never read as total.

    Two different narrowings land here and the block keeps them apart, because
    the sentence the console prints is not the same one:

    * **restricted** -- the caller's grants do not reach the whole estate. A
      zero means "zero that you may see" and they cannot widen it.
    * **team_filter** -- the caller chose one team from the selector. A zero
      means "zero for that team"; the estate view is one click away.

    Collapsing them would either accuse a full-visibility administrator of
    being restricted, or let a filtered figure pass as an estate figure.
    """
    if scope is None or not scope.restricted:
        return {"restricted": False, "teams": 0}
    block = {"restricted": scope.by_authorization, "teams": len(scope.team_ids),
             "team_ids": sorted(str(t) for t in scope.team_ids),
             "includes_unowned": scope.include_unowned}
    if scope.view_team_id is not None:
        block["team_filter"] = {"team_id": str(scope.view_team_id),
                                "team_name": scope.view_team_name}
    return block


def scope_block(scope=None) -> dict:
    """Public alias: routers that assemble their own payload use this one."""
    return _scope_block(scope)


def _count(session: Session, statement) -> int:
    return int(session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one() or 0)


# ---------------------------------------------------------------------------
# Executive dashboard
# ---------------------------------------------------------------------------
def executive_dashboard(session: Session, org_id: uuid.UUID, *, days: int = 90,
                        scope=None) -> dict:
    base = select(Finding).where(_scoped(org_id, scope))
    open_findings = _open(base)

    total_open = _count(session, open_findings)
    total_assets = _count(
        session, select(Asset).where(_scoped_asset(org_id, scope),
                                     Asset.deleted_at.is_(None))
    )

    by_severity = dict(session.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Finding.severity)
    ).all())
    by_risk_level = dict(session.execute(
        select(Finding.risk_level, func.count(Finding.id))
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Finding.risk_level)
    ).all())

    kev_open = _count(session, open_findings.where(Finding.kev.is_(True)))
    high_epss = _count(session, open_findings.where(Finding.epss_score >= 0.5))
    internet_open = _count(session, _open(
        select(Finding).join(Asset, Finding.asset_id == Asset.id)
        .where(_scoped(org_id, scope), Asset.exposure == "internet")
    ))
    sla_breached = _count(session, open_findings.where(Finding.sla_breached.is_(True)))
    escalated = _count(session, open_findings.where(Finding.escalation_level > 0))

    assets_affected = int(session.execute(
        select(func.count(func.distinct(Finding.asset_id)))
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
    ).scalar_one() or 0)

    average_risk = session.execute(
        select(func.avg(Finding.risk_score))
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)),
               Finding.risk_score.isnot(None))
    ).scalar_one()

    return {
        "generated_at": _now().isoformat(),
        "window_days": days,
        "scope": _scope_block(scope),
        "totals": {
            "open_findings": total_open,
            "assets": total_assets,
            "assets_with_open_findings": assets_affected,
            "asset_coverage_ratio": round(assets_affected / total_assets, 4)
                                    if total_assets else 0.0,
        },
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITY_ORDER},
        "by_risk_level": {level: by_risk_level.get(level, 0) for level in RISK_LEVELS},
        "exploitation": {
            "kev_open": kev_open,
            "high_epss_open": high_epss,
            "internet_facing_open": internet_open,
            # The intersection is the queue an incident responder actually works.
            "kev_and_internet_facing": _count(session, _open(
                select(Finding).join(Asset, Finding.asset_id == Asset.id)
                .where(_scoped(org_id, scope), Finding.kev.is_(True),
                       Asset.exposure == "internet")
            )),
        },
        "sla": {
            "breached_open": sla_breached,
            "escalated_open": escalated,
            "breach_ratio": round(sla_breached / total_open, 4) if total_open else 0.0,
            "sample": total_open,
        },
        "average_risk_score": round(float(average_risk), 2) if average_risk else None,
        "mttr": mttr(session, org_id, days=days, scope=scope),
        "risk_trend": risk_trend(session, org_id, days=days, scope=scope),
        "finding_trend": finding_trend(session, org_id, days=days, scope=scope),
        "top_products": top_products(session, org_id, scope=scope),
        "top_assets": top_assets(session, org_id, scope=scope),
        "top_teams": top_teams(session, org_id, scope=scope),
        "by_environment": by_environment(session, org_id, scope=scope),
    }


def mttr(session: Session, org_id: uuid.UUID, *, days: int = 90, scope=None) -> dict:
    """Mean time to remediate, in hours, over findings closed in the window.

    Measured detected_at -> remediated_at. Findings that were accepted or ruled
    false positives are excluded: counting them would let a team improve its
    MTTR by closing tickets rather than fixing anything.
    """
    since = _now() - dt.timedelta(days=days)
    rows = session.execute(
        select(Finding.detected_at, Finding.remediated_at, Finding.severity)
        .where(_scoped(org_id, scope),
               Finding.remediated_at.isnot(None),
               Finding.remediated_at >= since)
    ).all()

    if not rows:
        return {"hours": None, "sample": 0, "reliable": False, "by_severity": {}}

    def hours(detected, remediated) -> float:
        return max(0.0, (remediated - detected).total_seconds() / 3600)

    values = [hours(d, r) for d, r, _ in rows]
    per_severity: dict[str, list[float]] = {}
    for detected, remediated, severity in rows:
        per_severity.setdefault(severity or "unknown", []).append(hours(detected, remediated))

    return {
        "hours": round(sum(values) / len(values), 1),
        "median_hours": round(sorted(values)[len(values) // 2], 1),
        "sample": len(values),
        "reliable": len(values) >= MIN_MEANINGFUL_SAMPLE,
        "by_severity": {
            severity: {"hours": round(sum(v) / len(v), 1), "sample": len(v)}
            for severity, v in sorted(per_severity.items())
        },
    }


def risk_trend(session: Session, org_id: uuid.UUID, *, days: int = 90, scope=None,
               buckets: int = 12) -> list[dict]:
    """Average recorded risk score over time, from the risk history table."""
    since = _now() - dt.timedelta(days=days)
    rows = session.execute(
        select(RiskScoreHistory.created_at, RiskScoreHistory.risk_score)
        .where(_scoped_history(org_id, scope),
               RiskScoreHistory.created_at >= since)
        .order_by(RiskScoreHistory.created_at)
    ).all()
    return _bucket_average(rows, since, days, buckets)


def finding_trend(session: Session, org_id: uuid.UUID, *, days: int = 90, scope=None,
                  buckets: int = 12) -> list[dict]:
    """New findings detected vs findings remediated, per bucket."""
    since = _now() - dt.timedelta(days=days)
    width = dt.timedelta(days=days / buckets)

    detected = session.execute(
        select(Finding.detected_at).where(_scoped(org_id, scope),
                                          Finding.detected_at >= since)
    ).scalars().all()
    remediated = session.execute(
        select(Finding.remediated_at).where(_scoped(org_id, scope),
                                            Finding.remediated_at.isnot(None),
                                            Finding.remediated_at >= since)
    ).scalars().all()

    out = []
    for index in range(buckets):
        start = since + width * index
        end = start + width
        out.append({
            "from": start.isoformat(),
            "to": end.isoformat(),
            "detected": sum(1 for value in detected if start <= value < end),
            "remediated": sum(1 for value in remediated if start <= value < end),
        })
    return out


def _bucket_average(rows, since: dt.datetime, days: int, buckets: int) -> list[dict]:
    width = dt.timedelta(days=days / buckets)
    out = []
    for index in range(buckets):
        start = since + width * index
        end = start + width
        window = [score for stamp, score in rows if start <= stamp < end and score is not None]
        out.append({
            "from": start.isoformat(),
            "to": end.isoformat(),
            "average_risk": round(sum(window) / len(window), 2) if window else None,
            "sample": len(window),
        })
    return out


def top_products(session: Session, org_id: uuid.UUID, *, limit: int = 10, scope=None) -> list[dict]:
    """Products carrying the most open risk (spec section 8's rollup)."""
    rows = session.execute(
        select(
            Vendor.name, Product.name,
            func.count(Finding.id),
            func.sum(case((Finding.kev.is_(True), 1), else_=0)),
            func.max(Finding.risk_score),
        )
        .select_from(Finding)
        .join(AssetProduct, Finding.asset_product_id == AssetProduct.id)
        .join(Product, AssetProduct.product_id == Product.id)
        .join(Vendor, Product.vendor_id == Vendor.id)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Vendor.name, Product.name)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    ).all()
    return [
        {"vendor": vendor, "product": product, "open_findings": count,
         "kev_findings": int(kev or 0), "max_risk_score": max_risk}
        for vendor, product, count, kev, max_risk in rows
    ]


def top_assets(session: Session, org_id: uuid.UUID, *, limit: int = 10, scope=None) -> list[dict]:
    rows = session.execute(
        select(
            Asset.id, Asset.name, Asset.criticality, Asset.exposure,
            func.count(Finding.id),
            func.max(Finding.risk_score),
            func.sum(case((Finding.kev.is_(True), 1), else_=0)),
        )
        .select_from(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Asset.id, Asset.name, Asset.criticality, Asset.exposure)
        # Ordered by peak risk, not by count: 40 informational findings on a lab
        # box must not outrank one KEV on the payment gateway.
        .order_by(func.max(Finding.risk_score).desc().nullslast())
        .limit(limit)
    ).all()
    return [
        {"asset_id": str(asset_id), "name": name, "criticality": criticality,
         "exposure": exposure, "open_findings": count, "max_risk_score": max_risk,
         "kev_findings": int(kev or 0)}
        for asset_id, name, criticality, exposure, count, max_risk, kev in rows
    ]


def top_teams(session: Session, org_id: uuid.UUID, *, limit: int = 10, scope=None) -> list[dict]:
    rows = session.execute(
        select(
            Team.id, Team.name,
            func.count(Finding.id),
            func.sum(case((Finding.sla_breached.is_(True), 1), else_=0)),
            func.avg(Finding.risk_score),
        )
        .select_from(Finding)
        .join(Team, Finding.assigned_team_id == Team.id)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Team.id, Team.name)
        .order_by(func.count(Finding.id).desc())
        .limit(limit)
    ).all()
    out = []
    for team_id, name, count, breached, average in rows:
        breached = int(breached or 0)
        out.append({
            "team_id": str(team_id), "name": name, "open_findings": count,
            "sla_breached": breached,
            "breach_ratio": round(breached / count, 4) if count else 0.0,
            "average_risk_score": round(float(average), 2) if average else None,
        })
    return out


def by_environment(session: Session, org_id: uuid.UUID, *, scope=None) -> list[dict]:
    rows = session.execute(
        select(
            Asset.environment,
            func.count(Finding.id),
            func.avg(Finding.risk_score),
            func.sum(case((Finding.kev.is_(True), 1), else_=0)),
        )
        .select_from(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Asset.environment)
        .order_by(func.count(Finding.id).desc())
    ).all()
    return [
        {"environment": environment, "open_findings": count,
         "average_risk_score": round(float(average), 2) if average else None,
         "kev_findings": int(kev or 0)}
        for environment, count, average, kev in rows
    ]


# ---------------------------------------------------------------------------
# Technical dashboard
# ---------------------------------------------------------------------------
CVSS_BANDS = ((9.0, "9.0-10.0"), (7.0, "7.0-8.9"), (4.0, "4.0-6.9"),
              (0.1, "0.1-3.9"), (0.0, "0.0"))
EPSS_BANDS = ((0.9, ">=0.90"), (0.5, "0.50-0.89"), (0.1, "0.10-0.49"),
              (0.01, "0.01-0.09"), (0.0, "<0.01"))


def technical_dashboard(session: Session, org_id: uuid.UUID, *, scope=None) -> dict:
    open_findings = session.execute(
        select(Finding.cvss_score, Finding.epss_score, Finding.kev)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
    ).all()

    return {
        "generated_at": _now().isoformat(),
        "sample": len(open_findings),
        "cvss_distribution": _distribute(
            [row[0] for row in open_findings], CVSS_BANDS
        ),
        "epss_distribution": _distribute(
            [row[1] for row in open_findings], EPSS_BANDS
        ),
        "kev": {
            "open": sum(1 for row in open_findings if row[2]),
            "total_open": len(open_findings),
        },
        "scope": _scope_block(scope),
        "top_cwe": top_cwe(session, org_id, scope=scope),
        "exploitability": exploitability(session, org_id, scope=scope),
        "state_breakdown": state_breakdown(session, org_id, scope=scope),
        "scanner_breakdown": scanner_breakdown(session, org_id, scope=scope),
    }


def _distribute(values, bands) -> dict[str, int]:
    out = {label: 0 for _, label in bands}
    out["unscored"] = 0
    for value in values:
        if value is None:
            out["unscored"] += 1
            continue
        for threshold, label in bands:
            if value >= threshold:
                out[label] += 1
                break
    return out


def top_cwe(session: Session, org_id: uuid.UUID, *, limit: int = 10, scope=None) -> list[dict]:
    """CWE rollup. Read from the CVE catalogue, since CWE is a property of the
    weakness class, not of the tenant's copy."""
    rows = session.execute(
        select(Cve.cwe_ids, func.count(Finding.id))
        .select_from(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .join(Cve, Vulnerability.cve_id == Cve.id)
        .where(_scoped(org_id, scope),
               Finding.state.in_(list(OPEN_STATES)))
        .group_by(Cve.cwe_ids)
    ).all()
    tally: dict[str, int] = {}
    for cwe_ids, count in rows:
        for cwe in (cwe_ids or []):
            tally[cwe] = tally.get(cwe, 0) + count
    ranked = sorted(tally.items(), key=lambda kv: -kv[1])[:limit]
    # The name lives in the global dictionary, never in the tenant's data.
    # Without this lookup the UI has a Name column it can only fill with a
    # dash, which is exactly what it did. `display_name` is None until
    # `sync-cwe` has replaced the placeholder row NVD's ids create.
    catalogue = {
        row.id: row.display_name
        for row in session.execute(
            select(Cwe).where(Cwe.id.in_([cwe for cwe, _ in ranked]))
        ).scalars()
    } if ranked else {}
    return [{"cwe": cwe, "name": catalogue.get(cwe), "open_findings": count}
            for cwe, count in ranked]


def exploitability(session: Session, org_id: uuid.UUID, *, scope=None) -> dict:
    statement = select(Finding).where(_scoped(org_id, scope),
                                      Finding.state.in_(list(OPEN_STATES)))
    total = _count(session, statement)
    known_exploited = _count(session, statement.where(Finding.kev.is_(True)))
    likely = _count(session, statement.where(Finding.epss_score >= 0.1))
    return {
        "total_open": total,
        "known_exploited": known_exploited,
        "epss_over_10_percent": likely,
        # The gap between "exploitable in theory" and "exploited in practice" is
        # the single most useful prioritisation number this product produces.
        "theoretical_only": max(0, total - likely),
    }


def state_breakdown(session: Session, org_id: uuid.UUID, *, scope=None) -> dict[str, int]:
    rows = session.execute(
        select(Finding.state, func.count(Finding.id))
        .where(_scoped(org_id, scope))
        .group_by(Finding.state)
    ).all()
    return {state: count for state, count in rows}


def scanner_breakdown(session: Session, org_id: uuid.UUID, *, scope=None) -> list[dict]:
    rows = session.execute(
        select(Finding.scanner, func.count(Finding.id), func.max(Finding.last_seen_at))
        .where(_scoped(org_id, scope))
        .group_by(Finding.scanner)
        .order_by(func.count(Finding.id).desc())
    ).all()
    return [
        {"scanner": scanner or "manual", "findings": count,
         "last_seen_at": last.isoformat() if last else None}
        for scanner, count, last in rows
    ]


# ---------------------------------------------------------------------------
# SLA analytics
# ---------------------------------------------------------------------------
def sla_report(session: Session, org_id: uuid.UUID, *, days: int = 90, scope=None) -> dict:
    since = _now() - dt.timedelta(days=days)
    statement = select(Finding).where(_scoped(org_id, scope),
                                      Finding.sla_due_at.isnot(None))
    total = _count(session, statement)
    breached = _count(session, statement.where(Finding.sla_breached.is_(True)))
    open_breached = _count(session, _open(statement).where(Finding.sla_breached.is_(True)))

    at_risk = _count(session, _open(statement).where(
        Finding.sla_breached.is_(False),
        Finding.sla_due_at <= _now() + dt.timedelta(days=3),
    ))

    by_severity = session.execute(
        select(Finding.severity, func.count(Finding.id),
               func.sum(case((Finding.sla_breached.is_(True), 1), else_=0)))
        .where(_scoped(org_id, scope), Finding.sla_due_at.isnot(None))
        .group_by(Finding.severity)
    ).all()

    return {
        "generated_at": _now().isoformat(),
        "window_days": days,
        "scope": _scope_block(scope),
        "with_sla": total,
        "breached": breached,
        "open_and_breached": open_breached,
        "due_within_3_days": at_risk,
        "compliance_ratio": round((total - breached) / total, 4) if total else None,
        "sample": total,
        "reliable": total >= MIN_MEANINGFUL_SAMPLE,
        "by_severity": [
            {"severity": severity, "with_sla": count, "breached": int(breached_count or 0),
             "compliance_ratio": round((count - int(breached_count or 0)) / count, 4)
                                 if count else None}
            for severity, count, breached_count in by_severity
        ],
    }


def ticket_metrics(session: Session, org_id: uuid.UUID, *, scope=None) -> dict:
    rows = session.execute(
        select(Ticket.ticket_type, Ticket.state, func.count(Ticket.id))
        .where(_scoped_ticket(org_id, scope))
        .group_by(Ticket.ticket_type, Ticket.state)
    ).all()
    out: dict[str, dict[str, int]] = {}
    for ticket_type, state, count in rows:
        out.setdefault(ticket_type, {})[state] = count
    return out
