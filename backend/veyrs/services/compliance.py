"""Compliance engine (spec sections 16 and 27).

Three jobs:

1. **Seed and import catalogues** from `data/frameworks.py` or a licensed CSV.
2. **Evidence controls automatically** where VEYRS genuinely holds the answer.
   `AUTOMATED_SIGNALS` is the closed set of computable signals; each returns a
   measurement plus the query that produced it, so an auditor can re-derive it.
3. **Report coverage** -- what is mapped, evidenced, stale or unassessed.

What this engine deliberately does NOT do:

* It never returns "compliant" / "certified". It reports measurements and the
  organization's own claims. A tool that grades your ISO conformance from vuln
  data would be selling a fiction.
* It never fills an unassessed control with a guess. `not_assessed` is a real,
  visible state and it counts against coverage.
* It never treats an automated signal as proof on its own: a signal moves a
  control to `partial` at most. Reaching `implemented` requires a human claim,
  which is what an auditor actually interviews about.
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import io
import uuid
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..data.frameworks import BUILTIN_FRAMEWORKS, CROSSWALK, GUIDANCE
from ..models import Asset, AssetProduct, Finding, OPEN_STATES, ThreatSource, Vulnerability
from ..models.compliance import (
    AssessmentGap, AssessmentStatus, ComplianceAssessment, ComplianceControl,
    ComplianceFramework, ControlImplementation, ControlRiskLink, Evidence, EvidenceKind,
    ImplementationStatus,
)

# ---------------------------------------------------------------------------
# Catalogue seeding
# ---------------------------------------------------------------------------
def seed_frameworks(session: Session) -> dict[str, int]:
    """Install the built-in catalogues. Idempotent; safe to run on every boot.

    Frameworks are GLOBAL rows, so this runs once per database rather than once
    per tenant.
    """
    stats = {"frameworks": 0, "controls": 0, "updated": 0}
    for spec in BUILTIN_FRAMEWORKS:
        framework = session.execute(
            select(ComplianceFramework).where(
                ComplianceFramework.slug == spec["slug"],
                ComplianceFramework.version == spec["version"],
            )
        ).scalar_one_or_none()
        if framework is None:
            framework = ComplianceFramework(
                slug=spec["slug"], name=spec["name"], version=spec["version"],
                publisher=spec["publisher"], description=spec.get("description"),
                source_url=spec.get("source_url"), licence_note=spec.get("licence_note"),
                is_partial=spec.get("is_partial", True), is_builtin=True,
                official_control_count=spec.get("official_control_count"),
            )
            session.add(framework)
            session.flush()
            stats["frameworks"] += 1

        existing = {
            c.ref: c for c in session.execute(
                select(ComplianceControl).where(
                    ComplianceControl.framework_id == framework.id
                )
            ).scalars().all()
        }
        for order, (ref, title, theme, parent, signal) in enumerate(spec["controls"]):
            key = f"{spec['slug']}:{ref}"
            control = existing.get(ref)
            if control is None:
                session.add(ComplianceControl(
                    framework_id=framework.id, ref=ref, title=title, theme=theme,
                    parent_ref=parent, sort_order=order,
                    automation_signal=signal,
                    crosswalk=CROSSWALK.get(key, {}),
                    veyrs_guidance=GUIDANCE.get(key),
                ))
                stats["controls"] += 1
            else:
                # Keep an already-installed catalogue current without clobbering
                # anything a licensed import may have added.
                changed = False
                for field, value in (("title", title), ("theme", theme),
                                     ("parent_ref", parent), ("sort_order", order),
                                     ("automation_signal", signal)):
                    if getattr(control, field) != value:
                        setattr(control, field, value)
                        changed = True
                if CROSSWALK.get(key) and control.crosswalk != CROSSWALK[key]:
                    control.crosswalk = CROSSWALK[key]
                    changed = True
                if changed:
                    stats["updated"] += 1
    session.flush()
    return stats


CSV_REQUIRED = {"ref", "title"}


def import_controls_csv(
    session: Session, framework: ComplianceFramework, payload: bytes
) -> dict[str, Any]:
    """Load a licensed catalogue export.

    Expected columns: ref, title, [normative_text], [theme], [parent_ref].
    When the imported count reaches the publisher's official control count, the
    framework stops being flagged partial -- that flag is derived, never
    hand-set, so it cannot be turned off by wishful configuration.
    """
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = payload.decode("latin-1")
    reader = csv.DictReader(io.StringIO(text))
    headers = {(h or "").strip().lower() for h in (reader.fieldnames or [])}
    missing = CSV_REQUIRED - headers
    if missing:
        raise ValueError(f"CSV is missing required column(s): {sorted(missing)}")

    existing = {
        c.ref: c for c in session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
        ).scalars().all()
    }
    created = updated = 0
    for order, row in enumerate(reader):
        clean = {(k or "").strip().lower(): (v or "").strip() for k, v in row.items()}
        ref = clean.get("ref")
        if not ref:
            continue
        control = existing.get(ref)
        if control is None:
            session.add(ComplianceControl(
                framework_id=framework.id, ref=ref, title=clean.get("title") or ref,
                normative_text=clean.get("normative_text") or None,
                theme=clean.get("theme") or None,
                parent_ref=clean.get("parent_ref") or None,
                sort_order=order,
                crosswalk=CROSSWALK.get(f"{framework.slug}:{ref}", {}),
                veyrs_guidance=GUIDANCE.get(f"{framework.slug}:{ref}"),
            ))
            created += 1
        else:
            control.title = clean.get("title") or control.title
            if clean.get("normative_text"):
                control.normative_text = clean["normative_text"]
            updated += 1
    session.flush()

    total = session.execute(
        select(func.count(ComplianceControl.id)).where(
            ComplianceControl.framework_id == framework.id
        )
    ).scalar_one()
    if framework.official_control_count and total >= framework.official_control_count:
        framework.is_partial = False
    session.flush()
    return {"created": created, "updated": updated, "total": total,
            "is_partial": framework.is_partial}


# ---------------------------------------------------------------------------
# Automated signals
# ---------------------------------------------------------------------------
def _signal_asset_inventory_coverage(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id,
                                           Asset.deleted_at.is_(None))
    ).scalar_one()
    identified = session.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.deleted_at.is_(None),
            Asset.hostname.isnot(None),
        )
    ).scalar_one()
    return _ratio("assets with a hostname recorded", identified, total)


def _signal_product_inventory_coverage(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id,
                                           Asset.deleted_at.is_(None))
    ).scalar_one()
    with_software = session.execute(
        select(func.count(func.distinct(AssetProduct.asset_id)))
        .where(AssetProduct.organization_id == org_id)
    ).scalar_one()
    return _ratio("assets with at least one software product recorded",
                  with_software, total)


def _signal_asset_criticality_assigned(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id,
                                           Asset.deleted_at.is_(None))
    ).scalar_one()
    # "medium" is the column default, so it does not evidence a decision.
    assigned = session.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.deleted_at.is_(None),
            Asset.criticality != "medium",
        )
    ).scalar_one()
    return _ratio("assets with a non-default criticality", assigned, total)


def _signal_asset_classification_assigned(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id,
                                           Asset.deleted_at.is_(None))
    ).scalar_one()
    assigned = session.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.deleted_at.is_(None),
            Asset.data_classification != "internal",
        )
    ).scalar_one()
    return _ratio("assets with a non-default data classification", assigned, total)


def _signal_vulnerabilities_recorded(session: Session, org_id: uuid.UUID) -> dict:
    count = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id)
    ).scalar_one()
    return {"measure": "findings recorded", "value": count, "total": None,
            "ratio": 1.0 if count else 0.0,
            "detail": f"{count} finding(s) recorded against this organization's assets"}


def _signal_risk_scoring_active(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id)
    ).scalar_one()
    scored = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id,
                                             Finding.risk_score.isnot(None))
    ).scalar_one()
    return _ratio("findings carrying a computed VEYRS risk score", scored, total)


def _signal_findings_have_owners(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id,
                                             Finding.state.in_(list(OPEN_STATES)))
    ).scalar_one()
    owned = session.execute(
        select(func.count(Finding.id)).where(
            Finding.organization_id == org_id,
            Finding.state.in_(list(OPEN_STATES)),
            Finding.assigned_team_id.isnot(None),
        )
    ).scalar_one()
    return _ratio("open findings with an owning team", owned, total)


def _signal_remediation_within_sla(session: Session, org_id: uuid.UUID) -> dict:
    total = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id,
                                             Finding.sla_due_at.isnot(None))
    ).scalar_one()
    breached = session.execute(
        select(func.count(Finding.id)).where(Finding.organization_id == org_id,
                                             Finding.sla_breached.is_(True))
    ).scalar_one()
    return _ratio("findings inside their SLA", total - breached, total)


def _signal_no_overdue_kev(session: Session, org_id: uuid.UUID) -> dict:
    overdue = session.execute(
        select(func.count(Finding.id)).where(
            Finding.organization_id == org_id, Finding.kev.is_(True),
            Finding.state.in_(list(OPEN_STATES)), Finding.sla_breached.is_(True),
        )
    ).scalar_one()
    return {"measure": "open CISA KEV findings past SLA", "value": overdue,
            "total": None, "ratio": 0.0 if overdue else 1.0,
            "detail": f"{overdue} known-exploited finding(s) are open and past SLA"}


def _signal_scan_recency(session: Session, org_id: uuid.UUID, days: int = 30) -> dict:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    total = session.execute(
        select(func.count(Asset.id)).where(Asset.organization_id == org_id,
                                           Asset.deleted_at.is_(None))
    ).scalar_one()
    recent = session.execute(
        select(func.count(func.distinct(Finding.asset_id))).where(
            Finding.organization_id == org_id, Finding.last_seen_at >= cutoff
        )
    ).scalar_one()
    return _ratio(f"assets observed by a scan in the last {days} days", recent, total)


def _signal_internet_asset_scan_recency(session: Session, org_id: uuid.UUID,
                                        days: int = 30) -> dict:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    total = session.execute(
        select(func.count(Asset.id)).where(
            Asset.organization_id == org_id, Asset.deleted_at.is_(None),
            Asset.exposure == "internet",
        )
    ).scalar_one()
    recent = session.execute(
        select(func.count(func.distinct(Finding.asset_id)))
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.organization_id == org_id, Asset.exposure == "internet",
               Finding.last_seen_at >= cutoff)
    ).scalar_one()
    return _ratio(f"internet-facing assets observed in the last {days} days",
                  recent, total)


def _signal_threat_feeds_active(session: Session, org_id: uuid.UUID) -> dict:
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=7)
    total = session.execute(
        select(func.count(ThreatSource.id)).where(
            ThreatSource.organization_id == org_id, ThreatSource.is_enabled.is_(True)
        )
    ).scalar_one()
    polled = session.execute(
        select(func.count(ThreatSource.id)).where(
            ThreatSource.organization_id == org_id, ThreatSource.is_enabled.is_(True),
            ThreatSource.last_polled_at >= cutoff,
        )
    ).scalar_one()
    return _ratio("enabled threat sources polled in the last 7 days", polled, total)


def _ratio(measure: str, value: int, total: int) -> dict:
    ratio = (value / total) if total else 0.0
    return {"measure": measure, "value": value, "total": total,
            "ratio": round(ratio, 4),
            "detail": f"{value} of {total} {measure}" if total
                      else f"no applicable records ({measure})"}


#: Closed registry. A control's `automation_signal` must name a key here or the
#: control simply has no automated evidence -- there is no dynamic dispatch.
AUTOMATED_SIGNALS: dict[str, Callable[[Session, uuid.UUID], dict]] = {
    "asset_inventory_coverage": _signal_asset_inventory_coverage,
    "product_inventory_coverage": _signal_product_inventory_coverage,
    "asset_criticality_assigned": _signal_asset_criticality_assigned,
    "asset_classification_assigned": _signal_asset_classification_assigned,
    "vulnerabilities_recorded": _signal_vulnerabilities_recorded,
    "risk_scoring_active": _signal_risk_scoring_active,
    "findings_have_owners": _signal_findings_have_owners,
    "remediation_within_sla": _signal_remediation_within_sla,
    "no_overdue_kev": _signal_no_overdue_kev,
    "scan_recency": _signal_scan_recency,
    "internet_asset_scan_recency": _signal_internet_asset_scan_recency,
    "threat_feeds_active": _signal_threat_feeds_active,
}

#: A signal at or above this ratio is considered supporting evidence.
SIGNAL_PASS_RATIO = 0.9


def evaluate_signal(session: Session, org_id: uuid.UUID, signal: str) -> dict | None:
    handler = AUTOMATED_SIGNALS.get(signal)
    if handler is None:
        return None
    result = handler(session, org_id)
    result["signal"] = signal
    result["passing"] = result["ratio"] >= SIGNAL_PASS_RATIO
    result["evaluated_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    return result


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------
def get_or_create_implementation(
    session: Session, org_id: uuid.UUID, control: ComplianceControl
) -> ControlImplementation:
    implementation = session.execute(
        select(ControlImplementation).where(
            ControlImplementation.organization_id == org_id,
            ControlImplementation.control_id == control.id,
        )
    ).scalar_one_or_none()
    if implementation is None:
        implementation = ControlImplementation(
            organization_id=org_id, control_id=control.id,
            status=ImplementationStatus.NOT_ASSESSED.value,
            review_period_days=365,
        )
        session.add(implementation)
        session.flush()
    return implementation


def set_status(
    session: Session,
    implementation: ControlImplementation,
    status: str,
    *,
    statement: str | None = None,
    justification: str | None = None,
    review_period_days: int | None = None,
    actor_id: uuid.UUID | None = None,
) -> ControlImplementation:
    valid = {s.value for s in ImplementationStatus}
    if status not in valid:
        raise ValueError(f"unknown implementation status {status!r}")
    if status == ImplementationStatus.NOT_APPLICABLE.value and not (
        justification or implementation.justification
    ):
        # An unjustified N/A is the single most common audit finding in a
        # control set. Refusing it here is cheaper than explaining it later.
        raise ValueError("not_applicable requires a justification")

    implementation.status = status
    if statement is not None:
        implementation.statement = statement
    if justification is not None:
        implementation.justification = justification
    if review_period_days is not None:
        implementation.review_period_days = review_period_days

    now = dt.datetime.now(dt.timezone.utc)
    implementation.last_reviewed_at = now
    implementation.next_review_at = (
        now + dt.timedelta(days=implementation.review_period_days)
        if implementation.review_period_days else None
    )
    session.flush()
    return implementation


def refresh_automated_evidence(
    session: Session, org_id: uuid.UUID, framework_id: uuid.UUID | None = None
) -> dict[str, Any]:
    """Recompute every automated signal and record the result as evidence.

    A passing signal can lift `not_assessed` to `partial`, never to
    `implemented`: a measurement shows the machinery runs, not that the control
    is designed, owned and operating. Human claims are still required, and that
    boundary is what keeps this defensible in an audit.
    """
    statement = select(ComplianceControl).where(
        ComplianceControl.automation_signal.isnot(None)
    )
    if framework_id is not None:
        statement = statement.where(ComplianceControl.framework_id == framework_id)

    evaluated = 0
    promoted = 0
    for control in session.execute(statement).scalars().all():
        result = evaluate_signal(session, org_id, control.automation_signal)
        if result is None:
            continue
        implementation = get_or_create_implementation(session, org_id, control)
        implementation.automated_result = result
        evaluated += 1

        session.add(Evidence(
            organization_id=org_id, implementation_id=implementation.id,
            kind=EvidenceKind.AUTOMATED.value,
            title=f"Automated signal: {control.automation_signal}",
            summary=result["detail"],
            payload=result, is_automated=True,
            collected_at=dt.datetime.now(dt.timezone.utc),
            content_hash=hashlib.sha256(
                repr(sorted(result.items())).encode()
            ).hexdigest(),
        ))

        if result["passing"] and implementation.status == \
                ImplementationStatus.NOT_ASSESSED.value:
            implementation.status = ImplementationStatus.PARTIAL.value
            promoted += 1

    session.flush()
    return {"evaluated": evaluated, "promoted_to_partial": promoted}


def mark_stale_implementations(session: Session, org_id: uuid.UUID) -> int:
    """Move implemented-but-overdue controls to `stale`.

    Silence is not evidence: a control reviewed three years ago is not in the
    same state as one reviewed last month, and a dashboard that shows both as
    green is lying to its owner.
    """
    now = dt.datetime.now(dt.timezone.utc)
    rows = session.execute(
        select(ControlImplementation).where(
            ControlImplementation.organization_id == org_id,
            ControlImplementation.status == ImplementationStatus.IMPLEMENTED.value,
            ControlImplementation.next_review_at.isnot(None),
            ControlImplementation.next_review_at < now,
        )
    ).scalars().all()
    for implementation in rows:
        implementation.status = ImplementationStatus.STALE.value
    session.flush()
    return len(rows)


# ---------------------------------------------------------------------------
# Coverage reporting
# ---------------------------------------------------------------------------
def coverage(session: Session, org_id: uuid.UUID, framework: ComplianceFramework) -> dict:
    """Honest coverage report for one framework."""
    controls = session.execute(
        select(ComplianceControl)
        .where(ComplianceControl.framework_id == framework.id)
        .order_by(ComplianceControl.sort_order)
    ).scalars().all()
    implementations = {
        i.control_id: i for i in session.execute(
            select(ControlImplementation).where(
                ControlImplementation.organization_id == org_id
            )
        ).scalars().all()
    }

    buckets: dict[str, int] = {s.value: 0 for s in ImplementationStatus}
    evidenced = 0
    rows = []
    for control in controls:
        implementation = implementations.get(control.id)
        status = implementation.status if implementation \
            else ImplementationStatus.NOT_ASSESSED.value
        buckets[status] = buckets.get(status, 0) + 1
        evidence_count = 0
        if implementation is not None:
            evidence_count = session.execute(
                select(func.count(Evidence.id)).where(
                    Evidence.implementation_id == implementation.id
                )
            ).scalar_one()
            if evidence_count:
                evidenced += 1
        rows.append({
            "control_id": str(control.id),
            "ref": control.ref,
            "title": control.title,
            "theme": control.theme,
            "status": status,
            "evidence_count": evidence_count,
            "automation_signal": control.automation_signal,
            "automated_result": implementation.automated_result if implementation else {},
            "is_stale": implementation.is_stale if implementation else False,
            "next_review_at": implementation.next_review_at.isoformat()
                              if implementation and implementation.next_review_at else None,
        })

    shipped = len(controls)
    applicable = shipped - buckets.get(ImplementationStatus.NOT_APPLICABLE.value, 0)
    implemented = buckets.get(ImplementationStatus.IMPLEMENTED.value, 0)

    return {
        "framework": {
            "id": str(framework.id), "slug": framework.slug, "name": framework.name,
            "version": framework.version, "publisher": framework.publisher,
            "source_url": framework.source_url,
            "licence_note": framework.licence_note,
            "is_partial": framework.is_partial,
            "controls_shipped": shipped,
            "official_control_count": framework.official_control_count,
            "disclaimer": framework.coverage_disclaimer,
        },
        "counts": buckets,
        "applicable_controls": applicable,
        "implemented": implemented,
        # Ratio over the SHIPPED catalogue. When the catalogue is partial this
        # is explicitly not a conformance figure, and the disclaimer says so.
        "implemented_ratio": round(implemented / applicable, 4) if applicable else 0.0,
        "evidenced_controls": evidenced,
        "controls": rows,
    }


def link_object(
    session: Session, org_id: uuid.UUID, control: ComplianceControl,
    object_type: str, object_id: str, *, rationale: str | None = None,
    actor_id: uuid.UUID | None = None, automatic: bool = False,
    confidence: float = 1.0,
) -> ControlRiskLink:
    existing = session.execute(
        select(ControlRiskLink).where(
            ControlRiskLink.organization_id == org_id,
            ControlRiskLink.control_id == control.id,
            ControlRiskLink.object_type == object_type,
            ControlRiskLink.object_id == str(object_id),
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing
    link = ControlRiskLink(
        organization_id=org_id, control_id=control.id, object_type=object_type,
        object_id=str(object_id), rationale=rationale, linked_by_id=actor_id,
        is_automatic=automatic, confidence=confidence,
    )
    session.add(link)
    session.flush()
    return link


def control_chain(session: Session, org_id: uuid.UUID, control_id: uuid.UUID) -> dict:
    """Walk the spec's chain: Control -> linked objects -> risk -> evidence.

    This is the query an auditor actually asks: "show me, for control A.8.8,
    which systems it covers, what is currently wrong with them, and what you did
    about it."
    """
    control = session.get(ComplianceControl, control_id)
    if control is None:
        return {}
    links = session.execute(
        select(ControlRiskLink).where(
            ControlRiskLink.organization_id == org_id,
            ControlRiskLink.control_id == control_id,
        )
    ).scalars().all()

    assets, findings, tickets = [], [], []
    for link in links:
        if link.object_type == "asset":
            asset = session.get(Asset, uuid.UUID(link.object_id))
            if asset is not None:
                assets.append({"id": str(asset.id), "name": asset.name,
                               "criticality": asset.criticality,
                               "exposure": asset.exposure})
        elif link.object_type == "finding":
            finding = session.get(Finding, uuid.UUID(link.object_id))
            if finding is not None:
                findings.append({"id": str(finding.id), "title": finding.title,
                                 "state": finding.state,
                                 "risk_score": finding.risk_score,
                                 "sla_breached": finding.sla_breached})
        elif link.object_type == "ticket":
            tickets.append({"id": link.object_id})

    implementation = session.execute(
        select(ControlImplementation).where(
            ControlImplementation.organization_id == org_id,
            ControlImplementation.control_id == control_id,
        )
    ).scalar_one_or_none()
    evidence = session.execute(
        select(Evidence)
        .where(Evidence.organization_id == org_id,
               Evidence.implementation_id == (implementation.id if implementation else None))
        .order_by(Evidence.collected_at.desc())
        .limit(50)
    ).scalars().all() if implementation else []

    return {
        "control": {"id": str(control.id), "ref": control.ref, "title": control.title,
                    "veyrs_guidance": control.veyrs_guidance,
                    "crosswalk": control.crosswalk},
        "implementation": {
            "status": implementation.status if implementation else "not_assessed",
            "statement": implementation.statement if implementation else None,
            "is_stale": implementation.is_stale if implementation else False,
            "automated_result": implementation.automated_result if implementation else {},
        },
        "assets": assets,
        "findings": findings,
        "tickets": tickets,
        "evidence": [
            {"id": str(e.id), "kind": e.kind, "title": e.title,
             "collected_at": e.collected_at.isoformat(),
             "is_automated": e.is_automated, "is_expired": e.is_expired}
            for e in evidence
        ],
    }


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------
def complete_assessment(
    session: Session, assessment: ComplianceAssessment, *, summary: str | None = None
) -> ComplianceAssessment:
    """Freeze the current control positions onto the assessment.

    The snapshot is stored, not recomputed on read. An audit record that changes
    when the underlying data changes is not an audit record.
    """
    framework = session.get(ComplianceFramework, assessment.framework_id)
    report = coverage(session, assessment.organization_id, framework)
    assessment.snapshot = report
    assessment.status = AssessmentStatus.COMPLETE.value
    assessment.completed_on = dt.date.today()
    if summary is not None:
        assessment.summary = summary

    # Any control that is not implemented and not justified N/A is a gap. This
    # is generated, not typed, so no non-conformity gets forgotten.
    existing_refs = {
        gap.control_id for gap in session.execute(
            select(AssessmentGap).where(AssessmentGap.assessment_id == assessment.id)
        ).scalars().all()
    }
    for row in report["controls"]:
        if row["status"] in (ImplementationStatus.IMPLEMENTED.value,
                             ImplementationStatus.NOT_APPLICABLE.value):
            continue
        control_id = uuid.UUID(row["control_id"])
        if control_id in existing_refs:
            continue
        session.add(AssessmentGap(
            organization_id=assessment.organization_id, assessment_id=assessment.id,
            control_id=control_id,
            severity="high" if row["status"] == ImplementationStatus.NOT_ASSESSED.value
                     else "medium",
            title=f"{row['ref']} {row['title']}",
            detail=f"Status at assessment: {row['status']}"
                   + (" (evidence is stale)" if row["is_stale"] else ""),
        ))
    session.flush()
    return assessment
