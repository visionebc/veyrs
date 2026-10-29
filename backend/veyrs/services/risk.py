"""Persistence side of the risk engine: profile resolution and bulk re-scoring.

Kept separate from `engines/risk.py` so the maths stays a pure function that can
be unit-tested and driven by the UI's "what if" simulator without a database.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..engines import risk as engine
from ..models import (
    Asset, BusinessService, Cve, Finding, RiskProfile, RiskScoreHistory, Vulnerability,
)


def seed_profiles(session: Session, organization_id: uuid.UUID) -> int:
    """Create the built-in risk profiles for a tenant. Idempotent."""
    existing = {
        p.slug for p in session.execute(
            select(RiskProfile).where(RiskProfile.organization_id == organization_id)
        ).scalars().all()
    }
    created = 0
    for slug, spec in engine.BUILTIN_PROFILES.items():
        if slug in existing:
            continue
        session.add(RiskProfile(
            organization_id=organization_id, slug=slug, name=spec["name"],
            description=spec["description"], weights=spec["weights"],
            options=spec["options"], is_builtin=True,
            is_default=bool(spec.get("is_default")),
        ))
        created += 1
    session.flush()
    return created


def resolve_profile(
    session: Session, organization_id: uuid.UUID, profile_id: uuid.UUID | None = None
) -> RiskProfile | None:
    """Explicit profile, else the tenant default, else None (engine defaults)."""
    if profile_id is not None:
        profile = session.get(RiskProfile, profile_id)
        if profile is not None and profile.organization_id == organization_id:
            return profile
    return session.execute(
        select(RiskProfile).where(
            RiskProfile.organization_id == organization_id,
            RiskProfile.is_default.is_(True),
        )
    ).scalars().first()


def score_finding(
    session: Session,
    finding: Finding,
    *,
    profile: RiskProfile | None = None,
    record_history: bool = True,
    reason: str | None = None,
) -> engine.RiskResult:
    """Score one finding and write the result back onto the row."""
    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    cve = (
        session.get(Cve, vulnerability.cve_id)
        if vulnerability is not None and vulnerability.cve_id else None
    )
    business_service = (
        session.get(BusinessService, asset.business_service_id)
        if asset is not None and asset.business_service_id else None
    )

    data = engine.input_from_rows(finding, asset, cve, business_service)
    result = engine.evaluate(
        data,
        weights=(profile.weights if profile else None),
        options=(profile.options if profile else None),
        profile_slug=(profile.slug if profile else "balanced"),
    )

    previous = finding.risk_score
    finding.risk_score = result.score
    finding.risk_level = result.level
    finding.technical_risk = result.technical
    finding.exploitability_risk = result.exploitability
    finding.business_risk = result.business
    finding.exposure_risk = result.exposure
    finding.risk_explanation = result.explanation
    finding.risk_profile_id = profile.id if profile else None
    # keep the denormalized intelligence fields in step with what was scored
    if data.epss_score is not None:
        finding.epss_score = data.epss_score
    finding.kev = data.kev
    if data.cvss_score is not None and finding.cvss_score is None:
        finding.cvss_score = data.cvss_score
    if data.cvss_vector and not finding.cvss_vector:
        finding.cvss_vector = data.cvss_vector

    if record_history and (previous is None or abs((previous or 0) - result.score) >= 0.1):
        session.add(RiskScoreHistory(
            organization_id=finding.organization_id, finding_id=finding.id,
            risk_profile_id=profile.id if profile else None,
            risk_score=result.score, risk_level=result.level,
            technical_risk=result.technical, exploitability_risk=result.exploitability,
            business_risk=result.business, exposure_risk=result.exposure,
            reason=reason or ("initial score" if previous is None else "rescored"),
        ))
    return result


def rescore_findings(
    session: Session,
    organization_id: uuid.UUID,
    findings: list[Finding],
    *,
    profile: RiskProfile | None = None,
    reason: str | None = None,
) -> int:
    """Re-score a batch. Returns how many scores actually moved."""
    profile = profile or resolve_profile(session, organization_id)
    changed = 0
    for finding in findings:
        before = finding.risk_score
        result = score_finding(session, finding, profile=profile, reason=reason)
        if before is None or abs(before - result.score) >= 0.1:
            changed += 1
    session.flush()
    return changed


def rollup_vulnerability(session: Session, vulnerability: Vulnerability) -> None:
    """A vulnerability's risk is the worst of its open findings.

    Averaging would hide the one internet-facing box that matters among twenty
    lab machines, which is exactly the failure mode this product exists to fix.
    """
    from ..models import OPEN_STATES

    scores = [
        f.risk_score for f in vulnerability.findings
        if f.state in OPEN_STATES and f.risk_score is not None
    ]
    if scores:
        vulnerability.risk_score = max(scores)
        vulnerability.risk_level = engine.level_for(vulnerability.risk_score)
    session.flush()
