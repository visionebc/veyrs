"""VEYRS Risk Engine.

The product thesis in one module: CVSS is *severity*, not *risk*. This engine
combines severity with exploitation likelihood, business context and exposure to
produce a number you can defend in a steering committee.

Four sub-scores, each 0-100, then a weighted overall score:

  Technical Risk      - how bad is the flaw itself (CVSS, latest revision wins)
  Exploitability Risk - how likely is it to be used (EPSS, KEV, exploit maturity,
                        exposure duration)
  Business Risk       - what does it threaten (asset criticality, data
                        classification, business-service revenue, environment)
  Exposure Risk       - how reachable is it (internet exposure, attack vector,
                        privileges/UI required, compensating controls)

Overall = weighted mean of the four, then policy adjustments:
  * `kev_floor`  - a CISA KEV vulnerability can never score below this. Known
                   exploitation is a fact, not a probability.
  * `internet_kev_floor` - internet-facing AND KEV: higher floor still.
  * `age_penalty` - a finding that has sat open past its SLA accrues risk;
                    ignoring something does not make it safer.
  * `control_credit` - documented compensating controls reduce Exposure Risk
                    only, never Technical Risk. A WAF does not unpatch a bug.

Every score carries an `explanation` dict listing each contributing factor with
its raw value, weight and points, so the UI can answer "why is this critical?"
without re-implementing the maths.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from ..models.assets import (
    CLASSIFICATION_WEIGHT, CRITICALITY_WEIGHT, ENVIRONMENT_WEIGHT, EXPOSURE_WEIGHT,
)

# --- risk levels -----------------------------------------------------------

LEVEL_BANDS = (
    (90.0, "critical"),
    (70.0, "high"),
    (40.0, "medium"),
    (10.0, "low"),
    (0.0, "informational"),
)


def level_for(score: float) -> str:
    for threshold, label in LEVEL_BANDS:
        if score >= threshold:
            return label
    return "informational"


# --- default profile -------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, float] = {
    "technical": 0.30,
    "exploitability": 0.30,
    "business": 0.25,
    "exposure": 0.15,
}

DEFAULT_OPTIONS: dict[str, Any] = {
    "kev_floor": 75.0,
    "internet_kev_floor": 90.0,
    "active_exploitation_floor": 80.0,
    "age_penalty_per_30d": 3.0,
    "age_penalty_cap": 15.0,
    "epss_high_threshold": 0.5,
    "control_credit_cap": 0.5,
    "zero_cvss_is_informational": True,
}

#: How much each documented compensating control reduces Exposure Risk.
#: Conservative on purpose - controls mitigate, they do not remediate.
CONTROL_CREDIT: dict[str, float] = {
    "waf": 0.20,
    "ips": 0.15,
    "edr": 0.15,
    "network_segmentation": 0.25,
    "mfa": 0.10,
    "not_reachable": 0.40,
    "vendor_mitigation_applied": 0.30,
    "config_workaround": 0.25,
}

#: Built-in profiles from spec section 6. Tenants may add their own; these are
#: seeded so a fresh install produces sensible numbers immediately.
BUILTIN_PROFILES: dict[str, dict] = {
    "balanced": {
        "name": "Balanced (default)",
        "description": "Even weighting across technical severity, exploitation "
                       "likelihood, business impact and exposure.",
        "weights": DEFAULT_WEIGHTS,
        "options": DEFAULT_OPTIONS,
        "is_default": True,
    },
    "technical-security": {
        "name": "Technical Security",
        "description": "Prioritises CVSS severity and exploitability. For engineering "
                       "queues where business context is handled elsewhere.",
        "weights": {"technical": 0.45, "exploitability": 0.35, "business": 0.10,
                    "exposure": 0.10},
        "options": {**DEFAULT_OPTIONS, "kev_floor": 70.0},
    },
    "executive-risk": {
        "name": "Executive Risk",
        "description": "Prioritises business criticality, exposure, KEV and EPSS. "
                       "The view a CISO reports upward.",
        "weights": {"technical": 0.15, "exploitability": 0.25, "business": 0.40,
                    "exposure": 0.20},
        "options": {**DEFAULT_OPTIONS, "kev_floor": 80.0, "internet_kev_floor": 95.0},
    },
    "internet-exposure": {
        "name": "Internet Exposure",
        "description": "Ruthlessly favours internet-facing assets with known "
                       "exploitation or high EPSS.",
        "weights": {"technical": 0.20, "exploitability": 0.35, "business": 0.15,
                    "exposure": 0.30},
        "options": {**DEFAULT_OPTIONS, "internet_kev_floor": 98.0,
                    "epss_high_threshold": 0.3},
    },
    "compliance": {
        "name": "Compliance",
        "description": "Weights regulatory exposure: data classification, SLA age "
                       "and KEV due dates dominate.",
        "weights": {"technical": 0.20, "exploitability": 0.20, "business": 0.45,
                    "exposure": 0.15},
        "options": {**DEFAULT_OPTIONS, "age_penalty_per_30d": 6.0,
                    "age_penalty_cap": 30.0},
    },
}


# --- inputs ----------------------------------------------------------------


@dataclass
class RiskInput:
    """Everything the engine is allowed to look at. No DB access in here.

    Keeping this a plain dataclass means the engine is trivially testable and
    can be reused by the "what if" simulator in the UI without touching rows.
    """

    # technical
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_attack_vector: str | None = None       # N | A | L | P
    cvss_privileges_required: str | None = None  # N | L | H
    cvss_user_interaction: str | None = None     # N | R | P | A
    # exploitation likelihood
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    kev_due_date: dt.date | None = None
    exploit_known: bool = False
    exploit_maturity: str | None = None          # A | P | U (CVSS v4 E metric)
    active_exploitation: bool = False
    # business context
    asset_criticality: str = "medium"
    data_classification: str = "internal"
    environment: str = "production"
    business_service_criticality: str | None = None
    revenue_per_hour: int | None = None
    # exposure
    exposure: str = "internal"
    compensating_controls: list[str] = field(default_factory=list)
    # temporal
    detected_at: dt.datetime | None = None
    sla_due_at: dt.datetime | None = None
    vulnerability_age_days: int | None = None
    now: dt.datetime | None = None

    def clock(self) -> dt.datetime:
        return self.now or dt.datetime.now(dt.timezone.utc)


@dataclass
class RiskResult:
    score: float
    level: str
    technical: float
    exploitability: float
    business: float
    exposure: float
    profile_slug: str
    explanation: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.score,
            "risk_level": self.level,
            "technical_risk": self.technical,
            "exploitability_risk": self.exploitability,
            "business_risk": self.business,
            "exposure_risk": self.exposure,
            "risk_profile": self.profile_slug,
            "explanation": self.explanation,
        }


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


# --- sub-scores ------------------------------------------------------------


def technical_risk(data: RiskInput, factors: list[dict]) -> float:
    """CVSS severity, normalized to 0-100. Absent CVSS is NOT treated as zero."""
    if data.cvss_score is None:
        # An unscored finding is unknown, not harmless. 40 = medium, so it
        # surfaces for triage instead of sinking to the bottom of the queue.
        factors.append({"factor": "cvss", "value": None, "points": 40.0,
                        "note": "no CVSS available - defaulted to medium pending triage"})
        return 40.0
    points = data.cvss_score * 10.0
    factors.append({"factor": "cvss", "value": data.cvss_score,
                    "version": data.cvss_version, "points": round(points, 2)})
    return _clamp(points)


def exploitability_risk(data: RiskInput, options: dict, factors: list[dict]) -> float:
    """How likely is this to actually be exploited."""
    score = 0.0

    if data.epss_score is not None:
        # EPSS is a probability over the next 30 days. Its distribution is
        # extremely skewed (most CVEs < 0.01), so a linear map would make almost
        # everything look safe. sqrt spreads the low end without inventing risk.
        epss_points = (data.epss_score ** 0.5) * 60.0
        score += epss_points
        factors.append({"factor": "epss", "value": data.epss_score,
                        "percentile": data.epss_percentile,
                        "points": round(epss_points, 2),
                        "note": "sqrt-scaled: EPSS is heavily skewed toward zero"})
    else:
        factors.append({"factor": "epss", "value": None, "points": 0.0,
                        "note": "no EPSS record (CVE too new, or not a CVE)"})

    if data.kev:
        score += 30.0
        note = "listed in the CISA KEV catalogue - exploitation is observed, not predicted"
        if data.kev_due_date:
            days = (data.kev_due_date - dt.date.today()).days
            note += f"; remediation due in {days} days" if days >= 0 else \
                    f"; CISA due date passed {abs(days)} days ago"
        factors.append({"factor": "cisa_kev", "value": True, "points": 30.0, "note": note})

    if data.active_exploitation:
        score += 15.0
        factors.append({"factor": "active_exploitation", "value": True, "points": 15.0})
    elif data.exploit_known or data.exploit_maturity == "A":
        score += 10.0
        factors.append({"factor": "exploit_available", "value": True, "points": 10.0,
                        "maturity": data.exploit_maturity})
    elif data.exploit_maturity == "P":
        score += 5.0
        factors.append({"factor": "exploit_proof_of_concept", "value": True, "points": 5.0})

    return _clamp(score)


def business_risk(data: RiskInput, factors: list[dict]) -> float:
    """What the vulnerability threatens, in the organization's own terms."""
    criticality = CRITICALITY_WEIGHT.get(data.asset_criticality, 0.5)
    classification = CLASSIFICATION_WEIGHT.get(data.data_classification, 0.5)
    environment = ENVIRONMENT_WEIGHT.get(data.environment, 0.5)

    # asset criticality dominates; classification and environment modulate it
    score = (criticality * 55.0) + (classification * 25.0) + (environment * 10.0)
    factors.append({"factor": "asset_criticality", "value": data.asset_criticality,
                    "weight": criticality, "points": round(criticality * 55.0, 2)})
    factors.append({"factor": "data_classification", "value": data.data_classification,
                    "weight": classification, "points": round(classification * 25.0, 2)})
    factors.append({"factor": "environment", "value": data.environment,
                    "weight": environment, "points": round(environment * 10.0, 2)})

    if data.business_service_criticality:
        service = CRITICALITY_WEIGHT.get(data.business_service_criticality, 0.5)
        # take the more severe of asset vs service criticality, then add a bonus
        bonus = max(0.0, (service - criticality)) * 10.0
        score += bonus
        factors.append({"factor": "business_service_criticality",
                        "value": data.business_service_criticality,
                        "points": round(bonus, 2),
                        "note": "service criticality exceeds the asset's own rating"})

    if data.revenue_per_hour:
        # log-ish bands rather than a linear scale: 10k/h and 100k/h are both
        # "very expensive", and a linear map would let one asset dwarf the estate
        bands = [(100_000, 10.0), (10_000, 7.0), (1_000, 4.0), (100, 2.0)]
        bonus = next((points for limit, points in bands if data.revenue_per_hour >= limit), 0.0)
        score += bonus
        factors.append({"factor": "revenue_per_hour", "value": data.revenue_per_hour,
                        "points": bonus})

    return _clamp(score)


def exposure_risk(data: RiskInput, options: dict, factors: list[dict]) -> float:
    """How reachable the flaw is, net of documented compensating controls."""
    exposure_weight = EXPOSURE_WEIGHT.get(data.exposure, 0.4)
    score = exposure_weight * 60.0
    factors.append({"factor": "exposure", "value": data.exposure,
                    "weight": exposure_weight, "points": round(score, 2)})

    vector_points = {"N": 25.0, "A": 15.0, "L": 8.0, "P": 2.0}
    if data.cvss_attack_vector in vector_points:
        points = vector_points[data.cvss_attack_vector]
        score += points
        factors.append({"factor": "attack_vector", "value": data.cvss_attack_vector,
                        "points": points})

    # no privileges and no interaction required = a scanner-driven mass exploit
    if data.cvss_privileges_required == "N" and data.cvss_user_interaction in ("N", None):
        score += 15.0
        factors.append({"factor": "unauthenticated_no_interaction", "value": True,
                        "points": 15.0,
                        "note": "exploitable without credentials or a victim action"})

    score = _clamp(score)

    credit = 0.0
    applied: list[str] = []
    for control in data.compensating_controls or []:
        key = str(control).strip().lower().replace("-", "_").replace(" ", "_")
        if key in CONTROL_CREDIT:
            credit += CONTROL_CREDIT[key]
            applied.append(key)
    if credit:
        credit = min(credit, float(options.get("control_credit_cap", 0.5)))
        reduction = score * credit
        score -= reduction
        factors.append({"factor": "compensating_controls", "value": applied,
                        "credit": round(credit, 3), "points": -round(reduction, 2),
                        "note": "reduces exposure only - the flaw itself is unchanged"})

    return _clamp(score)


# --- overall ---------------------------------------------------------------


def evaluate(
    data: RiskInput,
    *,
    weights: dict[str, float] | None = None,
    options: dict[str, Any] | None = None,
    profile_slug: str = "balanced",
) -> RiskResult:
    """Score one finding. Pure function - safe to call from anywhere."""
    weights = {**DEFAULT_WEIGHTS, **(weights or {})}
    options = {**DEFAULT_OPTIONS, **(options or {})}

    explanation: dict[str, Any] = {
        "profile": profile_slug,
        "weights": weights,
        "technical": [], "exploitability": [], "business": [], "exposure": [],
        "adjustments": [], "summary": "",
    }

    technical = technical_risk(data, explanation["technical"])
    exploitability = exploitability_risk(data, options, explanation["exploitability"])
    business = business_risk(data, explanation["business"])
    exposure = exposure_risk(data, options, explanation["exposure"])

    total_weight = sum(weights.get(k, 0.0) for k in
                       ("technical", "exploitability", "business", "exposure")) or 1.0
    score = (
        technical * weights.get("technical", 0.0)
        + exploitability * weights.get("exploitability", 0.0)
        + business * weights.get("business", 0.0)
        + exposure * weights.get("exposure", 0.0)
    ) / total_weight

    base_score = score

    # --- policy floors: facts override arithmetic
    if data.kev:
        floor = float(
            options["internet_kev_floor"] if data.exposure == "internet"
            else options["kev_floor"]
        )
        if score < floor:
            explanation["adjustments"].append({
                "rule": "internet_kev_floor" if data.exposure == "internet" else "kev_floor",
                "from": round(score, 2), "to": floor,
                "note": ("known-exploited vulnerability on an internet-facing asset"
                         if data.exposure == "internet"
                         else "known-exploited vulnerability (CISA KEV)"),
            })
            score = floor

    if data.active_exploitation:
        floor = float(options["active_exploitation_floor"])
        if score < floor:
            explanation["adjustments"].append({
                "rule": "active_exploitation_floor",
                "from": round(score, 2), "to": floor,
                "note": "active exploitation reported against this organization's estate",
            })
            score = floor

    # --- age penalty: an ignored finding is a growing risk
    age_days = None
    if data.detected_at is not None:
        age_days = max(0, (data.clock() - data.detected_at).days)
    elif data.vulnerability_age_days is not None:
        age_days = data.vulnerability_age_days
    if age_days:
        overdue = data.sla_due_at is not None and data.clock() > data.sla_due_at
        # only penalise beyond 30 days, and double the rate once SLA is breached
        blocks = age_days // 30
        if blocks:
            rate = float(options["age_penalty_per_30d"]) * (2.0 if overdue else 1.0)
            penalty = min(blocks * rate, float(options["age_penalty_cap"]))
            if penalty:
                explanation["adjustments"].append({
                    "rule": "age_penalty", "age_days": age_days,
                    "sla_breached": overdue, "points": round(penalty, 2),
                    "note": ("open past its SLA deadline - penalty doubled" if overdue
                             else "open longer than 30 days"),
                })
                score += penalty

    # --- informational shortcut
    if options.get("zero_cvss_is_informational") and data.cvss_score == 0.0 \
            and not data.kev and not data.active_exploitation:
        explanation["adjustments"].append({
            "rule": "zero_cvss_is_informational", "from": round(score, 2), "to": 0.0,
            "note": "CVSS 0.0 with no exploitation signal",
        })
        score = 0.0

    score = round(_clamp(score), 1)
    result_level = level_for(score)

    drivers = _top_drivers(explanation)
    explanation["base_score"] = round(base_score, 2)
    explanation["final_score"] = score
    explanation["level"] = result_level
    explanation["summary"] = _summarize(data, score, result_level, drivers)
    explanation["drivers"] = drivers

    return RiskResult(
        score=score, level=result_level,
        technical=round(technical, 1), exploitability=round(exploitability, 1),
        business=round(business, 1), exposure=round(exposure, 1),
        profile_slug=profile_slug, explanation=explanation,
    )


def _top_drivers(explanation: dict, limit: int = 4) -> list[str]:
    scored: list[tuple[float, str]] = []
    for group in ("technical", "exploitability", "business", "exposure"):
        for factor in explanation[group]:
            points = factor.get("points") or 0.0
            if points > 0:
                scored.append((points, f"{factor['factor']}={factor.get('value')}"))
    for adjustment in explanation["adjustments"]:
        scored.append((100.0, adjustment["rule"]))  # floors always lead
    scored.sort(key=lambda item: item[0], reverse=True)
    return [label for _, label in scored[:limit]]


def _summarize(data: RiskInput, score: float, level: str, drivers: list[str]) -> str:
    parts = [f"VEYRS risk {score} ({level})."]
    if data.cvss_score is not None:
        parts.append(f"CVSS {data.cvss_score}")
    if data.epss_score is not None:
        parts.append(f"EPSS {data.epss_score:.1%}")
    if data.kev:
        parts.append("CISA KEV")
    if data.exposure == "internet":
        parts.append("internet-facing")
    parts.append(f"asset criticality {data.asset_criticality}")
    head = " · ".join(parts)
    return f"{head}. Leading factors: {', '.join(drivers)}." if drivers else head


# --- persistence-facing helpers -------------------------------------------


def input_from_rows(finding, asset, cve=None, business_service=None, now=None) -> RiskInput:
    """Build a RiskInput from ORM rows without importing the ORM into the maths."""
    vector_metrics: dict[str, str] = {}
    vector = (finding.cvss_vector if finding is not None else None) or (
        cve.cvss4_vector or cve.cvss3_vector if cve is not None else None
    )
    if vector:
        for part in str(vector).split("/"):
            if ":" in part:
                key, _, value = part.partition(":")
                vector_metrics[key] = value

    return RiskInput(
        cvss_score=(finding.cvss_score if finding is not None and finding.cvss_score is not None
                    else (cve.best_cvss_score if cve is not None else None)),
        # The CVE table has no `cvss4_version` column -- a v4 vector is v4 by
        # definition. Referencing a non-existent attribute here used to raise
        # AttributeError for every finding that had a CVE attached, i.e. the
        # entire correlation path.
        cvss_version=(
            (finding.cvss_version if finding is not None
             and getattr(finding, "cvss_version", None) else None)
            or ("4.0" if cve is not None and getattr(cve, "cvss4_score", None) is not None
                else (getattr(cve, "cvss3_version", None) if cve is not None else None))
        ),
        cvss_vector=vector,
        cvss_attack_vector=vector_metrics.get("AV"),
        cvss_privileges_required=vector_metrics.get("PR"),
        cvss_user_interaction=vector_metrics.get("UI"),
        epss_score=(finding.epss_score if finding is not None and finding.epss_score is not None
                    else (cve.epss_score if cve is not None else None)),
        epss_percentile=(cve.epss_percentile if cve is not None else None),
        kev=bool((finding.kev if finding is not None else False) or (cve.kev if cve else False)),
        kev_due_date=(cve.kev_due_date if cve is not None else None),
        exploit_known=bool(cve.exploit_known) if cve is not None else False,
        exploit_maturity=(cve.exploit_maturity if cve is not None else None),
        asset_criticality=getattr(asset, "criticality", "medium"),
        data_classification=getattr(asset, "data_classification", "internal"),
        environment=getattr(asset, "environment", "production"),
        exposure=getattr(asset, "exposure", "internal"),
        compensating_controls=list(getattr(asset, "compensating_controls", []) or []),
        business_service_criticality=(getattr(business_service, "criticality", None)
                                      if business_service is not None else None),
        revenue_per_hour=(getattr(business_service, "revenue_per_hour", None)
                          if business_service is not None else None),
        detected_at=getattr(finding, "detected_at", None),
        sla_due_at=getattr(finding, "sla_due_at", None),
        now=now,
    )


def run_cli(org_slug: str | None = None) -> int:
    """`python -m veyrs recompute-risk` - re-score every open finding."""
    from sqlalchemy import select

    from ..db import SessionLocal, set_tenant
    from ..models import Asset, BusinessService, Cve, Finding, Organization, OPEN_STATES
    from ..services import risk as risk_service

    with SessionLocal() as session:
        orgs = session.execute(
            select(Organization).where(
                Organization.slug == org_slug if org_slug else Organization.is_active.is_(True)
            )
        ).scalars().all()
        if not orgs:
            print(f"no organization matched {org_slug!r}")
            return 1
        grand_total = 0
        for org in orgs:
            set_tenant(session, org.id)
            findings = session.execute(
                select(Finding).where(
                    Finding.organization_id == org.id, Finding.state.in_(OPEN_STATES)
                )
            ).scalars().all()
            changed = risk_service.rescore_findings(session, org.id, findings)
            session.commit()
            print(f"{org.slug}: {len(findings)} findings scored, {changed} changed")
            grand_total += changed
        print(f"total changed: {grand_total}")
    return 0
