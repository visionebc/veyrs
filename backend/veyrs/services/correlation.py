"""CVE -> product -> asset correlation, and the finding lifecycle it produces.

This is the module that makes VEYRS a risk platform rather than a CVE viewer:
it turns a global vulnerability record into a per-asset, per-tenant Finding with
an owner, a risk score and a deadline.

The chain implemented here mirrors spec section 41:

    CVE -> CPE match -> Product -> AssetProduct -> Asset
        -> Vulnerability (tenant view of the CVE)
        -> Finding (one per affected asset)
        -> risk score -> assignment -> SLA

Two invariants matter more than anything else:

1. **Idempotence.** Re-running correlation for the same CVE must update existing
   findings, never create a second one. `Finding.dedupe_key` is the identity.
2. **No speculative findings.** An asset is only affected if we know which
   version it runs *and* that version falls inside the CVE's range. Missing
   inventory data produces no finding -- see `versions.in_range`.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Asset, AssetProduct, AssignmentRule, Cve, CveCpeMatch, Finding, FindingEvent,
    OPEN_STATES, Product, Team, Vendor, Vulnerability, can_transition,
)
from . import dedupe as dedupe_service
from . import risk as risk_service
from . import sla as sla_service
from .intelligence import severity_for_score
from .versions import in_range, parse_cpe23

#: States that assert "this is fixed". Re-detecting a finding in one of these is
#: a regression and must put it back in the queue.
REOPENABLE_STATES = {"remediated", "verified", "closed"}

# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def dedupe_key(
    *,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    vuln_ref: str,
    port: int | None = None,
    protocol: str | None = None,
    path: str | None = None,
) -> str:
    """Stable identity for a finding - the `legacy` deduplication algorithm.

    Deliberately includes port/protocol/path: the same CVE on :443 and :8443 of
    one host are two remediation items for the operator, and collapsing them
    would silently close one when the other is fixed.

    The implementation now lives in `services/dedupe.legacy_key` so that the
    configurable algorithms and this one cannot drift apart. This wrapper is
    kept because it is the identity every finding created before the dedupe
    engine existed already carries, and because the CVE correlation path (which
    has no scanner and therefore no registered config) still uses it.
    """
    return dedupe_service.legacy_key(
        organization_id=organization_id, asset_id=asset_id, vuln_ref=vuln_ref,
        port=port, protocol=protocol, path=path,
    )


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


def affected_installations(
    session: Session, organization_id: uuid.UUID, cve: Cve
) -> list[tuple[Asset, AssetProduct, CveCpeMatch]]:
    """Which of this tenant's installed products does the CVE actually hit?"""
    matches = session.execute(
        select(CveCpeMatch).where(
            CveCpeMatch.cve_id == cve.id, CveCpeMatch.vulnerable.is_(True)
        )
    ).scalars().all()
    if not matches:
        return []

    by_product: dict[uuid.UUID, list[CveCpeMatch]] = {}
    for match in matches:
        if match.product_id is not None:
            by_product.setdefault(match.product_id, []).append(match)
    if not by_product:
        return []

    rows = session.execute(
        select(AssetProduct, Asset)
        .join(Asset, Asset.id == AssetProduct.asset_id)
        .where(
            AssetProduct.organization_id == organization_id,
            AssetProduct.product_id.in_(list(by_product.keys())),
            Asset.is_active.is_(True),
            Asset.deleted_at.is_(None),
        )
    ).all()

    hits: list[tuple[Asset, AssetProduct, CveCpeMatch]] = []
    for installation, asset in rows:
        for match in by_product.get(installation.product_id, []):
            parsed = parse_cpe23(match.cpe23) or {}
            exact = parsed.get("version")
            if in_range(
                installation.version,
                start_including=match.version_start_including,
                start_excluding=match.version_start_excluding,
                end_including=match.version_end_including,
                end_excluding=match.version_end_excluding,
                exact=exact if exact not in ("*", "-", "", None) else None,
            ):
                hits.append((asset, installation, match))
                break
    return hits


# --------------------------------------------------------------------------
# Assignment (spec section 10)
# --------------------------------------------------------------------------


def assignment_context(
    session: Session, asset: Asset, installation: AssetProduct | None, cve: Cve | None
) -> dict[str, Any]:
    """Flat dict the declarative assignment rules are evaluated against."""
    product = vendor = None
    if installation is not None:
        product = session.get(Product, installation.product_id)
        if product is not None:
            vendor = session.get(Vendor, product.vendor_id)
    return {
        "asset_type": asset.asset_type,
        "asset_criticality": asset.criticality,
        "asset_environment": asset.environment,
        "asset_exposure": asset.exposure,
        "asset_tags": list(asset.tags or []),
        "asset_location": asset.location,
        "business_service_id": str(asset.business_service_id) if asset.business_service_id else None,
        "product": product.name if product else None,
        "product_normalized": product.normalized_name if product else None,
        "product_type": product.product_type if product else None,
        "vendor": vendor.name if vendor else None,
        "vendor_normalized": vendor.normalized_name if vendor else None,
        "kev": bool(cve.kev) if cve else False,
        "cwe_ids": list(cve.cwe_ids or []) if cve else [],
    }


def rule_matches(conditions: dict, context: dict) -> bool:
    """Flat AND-map evaluation.

    A condition whose field is unknown to the context returns False rather than
    being ignored -- a typo in a rule must not silently widen its scope.
    """
    for field, expected in (conditions or {}).items():
        if field not in context:
            return False
        actual = context[field]
        if isinstance(expected, list):
            if isinstance(actual, list):
                if not set(map(_fold, actual)) & set(map(_fold, expected)):
                    return False
            elif _fold(actual) not in {_fold(v) for v in expected}:
                return False
        elif isinstance(expected, bool):
            if bool(actual) is not expected:
                return False
        elif isinstance(actual, list):
            if _fold(expected) not in set(map(_fold, actual)):
                return False
        elif _fold(actual) != _fold(expected):
            return False
    return True


def _fold(value: Any) -> Any:
    return value.strip().lower() if isinstance(value, str) else value


def resolve_assignment(
    session: Session,
    organization_id: uuid.UUID,
    context: dict,
) -> tuple[uuid.UUID | None, uuid.UUID | None, str | None]:
    """First matching rule wins. Returns (team_id, user_id, reason)."""
    rules = session.execute(
        select(AssignmentRule)
        .where(
            AssignmentRule.organization_id == organization_id,
            AssignmentRule.is_enabled.is_(True),
        )
        .order_by(AssignmentRule.priority, AssignmentRule.created_at)
    ).scalars().all()
    for rule in rules:
        if rule_matches(rule.conditions, context):
            rule.match_count += 1
            rule.last_matched_at = dt.datetime.now(dt.timezone.utc)
            return rule.team_id, rule.user_id, f"rule:{rule.name}"

    # Fall back to the asset's own ownership before giving up: an unassigned
    # critical finding is worse than one routed to a plausible owner.
    return None, None, None


def apply_assignment(session: Session, finding: Finding, *, actor: str = "system") -> bool:
    """Assign a finding to a team/user. Returns True if anything changed."""
    asset = session.get(Asset, finding.asset_id)
    if asset is None:
        return False
    installation = (
        session.get(AssetProduct, finding.asset_product_id)
        if finding.asset_product_id else None
    )
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    cve = (
        session.get(Cve, vulnerability.cve_id)
        if vulnerability is not None and vulnerability.cve_id else None
    )

    context = assignment_context(session, asset, installation, cve)
    team_id, user_id, reason = resolve_assignment(session, finding.organization_id, context)

    if team_id is None and user_id is None:
        team_id, user_id = asset.team_id, asset.owner_id
        reason = "asset owner" if (team_id or user_id) else None
    if team_id is None and user_id is None:
        return False

    changed = (finding.assigned_team_id != team_id) or (finding.assigned_user_id != user_id)
    if not changed:
        return False

    finding.assigned_team_id = team_id
    finding.assigned_user_id = user_id
    finding.assignment_reason = reason
    finding.assigned_at = dt.datetime.now(dt.timezone.utc)
    if finding.state in ("new", "triaged", "risk_assessed"):
        # Walks new -> triaged -> risk_assessed -> assigned so the event log
        # shows the full lifecycle rather than an unexplained jump.
        advance(session, finding, "assigned", actor_label=actor, note=reason)
    else:
        record_event(session, finding, "assigned", actor_label=actor, details={"reason": reason})
    return True


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------

_TIMESTAMP_FOR_STATE = {
    "triaged": "triaged_at",
    "assigned": "assigned_at",
    "remediated": "remediated_at",
    "verified": "verified_at",
    "closed": "closed_at",
}


class TransitionError(ValueError):
    """Raised when a lifecycle transition is not permitted."""


def transition(
    session: Session,
    finding: Finding,
    target: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    note: str | None = None,
) -> Finding:
    """Move a finding through the lifecycle, enforcing the allowed graph."""
    current = finding.state
    if current == target:
        return finding
    if not can_transition(current, target):
        raise TransitionError(f"{current} -> {target} is not an allowed transition")

    finding.state = target
    stamp = _TIMESTAMP_FOR_STATE.get(target)
    now = dt.datetime.now(dt.timezone.utc)
    if stamp and getattr(finding, stamp, None) is None:
        setattr(finding, stamp, now)
    if target in ("closed", "false_positive", "duplicate") and finding.closed_at is None:
        finding.closed_at = now

    record_event(
        session, finding, "state_changed", actor_id=actor_id, actor_label=actor_label,
        details={"from": current, "to": target, "note": note},
    )
    if target == "remediated":
        sla_service.close_sla(session, finding, met=not finding.sla_breached)
    session.flush()
    return finding


def path_to(current: str, target: str) -> list[str] | None:
    """Shortest legal sequence of states from `current` to `target`.

    The automated pipeline (score -> assign) must not teleport a finding from
    `new` to `assigned`: the lifecycle in spec section 9 has triage and risk
    assessment in between, and an auditor reading the event log is entitled to
    see them. Rather than weakening the transition graph, automation walks it.
    """
    from ..models import ALLOWED_TRANSITIONS

    if current == target:
        return []
    seen = {current}
    queue: list[tuple[str, list[str]]] = [(current, [])]
    while queue:
        state, trail = queue.pop(0)
        for nxt in sorted(ALLOWED_TRANSITIONS.get(state, set())):
            if nxt in seen:
                continue
            route = trail + [nxt]
            if nxt == target:
                return route
            seen.add(nxt)
            queue.append((nxt, route))
    return None


def advance(
    session: Session,
    finding: Finding,
    target: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    note: str | None = None,
) -> Finding:
    """Move to `target` through every intermediate state, or raise."""
    route = path_to(finding.state, target)
    if route is None:
        raise TransitionError(f"{finding.state} -> {target} is unreachable")
    for step in route:
        transition(session, finding, step, actor_id=actor_id,
                   actor_label=actor_label, note=note)
    return finding


def record_event(
    session: Session,
    finding: Finding,
    event: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    details: dict | None = None,
) -> FindingEvent:
    row = FindingEvent(
        organization_id=finding.organization_id, finding_id=finding.id, event=event,
        actor_id=actor_id, actor_label=actor_label, details=details or {},
    )
    session.add(row)
    return row


# --------------------------------------------------------------------------
# Correlation entry points
# --------------------------------------------------------------------------


def ensure_vulnerability(
    session: Session, organization_id: uuid.UUID, cve: Cve
) -> Vulnerability:
    """The tenant's view of a global CVE. One row per (org, cve)."""
    row = session.execute(
        select(Vulnerability).where(
            Vulnerability.organization_id == organization_id,
            Vulnerability.cve_id == cve.id,
        )
    ).scalars().first()
    score = cve.best_cvss_score
    vector = cve.cvss4_vector or cve.cvss3_vector or cve.cvss2_vector
    version = "4.0" if cve.cvss4_vector else ("3.1" if cve.cvss3_vector else
                                              ("2.0" if cve.cvss2_vector else None))
    if row is None:
        row = Vulnerability(
            organization_id=organization_id, cve_id=cve.id,
            title=cve.title or cve.id,
            description=cve.description, source=cve.source, state="new",
        )
        session.add(row)
    row.severity = cve.cvss4_severity or cve.cvss3_severity or severity_for_score(score)
    row.cvss_score = score
    row.cvss_vector = vector
    row.cvss_version = version
    row.epss_score = cve.epss_score
    row.epss_percentile = cve.epss_percentile
    row.kev = bool(cve.kev)
    if not row.description and cve.description:
        row.description = cve.description
    session.flush()
    return row


def ensure_finding(
    session: Session,
    *,
    organization_id: uuid.UUID,
    vulnerability: Vulnerability,
    asset: Asset,
    installation: AssetProduct | None = None,
    title: str | None = None,
    detail: str | None = None,
    recommendation: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    path: str | None = None,
    scanner: str | None = None,
    scanner_plugin_id: str | None = None,
    evidence: dict | None = None,
    import_run_id: uuid.UUID | None = None,
    identity: "dedupe_service.Identity | None" = None,
) -> tuple[Finding, bool]:
    """Create or refresh the finding for (asset, vulnerability, location).

    `identity` lets an importer supply a deduplication identity computed under
    the scanner's registered algorithm. Omitted (the CVE correlation path, and
    every pre-existing caller) it falls back to the legacy key, so behaviour is
    unchanged for anything that does not opt in.
    """
    if identity is None:
        identity = dedupe_service.Identity(
            algorithm=dedupe_service.LEGACY,
            dedupe_key=dedupe_key(
                organization_id=organization_id, asset_id=asset.id,
                vuln_ref=vulnerability.cve_id or str(vulnerability.id),
                port=port, protocol=protocol, path=path,
            ),
        )
    now = dt.datetime.now(dt.timezone.utc)
    row = dedupe_service.find_existing(
        session, organization_id=organization_id, identity=identity, scanner=scanner
    )

    created = row is None
    if created:
        row = Finding(
            organization_id=organization_id, vulnerability_id=vulnerability.id,
            asset_id=asset.id,
            asset_product_id=installation.id if installation else None,
            dedupe_key=identity.dedupe_key,
            dedupe_algorithm=identity.algorithm,
            unique_id_from_tool=identity.unique_id,
            state="new",
            title=title or vulnerability.title,
            detected_at=now, first_seen_at=now,
            port=port, protocol=protocol, path=path,
        )
        session.add(row)
        session.flush()
        record_event(session, row, "detected", details={"scanner": scanner})
    elif row.state in REOPENABLE_STATES:
        # Seen again after we believed it fixed: a regression, not a duplicate.
        # Keyed on the *state*, not on `closed_at` -- `remediated` never sets
        # closed_at, so checking that column meant remediated findings could
        # never reopen and a failed patch would silently vanish from the queue.
        record_event(session, row, "reopened", details={
            "previous_state": row.state, "scanner": scanner,
            "previously_remediated_at":
                row.remediated_at.isoformat() if row.remediated_at else None,
        })
        row.state = "new"
        row.closed_at = None
        row.remediated_at = None
        row.verified_at = None
        row.sla_breached = False
        row.sla_breached_at = None
        row.escalation_level = 0
        row.detected_at = now  # the SLA clock restarts for the regression

    row.last_seen_at = now
    # Keep the stored identity current. A tool that starts emitting stable ids
    # mid-life, or a title edit that shifts the hash, must not fork the finding
    # on the NEXT import because the row still carries the old key. Guarded:
    # if another finding already holds the new key this row stays as it is,
    # since a duplicate here is worse than a stale key.
    if row.dedupe_key != identity.dedupe_key:
        clash = session.execute(
            select(Finding.id).where(
                Finding.organization_id == organization_id,
                Finding.dedupe_key == identity.dedupe_key,
                Finding.id != row.id,
            )
        ).scalars().first()
        if clash is None:
            row.dedupe_key = identity.dedupe_key
            row.dedupe_algorithm = identity.algorithm
    if identity.unique_id and row.unique_id_from_tool != identity.unique_id:
        row.unique_id_from_tool = identity.unique_id
    row.severity = vulnerability.severity
    row.cvss_vector = vulnerability.cvss_vector
    row.cvss_score = vulnerability.cvss_score
    row.epss_score = vulnerability.epss_score
    row.kev = vulnerability.kev
    if detail:
        row.detail = detail
    if recommendation:
        row.recommendation = recommendation
    if evidence:
        row.evidence = {**(row.evidence or {}), **evidence}
    if scanner:
        row.scanner = scanner
    if scanner_plugin_id:
        row.scanner_plugin_id = scanner_plugin_id
    if import_run_id:
        row.import_run_id = import_run_id
    if installation is not None and row.asset_product_id is None:
        row.asset_product_id = installation.id
    session.flush()
    return row, created


def process_finding(
    session: Session,
    finding: Finding,
    *,
    profile=None,
    actor: str = "system",
    fire_workflows: bool = True,
    is_new: bool = False,
) -> Finding:
    """Score -> assign -> SLA -> auto-ticket -> workflows. Spec section 13."""
    risk_service.score_finding(session, finding, profile=profile, reason="correlation")
    apply_assignment(session, finding, actor=actor)
    sla_service.apply_sla(session, finding)
    session.flush()

    # After scoring, assignment and SLA, never before: the ticket policy reads
    # `risk_score`, `assigned_team_id` and `sla_due_at`, and evaluating it any
    # earlier would judge every finding on values that are still None -- which
    # reads as "nothing qualifies" rather than as a bug.
    #
    # Imported late for the same reason workflows are: autoticket -> ticketing
    # -> correlation would be an import cycle.
    from . import autoticket as autoticket_service

    autoticket_service.consider(session, finding)

    if fire_workflows and is_new:
        # Imported late: workflow -> ticketing -> correlation would be a cycle.
        from . import workflow as workflow_service

        workflow_service.trigger(
            session, finding.organization_id, "finding.created", finding=finding
        )
    return finding


def correlate_cve(
    session: Session,
    organization_id: uuid.UUID,
    cve: Cve,
    *,
    profile=None,
    close_missing: bool = False,
) -> dict[str, Any]:
    """Full pipeline for one CVE against one tenant's inventory."""
    hits = affected_installations(session, organization_id, cve)
    stats = {"assets": len(hits), "created": 0, "updated": 0, "closed": 0}
    if not hits:
        return stats

    vulnerability = ensure_vulnerability(session, organization_id, cve)
    profile = profile or risk_service.resolve_profile(session, organization_id)

    seen_ids: set[uuid.UUID] = set()
    for asset, installation, match in hits:
        finding, created = ensure_finding(
            organization_id=organization_id, session=session,
            vulnerability=vulnerability, asset=asset, installation=installation,
            title=f"{cve.id} affects {asset.name}",
            detail=cve.description,
            evidence={"cpe23": match.cpe23, "installed_version": installation.version},
            scanner="veyrs-correlation",
        )
        process_finding(session, finding, profile=profile, is_new=created)
        seen_ids.add(finding.id)
        stats["created" if created else "updated"] += 1

    if close_missing:
        stale = session.execute(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.vulnerability_id == vulnerability.id,
                Finding.state.in_(tuple(OPEN_STATES)),
                Finding.scanner == "veyrs-correlation",
            )
        ).scalars().all()
        for finding in stale:
            if finding.id in seen_ids:
                continue
            record_event(session, finding, "no_longer_applicable")
            finding.state = "remediated"
            finding.remediated_at = dt.datetime.now(dt.timezone.utc)
            sla_service.close_sla(session, finding, met=not finding.sla_breached)
            stats["closed"] += 1

    risk_service.rollup_vulnerability(session, vulnerability)
    session.flush()
    return stats


def correlate_asset(
    session: Session, organization_id: uuid.UUID, asset: Asset, *, profile=None
) -> dict[str, Any]:
    """Reverse direction: a newly-inventoried asset against known CVEs.

    Runs when an importer or CMDB sync adds software to an asset -- without it,
    a freshly-onboarded host would stay invisible until the next feed refresh.
    """
    installations = session.execute(
        select(AssetProduct).where(
            AssetProduct.organization_id == organization_id,
            AssetProduct.asset_id == asset.id,
        )
    ).scalars().all()
    if not installations:
        return {"cves": 0, "created": 0, "updated": 0}

    product_ids = [i.product_id for i in installations]
    candidate_ids = session.execute(
        select(CveCpeMatch.cve_id).where(
            CveCpeMatch.product_id.in_(product_ids), CveCpeMatch.vulnerable.is_(True)
        ).distinct()
    ).scalars().all()

    profile = profile or risk_service.resolve_profile(session, organization_id)
    stats = {"cves": 0, "created": 0, "updated": 0}
    for cve_id in candidate_ids:
        cve = session.get(Cve, cve_id)
        if cve is None:
            continue
        result = correlate_cve(session, organization_id, cve, profile=profile)
        if result["assets"]:
            stats["cves"] += 1
            stats["created"] += result["created"]
            stats["updated"] += result["updated"]
    return stats


def correlate_batch(
    session: Session, organization_id: uuid.UUID, cve_ids: Sequence[str], *, profile=None
) -> dict[str, Any]:
    profile = profile or risk_service.resolve_profile(session, organization_id)
    totals = {"cves": 0, "assets": 0, "created": 0, "updated": 0}
    for cve_id in cve_ids:
        cve = session.get(Cve, cve_id)
        if cve is None:
            continue
        result = correlate_cve(session, organization_id, cve, profile=profile)
        if result["assets"]:
            totals["cves"] += 1
            totals["assets"] += result["assets"]
            totals["created"] += result["created"]
            totals["updated"] += result["updated"]
    return totals


__all__ = [
    "dedupe_key", "affected_installations", "assignment_context", "rule_matches",
    "resolve_assignment", "apply_assignment", "transition", "TransitionError",
    "record_event", "ensure_vulnerability", "ensure_finding", "process_finding",
    "correlate_cve", "correlate_asset", "correlate_batch",
]
