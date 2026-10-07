"""SLA and escalation engines (spec sections 11 and 12).

Both engines are pure data-driven: policies live in `sla_policies` /
`escalation_policies` rows and are edited through the API, never in code. The
functions here only *evaluate* them.

Deliberate design choices:

* The clock starts at **detection**, not at assignment. A finding that sits
  unassigned for three days has already burned three days of the customer's
  exposure window; starting the clock later would let a queue backlog hide a
  breach.
* Escalation levels are absolute offsets from detection, not relative to the
  previous level. A stalled escalation therefore catches up to the correct level
  on the next sweep instead of silently skipping steps.
* Business-hours policies use a simple Mon-Fri 09:00-17:00 UTC calendar. It is
  explicitly a *policy* toggle, off by default, because "critical + KEV +
  internet-facing = 4 hours" must not pause overnight.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Asset, EscalationPolicy, Finding, OPEN_STATES, SlaEvent, SlaPolicy,
)

def _scoped(statement, scope=None):
    """Narrow a `Finding` statement to the caller's team scope.

    Imported lazily for the same reason `services.analytics` does it:
    `security.scope` reaches back into `services.teams`, and a module-level
    import here would close the cycle.
    """
    if scope is None or not scope.restricted:
        return statement
    from ..security import scope as team_scope

    return team_scope.findings(statement, scope)


BUSINESS_START_HOUR = 9
BUSINESS_END_HOUR = 17
BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Monday-Friday

# Built-in ladder used when a tenant has not defined its own. Mirrors the
# example in the spec so a fresh install behaves sensibly on day one.
BUILTIN_SLA_POLICIES = [
    {
        "slug": "critical-kev-internet", "name": "Critical + KEV + Internet exposed",
        "priority": 10, "remediate_within_hours": 4, "triage_within_hours": 1,
        "verify_within_hours": 24, "warn_at_percent": 50,
        "conditions": {"kev": True, "exposure": ["internet"]},
    },
    {
        "slug": "critical", "name": "Critical", "priority": 20,
        "remediate_within_hours": 24, "triage_within_hours": 4,
        "verify_within_hours": 72, "conditions": {"severity": ["critical"]},
    },
    {
        "slug": "high", "name": "High", "priority": 30,
        "remediate_within_hours": 24 * 7, "triage_within_hours": 24,
        "conditions": {"severity": ["high"]},
    },
    {
        "slug": "medium", "name": "Medium", "priority": 40,
        "remediate_within_hours": 24 * 30, "conditions": {"severity": ["medium"]},
    },
    {
        "slug": "low", "name": "Low", "priority": 50,
        "remediate_within_hours": 24 * 90, "conditions": {"severity": ["low"]},
    },
    {
        "slug": "default", "name": "Default", "priority": 1000,
        "remediate_within_hours": 24 * 90, "conditions": {}, "is_default": True,
    },
]

BUILTIN_ESCALATION = {
    "slug": "standard", "name": "Standard escalation ladder", "is_default": True,
    "levels": [
        {"level": 1, "after_hours": 4, "notify": "team"},
        {"level": 2, "after_hours": 8, "notify": "team_manager"},
        {"level": 3, "after_hours": 24, "notify": "security_manager"},
        {"level": 4, "after_hours": 48, "notify": "ciso"},
    ],
}


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------


def seed_policies(session: Session, organization_id: uuid.UUID) -> dict[str, int]:
    """Create the built-in SLA + escalation policies for a tenant. Idempotent."""
    created = {"sla": 0, "escalation": 0}

    escalation = session.execute(
        select(EscalationPolicy).where(
            EscalationPolicy.organization_id == organization_id,
            EscalationPolicy.slug == BUILTIN_ESCALATION["slug"],
        )
    ).scalars().first()
    if escalation is None:
        escalation = EscalationPolicy(
            organization_id=organization_id, slug=BUILTIN_ESCALATION["slug"],
            name=BUILTIN_ESCALATION["name"], levels=BUILTIN_ESCALATION["levels"],
            is_default=True, targets={},
        )
        session.add(escalation)
        session.flush()
        created["escalation"] += 1

    existing = {
        p.slug for p in session.execute(
            select(SlaPolicy).where(SlaPolicy.organization_id == organization_id)
        ).scalars().all()
    }
    for spec in BUILTIN_SLA_POLICIES:
        if spec["slug"] in existing:
            continue
        session.add(SlaPolicy(
            organization_id=organization_id, escalation_policy_id=escalation.id,
            warn_at_percent=spec.get("warn_at_percent", 75),
            is_default=bool(spec.get("is_default")),
            **{k: v for k, v in spec.items() if k not in ("warn_at_percent", "is_default")},
        ))
        created["sla"] += 1
    session.flush()
    return created


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


def sla_context(session: Session, finding: Finding) -> dict:
    asset = session.get(Asset, finding.asset_id)
    return {
        "severity": finding.severity,
        "kev": bool(finding.kev),
        "cvss": finding.cvss_score,
        "epss": finding.epss_score,
        "risk": finding.risk_score,
        "exposure": asset.exposure if asset else None,
        "asset_criticality": asset.criticality if asset else None,
        "environment": asset.environment if asset else None,
        "asset_type": asset.asset_type if asset else None,
    }


def policy_matches(conditions: dict, context: dict) -> bool:
    """Evaluate an SLA policy's condition map.

    Numeric gates (`min_*`) treat a missing value as *not matching*: an unscored
    finding must fall through to a looser policy rather than accidentally
    inheriting the 4-hour critical deadline.
    """
    for field, expected in (conditions or {}).items():
        if field.startswith("min_"):
            actual = context.get(field[4:])
            if actual is None or float(actual) < float(expected):
                return False
            continue
        if field.startswith("max_"):
            actual = context.get(field[4:])
            if actual is None or float(actual) > float(expected):
                return False
            continue
        actual = context.get(field)
        if isinstance(expected, bool):
            if bool(actual) is not expected:
                return False
        elif isinstance(expected, list):
            if actual is None:
                return False
            if str(actual).lower() not in {str(v).lower() for v in expected}:
                return False
        elif actual is None or str(actual).lower() != str(expected).lower():
            return False
    return True


def resolve_policy(session: Session, finding: Finding) -> SlaPolicy | None:
    policies = session.execute(
        select(SlaPolicy)
        .where(
            SlaPolicy.organization_id == finding.organization_id,
            SlaPolicy.is_enabled.is_(True),
        )
        .order_by(SlaPolicy.priority, SlaPolicy.created_at)
    ).scalars().all()
    if not policies:
        return None
    context = sla_context(session, finding)
    for policy in policies:
        if policy.conditions and not policy_matches(policy.conditions, context):
            continue
        if policy.conditions or policy.is_default:
            return policy
    # No conditional policy matched and none is flagged default: use the loosest.
    return policies[-1]


# --------------------------------------------------------------------------
# Deadline maths
# --------------------------------------------------------------------------


def add_business_hours(start: dt.datetime, hours: float) -> dt.datetime:
    """Advance `start` by `hours` of Mon-Fri 09:00-17:00 UTC working time."""
    remaining = float(hours)
    cursor = start.astimezone(dt.timezone.utc)
    guard = 0
    while remaining > 0:
        guard += 1
        if guard > 10_000:  # ~5 years of working hours; policy is misconfigured
            return cursor
        if cursor.weekday() not in BUSINESS_DAYS:
            cursor = _next_business_open(cursor)
            continue
        day_start = cursor.replace(hour=BUSINESS_START_HOUR, minute=0, second=0, microsecond=0)
        day_end = cursor.replace(hour=BUSINESS_END_HOUR, minute=0, second=0, microsecond=0)
        if cursor < day_start:
            cursor = day_start
        if cursor >= day_end:
            cursor = _next_business_open(cursor)
            continue
        available = (day_end - cursor).total_seconds() / 3600.0
        if remaining <= available:
            return cursor + dt.timedelta(hours=remaining)
        remaining -= available
        cursor = _next_business_open(cursor)
    return cursor


def _next_business_open(cursor: dt.datetime) -> dt.datetime:
    nxt = (cursor + dt.timedelta(days=1)).replace(
        hour=BUSINESS_START_HOUR, minute=0, second=0, microsecond=0
    )
    while nxt.weekday() not in BUSINESS_DAYS:
        nxt += dt.timedelta(days=1)
    return nxt


def deadline_for(policy: SlaPolicy, start: dt.datetime, hours: int) -> dt.datetime:
    if policy.business_hours_only:
        return add_business_hours(start, hours)
    return start + dt.timedelta(hours=hours)


# --------------------------------------------------------------------------
# Application + evaluation
# --------------------------------------------------------------------------


def apply_sla(session: Session, finding: Finding, *, force: bool = False) -> SlaPolicy | None:
    """Attach the matching SLA policy and compute the remediation deadline."""
    policy = resolve_policy(session, finding)
    if policy is None:
        return None
    if finding.sla_policy_id == policy.id and finding.sla_due_at is not None and not force:
        return policy

    start = finding.detected_at or dt.datetime.now(dt.timezone.utc)
    if start.tzinfo is None:
        start = start.replace(tzinfo=dt.timezone.utc)
    finding.sla_policy_id = policy.id
    finding.sla_due_at = deadline_for(policy, start, policy.remediate_within_hours)
    session.add(SlaEvent(
        organization_id=finding.organization_id, finding_id=finding.id, event="set",
        sla_policy_id=policy.id,
        details={
            "policy": policy.slug,
            "due_at": finding.sla_due_at.isoformat(),
            "remediate_within_hours": policy.remediate_within_hours,
        },
    ))
    session.flush()
    return policy


def sla_status(finding: Finding, now: dt.datetime | None = None) -> dict:
    """Countdown data for the UI: remaining time, percent burned, state."""
    now = now or dt.datetime.now(dt.timezone.utc)
    if finding.sla_due_at is None:
        return {"state": "none", "due_at": None, "remaining_hours": None, "percent_used": None}
    due = finding.sla_due_at
    start = finding.detected_at or due
    if due.tzinfo is None:
        due = due.replace(tzinfo=dt.timezone.utc)
    if start.tzinfo is None:
        start = start.replace(tzinfo=dt.timezone.utc)

    total = max((due - start).total_seconds(), 1.0)
    used = (now - start).total_seconds()
    remaining_hours = (due - now).total_seconds() / 3600.0
    percent = round(min(max(used / total * 100.0, 0.0), 999.0), 1)

    if finding.state not in OPEN_STATES:
        state = "breached" if finding.sla_breached else "met"
    elif now > due:
        state = "breached"
    else:
        state = "on_track"
    return {
        "state": state,
        "due_at": due.isoformat(),
        "remaining_hours": round(remaining_hours, 2),
        "percent_used": percent,
        "escalation_level": finding.escalation_level,
    }


def close_sla(session: Session, finding: Finding, *, met: bool) -> None:
    session.add(SlaEvent(
        organization_id=finding.organization_id, finding_id=finding.id,
        event="met" if met else "breached", sla_policy_id=finding.sla_policy_id,
        escalation_level=finding.escalation_level,
        details={"state": finding.state},
    ))
    session.flush()


# --------------------------------------------------------------------------
# The sweep: breach detection + escalation
# --------------------------------------------------------------------------


def evaluate_findings(
    session: Session,
    organization_id: uuid.UUID,
    findings: Iterable[Finding] | None = None,
    *,
    now: dt.datetime | None = None,
    scope=None,
) -> dict[str, int]:
    """Run the SLA/escalation sweep over open findings.

    Returns counters, and emits `SlaEvent` rows plus notification requests. It
    is a plain function so tests can drive it with an injected clock instead of
    sleeping.

    **`scope` narrows what the sweep touches, not just what it reports.** This
    engine does not only count: it flips `sla_breached`, moves
    `escalation_level`, writes `SlaEvent` rows and fires notification
    workflows. Run unscoped on behalf of a team-restricted operator it would
    page another team about findings that operator may not even read, which is
    a side effect leaking exactly the fact the segregation exists to hide. An
    explicit `findings` list is trusted as given -- the caller already chose the
    rows, and every internal caller either passes the scope or is the
    unrestricted nightly sweep.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if findings is None:
        findings = session.execute(
            _scoped(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.state.in_(tuple(OPEN_STATES)),
                ),
                scope,
            )
        ).scalars().all()

    stats = {"checked": 0, "warned": 0, "breached": 0, "escalated": 0}
    policies: dict[uuid.UUID, SlaPolicy] = {}
    ladders: dict[uuid.UUID, EscalationPolicy] = {}
    # Late import: workflow -> ticketing -> correlation -> sla would be a cycle.
    from . import workflow as workflow_service

    fired: list[tuple[str, Finding, dict]] = []

    for finding in findings:
        stats["checked"] += 1
        if finding.sla_due_at is None:
            apply_sla(session, finding)
        if finding.sla_due_at is None:
            continue

        policy = policies.get(finding.sla_policy_id) if finding.sla_policy_id else None
        if policy is None and finding.sla_policy_id:
            policy = session.get(SlaPolicy, finding.sla_policy_id)
            if policy:
                policies[policy.id] = policy

        due = finding.sla_due_at
        if due.tzinfo is None:
            due = due.replace(tzinfo=dt.timezone.utc)
        start = finding.detected_at or due
        if start.tzinfo is None:
            start = start.replace(tzinfo=dt.timezone.utc)

        # Breach
        if now > due and not finding.sla_breached:
            finding.sla_breached = True
            finding.sla_breached_at = now
            session.add(SlaEvent(
                organization_id=organization_id, finding_id=finding.id, event="breached",
                sla_policy_id=finding.sla_policy_id,
                details={"due_at": due.isoformat(), "overdue_hours":
                         round((now - due).total_seconds() / 3600.0, 2)},
            ))
            stats["breached"] += 1
            fired.append(("sla.breached", finding, {
                "overdue_hours": round((now - due).total_seconds() / 3600.0, 2),
            }))
        elif not finding.sla_breached and policy is not None:
            total = max((due - start).total_seconds(), 1.0)
            used = (now - start).total_seconds()
            if used / total * 100.0 >= policy.warn_at_percent:
                already = session.execute(
                    select(SlaEvent).where(
                        SlaEvent.finding_id == finding.id, SlaEvent.event == "warned"
                    ).limit(1)
                ).scalars().first()
                if already is None:
                    session.add(SlaEvent(
                        organization_id=organization_id, finding_id=finding.id,
                        event="warned", sla_policy_id=finding.sla_policy_id,
                        details={"percent_used": round(used / total * 100.0, 1)},
                    ))
                    stats["warned"] += 1
                    fired.append(("sla.warned", finding, {
                        "percent_used": round(used / total * 100.0, 1),
                    }))

        # Escalation
        ladder = None
        if policy is not None and policy.escalation_policy_id:
            ladder = ladders.get(policy.escalation_policy_id)
            if ladder is None:
                ladder = session.get(EscalationPolicy, policy.escalation_policy_id)
                if ladder:
                    ladders[ladder.id] = ladder
        if ladder is None or not ladder.is_enabled:
            continue

        elapsed_hours = (now - start).total_seconds() / 3600.0
        target_level = 0
        notify = None
        for step in sorted(ladder.levels or [], key=lambda s: s.get("after_hours", 0)):
            if elapsed_hours >= float(step.get("after_hours", 0)):
                target_level = int(step.get("level", target_level + 1))
                notify = step.get("notify")
        if target_level > finding.escalation_level:
            finding.escalation_level = target_level
            finding.escalated_at = now
            session.add(SlaEvent(
                organization_id=organization_id, finding_id=finding.id, event="escalated",
                sla_policy_id=finding.sla_policy_id, escalation_level=target_level,
                details={"notify": notify, "elapsed_hours": round(elapsed_hours, 2)},
            ))
            stats["escalated"] += 1
            fired.append(("sla.escalated", finding, {
                "level": target_level, "notify": notify,
            }))

    session.flush()
    # Workflows fire after the sweep has settled, so a workflow that reads the
    # finding sees the final state rather than a half-applied one.
    for event, finding, extra in fired:
        workflow_service.trigger(
            session, organization_id, event, finding=finding, extra=extra
        )
    session.flush()
    return stats


def breach_summary(session: Session, organization_id: uuid.UUID, *, scope=None) -> dict:
    """Counters for the SLA widget on the dashboard, narrowed to `scope`.

    Took no scope at all until v0.17.1, which made it the one place a
    team-restricted identity still read the whole estate: `policies` sat in
    `EXEMPT_TAGS`, so the route guard waved it through, and the console papered
    over the symptom by hiding the widget whenever a team filter was on. The
    counters are the fix; hiding them was the workaround.
    """
    open_findings = session.execute(
        _scoped(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.state.in_(tuple(OPEN_STATES)),
            ),
            scope,
        )
    ).scalars().all()
    now = dt.datetime.now(dt.timezone.utc)
    summary = {"open": len(open_findings), "breached": 0, "due_24h": 0, "escalated": 0}
    for finding in open_findings:
        if finding.sla_breached:
            summary["breached"] += 1
        elif finding.sla_due_at is not None:
            due = finding.sla_due_at
            if due.tzinfo is None:
                due = due.replace(tzinfo=dt.timezone.utc)
            if (due - now).total_seconds() <= 86400:
                summary["due_24h"] += 1
        if finding.escalation_level > 0:
            summary["escalated"] += 1
    return summary


def run_cli() -> int:
    """`python -m veyrs run-sla` — the nightly SLA/escalation sweep.

    The CLI wired this command to a `veyrs.engines.sla` module that never
    existed, so the command had never run and no finding ever received a
    deadline outside a request. Same shape as `engines.risk.run_cli`: every
    active organization, unscoped on purpose — this is the sweep the scope
    docstring on `evaluate_findings` calls the "unrestricted nightly sweep".
    """
    from sqlalchemy import select as _select

    from ..db import SessionLocal, set_tenant
    from ..models import Organization

    with SessionLocal() as session:
        orgs = session.execute(
            _select(Organization).where(Organization.is_active.is_(True))
        ).scalars().all()
        if not orgs:
            print("no active organizations")
            return 1
        for org in orgs:
            set_tenant(session, org.id)
            stats = evaluate_findings(session, org.id)
            session.commit()
            print(f"{org.slug}: checked {stats['checked']} · warned {stats['warned']}"
                  f" · breached {stats['breached']} · escalated {stats['escalated']}")
    return 0


__all__ = [
    "seed_policies", "policy_matches", "resolve_policy", "apply_sla", "sla_status",
    "close_sla", "evaluate_findings", "breach_summary", "add_business_hours",
    "deadline_for", "run_cli", "BUILTIN_SLA_POLICIES", "BUILTIN_ESCALATION",
]
