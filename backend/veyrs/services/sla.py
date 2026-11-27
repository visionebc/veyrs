"""SLA and escalation engines (spec sections 11 and 12).

Both engines are pure data-driven: policies live in `sla_policies` /
`escalation_policies` rows and are edited through the API, never in code. The
functions here only *evaluate* them.

Deliberate design choices:

* The clock starts at **detection**, not at assignment. A finding that sits
  unassigned for three days has already burned three days of the customer's
  exposure window; starting the clock later would let a queue backlog hide a
  breach.
* Escalation levels are absolute offsets from the **SLA deadline** (`sla_due_at`),
  not from detection and not relative to the previous level. Until 0.41.0 they
  were counted from detection, so every finding with a ladder reached level 4
  within 48 hours of being seen, even a low with a 90-day deadline. Escalation
  exists to answer "the deadline passed and nobody acted": level 0 until the
  deadline, level N once `after_hours` of N have elapsed past it. A stalled
  sweep still catches up to the correct level on the next run instead of
  silently skipping steps.
* The `notify` value of each level is resolved to real users by
  `resolve_escalation_recipients` (see its docstring for the mapping) and they
  are notified through the normal notification pipeline.
* Business-hours policies use a simple Mon-Fri 09:00-17:00 UTC calendar. It is
  explicitly a *policy* toggle, off by default, because "critical + KEV +
  internet-facing = 4 hours" must not pause overnight.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Iterable

import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Asset, EscalationPolicy, Finding, OPEN_STATES, Role, SlaEvent, SlaPolicy, Team,
    User, UserRole,
)

log = logging.getLogger("veyrs.sla")

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


def missing_builtin_policies(session: Session, organization_id: uuid.UUID) -> dict[str, list[str]]:
    """Slugs of built-in policies this tenant does not have (read-only)."""
    have_esc = {
        e.slug for e in session.execute(
            select(EscalationPolicy).where(EscalationPolicy.organization_id == organization_id)
        ).scalars().all()
    }
    have_sla = {
        p.slug for p in session.execute(
            select(SlaPolicy).where(SlaPolicy.organization_id == organization_id)
        ).scalars().all()
    }
    return {
        "escalation": [] if BUILTIN_ESCALATION["slug"] in have_esc
        else [BUILTIN_ESCALATION["slug"]],
        "sla": [p["slug"] for p in BUILTIN_SLA_POLICIES if p["slug"] not in have_sla],
    }


def seed_policies(session: Session, organization_id: uuid.UUID) -> dict[str, int]:
    """Create the MISSING built-in SLA + escalation policies for a tenant.

    Idempotent and additive: a policy the tenant already has (matched by slug) is
    never touched, so an edited built-in keeps its edits. A built-in the tenant
    deleted on purpose comes back, which is why callers that must respect a
    deliberate deletion (`bootstrap` on an existing tenant) check
    `missing_builtin_policies` first. A built-in is only flagged `is_default`
    when the tenant has no default of its own, so seeding never creates a second.
    """
    created = {"sla": 0, "escalation": 0}

    escalation = session.execute(
        select(EscalationPolicy).where(
            EscalationPolicy.organization_id == organization_id,
            EscalationPolicy.slug == BUILTIN_ESCALATION["slug"],
        )
    ).scalars().first()
    if escalation is None:
        has_default_ladder = session.execute(
            select(EscalationPolicy.id).where(
                EscalationPolicy.organization_id == organization_id,
                EscalationPolicy.is_default.is_(True),
            ).limit(1)
        ).first() is not None
        escalation = EscalationPolicy(
            organization_id=organization_id, slug=BUILTIN_ESCALATION["slug"],
            name=BUILTIN_ESCALATION["name"], levels=BUILTIN_ESCALATION["levels"],
            is_default=not has_default_ladder, targets={},
        )
        session.add(escalation)
        session.flush()
        created["escalation"] += 1

    current = session.execute(
        select(SlaPolicy).where(SlaPolicy.organization_id == organization_id)
    ).scalars().all()
    existing = {p.slug for p in current}
    has_default = any(p.is_default for p in current)
    for spec in BUILTIN_SLA_POLICIES:
        if spec["slug"] in existing:
            continue
        make_default = bool(spec.get("is_default")) and not has_default
        has_default = has_default or make_default
        session.add(SlaPolicy(
            organization_id=organization_id, escalation_policy_id=escalation.id,
            warn_at_percent=spec.get("warn_at_percent", 75),
            is_default=make_default,
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
# Escalation targets -> people
# --------------------------------------------------------------------------

#: What each well-known `notify` target of an escalation level means, resolved
#: from the existing models. Documented in docs/functional/sla-escalation.md.
#:
#: * `team`             active members of the finding's assigned team
#: * `team_manager`     `Team.manager_id` of the assigned team
#: * `security_manager` users holding the `security-manager` role
#: * `ciso`             users holding a `ciso` role (a tenant-defined role; there
#:                      is no built-in one)
#: * `org_admin`        users holding `org-admin`
#: * `asset_owner`      `Asset.owner_id` of the finding's asset
#: * `assignee`         the finding's assigned user and team
#: * `role:<slug>`      users holding that role
#: * `team:<slug>`      active members of that team
#: * `user:<email>` or a bare e-mail address: that person / address
#:
#: A role grant counts only when it is organization-wide (`team_id IS NULL`): a
#: grant narrowed to one team is not "the security manager" of the estate.
#: `EscalationPolicy.targets` overrides a name: `{"ciso": ["a@example.com",
#: "<user id>"]}` replaces the lookup above for that name.
#:
#: A target that resolves to nobody falls back to the organization's
#: `org-admin` users and the sweep records `fallback: true` on the SlaEvent: an
#: escalation that reaches no one is the defect this replaces, and a routing
#: hole must be loud rather than silent.
TARGET_ROLE = {"security_manager": "security-manager", "ciso": "ciso",
               "org_admin": "org-admin"}
FALLBACK_ROLE = "org-admin"


@dataclass
class Recipients:
    users: list = field(default_factory=list)
    addresses: list = field(default_factory=list)
    fallback: bool = False
    unresolved: list = field(default_factory=list)


def _users_with_role(session: Session, organization_id: uuid.UUID, slug: str) -> list[User]:
    return session.execute(
        select(User).join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(
            UserRole.organization_id == organization_id,
            UserRole.team_id.is_(None),
            Role.slug == slug,
            (Role.organization_id.is_(None)) | (Role.organization_id == organization_id),
            User.organization_id == organization_id,
            User.is_active.is_(True),
            User.deleted_at.is_(None),
        ).order_by(User.email)
    ).scalars().all()


def _team_for(session: Session, finding: Finding) -> Team | None:
    if finding.assigned_team_id is None:
        return None
    return session.get(Team, finding.assigned_team_id)


def _resolve_one(session: Session, finding: Finding, target: str,
                 ladder: EscalationPolicy | None) -> tuple[list[User], list[str]]:
    from . import notifications

    org = finding.organization_id
    override = ((ladder.targets or {}).get(target) if ladder is not None else None)
    if override:
        users: list[User] = []
        addresses: list[str] = []
        for item in override if isinstance(override, list) else [override]:
            item = str(item).strip()
            user = None
            try:
                user = session.get(User, uuid.UUID(item))
            except (ValueError, AttributeError):
                if "@" in item:
                    user = session.execute(select(User).where(
                        User.organization_id == org, User.email == item.lower(),
                        User.is_active.is_(True))).scalars().first()
            if user is not None and user.organization_id == org:
                users.append(user)
            elif "@" in item:
                addresses.append(item)
        return users, addresses

    if target == "team":
        return (notifications.team_members(session, finding.assigned_team_id)
                if finding.assigned_team_id else []), []
    if target == "team_manager":
        team = _team_for(session, finding)
        manager = session.get(User, team.manager_id) if team and team.manager_id else None
        return ([manager] if manager is not None and manager.is_active else []), []
    if target == "assignee":
        users = []
        if finding.assigned_user_id:
            user = session.get(User, finding.assigned_user_id)
            if user is not None and user.is_active:
                users.append(user)
        if finding.assigned_team_id:
            users.extend(notifications.team_members(session, finding.assigned_team_id))
        return users, []
    if target == "asset_owner":
        asset = session.get(Asset, finding.asset_id)
        owner = session.get(User, asset.owner_id) if asset is not None and asset.owner_id else None
        return ([owner] if owner is not None and owner.is_active else []), []
    if target in TARGET_ROLE:
        return _users_with_role(session, org, TARGET_ROLE[target]), []
    if target.startswith("role:"):
        return _users_with_role(session, org, target.split(":", 1)[1]), []
    if target.startswith("team:"):
        team = session.execute(select(Team).where(
            Team.organization_id == org, Team.slug == target.split(":", 1)[1]
        )).scalars().first()
        return (notifications.team_members(session, team.id) if team else []), []
    if target.startswith("user:") or "@" in target:
        email = target.split(":", 1)[1] if target.startswith("user:") else target
        user = session.execute(select(User).where(
            User.organization_id == org, User.email == email.strip().lower(),
            User.is_active.is_(True))).scalars().first()
        return ([user] if user is not None else []), ([] if user is not None else [email.strip()])
    return [], []


def resolve_escalation_recipients(
    session: Session, finding: Finding, notify, ladder: EscalationPolicy | None = None,
) -> Recipients:
    """Turn a ladder level's `notify` (a name or a list of names) into people."""
    names = [notify] if isinstance(notify, str) else list(notify or [])
    out = Recipients()
    seen: set[uuid.UUID] = set()
    for name in names:
        users, addresses = _resolve_one(session, finding, str(name), ladder)
        if not users and not addresses:
            out.unresolved.append(str(name))
        for user in users:
            if user.id not in seen:
                seen.add(user.id)
                out.users.append(user)
        out.addresses.extend(a for a in addresses if a not in out.addresses)
    if not out.users and not out.addresses:
        out.users = _users_with_role(session, finding.organization_id, FALLBACK_ROLE)
        out.fallback = True
    return out


def _notify_escalation(session: Session, finding: Finding, ladder: EscalationPolicy | None,
                       level: int, notify, *, overdue_hours: float) -> dict:
    """Queue the `sla.escalated` notice for a level's resolved recipients.

    The finding's assigned user is left out: the built-in `escalation-notify`
    workflow (fired right after the sweep) already notifies the assignee, and a
    person told twice about one escalation learns to ignore both.
    """
    from . import notifications

    recipients = resolve_escalation_recipients(session, finding, notify, ladder)
    users = [u for u in recipients.users if u.id != finding.assigned_user_id]
    asset = session.get(Asset, finding.asset_id)
    due = finding.sla_due_at
    context = {
        "title": finding.title, "asset": asset.name if asset else "",
        "due_at": due.isoformat() if due else "", "level": level,
        "notify": notify if isinstance(notify, str) else ", ".join(notify or []),
        "overdue_hours": overdue_hours, "link": f"/findings/{finding.id}",
    }
    rows = notifications.queue(
        session, finding.organization_id, "sla.escalated", context,
        users=users, addresses=recipients.addresses, finding_id=finding.id,
    )
    if recipients.unresolved:
        log.warning("escalation level %s of finding %s: target(s) %s resolved to nobody%s",
                    level, finding.id, recipients.unresolved,
                    " (fell back to org-admin)" if recipients.fallback else "")
    return {"recipients": len({r.recipient_user_id or r.recipient_address for r in rows}),
            "unresolved": recipients.unresolved, "fallback": recipients.fallback}


def _ladder_level(ladder: EscalationPolicy, elapsed_hours: float) -> tuple[int, object]:
    """Highest level whose `after_hours` has elapsed since the deadline."""
    level, notify = 0, None
    for step in sorted(ladder.levels or [], key=lambda s: s.get("after_hours", 0)):
        if elapsed_hours >= float(step.get("after_hours", 0)):
            level = int(step.get("level", level + 1))
            notify = step.get("notify")
    return level, notify


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
    unrestricted tick sweep.
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

        # Counted from the DEADLINE: before it, nothing has been missed.
        elapsed_hours = (now - due).total_seconds() / 3600.0
        target_level, notify = _ladder_level(ladder, elapsed_hours) if elapsed_hours >= 0 \
            else (0, None)
        if target_level > finding.escalation_level:
            finding.escalation_level = target_level
            finding.escalated_at = now
            routed = _notify_escalation(
                session, finding, ladder, target_level, notify,
                overdue_hours=round(elapsed_hours, 2),
            )
            session.add(SlaEvent(
                organization_id=organization_id, finding_id=finding.id, event="escalated",
                sla_policy_id=finding.sla_policy_id, escalation_level=target_level,
                details={"notify": notify, "overdue_hours": round(elapsed_hours, 2),
                         **routed},
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


def recompute_escalation(
    session: Session, organization_id: uuid.UUID, *, apply: bool = False,
    notify: bool = False, now: dt.datetime | None = None,
) -> dict:
    """Re-derive every open finding's escalation level from its deadline.

    The one-off migration for the 0.41.0 change from "hours since detection" to
    "hours since the deadline". The sweep only ever moves a level UP, so a
    finding that reached level 4 under the old rule would sit at 4 forever and
    never notify anyone at its real breach. This sets each level to what the
    new rule gives today -- up or down -- SILENTLY: no notification, no workflow,
    one `escalation_recomputed` SlaEvent per finding that moved. `notify=True`
    additionally sends the level notice for findings that end above level 0.
    Dry run unless `apply`.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    findings = session.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.state.in_(tuple(OPEN_STATES)),
        )
    ).scalars().all()
    out = {"checked": 0, "changed": 0, "lowered": 0, "raised": 0, "unchanged": 0,
           "notified": 0, "applied": apply, "levels": {}}
    ladders: dict[uuid.UUID, EscalationPolicy | None] = {}
    for finding in findings:
        out["checked"] += 1
        ladder = None
        policy = session.get(SlaPolicy, finding.sla_policy_id) if finding.sla_policy_id else None
        if policy is not None and policy.escalation_policy_id:
            if policy.escalation_policy_id not in ladders:
                ladders[policy.escalation_policy_id] = session.get(
                    EscalationPolicy, policy.escalation_policy_id)
            ladder = ladders[policy.escalation_policy_id]
        if finding.sla_due_at is None or ladder is None or not ladder.is_enabled:
            target, step_notify, overdue = 0, None, 0.0
        else:
            due = finding.sla_due_at
            if due.tzinfo is None:
                due = due.replace(tzinfo=dt.timezone.utc)
            overdue = (now - due).total_seconds() / 3600.0
            target, step_notify = (_ladder_level(ladder, overdue) if overdue >= 0
                                   else (0, None))
        before = finding.escalation_level
        out["levels"][str(target)] = out["levels"].get(str(target), 0) + 1
        if target == before:
            out["unchanged"] += 1
            continue
        out["changed"] += 1
        out["lowered" if target < before else "raised"] += 1
        if not apply:
            continue
        finding.escalation_level = target
        finding.escalated_at = now if target > 0 else None
        session.add(SlaEvent(
            organization_id=organization_id, finding_id=finding.id,
            event="escalation_recomputed", sla_policy_id=finding.sla_policy_id,
            escalation_level=target,
            details={"from": before, "to": target, "overdue_hours": round(overdue, 2),
                     "rule": "counted from sla_due_at"},
        ))
        if notify and target > 0:
            _notify_escalation(session, finding, ladder, target, step_notify,
                               overdue_hours=round(overdue, 2))
            out["notified"] += 1
    session.flush()
    return out


def run_recompute_cli(*, apply: bool, notify: bool, org_slug: str | None) -> int:
    """`python -m veyrs recompute-escalation` -- see `recompute_escalation`."""
    from ..db import SessionLocal, set_tenant
    from ..models import Organization

    with SessionLocal() as session:
        stmt = select(Organization).where(Organization.is_active.is_(True))
        if org_slug:
            stmt = stmt.where(Organization.slug == org_slug)
        orgs = session.execute(stmt).scalars().all()
        if not orgs:
            print("no matching organization")
            return 1
        for org in orgs:
            set_tenant(session, org.id)
            stats = recompute_escalation(session, org.id, apply=apply, notify=notify)
            session.commit()
            verb = "applied" if apply else "dry run (use --apply)"
            print(f"{org.slug}: {verb} - checked {stats['checked']} · changed "
                  f"{stats['changed']} (lowered {stats['lowered']}, raised "
                  f"{stats['raised']}) · unchanged {stats['unchanged']} · "
                  f"notified {stats['notified']} · levels {stats['levels']}")
    return 0


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
    """`python -m veyrs run-sla` — the SLA/escalation sweep (every hourly tick).

    The CLI wired this command to a `veyrs.engines.sla` module that never
    existed, so the command had never run and no finding ever received a
    deadline outside a request. Same shape as `engines.risk.run_cli`: every
    active organization, unscoped on purpose — this is the sweep the scope
    docstring on `evaluate_findings` calls the "unrestricted sweep".
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
    "deadline_for", "run_cli", "run_recompute_cli", "recompute_escalation",
    "resolve_escalation_recipients", "missing_builtin_policies", "Recipients", "BUILTIN_SLA_POLICIES", "BUILTIN_ESCALATION",
]
