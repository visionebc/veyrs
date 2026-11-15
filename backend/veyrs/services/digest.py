"""The daily digest: VEYRS goes out and finds the operator.

The measurement that produced this module: 408 findings, 5 tickets, 74
notifications ever generated, zero webhook endpoints, and one user who had not
logged in for thirteen days. Everything the platform knew, it knew silently. A
console nobody opens is a console with no readers, not a console with no news.

Four decisions, and the reasons they are not obvious:

* **Off by default, per organization.** `organizations.settings["digest"]`,
  the same JSONB block `scanning` and `auto_ticket` use. Turning it on is a
  decision with a blast radius -- every eligible user starts receiving mail --
  and the platform does not get to make it on an administrator's behalf.
* **Recipients are computed from PERMISSIONS, not from team membership.**
  Membership answers "whose queue is this"; grants answer "what may you read".
  A digest sent on membership would tell somebody who joined a team what that
  team's estate looks like -- the exact leak `security/scope` exists to
  prevent, arriving by email where no scope banner can qualify it.
* **Every digest is built under its recipient's OWN scope.** Not one estate
  digest fanned out to a list. A restricted operator receives their slice, and
  the payload says so, because "3 critical" and "3 critical that you can see"
  are different sentences and email has no scope banner.
* **An empty digest is not sent.** A message that says "nothing happened"
  every morning trains its reader to delete it unread, and then the one that
  matters gets deleted too. `force=True` exists for the preview endpoint, where
  the operator asked to see it.

**What this module does NOT do: deliver.** It queues `Notification` rows
through `notifications.queue`, exactly like every other event, so the digest is
auditable ("was the CISO told?") and inherits the retry and per-user mute
machinery instead of reimplementing it. Delivery is `notifications.dispatch`.
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    Asset, Finding, FindingState, OPEN_STATES, Organization, Ticket, User,
)
from ..security import scope as team_scope
from . import notifications

log = logging.getLogger("veyrs.digest")

SETTINGS_KEY = "digest"
EVENT = "digest.daily"

DEFAULT_ENABLED = False
#: UTC hour the timer should fire. Stored so the console can show it and the
#: shell can ask; the timer itself runs hourly and asks whether it is time.
DEFAULT_HOUR = 7
DEFAULT_WINDOW_HOURS = 24
#: What counts as worth waking somebody for. `high` and above by default: a
#: digest that lists every informational finding is a digest nobody finishes.
DEFAULT_MIN_SEVERITY = "high"
DEFAULT_CHANNELS = ("in_app", "email")
#: How many rows are named in the message. The rest are a count and a link --
#: a hundred-line email is an attachment, not a notification.
TOP_N = 8

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": 0}


class DigestError(ValueError):
    """Rejected configuration. The API turns this into a 422."""


def _block(organization: Organization | None) -> dict[str, Any]:
    if organization is None:
        return {}
    return dict((organization.settings or {}).get(SETTINGS_KEY) or {})


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The effective policy, defaults filled in. Never returns None."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    return {
        "enabled": bool(block.get("enabled", DEFAULT_ENABLED)),
        "hour": int(block.get("hour", DEFAULT_HOUR)),
        "window_hours": int(block.get("window_hours", DEFAULT_WINDOW_HOURS)),
        "min_severity": str(block.get("min_severity", DEFAULT_MIN_SEVERITY)),
        "channels": list(block.get("channels", DEFAULT_CHANNELS)),
        "include_sla": bool(block.get("include_sla", True)),
        "include_unassigned": bool(block.get("include_unassigned", True)),
        "last_run_at": block.get("last_run_at"),
        "last_recipients": block.get("last_recipients"),
    }


def set_policy(session: Session, organization_id: uuid.UUID,
               payload: dict[str, Any]) -> dict[str, Any]:
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise DigestError("unknown organization")
    block = _block(organization)
    if "hour" in payload and payload["hour"] is not None:
        hour = int(payload["hour"])
        if not 0 <= hour <= 23:
            raise DigestError("hour must be 0-23 (UTC)")
        block["hour"] = hour
    if "window_hours" in payload and payload["window_hours"] is not None:
        window = int(payload["window_hours"])
        if not 1 <= window <= 168:
            raise DigestError("window_hours must be between 1 and 168")
        block["window_hours"] = window
    if payload.get("min_severity") is not None:
        severity = str(payload["min_severity"]).lower()
        if severity not in SEVERITY_RANK:
            raise DigestError(f"unknown severity {severity!r}")
        block["min_severity"] = severity
    if payload.get("channels") is not None:
        channels = [str(c) for c in payload["channels"]]
        unknown = [c for c in channels if c not in notifications.TRANSPORTS]
        if unknown:
            raise DigestError(f"no transport for channel(s): {', '.join(unknown)}")
        if not channels:
            raise DigestError("a digest with no channel is a digest nobody receives")
        block["channels"] = channels
    for flag in ("enabled", "include_sla", "include_unassigned"):
        if payload.get(flag) is not None:
            block[flag] = bool(payload[flag])
    # Reassign rather than mutate: SQLAlchemy does not track in-place JSONB edits,
    # so a mutated dict is a setting that saves in tests and not in production.
    organization.settings = {**(organization.settings or {}), SETTINGS_KEY: block}
    session.flush()
    return state(session, organization_id)


def _mark_run(session: Session, organization_id: uuid.UUID, recipients: int) -> None:
    organization = session.get(Organization, organization_id)
    if organization is None:
        return
    block = _block(organization)
    block["last_run_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    block["last_recipients"] = recipients
    organization.settings = {**(organization.settings or {}), SETTINGS_KEY: block}
    session.flush()


# ---------------------------------------------------------------------------
# Building one person's digest
# ---------------------------------------------------------------------------


def _severity_floor(minimum: str) -> list[str]:
    floor = SEVERITY_RANK.get(minimum, 3)
    return [name for name, rank in SEVERITY_RANK.items() if rank >= floor and rank > 0]


def build(
    session: Session,
    organization_id: uuid.UUID,
    *,
    scope: team_scope.TeamScope | None = None,
    user: User | None = None,
    policy: dict[str, Any] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """What one recipient would be told, under their own scope.

    Read-only. The preview endpoint and the sender call the SAME function, so
    "show me what this will send" cannot drift from what it sends -- the defect
    `autoticket.matches()` was written as one predicate to avoid.
    """
    policy = policy or state(session, organization_id)
    now = now or dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(hours=int(policy.get("window_hours") or DEFAULT_WINDOW_HOURS))
    severities = _severity_floor(policy.get("min_severity") or DEFAULT_MIN_SEVERITY)

    base = Finding.organization_id == organization_id
    if scope is not None and scope.restricted:
        from sqlalchemy import and_

        base = and_(base, team_scope.finding_clause(scope))

    open_states = tuple(OPEN_STATES)

    def count(stmt) -> int:
        return int(session.execute(
            select(func.count()).select_from(stmt.subquery())
        ).scalar_one() or 0)

    new_stmt = (select(Finding).where(base)
                .where(Finding.detected_at >= since)
                .where(Finding.severity.in_(severities))
                .where(Finding.state.in_(open_states)))
    breached_stmt = (select(Finding).where(base)
                     .where(Finding.sla_breached.is_(True))
                     .where(Finding.state.in_(open_states)))
    kev_stmt = (select(Finding).where(base)
                .where(Finding.kev.is_(True))
                .where(Finding.state.in_(open_states)))
    untriaged_stmt = (select(Finding).where(base)
                      .where(Finding.state == FindingState.NEW.value))

    top = session.execute(
        new_stmt.order_by(Finding.risk_score.desc().nullslast()).limit(TOP_N)
    ).scalars().all()
    late = session.execute(
        breached_stmt.order_by(Finding.sla_due_at.asc().nullslast()).limit(TOP_N)
    ).scalars().all()

    asset_names: dict[uuid.UUID, str] = {}
    ids = {f.asset_id for f in [*top, *late] if f.asset_id}
    if ids:
        asset_names = {
            a.id: a.name for a in session.execute(
                select(Asset).where(Asset.id.in_(tuple(ids)))
            ).scalars().all()
        }

    def row(f: Finding) -> dict[str, Any]:
        return {
            "id": str(f.id), "title": f.title, "severity": f.severity,
            "risk_score": float(f.risk_score) if f.risk_score is not None else None,
            "kev": bool(f.kev), "state": f.state,
            "asset": asset_names.get(f.asset_id) or "",
            "due_at": f.sla_due_at.isoformat() if f.sla_due_at else None,
        }

    ticket_clause = Ticket.organization_id == organization_id
    if scope is not None and scope.restricted:
        from sqlalchemy import and_

        ticket_clause = and_(ticket_clause, team_scope.ticket_clause(scope))
    open_tickets = count(select(Ticket).where(ticket_clause)
                         .where(Ticket.state.notin_(("resolved", "closed", "cancelled"))))

    counts = {
        "new_findings": count(new_stmt),
        "sla_breached": count(breached_stmt) if policy.get("include_sla", True) else 0,
        "kev_open": count(kev_stmt),
        "untriaged": count(untriaged_stmt) if policy.get("include_unassigned", True) else 0,
        "open_tickets": open_tickets,
    }
    return {
        "generated_at": now.isoformat(),
        "window_hours": int(policy.get("window_hours") or DEFAULT_WINDOW_HOURS),
        "min_severity": policy.get("min_severity") or DEFAULT_MIN_SEVERITY,
        "recipient": {"id": str(user.id), "email": user.email,
                      "name": user.full_name or user.email} if user else None,
        "counts": counts,
        "top_new": [row(f) for f in top],
        "top_breached": [row(f) for f in late],
        # Same contract as every dashboard: a partial view must never read as
        # a total one, and an email carries no banner to say so.
        "scope": {"restricted": bool(scope.restricted) if scope else False,
                  "teams": len(scope.team_ids) if scope and scope.restricted else 0},
        "empty": not any(counts.values()),
    }


def render_body(payload: dict[str, Any], *, console_url: str = "") -> str:
    """Plain text. The digest has to survive a phone's lock screen."""
    c = payload["counts"]
    lines = [
        f"VEYRS daily digest - last {payload['window_hours']} h",
        "",
        f"  New findings ({payload['min_severity']}+): {c['new_findings']}",
        f"  Past SLA:                    {c['sla_breached']}",
        f"  Known exploited (KEV) open:  {c['kev_open']}",
        f"  Never triaged:               {c['untriaged']}",
        f"  Open tickets:                {c['open_tickets']}",
    ]
    if payload["scope"]["restricted"]:
        lines += ["", "These figures cover your teams only. A zero here means "
                      "zero in your scope."]
    if payload["top_new"]:
        lines += ["", "Highest risk, newly detected:"]
        lines += [f"  - [{f['severity']}] {f['title']} ({f['asset']})"
                  f"{' KEV' if f['kev'] else ''}" for f in payload["top_new"]]
    if payload["top_breached"]:
        lines += ["", "Already past its deadline:"]
        lines += [f"  - {f['title']} ({f['asset']}) due {f['due_at'] or 'unknown'}"
                  for f in payload["top_breached"]]
    if console_url:
        lines += ["", f"Triage queue: {console_url.rstrip('/')}/#/triage"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------


def recipients(session: Session, organization_id: uuid.UUID) -> list[User]:
    """Active users whose grants let them read findings.

    Permissions, not membership -- see the module docstring. Resolving them one
    user at a time is a handful of queries once a day; the alternative is a
    join that has to be kept in step with `effective_permissions`, and the copy
    that drifts is the one that decides who gets told about a breach.
    """
    from ..security.deps import effective_permissions

    rows = session.execute(
        select(User).where(User.organization_id == organization_id,
                           User.is_active.is_(True))
    ).scalars().all()
    out: list[User] = []
    for user in rows:
        perms = effective_permissions(session, user)
        if getattr(user, "is_superuser", False) or "finding:read" in perms:
            out.append(user)
    return out


def run(
    session: Session,
    organization_id: uuid.UUID,
    *,
    dry_run: bool = False,
    force: bool = False,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Queue today's digest for every eligible recipient.

    `force` skips the enabled check and the empty-digest suppression; it is
    what the preview endpoint and `--force` on the CLI use. It does NOT skip
    per-user mutes: an operator who switched the digest off asked for that, and
    an administrator pressing "send now" is not new information.
    """
    policy = state(session, organization_id)
    now = now or dt.datetime.now(dt.timezone.utc)
    if not policy["enabled"] and not force:
        return {"enabled": False, "queued": 0, "recipients": 0, "skipped_empty": 0,
                "reason": "digest is disabled for this organization"}

    people = recipients(session, organization_id)
    queued = 0
    skipped_empty = 0
    per_user: list[dict[str, Any]] = []
    for user in people:
        scope = team_scope.resolve_for_user(
            session, user.id, organization_id,
            is_superuser=bool(getattr(user, "is_superuser", False)),
        )
        payload = build(session, organization_id, scope=scope, user=user,
                        policy=policy, now=now)
        if payload["empty"] and not force:
            skipped_empty += 1
            per_user.append({"user": user.email, "queued": 0, "empty": True})
            continue
        made: list = []
        if not dry_run:
            made = notifications.queue(
                session, organization_id, EVENT,
                {
                    "subject_counts": (
                        f"{payload['counts']['new_findings']} new, "
                        f"{payload['counts']['sla_breached']} past SLA"
                    ),
                    "body": render_body(payload),
                    **{k: str(v) for k, v in payload["counts"].items()},
                },
                users=[user], channels=tuple(policy["channels"]),
            )
            queued += len(made)
        per_user.append({"user": user.email, "queued": len(made),
                         "empty": False, "counts": payload["counts"]})
    if not dry_run:
        _mark_run(session, organization_id, len(per_user) - skipped_empty)
    return {"enabled": policy["enabled"], "dry_run": dry_run,
            "recipients": len(people), "queued": queued,
            "skipped_empty": skipped_empty, "detail": per_user}


def due_now(policy: dict[str, Any], *, now: dt.datetime | None = None) -> bool:
    """Is this the hour? The timer fires hourly and asks.

    An `OnCalendar` pinned to one hour cannot be changed from the console, and a
    setting the console shows but the machine ignores is worse than no setting.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if not policy.get("enabled"):
        return False
    if now.hour != int(policy.get("hour", DEFAULT_HOUR)):
        return False
    last = policy.get("last_run_at")
    if not last:
        return True
    try:
        previous = dt.datetime.fromisoformat(str(last))
    except ValueError:
        return True
    if previous.tzinfo is None:
        previous = previous.replace(tzinfo=dt.timezone.utc)
    # Guards against a double fire inside the same hour after a restart.
    return (now - previous) >= dt.timedelta(hours=12)


def run_cli(*, dry_run: bool = False, force: bool = False) -> int:
    """`python -m veyrs digest`. Every enabled organization whose hour it is."""
    from ..db import SessionLocal, set_tenant

    sent = 0
    with SessionLocal() as session:
        orgs = session.execute(
            select(Organization).where(Organization.is_active.is_(True))
        ).scalars().all()
        for org in orgs:
            set_tenant(session, org.id)
            policy = state(session, org.id)
            if not force and not due_now(policy):
                continue
            result = run(session, org.id, dry_run=dry_run, force=force)
            sent += result["queued"]
            print(f"{org.slug}: queued {result['queued']} for "
                  f"{result['recipients']} recipient(s), "
                  f"{result['skipped_empty']} had nothing to say")
            if not dry_run:
                stats = notifications.dispatch(session, org.id)
                print(f"{org.slug}: dispatch {stats}")
            session.commit()
    return 0
