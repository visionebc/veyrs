"""The hourly tick: what it does besides the feeds, and proof that it ran.

`scripts/sync-intel.sh` is the tick (a systemd timer on a host, the `workers`
profile in Docker). It refreshes the feeds that are due, runs the SLA sweep and
then `veyrs maintenance`, which is this module's `run_maintenance`:

1. **dispatch** queued notifications (in-app and e-mail) for every organization.
   Until 0.41.0 only the digest run did, so SLA and workflow e-mails waited for
   the digest hour or never left when the digest was off (the default).
2. **reap** expired agent job leases and mark silent agents offline.
3. **expire** risk acceptances whose date has passed (and warn about the ones
   about to).
4. **prune** by the retention settings (`services/retention`).

Each step is isolated: one failing never skips the rest, and the first failure
makes the tick exit non-zero so the timer unit records a real failure.

The tick used to be invisible: a stopped timer left feeds and SLA stale with
nothing in the console to say so. `mark_start` / `mark_finish` record the last
start, finish, result and last success per organization in
`organizations.settings["tick"]`; `health` reports it and
`GET /api/v1/intel/health` exposes it as `tick`. `mark_start` also prints the
minutes since the last success so the journal shows a gap the moment the tick
resumes.
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Organization

log = logging.getLogger("veyrs.tick")

SETTINGS_KEY = "tick"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _parse(value: Any) -> dt.datetime | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _write(session: Session, org: Organization, **fields: Any) -> None:
    block = {**((org.settings or {}).get(SETTINGS_KEY) or {}), **fields}
    org.settings = {**(org.settings or {}), SETTINGS_KEY: block}


def minutes_since_success(block: dict | None, now: dt.datetime | None = None) -> float | None:
    last = _parse((block or {}).get("last_success_at"))
    if last is None:
        return None
    return round(((now or _now()) - last).total_seconds() / 60.0, 1)


def mark_start(*, now: dt.datetime | None = None) -> dict[str, float | None]:
    """Record that a tick began; returns `{org slug: minutes since last success}`."""
    from ..db import SessionLocal  # organizations carries no RLS policy

    now = now or _now()
    gaps: dict[str, float | None] = {}
    with SessionLocal() as session:
        for org in session.execute(
            select(Organization).where(Organization.is_active.is_(True))
        ).scalars().all():
            block = (org.settings or {}).get(SETTINGS_KEY) or {}
            gaps[org.slug] = minutes_since_success(block, now)
            _write(session, org, last_started_at=now.isoformat(), last_status="running")
        session.commit()
    return gaps


def mark_finish(ok: bool, detail: str = "", *, now: dt.datetime | None = None) -> int:
    from ..db import SessionLocal

    now = now or _now()
    count = 0
    with SessionLocal() as session:
        for org in session.execute(
            select(Organization).where(Organization.is_active.is_(True))
        ).scalars().all():
            fields: dict[str, Any] = {
                "last_finished_at": now.isoformat(),
                "last_status": "ok" if ok else "failed",
                "last_detail": detail[:500],
            }
            if ok:
                fields["last_success_at"] = now.isoformat()
            _write(session, org, **fields)
            count += 1
        session.commit()
    return count


def health(session: Session, organization_id: uuid.UUID, *,
           now: dt.datetime | None = None) -> dict[str, Any]:
    """What `GET /intel/health` reports as `tick`."""
    now = now or _now()
    org = session.get(Organization, organization_id)
    block = ((org.settings or {}).get(SETTINGS_KEY) or {}) if org else {}
    since = minutes_since_success(block, now)
    limit = settings.tick_stale_minutes
    if not block.get("last_started_at") and since is None:
        status = "never_run"
    elif since is None or since > limit:
        status = "stale"
    elif block.get("last_status") == "failed":
        status = "failing"
    else:
        status = "ok"
    return {
        "status": status,
        "last_started_at": block.get("last_started_at"),
        "last_finished_at": block.get("last_finished_at"),
        "last_success_at": block.get("last_success_at"),
        "last_result": block.get("last_status"),
        "last_detail": block.get("last_detail"),
        "minutes_since_success": since,
        "stale_after_minutes": limit,
    }


# --------------------------------------------------------------------------
# Maintenance steps
# --------------------------------------------------------------------------


def _step_dispatch(session: Session, org: Organization) -> str:
    from . import notifications

    hold = not settings.smtp_host
    stats = notifications.dispatch(session, org.id, hold_email=hold)
    note = " (e-mail held: VEYRS_SMTP_HOST is empty)" if hold and settings.notify_email_enabled \
        else ""
    return f"dispatch {stats}{note}"


def _step_reap(session: Session, org: Organization) -> str:
    from . import agents

    leases = agents.reap_expired_leases(session, org.id)
    offline = agents.mark_stale_agents_offline(session, org.id)
    return f"agents: {leases}, {offline} marked offline"


def _step_expire(session: Session, org: Organization) -> str:
    from . import engagements

    result = engagements.expire_due(session, org.id)
    return f"risk acceptances: {result}"


STEPS = (("dispatch", _step_dispatch), ("reap-agents", _step_reap),
         ("expire-acceptances", _step_expire))


def run_maintenance(*, prune_apply: bool = True) -> int:
    """`python -m veyrs maintenance`. Returns 0, or 1 if any step failed."""
    from ..db import SessionLocal, set_tenant
    from . import retention

    failed = 0
    with SessionLocal() as session:
        orgs = session.execute(
            select(Organization).where(Organization.is_active.is_(True))
        ).scalars().all()
        for org in orgs:
            for name, step in STEPS:
                try:
                    set_tenant(session, org.id)
                    message = step(session, org)
                    session.commit()
                    print(f"{org.slug}: {message}")
                except Exception as exc:  # noqa: BLE001 - isolated per step
                    session.rollback()
                    failed += 1
                    log.exception("maintenance step %s failed for %s", name, org.slug)
                    print(f"!!! {org.slug}: {name} failed: {type(exc).__name__}: {exc}")
    try:
        result = retention.prune(apply=prune_apply)
        for table, entry in result.items():
            if entry["rows"]:
                verb = "deleted" if prune_apply else "would delete"
                print(f"retention: {table}: {verb} {entry['rows']}")
    except Exception as exc:  # noqa: BLE001
        failed += 1
        log.exception("retention failed")
        print(f"!!! retention failed: {type(exc).__name__}: {exc}")
    return 1 if failed else 0
