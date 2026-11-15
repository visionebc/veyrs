"""How often each intelligence feed refreshes, and who gets to decide.

Until now the cadence was a fact about the host, not about the product: the
four feeds ran because ``veyrs-intel-sync.timer`` fired at 03:30, and the only
way to change that was to edit a systemd unit over SSH. That is not a setting,
it is a deployment detail wearing a setting's clothes -- an operator reading
"Threat Intel" in the console had no way to learn when it last ran, when it
runs next, or to make KEV hourly during an active exploitation event.

**The awkward part, stated rather than hidden.** The corpus these feeds
download is GLOBAL: ``cves``, ``kev_entries``, ``epss_scores`` and ``cwe`` have
no ``organization_id``, because CVE-2024-3094 is the same row for every tenant.
So a per-tenant cadence cannot mean "download my own copy". What it means here
is the tenant's *demand*, and the effective schedule is the TIGHTEST demand
across the tenants that want the feed:

* a feed is fetched if **any** active organization has it enabled;
* it is fetched at the **smallest** interval any of those organizations asked
  for.

Averaging them would give every tenant a cadence nobody chose. Taking the
loosest would let one tenant's monthly setting starve another's hourly one --
silently, and in the direction of stale intelligence, which is the direction
that costs money. Taking the tightest costs one deployment more bandwidth and
is the only option where nobody gets less than they configured. The API says
so out loud (``shared``/``effective``) so an administrator who sets 24h and
observes 1h is not looking at a bug.

**The timer becomes a tick, not a schedule.** ``veyrs-intel-sync.timer`` fires
hourly and the script asks this module what is actually due, so changing a
cadence in the console takes effect without touching systemd. A feed whose
interval has not elapsed is skipped, and skipping is reported -- a run that
silently does nothing looks exactly like a run that worked.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import FeedRun  # noqa: F401 - re-exported type for callers
from ..models.tenancy import Organization

#: Key under ``organizations.settings``.
SETTINGS_KEY = "intel_schedule"

#: The feeds this module schedules, in the order ``sync-intel.sh`` runs them.
#: Order is not cosmetic: CWE names what NVD creates, EPSS skips CVEs it has
#: never seen, and KEV is the last word on the day's priority order.
FEEDS: tuple[str, ...] = ("cwe", "nvd", "epss", "kev")

FEED_LABEL = {
    "cwe": "CWE dictionary (MITRE)",
    "nvd": "NVD CVE records",
    "epss": "EPSS exploit probability",
    "kev": "CISA Known Exploited Vulnerabilities",
}

#: Defaults reproduce the pre-setting behaviour EXACTLY: every feed enabled,
#: every feed daily. An upgrade must not change what a deployment does; the
#: operator changes it, or nothing changes.
DEFAULT_INTERVAL_MINUTES = {"cwe": 1440, "nvd": 1440, "epss": 1440, "kev": 1440}

#: One hour is the floor because the timer ticks hourly -- offering 15 minutes
#: in a form that can only act every 60 would be a control that lies. The
#: ceiling is 30 days: past that a feed is not "slow", it is off, and there is
#: an enable switch for saying so honestly.
MIN_INTERVAL_MINUTES = 60
MAX_INTERVAL_MINUTES = 43200


class ScheduleError(ValueError):
    """Raised for a cadence the scheduler will not accept."""


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def _feed_block(block: dict[str, Any], feed: str) -> dict[str, Any]:
    entry = (block.get("feeds") or {}).get(feed)
    if not isinstance(entry, dict):
        entry = {}
    return {
        "enabled": bool(entry.get("enabled", True)),
        "interval_minutes": int(entry.get("interval_minutes", DEFAULT_INTERVAL_MINUTES[feed])),
        "explicit": "enabled" in entry or "interval_minutes" in entry,
    }


def clamp(minutes: int) -> int:
    """Bring a requested cadence inside the range the tick can honour."""
    return max(MIN_INTERVAL_MINUTES, min(MAX_INTERVAL_MINUTES, int(minutes)))


def last_run(session: Session, feed: str) -> FeedRun | None:
    """The last SUCCESSFUL run, which is what "due" is measured from.

    A failed run must not reset the clock: if NVD errors at 03:30, the feed is
    still as stale as it was, and treating the failure as a refresh is how an
    outage turns into a week of quietly old data.

    It delegates to `intelligence.last_successful_run` rather than writing the
    predicate again. The first draft of this module spelled the terminal state
    `"success"`; the column holds `"succeeded"`, so the query matched nothing,
    every feed reported "never completed successfully" and the scheduler would
    have run all four on every single tick -- a setting that silently does the
    opposite of what it says. There is one definition of a successful feed run
    and this is not the place to keep a second copy of it.
    """
    from . import intelligence

    return intelligence.last_successful_run(session, feed)


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=dt.timezone.utc)


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The schedule as one tenant asked for it, next to what actually happens."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    effective = effective_schedule(session)
    now = dt.datetime.now(dt.timezone.utc)

    feeds = []
    for feed in FEEDS:
        mine = _feed_block(block, feed)
        run = last_run(session, feed)
        finished = _as_utc(run.finished_at or run.started_at) if run is not None else None
        eff = effective[feed]
        next_due = (
            finished + dt.timedelta(minutes=eff["interval_minutes"])
            if finished is not None and eff["enabled"] else None
        )
        feeds.append({
            "feed": feed,
            "label": FEED_LABEL[feed],
            "enabled": mine["enabled"],
            "interval_minutes": mine["interval_minutes"],
            "explicit": mine["explicit"],
            "effective_enabled": eff["enabled"],
            "effective_interval_minutes": eff["interval_minutes"],
            "last_success_at": finished.isoformat() if finished else None,
            "next_due_at": next_due.isoformat() if next_due else None,
            "due_now": bool(eff["enabled"] and (next_due is None or next_due <= now)),
        })
    return {
        "feeds": feeds,
        # Never defaulted away: an operator has to be able to tell a decision
        # somebody made from the value VEYRS shipped with.
        "explicit": any(f["explicit"] for f in feeds),
        # The corpus is shared, so "your" schedule and "the" schedule can
        # legitimately differ. Saying it in the payload beats a footnote.
        "shared": True,
        "min_interval_minutes": MIN_INTERVAL_MINUTES,
        "max_interval_minutes": MAX_INTERVAL_MINUTES,
        "changed_at": block.get("changed_at"),
        "changed_by_id": block.get("changed_by_id"),
    }


def effective_schedule(session: Session) -> dict[str, dict[str, Any]]:
    """Tightest demand across active tenants, per feed. See the module docstring."""
    organizations = session.execute(
        select(Organization).where(Organization.is_active.is_(True))
    ).scalars().all()

    out: dict[str, dict[str, Any]] = {}
    for feed in FEEDS:
        enabled = False
        interval = DEFAULT_INTERVAL_MINUTES[feed]
        wanted: list[int] = []
        for organization in organizations:
            mine = _feed_block(_block(organization), feed)
            if mine["enabled"]:
                enabled = True
                wanted.append(clamp(mine["interval_minutes"]))
        if wanted:
            interval = min(wanted)
        if not organizations:
            # A deployment with no active tenant still refreshes: the corpus is
            # what a new tenant is onboarded ONTO, and arriving to an empty CVE
            # table is a worse first day than one wasted download.
            enabled = True
        out[feed] = {"enabled": enabled, "interval_minutes": clamp(interval)}
    return out


def due_feeds(session: Session, *, now: dt.datetime | None = None) -> list[dict[str, Any]]:
    """Which feeds the next tick should actually run, and why each one was skipped."""
    now = now or dt.datetime.now(dt.timezone.utc)
    effective = effective_schedule(session)
    decisions = []
    for feed in FEEDS:
        eff = effective[feed]
        if not eff["enabled"]:
            decisions.append({"feed": feed, "due": False, "reason": "disabled by every tenant"})
            continue
        run = last_run(session, feed)
        finished = _as_utc(run.finished_at or run.started_at) if run is not None else None
        if finished is None:
            decisions.append({"feed": feed, "due": True, "reason": "never completed successfully"})
            continue
        elapsed = (now - finished).total_seconds() / 60.0
        if elapsed >= eff["interval_minutes"]:
            decisions.append({
                "feed": feed, "due": True,
                "reason": f"{int(elapsed)} min since last success, interval "
                          f"{eff['interval_minutes']} min",
            })
        else:
            decisions.append({
                "feed": feed, "due": False,
                "reason": f"{int(elapsed)} min since last success, interval "
                          f"{eff['interval_minutes']} min",
            })
    return decisions


def set_schedule(
    session: Session,
    organization_id: uuid.UUID,
    feeds: dict[str, dict[str, Any]],
    *,
    actor_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Set this tenant's demand for some or all feeds.

    An unknown feed name is REFUSED rather than ignored: a client that typos
    ``nvd2`` and gets a 200 believes it changed something it did not, and the
    only symptom is intelligence that never speeds up.
    """
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    unknown = sorted(set(feeds) - set(FEEDS))
    if unknown:
        raise ScheduleError(
            f"unknown feed(s): {', '.join(unknown)}; known feeds are {', '.join(FEEDS)}"
        )

    block = _block(organization)
    current = dict(block.get("feeds") or {})
    for feed, spec in feeds.items():
        entry = dict(current.get(feed) or {})
        if "enabled" in spec:
            entry["enabled"] = bool(spec["enabled"])
        if spec.get("interval_minutes") is not None:
            requested = int(spec["interval_minutes"])
            if requested < MIN_INTERVAL_MINUTES or requested > MAX_INTERVAL_MINUTES:
                raise ScheduleError(
                    f"{feed}: interval must be between {MIN_INTERVAL_MINUTES} and "
                    f"{MAX_INTERVAL_MINUTES} minutes; got {requested}"
                )
            entry["interval_minutes"] = requested
        current[feed] = entry

    block["feeds"] = current
    block["changed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    block["changed_by_id"] = str(actor_id) if actor_id else None

    # Reassign rather than mutate: SQLAlchemy does not track in-place mutation
    # of a plain dict inside JSONB, and an in-place update is a write that
    # silently does not happen. Same trap as services/scanning.py.
    settings = dict(organization.settings or {})
    settings[SETTINGS_KEY] = block
    organization.settings = settings
    session.flush()
    return state(session, organization_id)
