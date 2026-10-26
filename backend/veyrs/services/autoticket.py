"""Open remediation tickets without a human clicking, and refuse to do it badly.

Phase 29 wired the console to `POST /tickets` so a finding could become a
ticket. It was still a person, one finding at a time -- which is why the
production estate reached 407 findings and 0 tickets: the capability existed
and nothing exercised it.

**The reason this is OFF by default, and stays off until somebody says
otherwise.** Turning it on against an estate that already has hundreds of open
findings would, on the next correlation pass, create hundreds of tickets --
each with a reference number, an SLA deadline and a notification. That is not
"the feature working", that is a queue nobody can triage and an ITSM connector
pushing hundreds of rows into somebody else's Jira. So:

* the switch defaults to disabled, and enabling it changes NOTHING about
  findings that already exist;
* `preview()` answers *how many tickets this would create* before the operator
  commits, from the same predicate the automation uses -- not a similar one;
* the backlog is an explicit, separately-authorised `backfill()`, with a
  `dry_run` and a hard `limit`, never a side effect of flipping a switch;
* every run is capped. A cap that is hit is REPORTED (`capped: true`), because
  a silent truncation reads as "everything is ticketed" when it is not.

**What decides whether a finding earns a ticket** is a conjunction, evaluated
in `matches()`, and it is the single place that answers the question -- the
preview, the backfill and the live hook all call it. Two implementations of
"which findings matter" is how a preview promises 12 and the automation
produces 300.

Deliberately NOT configurable, because each would be a way to make the feature
quietly wrong:

* **Ticket type is always `remediation`.** It is the only type that dedupes per
  finding, carries the REM prefix, and advances its finding on resolution. The
  backend accepts any string and silently creates a dead-end type (the console
  bug found in phase 29).
* **Dedupe is not optional.** `ticketing.ticket_for_finding` returns the
  existing open ticket rather than a second one; a "create anyway" mode is how
  a vulnerability programme loses the plot.
* **Closed and remediated findings never get one.** A ticket for work that is
  already done is an inbox item whose only possible outcome is being closed
  again.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Asset, Finding, OPEN_STATES, Ticket, TicketEvent
from ..models.tenancy import Organization
from . import remediation, ticketing

#: The label every automatic creation is stamped with. It is what makes the
#: budget below countable, and what lets an operator tell in the ticket's own
#: history whether a person or the platform opened it.
ACTOR_LABEL = "auto-ticket"

#: The budget window. `max_per_run` is enforced over the last hour rather than
#: over "a run", because there is no such thing as a run: findings are
#: processed one at a time from four different entry points (feed correlation,
#: a new asset, an import, a connector sync). Threading a counter through all
#: of them works exactly until somebody adds the fifth -- the same failure the
#: phase-26 scope guardrail exists to prevent. A wall-clock window is enforced
#: identically no matter who calls.
BUDGET_WINDOW_MINUTES = 60

#: Key under ``organizations.settings``.
SETTINGS_KEY = "auto_ticket"

#: Default OFF. See the module docstring: an upgrade that starts opening
#: tickets on its own is an upgrade that pages somebody at 03:30.
DEFAULT_ENABLED = False

#: Default trigger, used when the switch is turned on without a threshold.
#: 70 is the floor of `high` in the risk bands (`engines/risk.py`), so the
#: shipped default is "high and critical" -- the band an operator would name
#: if asked, rather than a number invented here.
DEFAULT_MIN_RISK_SCORE = 70.0

#: A single correlation pass creating more than this is not a working
#: automation, it is an incident. The cap is reported, never silent.
DEFAULT_MAX_PER_RUN = 50
MAX_PER_RUN_CEILING = 500

#: `backfill` reaches further than a live pass because it is a deliberate,
#: audited, one-off catch-up rather than a background side effect.
BACKFILL_CEILING = 2000

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info", "none")


class AutoTicketError(ValueError):
    """Raised for a configuration the automation will not accept."""


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The policy as the console and the automation both read it."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    severities = block.get("severities")
    if not isinstance(severities, list):
        severities = []
    return {
        "enabled": bool(block.get("enabled", DEFAULT_ENABLED)),
        "min_risk_score": (
            None if block.get("min_risk_score", DEFAULT_MIN_RISK_SCORE) is None
            else float(block.get("min_risk_score", DEFAULT_MIN_RISK_SCORE))
        ),
        "severities": [s for s in severities if s in VALID_SEVERITIES],
        "require_kev": bool(block.get("require_kev", False)),
        "internet_exposed_only": bool(block.get("internet_exposed_only", False)),
        "require_owner": bool(block.get("require_owner", True)),
        "max_per_run": int(block.get("max_per_run", DEFAULT_MAX_PER_RUN)),
        # Never defaulted away: "disabled" as a decision and "disabled" as the
        # shipped default are different facts, and only one of them means
        # somebody has thought about it.
        "explicit": "enabled" in block,
        "changed_at": block.get("changed_at"),
        "changed_by_id": block.get("changed_by_id"),
    }


def is_enabled(session: Session, organization_id: uuid.UUID) -> bool:
    return bool(state(session, organization_id)["enabled"])


def _has_owner(finding: Finding, asset: Asset | None) -> bool:
    """The EFFECTIVE owner, not the explicit one.

    This read `finding.assigned_team_id` alone until v0.22.0, which is the
    phase-26 defect in its most expensive form. Ownership in VEYRS is an
    explicit assignment *or*, failing that, the team that owns the asset --
    that is what `services.teams.owning_team()` computes and what every queue
    filters on. Almost no finding carries an explicit assignment: production
    had 408 findings over 14 fully-owned assets, 5 of them above the risk
    threshold, and `require_owner` (which defaults ON) rejected every one.
    Automatic ticketing could be switched on, report success, and create
    nothing, forever, on an estate that is completely owned -- and the operator
    would read that as "no findings qualify".

    Resolved from the `asset` every caller already loads rather than with a
    query: `owning_team()` is a correlated subquery built for a SELECT, and
    this is a predicate over a row already in memory.
    """
    if finding.assigned_team_id or finding.assigned_user_id:
        return True
    return asset is not None and getattr(asset, "team_id", None) is not None


def matches(finding: Finding, policy: dict[str, Any], *, asset: Asset | None = None) -> bool:
    """The one predicate. Preview, backfill and the live hook all come here.

    An empty `severities` list means "do not filter by severity", NOT "match
    nothing": an omitted optional and a deliberate empty set are the same JSON,
    and reading it as an exclusion would make a policy that names only a risk
    threshold silently ticket nothing at all.
    """
    if finding.state not in OPEN_STATES:
        return False

    threshold = policy.get("min_risk_score")
    if threshold is not None:
        # A finding with no risk score yet has not been through the engine.
        # Treating "unknown" as "above the bar" would ticket every row the
        # moment it is created, before anything is known about it.
        if finding.risk_score is None or finding.risk_score < threshold:
            return False

    severities = policy.get("severities") or []
    if severities and (finding.severity or "").lower() not in severities:
        return False

    if policy.get("require_kev") and not finding.kev:
        return False

    if policy.get("internet_exposed_only"):
        if asset is None or asset.exposure != "internet":
            return False

    if policy.get("require_owner") and not _has_owner(finding, asset):
        # A ticket with no assignee lands in a queue nobody reads. Defaulted ON
        # because an unowned estate is a real state here: production ran with
        # zero teams until phase 27.
        return False

    return True


def recent_auto_created(
    session: Session,
    organization_id: uuid.UUID,
    *,
    window_minutes: int = BUDGET_WINDOW_MINUTES,
    now: dt.datetime | None = None,
) -> int:
    """How many tickets the automation has opened in the last window.

    Counted from `ticket_events`, not from a process-local variable: the API
    runs several workers and a batch can span more than one of them, so an
    in-memory counter would give each worker its own full budget and the real
    cap would be `max_per_run x workers`.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(minutes=window_minutes)

    # In external ticketing mode there are no `ticket_events` to count, so this
    # query would return 0 forever and the cap would be silently OFF -- the
    # automation would be free to open an unbounded number of Jira issues,
    # which is the single worst thing a vulnerability platform can do to
    # somebody else's queue. External links created in the window are counted
    # instead. That over-counts slightly (a hand-raised issue also lands in the
    # window), and over-counting is the safe direction: it throttles the
    # automation early rather than flooding a queue nobody can unsend.
    from . import ticketing_mode

    if ticketing_mode.is_external(session, organization_id):
        from ..models.integration import ExternalLink

        return len(session.execute(
            select(ExternalLink.id).where(
                ExternalLink.organization_id == organization_id,
                ExternalLink.object_type == "finding",
                ExternalLink.created_at >= since,
            )
        ).scalars().all())

    return len(session.execute(
        select(TicketEvent.id)
        .join(Ticket, Ticket.id == TicketEvent.ticket_id)
        .where(
            Ticket.organization_id == organization_id,
            TicketEvent.event == "created",
            TicketEvent.actor_label == ACTOR_LABEL,
            TicketEvent.created_at >= since,
        )
    ).scalars().all())


def budget_left(
    session: Session,
    organization_id: uuid.UUID,
    policy: dict[str, Any],
    *,
    now: dt.datetime | None = None,
) -> int:
    cap = int(policy.get("max_per_run") or DEFAULT_MAX_PER_RUN)
    return max(0, cap - recent_auto_created(session, organization_id, now=now))


def consider(
    session: Session,
    finding: Finding,
    *,
    policy: dict[str, Any] | None = None,
    actor_label: str = ACTOR_LABEL,
) -> Any:
    """Open a ticket for ONE finding if the policy says so. Returns it or None.

    Called from `correlation.process_finding`, after scoring, assignment and
    SLA. The order is load-bearing: the policy reads `risk_score`,
    `assigned_team_id` and `sla_due_at`, and evaluating it earlier would judge
    every finding on values that are still None.

    It never raises into the correlation path. A ticketing failure must not
    lose the finding that caused it -- the finding is the record of the
    vulnerability, the ticket is only how somebody is asked to fix it.
    """
    policy = policy if policy is not None else state(session, finding.organization_id)
    if not policy.get("enabled"):
        return None

    asset = session.get(Asset, finding.asset_id) if finding.asset_id else None
    if not matches(finding, policy, asset=asset):
        return None

    # Checked AFTER the predicate so a full budget costs one COUNT per
    # *eligible* finding rather than one per finding processed, and skipped
    # loudly: a cap that is being hit is the operator's business.
    if budget_left(session, finding.organization_id, policy) <= 0:
        import logging

        logging.getLogger("veyrs.autoticket").warning(
            "auto-ticket budget of %s per %s min exhausted for organization %s; "
            "finding %s was NOT ticketed",
            policy.get("max_per_run"), BUDGET_WINDOW_MINUTES,
            finding.organization_id, finding.id,
        )
        return None

    try:
        record, created = remediation.open_for_finding(
            session, finding, actor_label=actor_label,
        )
    except Exception:  # noqa: BLE001 - see the docstring
        import logging

        logging.getLogger("veyrs.autoticket").exception(
            "auto-ticket failed for finding %s", finding.id
        )
        return None
    return record if created else None


def _candidate_query(organization_id: uuid.UUID, policy: dict[str, Any]):
    """Narrow in SQL what can be narrowed, then let `matches()` have the last word.

    The predicate is duplicated here ONLY as an optimisation over an estate of
    hundreds of thousands of rows; `matches()` still runs on every row that
    survives, so a divergence between the two makes the query slower, never
    wrong. Anything that cannot be expressed identically in SQL (the ownership
    and exposure rules) is left out of this half on purpose.
    """
    stmt = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.state.in_(tuple(OPEN_STATES)),
    )
    threshold = policy.get("min_risk_score")
    if threshold is not None:
        stmt = stmt.where(Finding.risk_score.is_not(None), Finding.risk_score >= threshold)
    severities = policy.get("severities") or []
    if severities:
        stmt = stmt.where(Finding.severity.in_(severities))
    if policy.get("require_kev"):
        stmt = stmt.where(Finding.kev.is_(True))
    return stmt.order_by(Finding.risk_score.desc().nullslast(), Finding.created_at.asc())


def preview(
    session: Session,
    organization_id: uuid.UUID,
    *,
    policy: dict[str, Any] | None = None,
    limit: int = BACKFILL_CEILING,
) -> dict[str, Any]:
    """How many tickets this policy would open right now, and on what.

    This is the answer an operator needs BEFORE flipping the switch, and it is
    computed from the automation's own predicate rather than a hand-written
    approximation of it.
    """
    policy = policy if policy is not None else state(session, organization_id)
    rows = session.execute(_candidate_query(organization_id, policy).limit(limit)).scalars().all()

    would_create: list[Finding] = []
    already: int = 0
    for finding in rows:
        asset = session.get(Asset, finding.asset_id) if finding.asset_id else None
        if not matches(finding, policy, asset=asset):
            continue
        if remediation.existing_for_finding(
                session, organization_id, finding.id) is not None:
            already += 1
            continue
        would_create.append(finding)

    by_severity: dict[str, int] = {}
    for finding in would_create:
        key = (finding.severity or "unknown").lower()
        by_severity[key] = by_severity.get(key, 0) + 1

    return {
        "policy": policy,
        "would_create": len(would_create),
        "already_ticketed": already,
        "by_severity": by_severity,
        "scanned": len(rows),
        # True when the scan itself hit the ceiling, so `would_create` is a
        # floor rather than a total. Said out loud rather than implied.
        "truncated": len(rows) >= limit,
        "sample": [
            {
                "finding_id": str(f.id),
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "kev": bool(f.kev),
            }
            for f in would_create[:20]
        ],
    }


def backfill(
    session: Session,
    organization_id: uuid.UUID,
    *,
    dry_run: bool = True,
    limit: int = 200,
    actor_label: str = "auto-ticket backfill",
) -> dict[str, Any]:
    """Ticket the existing backlog, once, on purpose.

    `dry_run` defaults to True: the destructive direction of a mistake here is
    hundreds of tickets and hundreds of notifications, and undoing that is
    manual. The caller has to ask for the real thing.

    It ignores `enabled`: a backfill is the operator saying "do this now",
    which is a different decision from "keep doing this from now on". Coupling
    them would force somebody who wants a one-off catch-up to leave the
    automation running afterwards.
    """
    limit = max(1, min(BACKFILL_CEILING, int(limit)))
    policy = state(session, organization_id)
    rows = session.execute(
        _candidate_query(organization_id, policy).limit(BACKFILL_CEILING)
    ).scalars().all()

    created: list[str] = []
    skipped_existing = 0
    eligible = 0
    for finding in rows:
        asset = session.get(Asset, finding.asset_id) if finding.asset_id else None
        if not matches(finding, policy, asset=asset):
            continue
        if remediation.existing_for_finding(
                session, organization_id, finding.id) is not None:
            skipped_existing += 1
            continue
        eligible += 1
        if len(created) >= limit:
            continue
        if dry_run:
            created.append(str(finding.id))
            continue
        record, was_created = remediation.open_for_finding(
            session, finding, actor_label=actor_label,
        )
        if was_created:
            created.append(record.reference)

    if not dry_run:
        session.flush()

    return {
        "dry_run": dry_run,
        "created": len(created),
        "references": created[:100],
        "skipped_existing": skipped_existing,
        "eligible": eligible,
        # `capped` is the honest name for "there was more work than the limit".
        # Reporting a clean count while quietly dropping the tail is how a
        # backfill gets believed and re-run forever.
        "capped": eligible > len(created),
        "remaining": max(0, eligible - len(created)),
    }


def set_policy(
    session: Session,
    organization_id: uuid.UUID,
    changes: dict[str, Any],
    *,
    actor_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Write the policy. Validates hard, because the failure mode is volume."""
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    block = _block(organization)

    if "enabled" in changes:
        block["enabled"] = bool(changes["enabled"])

    if "min_risk_score" in changes:
        value = changes["min_risk_score"]
        if value is None:
            severities = changes.get("severities", block.get("severities")) or []
            if not severities and not changes.get("require_kev", block.get("require_kev")):
                # No threshold, no severity list and no KEV requirement means
                # "every open finding". That is almost certainly a mistake and
                # it is unrecoverable at volume, so it is refused rather than
                # obeyed. An operator who really wants it says so with an
                # explicit `min_risk_score: 0`.
                raise AutoTicketError(
                    "a policy with no risk threshold, no severity list and no KEV "
                    "requirement would ticket every open finding; set "
                    "min_risk_score to 0 if that is genuinely what you want"
                )
            block["min_risk_score"] = None
        else:
            value = float(value)
            if not 0.0 <= value <= 100.0:
                raise AutoTicketError("min_risk_score must be between 0 and 100")
            block["min_risk_score"] = value

    if "severities" in changes:
        severities = changes["severities"] or []
        unknown = sorted(set(severities) - set(VALID_SEVERITIES))
        if unknown:
            raise AutoTicketError(
                f"unknown severity/severities: {', '.join(unknown)}; known values are "
                f"{', '.join(VALID_SEVERITIES)}"
            )
        block["severities"] = list(severities)

    for flag in ("require_kev", "internet_exposed_only", "require_owner"):
        if flag in changes:
            block[flag] = bool(changes[flag])

    if "max_per_run" in changes and changes["max_per_run"] is not None:
        cap = int(changes["max_per_run"])
        if cap < 1 or cap > MAX_PER_RUN_CEILING:
            raise AutoTicketError(f"max_per_run must be between 1 and {MAX_PER_RUN_CEILING}")
        block["max_per_run"] = cap

    block["changed_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    block["changed_by_id"] = str(actor_id) if actor_id else None

    # Reassign rather than mutate in place: SQLAlchemy does not track mutation
    # of a plain dict inside JSONB. Same trap as services/scanning.py.
    settings = dict(organization.settings or {})
    settings[SETTINGS_KEY] = block
    organization.settings = settings
    session.flush()
    return state(session, organization_id)
