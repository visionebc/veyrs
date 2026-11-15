"""Which ticketing system is the authority: VEYRS' own queue, or an external one.

VEYRS ships with a full ITSM: `tickets`, states, comments, approvals, an SLA
mirror and an escalation chain. An operator who already runs Jira does not want
a second queue -- they want the vulnerability, the device, the dates and the
risk to arrive in the queue their engineers already work from, and they want
VEYRS to stop pretending it owns the work.

Turning that off is not a UI concern, for exactly the reason the scanning
switch is not (`services/scanning.py`): **hiding a section leaves the API, the
automation and the workflow engine creating rows nobody will ever look at.**
That is the failure mode this module exists to prevent -- an operator who
believes remediation lives in Jira while `autoticket` quietly opens 40 internal
tickets a night against an SLA clock nobody is watching.

So the switch is enforced where work is CREATED, and deliberately NOT enforced
where work is FINISHED or READ:

===================================== ============ ==================================
call                                  in external  why
===================================== ============ ==================================
``POST /tickets``                     refused 409  the internal queue is not the
                                                   authority; creating there would
                                                   split remediation in two.
``remediation.open_for_finding``      redirected   creates the issue in the external
                                                   system and records the relation.
                                                   This is the whole point.
``autoticket`` / workflow actions     redirected   through the same dispatcher, so
                                                   automation cannot route around it.
``POST /tickets/{id}/transition``     allowed      **this one matters.** Flipping the
                                                   switch with 40 open internal
                                                   tickets must not strand them
                                                   unclosable. New work goes to Jira;
                                                   existing work can still be
                                                   finished and audited.
``GET /tickets``                      allowed      history from before the flip is
                                                   evidence. Hiding it would destroy
                                                   an audit trail to tidy a menu.
``inbound webhook``                   allowed      it updates the relation, which is
                                                   the record external mode keeps.
===================================== ============ ==================================

**The mode is `external`, not `jira`.** The connector layer already speaks
ServiceNow, Jira and generic webhook; naming the tenant policy after one vendor
is the same mistake as the hardcoded `/rest/api/3` that made Data Center
unsupported (phase 43). The mode names the *shape* of the decision and
``connector_id`` names who holds the authority -- which also means the answer to
"where did this ticket go?" is a row, not a guess.

``connector_id`` is REQUIRED to enter external mode. A tenant in external mode
with no connector has no ticketing at all: every creation path refuses and
nothing is written anywhere. Validating it here means that state is
unreachable rather than merely unlikely.

The state lives in ``organizations.settings["ticketing"]`` -- the same JSONB the
scanning switch and the team-scope guardrail use -- because it is tenant policy
and not an entity.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.tenancy import Organization
from ..models.ticketing import ItsmConnector, Ticket

#: Key under ``organizations.settings``.
SETTINGS_KEY = "ticketing"

MODE_INTERNAL = "internal"
MODE_EXTERNAL = "external"
MODES = (MODE_INTERNAL, MODE_EXTERNAL)

#: Default when the key is absent. Every deployment that existed before this
#: switch ran on the internal queue, and an upgrade does not get to move an
#: operator's remediation workflow into a system they never configured.
DEFAULT_MODE = MODE_INTERNAL


class TicketingModeError(RuntimeError):
    """Raised where an internal ticket would be created in external mode."""


class TicketingModeInvalid(ValueError):
    """Raised when the requested configuration cannot be satisfied."""


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The switch as the console, the API and the automation should read it."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    mode = block.get("mode")
    if mode not in MODES:
        mode = DEFAULT_MODE

    connector_id = block.get("connector_id")
    connector = None
    if connector_id:
        try:
            connector = session.get(ItsmConnector, uuid.UUID(str(connector_id)))
        except (ValueError, TypeError):
            connector = None
        if connector is not None and connector.organization_id != organization_id:
            connector = None

    # Reported separately from `mode` on purpose. A tenant switched to external
    # whose connector was deleted underneath it is BROKEN, not internal, and
    # silently falling back to the internal queue would be the platform
    # deciding on its own where somebody's remediation work goes.
    usable = mode == MODE_INTERNAL or (
        connector is not None and connector.is_enabled
    )

    return {
        "mode": mode,
        "connector_id": str(connector.id) if connector is not None else None,
        "connector_name": connector.name if connector is not None else None,
        "connector_system": connector.system if connector is not None else None,
        "connector_enabled": bool(connector.is_enabled) if connector is not None else None,
        #: False here means creation refuses everywhere. Surfaced so the console
        #: can say WHY instead of showing an empty screen.
        "usable": bool(usable),
        "changed_at": block.get("changed_at"),
        "changed_by_id": block.get("changed_by_id"),
        "reason": block.get("reason"),
        #: Never defaulted away: an operator reading "internal" needs to know
        #: whether that is a decision somebody made or the shipped default.
        "explicit": "mode" in block,
        #: How much internal history the flip left behind. An operator moving to
        #: Jira with 40 open internal tickets is owed that number BEFORE the
        #: menu disappears, not after.
        "open_internal_tickets": open_internal_count(session, organization_id),
    }


def open_internal_count(session: Session, organization_id: uuid.UUID) -> int:
    from ..models.ticketing import OPEN_TICKET_STATES

    return len(session.execute(
        select(Ticket.id).where(
            Ticket.organization_id == organization_id,
            Ticket.state.in_(tuple(OPEN_TICKET_STATES)),
        )
    ).scalars().all())


def mode(session: Session, organization_id: uuid.UUID) -> str:
    return str(state(session, organization_id)["mode"])


def is_external(session: Session, organization_id: uuid.UUID) -> bool:
    return mode(session, organization_id) == MODE_EXTERNAL


def active_connector(
    session: Session, organization_id: uuid.UUID
) -> ItsmConnector | None:
    """The connector that owns remediation work, or None in internal mode."""
    current = state(session, organization_id)
    if current["mode"] != MODE_EXTERNAL or not current["connector_id"]:
        return None
    return session.get(ItsmConnector, uuid.UUID(current["connector_id"]))


def require_internal(session: Session, organization_id: uuid.UUID, what: str) -> None:
    """Refuse `what` when the tenant has handed ticketing to an external system."""
    current = state(session, organization_id)
    if current["mode"] != MODE_EXTERNAL:
        return
    where = current["connector_name"] or "the configured external system"
    raise TicketingModeError(
        f"this organization keeps its remediation work in {where}, so {what} is "
        "refused; VEYRS records the relation between the external issue and the "
        "finding, asset and dates instead of opening a second queue. Change it "
        "in Administration -> Ticketing."
    )


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise and check a mode change. Raises `TicketingModeInvalid`."""
    requested = str(payload.get("mode") or "").strip().lower()
    if requested not in MODES:
        raise TicketingModeInvalid(
            f"mode must be one of {', '.join(MODES)}; got {requested!r}"
        )
    connector_id = payload.get("connector_id")
    if requested == MODE_EXTERNAL and not connector_id:
        # Refused rather than accepted-and-broken. External mode with no
        # connector refuses every creation path, so the tenant would have no
        # ticketing at all and the only symptom would be work quietly not
        # happening.
        raise TicketingModeInvalid(
            "external ticketing needs a connector: name the ITSM connector that "
            "will own remediation work. Create one in Integrations -> ITSM first."
        )
    if requested == MODE_INTERNAL:
        connector_id = None
    return {"mode": requested, "connector_id": connector_id}


def set_mode(
    session: Session,
    organization_id: uuid.UUID,
    payload: dict[str, Any],
    *,
    actor_id: uuid.UUID | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Flip the switch. Returns the new state.

    Nothing is migrated, closed or deleted. Internal tickets that already exist
    keep existing and stay transitionable -- see the table in the module
    docstring. A switch that silently closed 40 open tickets to make a menu
    consistent would be destroying the record of work in progress.
    """
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    normalised = validate(payload)
    if normalised["mode"] == MODE_EXTERNAL:
        connector = session.get(
            ItsmConnector, uuid.UUID(str(normalised["connector_id"]))
        )
        if connector is None or connector.organization_id != organization_id:
            raise TicketingModeInvalid("connector not found in this organization")
        # Deliberately NOT gated on `connector.is_enabled`: an operator may
        # reasonably configure the mode before switching the connector on, and
        # `state()["usable"]` already reports the gap loudly. Refusing here
        # would force the enable-to-configure ordering that phase 43 removed
        # from `/test` for the same reason.
        normalised["connector_id"] = str(connector.id)

    block = _block(organization)
    block.update({
        "mode": normalised["mode"],
        "connector_id": normalised["connector_id"],
        "changed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "changed_by_id": str(actor_id) if actor_id else None,
        "reason": (reason or "").strip()[:500] or None,
    })
    # Reassign rather than mutate in place: SQLAlchemy does not track mutation
    # of a plain dict inside JSONB, and an in-place update is a write that
    # silently does not happen.
    settings = dict(organization.settings or {})
    settings[SETTINGS_KEY] = block
    organization.settings = settings
    session.flush()
    return state(session, organization_id)


__all__ = [
    "SETTINGS_KEY", "MODE_INTERNAL", "MODE_EXTERNAL", "MODES", "DEFAULT_MODE",
    "TicketingModeError", "TicketingModeInvalid",
    "state", "mode", "is_external", "active_connector", "require_internal",
    "validate", "set_mode", "open_internal_count",
]
