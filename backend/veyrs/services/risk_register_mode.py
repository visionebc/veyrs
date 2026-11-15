"""The switch that decides whether this tenant keeps a risk register at all.

Not every deployment wants one. An organisation whose enterprise risk lives in
a GRC tool does not need a second register here -- they need VEYRS to stay the
vulnerability platform and to stop offering a screen that will be filled in once
and abandoned. A half-maintained risk register is worse than none: it is read as
current.

Turning it off is not a UI concern, for exactly the reason the scanning and
ticketing switches are not. Hiding a menu entry leaves the API, and anything
automated built on top of it, writing rows nobody will ever look at:

======================================== ============ =============================
call                                     with off     why
======================================== ============ =============================
``POST /risks``                          refused 409  no new entries in a register
                                                      this tenant does not keep.
``PATCH /risks/{id}``                    refused 409  same -- including status and
                                                      score changes.
``DELETE /risks/{id}``                   refused 409  **deliberate.** Turning the
                                                      module off must not become a
                                                      quiet way to erase risk
                                                      records; turn it back on and
                                                      delete them on the record.
``PUT /risks/{id}/raci`` and the links   refused 409  assignment is the work this
                                                      module does.
``GET /risks`` and ``/risks/{id}``       allowed      entries written before the
                                                      flip are evidence. Hiding
                                                      them to tidy a menu destroys
                                                      the reason somebody wrote
                                                      them down.
``GET /risks/summary``                   allowed      so the console can say "23
                                                      entries are still here" on
                                                      the switch itself, instead of
                                                      letting an operator disable
                                                      the module blind.
======================================== ============ =============================

**Default is ON.** The scanning switch defaults to its previous behaviour
because there was behaviour to preserve; this module is new, nobody has any, and
an operator who asked for the section does not want to hunt for a second switch
before the section appears. The switch exists to remove it, not to withhold it
on arrival.

The state lives in ``organizations.settings["risk_register"]`` -- the same JSONB
the scanning switch, the ticketing mode and the team-scope guardrail use --
because it is tenant policy and not an entity.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.risk_register import OPEN_RISK_STATUSES, RiskEntry
from ..models.tenancy import Organization

#: Key under ``organizations.settings``.
SETTINGS_KEY = "risk_register"

#: See the module docstring: new module, nothing to preserve, on by default.
DEFAULT_ENABLED = True


class RiskRegisterDisabled(RuntimeError):
    """Raised where a register entry would be created or changed with the module off."""


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def entry_counts(session: Session, organization_id: uuid.UUID) -> dict[str, int]:
    """How much is in the register right now.

    Reported on the switch so an operator turning the module off is told what
    they are about to hide, rather than discovering it afterwards.
    """
    total = session.execute(
        select(func.count(RiskEntry.id)).where(
            RiskEntry.organization_id == organization_id,
            RiskEntry.deleted_at.is_(None),
        )
    ).scalar_one()
    open_count = session.execute(
        select(func.count(RiskEntry.id)).where(
            RiskEntry.organization_id == organization_id,
            RiskEntry.deleted_at.is_(None),
            RiskEntry.status.in_(tuple(OPEN_RISK_STATUSES)),
        )
    ).scalar_one()
    return {"entries": int(total), "open_entries": int(open_count)}


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The switch as the console, the API and any automation should read it."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    raw = block.get("enabled")
    enabled = DEFAULT_ENABLED if not isinstance(raw, bool) else raw
    out: dict[str, Any] = {
        "enabled": bool(enabled),
        "changed_at": block.get("changed_at"),
        "changed_by_id": block.get("changed_by_id"),
        "reason": block.get("reason"),
        #: Never defaulted away: an operator reading "on" needs to know whether
        #: that is a decision somebody made or the shipped default.
        "explicit": isinstance(raw, bool),
    }
    out.update(entry_counts(session, organization_id))
    return out


def is_enabled(session: Session, organization_id: uuid.UUID) -> bool:
    return bool(state(session, organization_id)["enabled"])


def require_enabled(session: Session, organization_id: uuid.UUID, what: str) -> None:
    """Refuse `what` when this tenant does not keep a risk register."""
    if is_enabled(session, organization_id):
        return
    raise RiskRegisterDisabled(
        f"the risk register is turned off for this organization, so {what} is "
        "refused. Existing entries are still readable and nothing has been "
        "deleted. Turn it back on in Administration -> Risk Register."
    )


def set_enabled(
    session: Session,
    organization_id: uuid.UUID,
    enabled: bool,
    *,
    actor_id: uuid.UUID | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Flip the switch. Returns the new state.

    Nothing is deleted, closed or migrated. Turning the register off hides a
    section and refuses writes; the rows stay exactly where they are, because a
    switch that tidied the menu by dropping somebody's risk assessment would be
    destroying the only record that an accepted risk was ever accepted.
    """
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    block = _block(organization)
    block.update({
        "enabled": bool(enabled),
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
    "SETTINGS_KEY", "DEFAULT_ENABLED", "RiskRegisterDisabled",
    "state", "is_enabled", "require_enabled", "set_enabled", "entry_counts",
]
