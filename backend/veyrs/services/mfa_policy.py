"""Organization policy: a second factor is required to use VEYRS (R-07).

Off by default. When an administrator turns it on (`PUT /api/v1/mfa-policy`,
`settings:admin`), it applies to every account of the organization signing in
with a password -- local, directory or RADIUS -- platform administrators
included:

* An account WITH a second factor signs in exactly as before.
* An account WITHOUT one still gets in with its password, but only into
  enrolment: the login answers with an access token whose scope is
  `mfa_enroll` (`security.auth.SCOPE_MFA_ENROLL`), no refresh token and no
  permission. That token reaches only the MFA set-up routes, `/auth/me` and
  logout (`security.deps.ENROLLMENT_ROUTES`). Activating a factor returns a
  normal token pair. Nobody is ever locked out of enrolling, because the
  password alone is enough to reach the enrolment screen.
* Sessions that predate the switch stop at their next refresh: a refresh for an
  account without a factor whose session was proved by password alone is
  refused, so the person signs in again and lands in enrolment. Access tokens
  already issued live out their (short) lifetime.
* A RADIUS server that ran its own challenge counts as the second factor, as it
  does for an account that has one.
* Single sign-on is unaffected: the identity provider owns the second factor
  there (`oidc.require_mfa_amr` refuses a provider that does not report one).

Stored as `organizations.settings["mfa_policy"]`.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.tenancy import Organization, User, settings_block

SETTINGS_KEY = "mfa_policy"
DEFAULTS: dict[str, Any] = {"require_mfa": False}


def required(organization: Organization | None) -> bool:
    return bool(settings_block(organization, SETTINGS_KEY).get("require_mfa"))


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The policy plus how many active accounts would be sent to enrolment."""
    organization = session.get(Organization, organization_id)
    out = dict(DEFAULTS)
    out.update(settings_block(organization, SETTINGS_KEY))
    out["require_mfa"] = bool(out.get("require_mfa"))
    out["users_without_mfa"] = session.execute(
        select(func.count()).select_from(User).where(
            User.organization_id == organization_id, User.deleted_at.is_(None),
            User.is_active.is_(True), User.mfa_enabled.is_(False))
    ).scalar_one()
    return out


def set_required(session: Session, organization_id: uuid.UUID, value: bool, *,
                 actor_id: uuid.UUID | None = None) -> dict[str, Any]:
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")
    block = settings_block(organization, SETTINGS_KEY)
    block.update(require_mfa=bool(value),
                 changed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                 changed_by_id=str(actor_id) if actor_id else None)
    stored = dict(organization.settings or {})
    stored[SETTINGS_KEY] = block
    organization.settings = stored          # reassigned: JSONB edits in place are not tracked
    session.flush()
    return state(session, organization_id)
