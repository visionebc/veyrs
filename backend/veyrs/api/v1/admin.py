"""Tenant administration: organizations, users, teams, departments, roles,
API keys and the audit trail.

Tenancy rule enforced in every handler: the organization is taken from the
authenticated principal, NEVER from the request body or path. A caller cannot
address another tenant's object even by guessing its UUID, because every query
is filtered on `principal.organization_id` (and RLS backs that up).
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import Response, APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...models.audit import AuditLog
from ...models.tenancy import (
    ApiKey, Department, Organization, Role, Team, TeamMember, User, UserRole,
)
from ...security import permissions as perms
from ...security.auth import hash_password, new_api_key
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...security import scope as team_scope
from ...services import audit, ldap_auth, risk_register_mode, scanning, ticketing_mode
from .schemas import (
    ApiKeyCreate, ApiKeyCreated, ApiKeyOut, AuditOut, DepartmentCreate, DepartmentOut,
    OrganizationOut, OrganizationUpdate, Page, RoleCreate, RoleOut, RoleUpdate,
    LdapSettingsUpdate, LdapTestRequest, RiskRegisterUpdate, ScanningUpdate,
    TicketingUpdate,
    TeamCreate, TeamOut, TeamUpdate, UserCreate, UserOut, UserScopeUpdate, UserUpdate,
)

router = APIRouter(tags=["administration"])


def _actor(request: Request, principal: Principal) -> dict:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": ip,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


def _roles_of(session: Session, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    if not user_ids:
        return {}
    rows = session.execute(
        select(UserRole.user_id, Role.slug)
        .join(Role, Role.id == UserRole.role_id)
        .where(UserRole.user_id.in_(user_ids))
    ).all()
    out: dict[uuid.UUID, list[str]] = {}
    for user_id, slug in rows:
        out.setdefault(user_id, []).append(slug)
    return out


# --- organization ---------------------------------------------------------


@router.get("/organization", response_model=OrganizationOut, summary="Own organization")
def get_organization(principal: Annotated[Principal, Depends(require("organization:read"))],
                     session: TenantSession) -> Organization:
    org = session.get(Organization, principal.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    return org


@router.patch("/organization", response_model=OrganizationOut, summary="Update own organization")
def update_organization(
    payload: OrganizationUpdate,
    principal: Annotated[Principal, Depends(require("organization:write"))],
    session: TenantSession,
    request: Request,
) -> Organization:
    org = session.get(Organization, principal.organization_id)
    if org is None:
        raise HTTPException(status_code=404, detail="organization not found")
    before = org.as_dict()
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(org, field, value)
    audit.record(session, action="organization.update", object_type="organization",
                 object_id=org.id, object_label=org.slug,
                 changes=audit.diff(before, org.as_dict()), **_actor(request, principal))
    session.commit()
    return org


# --- users ----------------------------------------------------------------


@router.get("/scanning", summary="Is VEYRS allowed to run scans itself?")
def get_scanning(
    principal: Annotated[Principal, Depends(require("settings:read"))],
    session: TenantSession,
) -> dict:
    """Read-open on purpose.

    An operator looking at an empty scan queue has to be able to tell "nothing
    is scheduled" from "this platform does not scan"; making that answer an
    admin secret is how the first one gets debugged for an afternoon.
    """
    state = scanning.state(session, principal.organization_id)
    state["queued_jobs"] = scanning.queued_job_count(session, principal.organization_id)
    return state


@router.put("/scanning", summary="Turn active scanning on or off")
def set_scanning(
    payload: ScanningUpdate,
    request: Request,
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """`settings:admin`, and never a team-scoped grant.

    The switch governs the whole estate: a team that could turn scanning off
    would silently stop the sweeps every other team's findings depend on. The
    refusal is the same one policy writes take in `policies` (phase 28).
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "the scanning mode governs the whole estate and cannot be changed by a "
        "team-scoped identity; it requires an estate-wide role grant",
    )
    before = scanning.state(session, principal.organization_id)
    state = scanning.set_enabled(
        session,
        principal.organization_id,
        payload.active_scanning_enabled,
        actor_id=principal.user_id,
        reason=payload.reason,
        cancel_queued_jobs=payload.cancel_queued_jobs,
    )
    audit.record(
        session,
        action="organization.scanning_mode_changed",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="active scanning",
        changes={
            "active_scanning_enabled": [
                before["active_scanning_enabled"], state["active_scanning_enabled"]
            ],
            "reason": payload.reason,
            "jobs_cancelled": state.get("jobs_cancelled", 0),
        },
        **_actor(request, principal),
    )
    session.commit()
    return state


# --- ticketing mode (internal queue vs external ITSM) ---------------------


@router.get("/ticketing", summary="Which system owns remediation work")
def get_ticketing(
    principal: Annotated[Principal, Depends(require("settings:read"))],
    session: TenantSession,
) -> dict:
    """Read-open, like `/scanning` and unlike `/ldap`.

    The console needs this on EVERY page load to decide whether the Tickets
    section exists at all, so gating it on `settings:admin` would hide the menu
    from every non-admin -- which looks exactly like the bug this mode is
    supposed to fix. It is also safe to read: unlike the directory payload, it
    names no host, no service account and no secret. The connector's own
    credentials stay behind `ticket:admin` in `/integrations/connectors`.
    """
    return ticketing_mode.state(session, principal.organization_id)


@router.put("/ticketing", summary="Choose the internal queue or an external ITSM")
def set_ticketing(
    payload: TicketingUpdate,
    request: Request,
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """Same refusal as the scanning switch, for the same reason.

    Nothing is migrated or closed. Internal tickets that already exist stay
    open and stay transitionable -- see the table in `services/ticketing_mode`.
    A switch that tidied the menu by closing 40 tickets in flight would be
    destroying the record of work somebody is doing.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "the ticketing mode governs the whole estate and cannot be changed by a "
        "team-scoped identity; it requires an estate-wide role grant",
    )
    before = ticketing_mode.state(session, principal.organization_id)
    try:
        state = ticketing_mode.set_mode(
            session, principal.organization_id,
            payload.model_dump(exclude={"reason"}, exclude_unset=True),
            actor_id=principal.user_id, reason=payload.reason,
        )
    except ticketing_mode.TicketingModeInvalid as exc:
        # 422 rather than 400: every complaint `validate` makes is about the
        # content of a field the caller sent.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(
        session,
        action="organization.ticketing_mode_changed",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="ticketing mode",
        changes={
            "mode": [before["mode"], state["mode"]],
            "connector_id": [before["connector_id"], state["connector_id"]],
            "reason": payload.reason,
            # Recorded at the moment of the flip: "there were 37 open internal
            # tickets when we moved to Jira" is the number the next reader
            # needs, and it is unrecoverable afterwards.
            "open_internal_tickets": before["open_internal_tickets"],
        },
        **_actor(request, principal),
    )
    session.commit()
    return state


# --- risk register (on or off for this tenant) ----------------------------


@router.get("/risk-register", summary="Does this organization keep a risk register?")
def get_risk_register(
    principal: Annotated[Principal, Depends(require("settings:read"))],
    session: TenantSession,
) -> dict:
    """Read-open, like `/scanning` and `/ticketing`.

    The console needs this on every page load to decide whether the Risk
    Register section exists at all, so gating it on `settings:admin` would hide
    the menu from every non-admin -- which looks exactly like the bug the switch
    is supposed to make visible. It names no host, no account and no secret.
    """
    return risk_register_mode.state(session, principal.organization_id)


@router.put("/risk-register", summary="Turn the risk register on or off")
def set_risk_register(
    payload: RiskRegisterUpdate,
    request: Request,
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """Same refusal as the scanning and ticketing switches, for the same reason.

    Nothing is deleted. Entries written before the flip stay readable and stay
    exportable -- a switch that tidied a menu by dropping the record of an
    accepted risk would be destroying the only evidence that it was ever
    accepted.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "the risk register governs the whole organization and cannot be turned "
        "on or off by a team-scoped identity; it requires an estate-wide role grant",
    )
    before = risk_register_mode.state(session, principal.organization_id)
    state = risk_register_mode.set_enabled(
        session,
        principal.organization_id,
        payload.risk_register_enabled,
        actor_id=principal.user_id,
        reason=payload.reason,
    )
    audit.record(
        session,
        action="organization.risk_register_changed",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="risk register",
        changes={
            "risk_register_enabled": [before["enabled"], state["enabled"]],
            "reason": payload.reason,
            # Recorded at the moment of the flip: "there were 23 entries, 9 of
            # them open, when we turned the register off" is the number the next
            # reader needs and cannot reconstruct afterwards.
            "entries": before["entries"],
            "open_entries": before["open_entries"],
        },
        **_actor(request, principal),
    )
    session.commit()
    return state


# --- directory (LDAP / Active Directory) ----------------------------------


@router.get("/ldap", summary="Directory authentication settings")
def get_ldap(
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """`settings:admin`, and NOT read-open like `/scanning`.

    The scanning switch is read-open because an operator staring at an empty
    queue has to be able to tell "nothing scheduled" from "this deployment does
    not scan". Nothing here is that: this payload names the directory host, the
    service-account DN, the search base and the exact group-to-role mapping --
    a map of how to become an administrator, drawn for whoever asks. The
    password never leaves the process at all (`ldap_auth.state`).
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "directory settings govern authentication for the whole estate and are "
        "not readable by a team-scoped identity",
    )
    return ldap_auth.state(session, principal.organization_id)


@router.put("/ldap", summary="Configure directory authentication")
def set_ldap(
    payload: LdapSettingsUpdate,
    request: Request,
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """Same refusal as the scanning switch, for the same reason.

    A team-scoped identity that could point this at a directory it controls
    would own every account in the tenant on the next login. This is the single
    most privileged write in the API and it takes an estate-wide grant.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "directory settings govern authentication for the whole estate and "
        "cannot be changed by a team-scoped identity; they require an "
        "estate-wide role grant",
    )
    before = ldap_auth.state(session, principal.organization_id)
    # `exclude_unset`: an absent key means "not mentioned", never "set to null".
    fields = payload.model_dump(exclude_unset=True)
    bind_password = fields.pop("bind_password", None)
    clear_password = bool(fields.pop("clear_bind_password", False))
    try:
        state = ldap_auth.set_config(
            session,
            principal.organization_id,
            fields,
            bind_password=bind_password,
            clear_bind_password=clear_password,
            actor_id=principal.user_id,
        )
    except ValueError as exc:
        # 422 rather than 400: every one of `ldap_auth.validate`'s complaints is
        # about the content of this body, and all of them are returned at once
        # so the form can be fixed in one pass instead of four round trips.
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    audit.record(
        session,
        action="organization.directory_configured",
        object_type="organization",
        object_id=principal.organization_id,
        object_label="directory authentication",
        # The password is never in `state()`, so it can never reach the audit
        # log through this diff. That is the point of diffing the redacted
        # views rather than the raw settings block.
        changes=audit.diff(before, state),
        **_actor(request, principal),
    )
    session.commit()
    return state


@router.post("/ldap/test", summary="Test the directory connection")
def test_ldap(
    payload: LdapTestRequest,
    principal: Annotated[Principal, Depends(require("settings:admin"))],
    session: TenantSession,
) -> dict:
    """Diagnose the CURRENTLY SAVED configuration, step by step.

    It tests what is stored, not what is on screen, and that is deliberate: the
    thing an operator needs to know is whether the configuration the login path
    will actually use works. A test that ran against unsaved form values could
    pass and leave sign-in broken.

    Never 500s on a bad directory. Unreachable, wrong service account, wrong
    base DN and wrong filter are four different fixes, so they are four
    different steps with their own outcome rather than one boolean.
    """
    team_scope.refuse_if_restricted(
        principal.scope,
        "directory settings are not readable by a team-scoped identity",
    )
    return ldap_auth.test_connection(
        session, principal.organization_id,
        sample_identifier=(payload.sample_identifier or "").strip() or None,
    )


@router.get("/users", response_model=Page[UserOut], summary="List users")
def list_users(
    principal: Annotated[Principal, Depends(require("user:read"))],
    session: TenantSession,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, max_length=120),
    active: bool | None = None,
) -> Page[UserOut]:
    where = [User.organization_id == principal.organization_id, User.deleted_at.is_(None)]
    if q:
        pattern = f"%{q.lower()}%"
        where.append(func.lower(User.email).like(pattern) | func.lower(User.full_name).like(pattern))
    if active is not None:
        where.append(User.is_active.is_(active))
    total = session.execute(select(func.count()).select_from(User).where(*where)).scalar_one()
    rows = session.execute(
        select(User).where(*where).order_by(User.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    role_map = _roles_of(session, [u.id for u in rows])
    items = []
    for user in rows:
        out = UserOut.model_validate(user)
        out.roles = sorted(role_map.get(user.id, []))
        items.append(out)
    return Page[UserOut](items=items, total=total, limit=limit, offset=offset)


@router.post("/users", response_model=UserOut, status_code=201, summary="Create a user")
def create_user(
    payload: UserCreate,
    principal: Annotated[Principal, Depends(require("user:write"))],
    session: TenantSession,
    request: Request,
) -> UserOut:
    user = User(
        organization_id=principal.organization_id,
        email=payload.email.lower(),
        username=payload.username,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password) if payload.password else None,
        job_title=payload.job_title,
        locale=payload.locale,
    )
    session.add(user)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        # Two unique constraints can land here now. Naming only the email would
        # send an administrator to check an address that is perfectly free.
        raise HTTPException(
            status_code=409,
            detail="a user with that email address or username already exists",
        )

    granted = _assign_roles(session, user, payload.role_slugs, principal,
                            payload.scope_team_ids)
    for team_id in payload.team_ids:
        team = session.get(Team, team_id)
        if team is None or team.organization_id != principal.organization_id:
            raise HTTPException(status_code=422, detail=f"unknown team {team_id}")
        session.add(TeamMember(organization_id=principal.organization_id,
                               team_id=team_id, user_id=user.id))

    audit.record(session, action="user.create", object_type="user", object_id=user.id,
                 object_label=user.email,
                 changes={"email": {"from": None, "to": user.email}, "roles": granted},
                 **_actor(request, principal))
    session.commit()
    out = UserOut.model_validate(user)
    out.roles = sorted(granted)
    return out


def _assign_roles(
    session: Session, user: User, slugs: list[str], principal: Principal,
    scope_team_ids: list[uuid.UUID] | None = None,
) -> list[str]:
    """Grant roles by slug, accepting both built-in and tenant-defined roles.

    Privilege-escalation guard: a caller without `role:admin` cannot grant a role
    whose permission set exceeds their own.
    """
    if not slugs:
        return []
    rows = session.execute(
        select(Role).where(
            Role.slug.in_(slugs),
            # NOT `.in_([org_id, None])`: SQL `IN (x, NULL)` never matches a NULL
            # row, which would make every built-in role invisible.
            or_(Role.organization_id == principal.organization_id,
                Role.organization_id.is_(None)),
        )
    ).scalars().all()
    found = {r.slug: r for r in rows}
    missing = sorted(set(slugs) - set(found))
    if missing:
        raise HTTPException(status_code=422, detail=f"unknown roles: {', '.join(missing)}")
    if not principal.is_superuser and not principal.can("role:admin"):
        for role in rows:
            excess = perms.expand(role.permissions or []) - principal.permissions
            if excess:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"cannot grant role {role.slug!r}: it carries permissions you "
                        f"do not hold ({', '.join(sorted(excess)[:5])})"
                    ),
                )
    scoped_to = list(scope_team_ids or [])
    for team_id in scoped_to:
        team = session.get(Team, team_id)
        if team is None or team.organization_id != principal.organization_id:
            raise HTTPException(status_code=422, detail=f"unknown team {team_id}")
    for role in rows:
        # One grant per team when scoped: `UserRole.team_id` is the column
        # `security.scope` reads, and a single NULL row anywhere in the set
        # makes the whole identity estate-wide again.
        for team_id in (scoped_to or [None]):
            session.add(UserRole(organization_id=principal.organization_id,
                                 user_id=user.id, role_id=role.id, team_id=team_id))
    session.flush()
    return sorted(found)


@router.put("/users/{user_id}/scope", summary="Narrow a user's grants to teams")
def set_user_scope(user_id: uuid.UUID, payload: UserScopeUpdate,
                   principal: Annotated[Principal, Depends(require("role:admin"))],
                   session: TenantSession, request: Request) -> dict:
    """Re-point every one of the user's role grants at the given teams.

    Needs `role:admin`, not `user:write`: clearing the list restores estate-wide
    visibility, which grants privilege rather than merely editing a profile.

    A caller cannot narrow their own grants. Not paternalism -- an administrator
    who scopes themselves loses `role:admin` reach over the users outside that
    scope and cannot undo it, which turns a mistake into a support call.
    """
    user = session.get(User, user_id)
    if user is None or user.organization_id != principal.organization_id or user.is_deleted:
        raise HTTPException(status_code=404, detail="user not found")
    if principal.user_id == user_id and payload.team_ids:
        raise HTTPException(status_code=422,
                            detail="refusing to narrow your own scope; ask another administrator")
    for team_id in payload.team_ids:
        team = session.get(Team, team_id)
        if team is None or team.organization_id != principal.organization_id:
            raise HTTPException(status_code=422, detail=f"unknown team {team_id}")

    grants = session.execute(
        select(UserRole).where(UserRole.user_id == user.id)
    ).scalars().all()
    if not grants:
        raise HTTPException(status_code=422, detail="user has no role grants to scope")
    role_ids = {g.role_id for g in grants}
    for grant in grants:
        session.delete(grant)
    session.flush()
    for role_id in sorted(role_ids, key=str):
        for team_id in (payload.team_ids or [None]):
            session.add(UserRole(organization_id=principal.organization_id,
                                 user_id=user.id, role_id=role_id, team_id=team_id))
    audit.record(session, action="user.scope", object_type="user", object_id=user.id,
                 object_label=user.email,
                 changes={"scope_team_ids": {"to": [str(t) for t in payload.team_ids]}},
                 **_actor(request, principal))
    session.commit()
    return {"user_id": str(user.id), "restricted": bool(payload.team_ids),
            "team_ids": [str(t) for t in payload.team_ids],
            "roles": len(role_ids)}


@router.get("/users/{user_id}", response_model=UserOut, summary="Get a user")
def get_user(user_id: uuid.UUID,
             principal: Annotated[Principal, Depends(require("user:read"))],
             session: TenantSession) -> UserOut:
    user = session.get(User, user_id)
    if user is None or user.organization_id != principal.organization_id or user.is_deleted:
        raise HTTPException(status_code=404, detail="user not found")
    out = UserOut.model_validate(user)
    out.roles = sorted(_roles_of(session, [user.id]).get(user.id, []))
    return out


@router.patch("/users/{user_id}", response_model=UserOut, summary="Update a user")
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    principal: Annotated[Principal, Depends(require("user:write"))],
    session: TenantSession,
    request: Request,
) -> UserOut:
    user = session.get(User, user_id)
    if user is None or user.organization_id != principal.organization_id or user.is_deleted:
        raise HTTPException(status_code=404, detail="user not found")
    data = payload.model_dump(exclude_unset=True)
    role_slugs = data.pop("role_slugs", None)
    before = user.as_dict()
    for field, value in data.items():
        setattr(user, field, value)
    granted = None
    if role_slugs is not None:
        # Only the MANUAL grants are replaced. A grant derived from a directory
        # group is owned by `ldap_auth`/`_sync_directory_roles` and is
        # reconciled on every login: deleting it here would either resurrect it
        # seconds later (confusing) or, because `_assign_roles` writes
        # `origin="manual"`, quietly relabel it as a human decision -- after
        # which removing somebody from the AD group would no longer remove the
        # role, forever. See `models.tenancy.UserRole.origin`.
        session.query(UserRole).filter(
            UserRole.user_id == user.id, UserRole.origin != "directory"
        ).delete(synchronize_session=False)
        granted = _assign_roles(session, user, role_slugs, principal)
    changes = audit.diff(before, user.as_dict())
    if granted is not None:
        changes["roles"] = {"to": granted}
    audit.record(session, action="user.update", object_type="user", object_id=user.id,
                 object_label=user.email, changes=changes, **_actor(request, principal))
    try:
        session.commit()
    except IntegrityError:
        # `username` is unique per tenant, so a PATCH can collide exactly as a
        # POST can. Without this the collision surfaces at commit time as a 500
        # on a request whose only fault is a name somebody else already has.
        session.rollback()
        raise HTTPException(
            status_code=409,
            detail="a user with that email address or username already exists",
        )
    out = UserOut.model_validate(user)
    out.roles = sorted(_roles_of(session, [user.id]).get(user.id, []))
    return out


@router.delete("/users/{user_id}", status_code=204, response_model=None, response_class=Response, summary="Deactivate a user (soft delete)")
def delete_user(
    user_id: uuid.UUID,
    principal: Annotated[Principal, Depends(require("user:delete"))],
    session: TenantSession,
    request: Request,
) -> None:
    user = session.get(User, user_id)
    if user is None or user.organization_id != principal.organization_id or user.is_deleted:
        raise HTTPException(status_code=404, detail="user not found")
    if user.id == principal.user_id:
        raise HTTPException(status_code=422, detail="you cannot delete your own account")
    user.deleted_at = dt.datetime.now(dt.timezone.utc)
    user.is_active = False
    audit.record(session, action="user.delete", object_type="user", object_id=user.id,
                 object_label=user.email, **_actor(request, principal))
    session.commit()


# --- teams and departments ------------------------------------------------


@router.get("/teams", response_model=Page[TeamOut], summary="List teams")
def list_teams(principal: Annotated[Principal, Depends(require("team:read"))],
               session: TenantSession,
               limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)) -> Page[TeamOut]:
    where = [Team.organization_id == principal.organization_id]
    total = session.execute(select(func.count()).select_from(Team).where(*where)).scalar_one()
    rows = session.execute(
        select(Team).where(*where).order_by(Team.name).limit(limit).offset(offset)
    ).scalars().all()
    counts = dict(
        session.execute(
            select(TeamMember.team_id, func.count())
            .where(TeamMember.team_id.in_([t.id for t in rows] or [uuid.uuid4()]))
            .group_by(TeamMember.team_id)
        ).all()
    )
    items = []
    for team in rows:
        out = TeamOut.model_validate(team)
        out.member_count = counts.get(team.id, 0)
        items.append(out)
    return Page[TeamOut](items=items, total=total, limit=limit, offset=offset)


@router.post("/teams", response_model=TeamOut, status_code=201, summary="Create a team")
def create_team(payload: TeamCreate,
                principal: Annotated[Principal, Depends(require("team:write"))],
                session: TenantSession, request: Request) -> TeamOut:
    team = Team(organization_id=principal.organization_id,
                **payload.model_dump(exclude_unset=False))
    session.add(team)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="a team with that slug already exists")
    audit.record(session, action="team.create", object_type="team", object_id=team.id,
                 object_label=team.slug, **_actor(request, principal))
    session.commit()
    return TeamOut.model_validate(team)


@router.patch("/teams/{team_id}", response_model=TeamOut, summary="Update a team")
def update_team(team_id: uuid.UUID, payload: TeamUpdate,
                principal: Annotated[Principal, Depends(require("team:write"))],
                session: TenantSession, request: Request) -> TeamOut:
    team = session.get(Team, team_id)
    if team is None or team.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="team not found")
    before = team.as_dict()
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(team, field, value)
    audit.record(session, action="team.update", object_type="team", object_id=team.id,
                 object_label=team.slug, changes=audit.diff(before, team.as_dict()),
                 **_actor(request, principal))
    session.commit()
    return TeamOut.model_validate(team)


@router.post("/teams/{team_id}/members/{user_id}", status_code=204, response_model=None, response_class=Response, summary="Add a team member")
def add_member(team_id: uuid.UUID, user_id: uuid.UUID,
               principal: Annotated[Principal, Depends(require("team:write"))],
               session: TenantSession, request: Request) -> None:
    team, user = session.get(Team, team_id), session.get(User, user_id)
    if team is None or team.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="team not found")
    if user is None or user.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="user not found")
    exists = session.execute(
        select(TeamMember).where(TeamMember.team_id == team_id, TeamMember.user_id == user_id)
    ).scalar_one_or_none()
    if exists is None:
        session.add(TeamMember(organization_id=principal.organization_id,
                               team_id=team_id, user_id=user_id))
        audit.record(session, action="team.member.add", object_type="team", object_id=team.id,
                     object_label=team.slug, changes={"user": {"to": user.email}},
                     **_actor(request, principal))
    session.commit()


@router.delete("/teams/{team_id}/members/{user_id}", status_code=204, response_model=None, response_class=Response,
               summary="Remove a team member")
def remove_member(team_id: uuid.UUID, user_id: uuid.UUID,
                  principal: Annotated[Principal, Depends(require("team:write"))],
                  session: TenantSession, request: Request) -> None:
    team = session.get(Team, team_id)
    if team is None or team.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="team not found")
    session.query(TeamMember).filter(
        TeamMember.team_id == team_id, TeamMember.user_id == user_id
    ).delete(synchronize_session=False)
    audit.record(session, action="team.member.remove", object_type="team", object_id=team.id,
                 object_label=team.slug, **_actor(request, principal))
    session.commit()


@router.get("/departments", response_model=list[DepartmentOut], summary="List departments")
def list_departments(principal: Annotated[Principal, Depends(require("team:read"))],
                     session: TenantSession) -> list[Department]:
    return list(session.execute(
        select(Department).where(Department.organization_id == principal.organization_id)
        .order_by(Department.name)
    ).scalars().all())


@router.post("/departments", response_model=DepartmentOut, status_code=201,
             summary="Create a department")
def create_department(payload: DepartmentCreate,
                      principal: Annotated[Principal, Depends(require("team:write"))],
                      session: TenantSession, request: Request) -> Department:
    dept = Department(organization_id=principal.organization_id, **payload.model_dump())
    session.add(dept)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="a department with that name exists")
    audit.record(session, action="department.create", object_type="department",
                 object_id=dept.id, object_label=dept.name, **_actor(request, principal))
    session.commit()
    return dept


# --- roles ----------------------------------------------------------------


@router.get("/roles", response_model=list[RoleOut], summary="List roles (built-in + tenant)")
def list_roles(principal: Annotated[Principal, Depends(require("role:read"))],
               session: TenantSession) -> list[Role]:
    return list(session.execute(
        select(Role)
        .where(or_(Role.organization_id == principal.organization_id,
                   Role.organization_id.is_(None)))
        .order_by(Role.is_builtin.desc(), Role.name)
    ).scalars().all())


@router.get("/permissions", response_model=list[str], summary="Every assignable permission")
def list_permissions(_: Annotated[Principal, Depends(require("role:read"))]) -> list[str]:
    return sorted(perms.ALL_PERMISSIONS)


@router.post("/roles", response_model=RoleOut, status_code=201, summary="Create a custom role")
def create_role(payload: RoleCreate,
                principal: Annotated[Principal, Depends(require("role:admin"))],
                session: TenantSession, request: Request) -> Role:
    invalid = [p for p in payload.permissions if not perms.is_valid(p)]
    if invalid:
        raise HTTPException(status_code=422,
                            detail=f"unknown permissions: {', '.join(sorted(invalid))}")
    role = Role(organization_id=principal.organization_id, is_builtin=False,
                **payload.model_dump())
    session.add(role)
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="a role with that slug already exists")
    audit.record(session, action="role.create", object_type="role", object_id=role.id,
                 object_label=role.slug, changes={"permissions": {"to": role.permissions}},
                 **_actor(request, principal))
    session.commit()
    return role


@router.patch("/roles/{role_id}", response_model=RoleOut, summary="Update a custom role")
def update_role(role_id: uuid.UUID, payload: RoleUpdate,
                principal: Annotated[Principal, Depends(require("role:admin"))],
                session: TenantSession, request: Request) -> Role:
    role = session.get(Role, role_id)
    if role is None or role.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="role not found")
    if role.is_builtin:
        raise HTTPException(status_code=422, detail="built-in roles cannot be modified")
    data = payload.model_dump(exclude_unset=True)
    if "permissions" in data:
        invalid = [p for p in data["permissions"] if not perms.is_valid(p)]
        if invalid:
            raise HTTPException(status_code=422,
                                detail=f"unknown permissions: {', '.join(sorted(invalid))}")
    before = role.as_dict()
    for field, value in data.items():
        setattr(role, field, value)
    audit.record(session, action="role.update", object_type="role", object_id=role.id,
                 object_label=role.slug, changes=audit.diff(before, role.as_dict()),
                 **_actor(request, principal))
    session.commit()
    return role


# --- api keys -------------------------------------------------------------


@router.get("/api-keys", response_model=list[ApiKeyOut], summary="List API keys")
def list_api_keys(principal: Annotated[Principal, Depends(require("apikey:read"))],
                  session: TenantSession) -> list[ApiKey]:
    return list(session.execute(
        select(ApiKey).where(ApiKey.organization_id == principal.organization_id)
        .order_by(ApiKey.created_at.desc())
    ).scalars().all())


@router.post("/api-keys", response_model=ApiKeyCreated, status_code=201,
             summary="Issue an API key (secret shown once)")
def create_api_key(payload: ApiKeyCreate,
                   principal: Annotated[Principal, Depends(require("apikey:write"))],
                   session: TenantSession, request: Request) -> ApiKeyCreated:
    invalid = [p for p in payload.scopes if not perms.is_valid(p)]
    if invalid:
        raise HTTPException(status_code=422,
                            detail=f"unknown scopes: {', '.join(sorted(invalid))}")
    # A key can never be more powerful than the identity that minted it.
    excess = perms.expand(payload.scopes) - principal.permissions
    if excess and not principal.is_superuser:
        raise HTTPException(
            status_code=403,
            detail=f"scopes exceed your own permissions: {', '.join(sorted(excess)[:5])}",
        )
    clear, prefix, key_hash = new_api_key()
    record = ApiKey(
        organization_id=principal.organization_id,
        name=payload.name, prefix=prefix, key_hash=key_hash,
        created_by_id=principal.user_id, scopes=payload.scopes,
        expires_at=(
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=payload.expires_in_days)
            if payload.expires_in_days else None
        ),
    )
    session.add(record)
    session.flush()
    audit.record(session, action="apikey.create", object_type="apikey", object_id=record.id,
                 object_label=record.name, changes={"scopes": {"to": payload.scopes}},
                 **_actor(request, principal))
    session.commit()
    # `api_key` has no counterpart on the ORM row (by design - only the hash is
    # stored), so build the response from the validated base plus the clear key.
    return ApiKeyCreated(**ApiKeyOut.model_validate(record).model_dump(), api_key=clear)


@router.delete("/api-keys/{key_id}", status_code=204, response_model=None, response_class=Response, summary="Revoke an API key")
def revoke_api_key(key_id: uuid.UUID,
                   principal: Annotated[Principal, Depends(require("apikey:delete"))],
                   session: TenantSession, request: Request) -> None:
    record = session.get(ApiKey, key_id)
    if record is None or record.organization_id != principal.organization_id:
        raise HTTPException(status_code=404, detail="api key not found")
    record.revoked_at = dt.datetime.now(dt.timezone.utc)
    audit.record(session, action="apikey.revoke", object_type="apikey", object_id=record.id,
                 object_label=record.name, **_actor(request, principal))
    session.commit()


# --- audit trail ----------------------------------------------------------


@router.get("/audit", response_model=Page[AuditOut], summary="Query the audit trail")
def list_audit(
    principal: Annotated[Principal, Depends(require("audit:read"))],
    session: TenantSession,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None, max_length=80),
    object_type: str | None = Query(None, max_length=80),
    object_id: str | None = Query(None, max_length=80),
    since: dt.datetime | None = None,
) -> Page[AuditOut]:
    where = [AuditLog.organization_id == principal.organization_id]
    if action:
        where.append(AuditLog.action == action)
    if object_type:
        where.append(AuditLog.object_type == object_type)
    if object_id:
        where.append(AuditLog.object_id == object_id)
    if since:
        where.append(AuditLog.created_at >= since)
    total = session.execute(select(func.count()).select_from(AuditLog).where(*where)).scalar_one()
    rows = session.execute(
        select(AuditLog).where(*where)
        .order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page[AuditOut](
        items=[AuditOut.model_validate(r) for r in rows], total=total, limit=limit, offset=offset
    )
