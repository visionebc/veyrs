"""Authentication endpoints: login, refresh, logout, me, password change.

Hardening decisions worth reading before changing anything here:
  * A wrong password, an unknown email, a disabled user and a disabled
    organization all produce the SAME 401 body. Account enumeration through this
    endpoint is not possible.
  * Failed logins increment a counter and lock the account for 15 minutes after
    10 failures. The lock is per-user, not per-IP, so a distributed attempt does
    not bypass it.
  * Refresh tokens rotate on every use. Presenting an already-rotated token
    revokes the whole family - the standard stolen-token signal.
"""
from __future__ import annotations

import datetime as dt
import uuid

from fastapi import Response, APIRouter, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ...config import settings
from ...db import get_session, set_tenant
from ...models.tenancy import Organization, RefreshToken, Role, Team, TeamMember, User, UserRole
from ...security.auth import (
    create_access_token,
    hash_password,
    hash_token,
    needs_rehash,
    new_refresh_token,
    refresh_expiry,
    verify_password,
)
from ...security import mfa
from ...security.deps import CurrentPrincipal, effective_permissions
from ...services import audit, ldap_auth, scanning
from ...services import risk_register_mode, ticketing_mode
from .schemas import (
    LoginRequest,
    MeResponse,
    MfaActivate,
    MfaDisable,
    MfaEnrollResponse,
    PasswordChange,
    RefreshRequest,
    TokenPair,
    UserPreferencesPatch,
)

from fastapi import Depends
from typing import Annotated

router = APIRouter(prefix="/auth", tags=["authentication"])

MAX_FAILED = 10
LOCK_MINUTES = 15
GENERIC_401 = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="invalid credentials",
    headers={"WWW-Authenticate": "Bearer"},
)

DbSession = Annotated[Session, Depends(get_session)]


def _client(request: Request) -> tuple[str | None, str | None, str | None]:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    return ip, request.headers.get("User-Agent"), getattr(request.state, "correlation_id", None)


def _issue(session: Session, user: User, request: Request) -> TokenPair:
    permissions = sorted(effective_permissions(session, user))
    access, expires = create_access_token(
        user_id=user.id,
        organization_id=user.organization_id,
        permissions=permissions,
        is_superuser=user.is_superuser,
    )
    clear, token_hash = new_refresh_token()
    ip, user_agent, _ = _client(request)
    record = RefreshToken(
        organization_id=user.organization_id,
        user_id=user.id,
        token_hash=token_hash,
        family_id=user.id,  # family root; rotation keeps the same family
        expires_at=refresh_expiry(),
        ip_address=ip,
        user_agent=(user_agent or "")[:255] or None,
    )
    session.add(record)
    return TokenPair(
        access_token=access,
        refresh_token=clear,
        expires_at=expires,
        organization_id=user.organization_id,
        user_id=user.id,
        permissions=permissions,
    )


def _spend_attempt(user: User) -> None:
    """Charge one failed attempt and lock the account once the budget is out.

    Password failures and MFA failures share this counter deliberately: two
    separate budgets would let an attacker who already knows the password
    spend an unlimited number of guesses on the six-digit second factor.
    """
    user.failed_logins += 1
    if user.failed_logins >= MAX_FAILED:
        user.locked_until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=LOCK_MINUTES)
        user.failed_logins = 0


def _sync_directory_roles(session: Session, user: User, slugs: list[str]) -> None:
    """Reconcile the DIRECTORY-granted role set. Manual grants are untouchable.

    `UserRole.origin` is what makes this safe (see the model). Rows this
    function created and the directory no longer justifies are removed; rows a
    person created by hand are left exactly where they are, even when the same
    role also arrives from a group.

    Every grant written here is estate-wide (`team_id=None`). Narrowing a role
    to a team is a VEYRS-side authorization decision with no equivalent in a
    directory group, and inventing one from a group name would be guessing at
    who may read what.
    """
    from ...models.tenancy import Role, UserRole

    wanted = {s for s in slugs if s}
    existing = session.execute(
        select(UserRole).where(UserRole.user_id == user.id)
    ).scalars().all()

    manual = {ur.role_id for ur in existing if ur.origin != "directory"}
    from_dir = {ur.role_id: ur for ur in existing if ur.origin == "directory"}

    roles = session.execute(
        select(Role).where(
            Role.slug.in_(wanted) if wanted else Role.slug.is_(None),
            # NOT `.in_([org_id, None])`: SQL `IN (x, NULL)` never matches a
            # NULL row, which would make every built-in role invisible. Same
            # trap `admin._assign_roles` documents.
            or_(Role.organization_id == user.organization_id, Role.organization_id.is_(None)),
        )
    ).scalars().all() if wanted else []

    wanted_ids = {r.id for r in roles}
    for role in roles:
        if role.id in manual or role.id in from_dir:
            continue
        session.add(UserRole(organization_id=user.organization_id, user_id=user.id,
                             role_id=role.id, team_id=None, origin="directory"))
    for role_id, grant in from_dir.items():
        if role_id not in wanted_ids:
            session.delete(grant)


def _jit_target_organization(session: Session, org_slug: str | None) -> uuid.UUID | None:
    """Which tenant a just-in-time account would be created in.

    With no local row there is no tenant to read off the account, so it has to
    come from somewhere unambiguous: the slug the caller supplied, or -- if
    exactly one tenant runs a directory -- that one. Anything else is a guess,
    and a guess here files a real person under the wrong customer.
    """
    if org_slug:
        org = session.execute(
            select(Organization).where(Organization.slug == org_slug)
        ).scalars().first()
        return org.id if org is not None else None
    enabled = ldap_auth.enabled_organization_ids(session)
    return enabled[0] if len(enabled) == 1 else None


def _provision_from_directory(
    session: Session, identifier: str, password: str, org_slug: str | None
) -> User | None:
    """Create the local row for somebody who exists upstream and not here.

    Off unless `jit_provisioning` is on, and it ships off. With it on, everyone
    the directory will bind -- contractors, the service desk, the intern -- can
    sign in to the platform holding the estate's unpatched vulnerabilities. What
    they can then SEE is `default_role_slugs`, which defaults to empty: an
    account that logs in and reads nothing until somebody grants it something.
    """
    org_id = _jit_target_organization(session, org_slug)
    if org_id is None:
        return None
    cfg = ldap_auth.config(session, org_id)
    if not cfg.get("jit_provisioning") or not ldap_auth.is_enabled(session, org_id):
        return None
    try:
        identity = ldap_auth.authenticate(session, org_id, identifier, password)
    except ldap_auth.LdapError:
        return None
    if identity is None:
        return None
    if not identity.email:
        # `users.email` is NOT NULL and the address is what every notification,
        # ticket assignment and digest is delivered to. Synthesising one would
        # produce an account whose mail silently goes nowhere; refusing leaves a
        # named reason in the audit log for the operator to act on.
        audit.record_auth(session, event="login", success=False,
                          organization_id=org_id, email_attempted=identifier,
                          reason="jit_no_email")
        return None

    # Still pre-auth, so nothing has bound the tenant yet -- and what follows
    # writes to strictly isolated tables (`user_roles` for the directory's
    # grants, `audit_log`), where an unbound INSERT fails WITH CHECK. The
    # directory of exactly this organization just vouched for the account,
    # which is the same fact `get_principal` binds on the next request.
    set_tenant(session, org_id)
    user = User(
        organization_id=org_id,
        email=identity.email.lower(),
        username=(identity.username or identifier).lower(),
        full_name=identity.full_name or identity.username or identifier,
        # No local password, deliberately: this account authenticates upstream
        # and there must be nothing here to brute force or to keep working
        # after the directory revokes it.
        password_hash=None,
        ldap_dn=identity.dn,
        is_active=True,
    )
    session.add(user)
    session.flush()
    _sync_directory_roles(session, user, ldap_auth.roles_for(cfg, identity))
    audit.record(session, organization_id=org_id,
                 action="user.provisioned_from_directory", object_type="user",
                 object_id=user.id, object_label=user.email,
                 changes={"dn": {"from": None, "to": identity.dn}})
    return user


def _check_credential(session: Session, user: User, password: str) -> str | None:
    """How this password checked out: `"local"`, `"directory"`, or None.

    Order is local first, directory second, and it is not arbitrary. A local
    password is a fact this database already holds -- checking it costs one
    Argon2 verification and cannot be affected by a firewall. Asking the
    directory first would put a network round trip in front of every login,
    including the break-glass one an operator makes precisely because the
    network is what broke.

    A platform superuser is NEVER delegated. See the module docstring of
    `services/ldap_auth.py`: the account that can repair a bad directory
    configuration must not depend on the directory being good.
    """
    if user.password_hash and verify_password(password, user.password_hash):
        return "local"
    if user.is_superuser:
        return None
    if not ldap_auth.is_enabled(session, user.organization_id):
        return None
    try:
        identity = ldap_auth.authenticate(
            session, user.organization_id, user.username or user.email, password
        )
    except ldap_auth.LdapError:
        # Unreachable, misconfigured, or the library is missing. This is NOT a
        # credential failure, and it must not be reported as one -- but there is
        # no safe way to let somebody in, so the answer is still no. The
        # distinction survives in the audit reason, which is where an operator
        # looks when "everyone's password stopped working" at 09:00.
        return "directory_unavailable"
    if identity is None:
        return None
    if not _identity_matches(user, identity):
        # The directory answered about somebody else. Happens when a local row
        # was hand-created with a username that belongs to a different person
        # upstream; binding successfully proves the TYPIST owns that directory
        # account, not that they own this VEYRS row.
        return None
    _apply_identity(session, user, identity)
    return "directory"


def _identity_matches(user: User, identity: "ldap_auth.LdapIdentity") -> bool:
    """Is this directory entry the one this local row represents?

    DN first, because that is what the directory considers stable across a
    rename. Falling back to the account name and then the address covers the
    first login of an account created by hand before the directory was wired
    up, which has no DN recorded yet.
    """
    if user.ldap_dn and identity.dn:
        return user.ldap_dn.lower() == identity.dn.lower()
    if user.username and identity.username:
        return user.username.lower() == identity.username.lower()
    if user.email and identity.email:
        return user.email.lower() == identity.email.lower()
    return False


def _apply_identity(session: Session, user: User, identity: "ldap_auth.LdapIdentity") -> None:
    """Copy what the directory is authoritative about onto the local row.

    Deliberately narrow: DN, account name, display name. NOT `is_active`, and
    NOT the email address once one is set -- an address change upstream that
    silently repoints VEYRS notifications is a surprise nobody asked for, and
    an operator who disabled somebody here must not have that undone by a sync.
    """
    if identity.dn:
        user.ldap_dn = identity.dn
    if identity.username and not user.username:
        user.username = identity.username.lower()
    if identity.full_name and not user.full_name:
        user.full_name = identity.full_name
    if identity.email and not user.email:
        user.email = identity.email.lower()

    cfg = ldap_auth.config(session, user.organization_id)
    if cfg.get("sync_roles_on_login"):
        # Pre-auth: `user_roles` is strictly isolated, so without a bound tenant
        # every grant fails WITH CHECK and the login dies with a 500. The
        # directory has just vouched that this row is this person.
        set_tenant(session, user.organization_id)
        _sync_directory_roles(session, user, ldap_auth.roles_for(cfg, identity))


@router.post("/login", response_model=TokenPair, summary="Exchange credentials for tokens")
def login(payload: LoginRequest, request: Request, session: DbSession) -> TokenPair:
    ip, user_agent, correlation_id = _client(request)
    # A username OR an email address. `LoginRequest.login_identifier` folds the
    # legacy `email` field into the same value, so a client that predates this
    # release keeps working unchanged.
    identifier = payload.login_identifier
    query = select(User).join(Organization).where(
        or_(User.email == identifier, User.username == identifier),
        User.deleted_at.is_(None),
    )
    if payload.organization:
        query = query.where(Organization.slug == payload.organization)
    candidates = session.execute(query).scalars().all()

    if len(candidates) > 1:
        # Same identifier in several tenants and no slug supplied. Tell the
        # caller which slugs to choose from ONLY if they already proved the
        # password -- otherwise this route enumerates tenancy for free.
        verified = [u for u in candidates if _check_credential(session, u, payload.password)
                    in {"local", "directory"}]
        if not verified:
            audit.record_auth(session, event="login", success=False,
                              email_attempted=identifier, reason="bad_password",
                              ip_address=ip, user_agent=user_agent,
                              correlation_id=correlation_id)
            session.commit()
            raise GENERIC_401
        if len(verified) > 1:
            slugs = sorted(session.get(Organization, u.organization_id).slug for u in verified)
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={"error": "organization_required", "organizations": slugs},
            )
        candidates = verified

    user = candidates[0] if candidates else None
    if user is None:
        # Nobody local. If a tenant runs a directory with just-in-time
        # provisioning on, this is the first login of somebody who exists
        # upstream and has never been here.
        user = _provision_from_directory(
            session, identifier, payload.password, payload.organization
        )
    if user is None:
        # Burn comparable time so a missing account is not measurably faster.
        verify_password(payload.password, None)
        audit.record_auth(session, event="login", success=False,
                          email_attempted=identifier, reason="unknown_user",
                          ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    if user.is_locked:
        audit.record_auth(session, event="login", success=False, user_id=user.id,
                          organization_id=user.organization_id, email_attempted=identifier,
                          reason="locked", ip_address=ip, user_agent=user_agent,
                          correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    method = _check_credential(session, user, payload.password)
    if method not in {"local", "directory"}:
        _spend_attempt(user)
        audit.record_auth(session, event="login", success=False, user_id=user.id,
                          organization_id=user.organization_id, email_attempted=identifier,
                          reason=("directory_unavailable" if method == "directory_unavailable"
                                  else "bad_password"),
                          ip_address=ip, user_agent=user_agent,
                          correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    organization = session.get(Organization, user.organization_id)
    if not user.is_active or organization is None or not organization.is_active:
        audit.record_auth(session, event="login", success=False, user_id=user.id,
                          organization_id=user.organization_id, email_attempted=identifier,
                          reason="inactive", ip_address=ip, user_agent=user_agent,
                          correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    if user.mfa_enabled:
        if not payload.mfa_code:
            # A challenge, not a failure: the client is expected to come back
            # with a code, so this must not spend the lockout budget.
            session.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail={"error": "mfa_required"})
        try:
            secret = mfa.unseal(user.mfa_secret)
        except mfa.MfaError:
            # Enabled but unusable (key rotated, row corrupt). Fail CLOSED:
            # falling through to password-only would silently downgrade the
            # one account that explicitly asked for a second factor.
            _spend_attempt(user)
            audit.record_auth(session, event="login", success=False, user_id=user.id,
                              organization_id=user.organization_id,
                              email_attempted=identifier, reason="mfa_unusable",
                              ip_address=ip, user_agent=user_agent,
                              correlation_id=correlation_id)
            session.commit()
            raise GENERIC_401
        matched_step = mfa.verify(secret, payload.mfa_code, last_step=user.mfa_last_step)
        if matched_step is None:
            # Wrong, malformed or replayed. Shares the password budget on
            # purpose: six digits are guessable if attempts are not capped.
            _spend_attempt(user)
            audit.record_auth(session, event="login", success=False, user_id=user.id,
                              organization_id=user.organization_id,
                              email_attempted=identifier, reason="bad_mfa",
                              ip_address=ip, user_agent=user_agent,
                              correlation_id=correlation_id)
            session.commit()
            raise GENERIC_401
        user.mfa_last_step = matched_step

    # `method == "local"` is load-bearing, not a tidy-up. `needs_rehash("")` is
    # True, so without this guard a directory login would fall in here and write
    # `hash_password(payload.password)` onto a row whose whole point is that it
    # has NO local password. The estate would silently acquire a local copy of
    # every domain password typed into it, each one frozen at the moment it was
    # typed -- so a password changed or revoked upstream would keep working here
    # forever, which is the exact failure delegating authentication is meant to
    # remove.
    if method == "local" and needs_rehash(user.password_hash or ""):
        user.password_hash = hash_password(payload.password)

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    tokens = _issue(session, user, request)
    audit.record_auth(session, event="login", success=True, user_id=user.id,
                      organization_id=user.organization_id, email_attempted=identifier,
                      reason=f"auth:{method}",
                      ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
    session.commit()
    return tokens


@router.post("/refresh", response_model=TokenPair, summary="Rotate a refresh token")
def refresh(payload: RefreshRequest, request: Request, session: DbSession) -> TokenPair:
    ip, user_agent, correlation_id = _client(request)
    token_hash = hash_token(payload.refresh_token)
    record = session.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    ).scalar_one_or_none()
    now = dt.datetime.now(dt.timezone.utc)

    if record is None:
        audit.record_auth(session, event="refresh", success=False, reason="unknown_token",
                          ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    if record.revoked_at is not None:
        # Replay of a rotated token: assume theft, kill the family.
        session.query(RefreshToken).filter(
            RefreshToken.family_id == record.family_id,
            RefreshToken.revoked_at.is_(None),
        ).update({RefreshToken.revoked_at: now}, synchronize_session=False)
        audit.record_auth(session, event="refresh", success=False, user_id=record.user_id,
                          organization_id=record.organization_id, reason="reuse_detected",
                          ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    if record.expires_at <= now:
        record.revoked_at = now
        audit.record_auth(session, event="refresh", success=False, user_id=record.user_id,
                          organization_id=record.organization_id, reason="expired",
                          ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
        session.commit()
        raise GENERIC_401

    user = session.get(User, record.user_id)
    if user is None or not user.is_active or user.is_deleted:
        record.revoked_at = now
        session.commit()
        raise GENERIC_401

    record.revoked_at = now
    tokens = _issue(session, user, request)
    # keep the rotated token in the original family for reuse detection
    session.flush()
    latest = session.execute(
        select(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .order_by(RefreshToken.created_at.desc())
    ).scalars().first()
    if latest is not None:
        latest.family_id = record.family_id
    audit.record_auth(session, event="refresh", success=True, user_id=user.id,
                      organization_id=user.organization_id, ip_address=ip,
                      user_agent=user_agent, correlation_id=correlation_id)
    session.commit()
    return tokens


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, response_model=None, response_class=Response, summary="Revoke refresh tokens")
def logout(principal: CurrentPrincipal, session: DbSession, request: Request) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    session.query(RefreshToken).filter(
        RefreshToken.user_id == principal.user_id,
        RefreshToken.revoked_at.is_(None),
    ).update({RefreshToken.revoked_at: now}, synchronize_session=False)
    ip, user_agent, correlation_id = _client(request)
    audit.record_auth(session, event="logout", success=True, user_id=principal.user_id,
                      organization_id=principal.organization_id, ip_address=ip,
                      user_agent=user_agent, correlation_id=correlation_id)
    session.commit()


@router.get("/me", response_model=MeResponse, summary="The authenticated identity")
def me(principal: CurrentPrincipal, session: DbSession) -> MeResponse:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    roles = session.execute(
        select(Role.slug).join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id)
    ).scalars().all()
    teams = session.execute(
        select(Team.slug).join(TeamMember, TeamMember.team_id == Team.id)
        .where(TeamMember.user_id == user.id)
    ).scalars().all()
    out = MeResponse.model_validate(user)
    out.permissions = sorted(principal.permissions)
    out.roles = sorted(roles)
    out.teams = sorted(teams)
    out.scope = principal.scope.as_dict()
    # `DbSession` is bound: `CurrentPrincipal` resolved first and FastAPI caches
    # `get_session` per request, so `veyrs.current_org` is already set on this
    # very session -- the same reason the preference routes below can use it.
    out.active_scanning = scanning.is_enabled(session, principal.organization_id)
    # Shipped here rather than left to `GET /ticketing` for the reason
    # `active_scanning` is: the console paints its nav once, at boot, and a
    # tenant whose remediation lives in Jira must not be shown a Tickets
    # section that disappears a moment later.
    _ticketing = ticketing_mode.state(session, principal.organization_id)
    out.ticketing_mode = _ticketing["mode"]
    out.ticketing_usable = _ticketing["usable"]
    # Shipped here for the reason `active_scanning` and `ticketing_mode` are:
    # the nav is painted once at boot, and a section that appears and then
    # vanishes a moment later reads as the console losing pages by itself.
    out.risk_register_enabled = risk_register_mode.is_enabled(
        session, principal.organization_id
    )
    return out


# ---------------------------------------------------------------------------
# Console preferences
#
# Not audited, and that is a decision rather than an omission. The dashboard
# scope picker writes here on every change; an audit trail that fills with
# "looked at one team instead of the estate" buries the entries somebody will
# one day need to find. Nothing written here grants or removes anything --
# `?team_id=` is a view filter that can only ever intersect the caller's own
# scope, resolved from scratch on every read (`security.scope.resolve_view`).
#
# `DbSession` is not a hole here: `CurrentPrincipal` runs first and FastAPI
# caches `get_session` per request, so `get_principal` has already bound
# `veyrs.current_org` on this very session. Without that, `teams` -- which is
# RLS-FORCED with no unbound escape, unlike `users` -- would return zero rows
# and every valid team id would be refused as "not found".
# ---------------------------------------------------------------------------
PREFERENCE_KEYS = ("dashboard_team_id",)


def _preferences(user: User) -> dict:
    """Every known key, always present; nothing else ever leaves.

    Reading through the whitelist rather than returning the raw column means a
    key retired in a later version stops being served the moment it is removed
    from `PREFERENCE_KEYS`, without a migration to clean rows that no longer
    matter.
    """
    stored = user.preferences or {}
    return {key: stored.get(key) for key in PREFERENCE_KEYS}


def _me(principal, session: Session) -> User:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    return user


@router.get("/me/preferences", summary="My console preferences")
def my_console_preferences(principal: CurrentPrincipal, session: DbSession) -> dict:
    return _preferences(_me(principal, session))


@router.patch("/me/preferences", summary="Remember a console preference")
def patch_console_preferences(
    payload: UserPreferencesPatch, principal: CurrentPrincipal, session: DbSession
) -> dict:
    user = _me(principal, session)
    sent = payload.model_dump(exclude_unset=True)
    team_id = sent.get("dashboard_team_id")
    if team_id is not None:
        # Validated on write so a dangling id is never stored. 404, the same
        # answer `resolve_view` gives, because 403 would confirm that a team
        # exists in a tenant the caller cannot read.
        #
        # A team-restricted principal may still save a team outside their
        # scope: it is a view filter, and the read it feeds intersects their
        # authorization anyway. Refusing here would mean this route quietly
        # became a second, weaker copy of the scope check.
        team = session.get(Team, team_id)
        if team is None or team.organization_id != user.organization_id:
            raise HTTPException(status_code=404, detail="team not found")
    merged = dict(user.preferences or {})
    for key, value in sent.items():
        # Stringified: JSONB has no UUID type, and a value that comes back as
        # a string on read but goes out as a UUID on write is how a comparison
        # against the team list silently fails.
        merged[key] = str(value) if value is not None else None
    # Reassigned, not mutated in place: SQLAlchemy does not track a JSONB dict
    # that is edited under it, and the commit would be a no-op that reports
    # success.
    user.preferences = merged
    session.commit()
    return _preferences(user)


@router.get("/me/scope", summary="What this identity may see, and what nobody can")
def my_scope(principal: CurrentPrincipal, session: DbSession) -> dict:
    """The scope plus the estate's unowned residue.

    The second half is the point. Deny-by-default on unowned rows means work
    with no team is invisible to every scoped user at once -- a blind spot that
    grows quietly as new assets arrive without an owner. Counting it here turns
    "my queue is empty" into a question with an answer.
    """
    from ...security import scope as team_scope

    coverage = team_scope.coverage(session, principal.organization_id)
    return {
        "scope": principal.scope.as_dict(),
        "unowned": coverage,
        "warning": (
            "assets and findings with no owning team are invisible to every "
            "team-scoped identity"
            if (coverage["assets"]["unowned"] or coverage["findings"]["unowned"])
            else None
        ),
    }


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT, response_model=None, response_class=Response, summary="Change own password")
def change_password(
    payload: PasswordChange, principal: CurrentPrincipal, session: DbSession, request: Request
) -> None:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None or not verify_password(payload.current_password, user.password_hash):
        raise GENERIC_401
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=422, detail="new password must differ")
    user.password_hash = hash_password(payload.new_password)
    now = dt.datetime.now(dt.timezone.utc)
    # A password change invalidates every existing session.
    session.query(RefreshToken).filter(
        RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)
    ).update({RefreshToken.revoked_at: now}, synchronize_session=False)
    ip, user_agent, correlation_id = _client(request)
    audit.record(session, action="password.change", object_type="user", object_id=user.id,
                 object_label=user.email, organization_id=user.organization_id,
                 actor_id=user.id, actor_label=user.email, correlation_id=correlation_id,
                 ip_address=ip, user_agent=user_agent)
    session.commit()


# ---------------------------------------------------------------------------
# MFA enrolment lifecycle.
#
# Three steps on purpose. `enroll` hands out a secret but leaves the account on
# password-only; `activate` is the proof that the operator's authenticator app
# actually works. Enabling in one step is how administrators lock themselves
# out of the console they administer.
# ---------------------------------------------------------------------------
@router.post("/mfa/enroll", response_model=MfaEnrollResponse,
             summary="Begin MFA enrolment (returns the shared secret once)")
def mfa_enroll(principal: CurrentPrincipal, session: DbSession,
               request: Request) -> MfaEnrollResponse:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    if user.mfa_enabled:
        # Re-enrolling would silently invalidate the working authenticator.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_already_enabled"})

    secret = mfa.generate_secret()
    user.mfa_secret = mfa.seal(secret)
    user.mfa_last_step = None
    ip, user_agent, correlation_id = _client(request)
    audit.record(session, action="mfa.enroll", object_type="user", object_id=user.id,
                 object_label=user.email, organization_id=user.organization_id,
                 actor_id=user.id, actor_label=user.email, correlation_id=correlation_id,
                 ip_address=ip, user_agent=user_agent)
    session.commit()
    return MfaEnrollResponse(
        secret=secret,
        provisioning_uri=mfa.provisioning_uri(secret, account=user.email,
                                              issuer=settings.app_name),
        digits=mfa.DIGITS,
        period=mfa.PERIOD,
    )


@router.post("/mfa/activate", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
             response_class=Response, summary="Confirm enrolment and require MFA at login")
def mfa_activate(payload: MfaActivate, principal: CurrentPrincipal, session: DbSession,
                 request: Request) -> None:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_already_enabled"})
    try:
        secret = mfa.unseal(user.mfa_secret)
    except mfa.MfaError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_not_enrolled"})

    step = mfa.verify(secret, payload.code, last_step=user.mfa_last_step)
    if step is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"error": "invalid_code"})
    user.mfa_enabled = True
    user.mfa_last_step = step
    ip, user_agent, correlation_id = _client(request)
    audit.record(session, action="mfa.activate", object_type="user", object_id=user.id,
                 object_label=user.email, organization_id=user.organization_id,
                 actor_id=user.id, actor_label=user.email, correlation_id=correlation_id,
                 ip_address=ip, user_agent=user_agent)
    session.commit()


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
             response_class=Response, summary="Turn MFA off (password AND a valid code)")
def mfa_disable(payload: MfaDisable, principal: CurrentPrincipal, session: DbSession,
                request: Request) -> None:
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_not_enabled"})
    # Both factors. A stolen access token alone must not be able to strip the
    # second factor off the account it was stolen from.
    if not verify_password(payload.password, user.password_hash):
        raise GENERIC_401
    try:
        secret = mfa.unseal(user.mfa_secret)
    except mfa.MfaError:
        # Unusable secret: the password alone is enough to clear the dead
        # state, otherwise a key rotation would brick the account for good.
        secret = None
    if secret is not None and mfa.verify(secret, payload.code,
                                         last_step=user.mfa_last_step) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"error": "invalid_code"})

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_last_step = None
    ip, user_agent, correlation_id = _client(request)
    audit.record(session, action="mfa.disable", object_type="user", object_id=user.id,
                 object_label=user.email, organization_id=user.organization_id,
                 actor_id=user.id, actor_label=user.email, correlation_id=correlation_id,
                 ip_address=ip, user_agent=user_agent)
    session.commit()
