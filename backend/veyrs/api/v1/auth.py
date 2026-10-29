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
from fastapi.responses import HTMLResponse, RedirectResponse
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
from ...security import mfa, mfa_delivery
from ...security.deps import CurrentPrincipal, effective_permissions
from ...services import audit, ldap_auth, oidc_auth, radius_auth, scanning
from ...services import risk_register_mode, ticketing_mode
from .schemas import (
    LoginRequest,
    MeResponse,
    MfaActivate,
    MfaDisable,
    MfaEnrollRequest,
    OidcExchange,
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


def _check_credential(session: Session, user: User, password: str,
                      ctx: dict | None = None) -> str | None:
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
        return _check_radius(session, user, password, ctx)
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
        # Not the directory's password. An organization may run both: RADIUS
        # is asked next (directory first, because it also describes the person).
        return _check_radius(session, user, password, ctx)
    if not _identity_matches(user, identity):
        # The directory answered about somebody else. Happens when a local row
        # was hand-created with a username that belongs to a different person
        # upstream; binding successfully proves the TYPIST owns that directory
        # account, not that they own this VEYRS row.
        return None
    _apply_identity(session, user, identity)
    return "directory"


def _check_radius(session: Session, user: User, password: str, ctx: dict | None) -> str | None:
    """RADIUS (services/radius_auth.py): "radius", "radius_challenge", "radius_unavailable" or None."""
    if not radius_auth.is_enabled(session, user.organization_id):
        return None
    try:
        answer = radius_auth.authenticate(session, user.organization_id,
                                          user.username or user.email, password)
    except radius_auth.RadiusError:
        # Same shape as the directory: unreachable is not a wrong password, and
        # it is not a way in either. The audit reason keeps the difference.
        return "radius_unavailable"
    return _radius_outcome(session, user, answer, ctx)


def _radius_outcome(session: Session, user: User, answer: "radius_auth.RadiusAnswer",
                    ctx: dict | None) -> str | None:
    if answer.outcome == "accept":
        roles = radius_auth.roles_for(radius_auth.config(session, user.organization_id), answer)
        if roles is not None:
            # The server just vouched for this name; bind the tenant before
            # touching user_roles (strictly isolated), as the directory does.
            set_tenant(session, user.organization_id)
            _sync_directory_roles(session, user, roles)
        return "radius"
    if answer.outcome == "challenge":
        if ctx is None:
            return None          # a caller that cannot carry a challenge treats it as "no"
        try:
            ctx["challenge"] = radius_auth.save_challenge(user.id, answer)
        except Exception:  # noqa: BLE001 - no code store = no second round: fail closed
            return "radius_unavailable"
        ctx["message"] = answer.reply_message
        return "radius_challenge"
    return None


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

    radius_ctx: dict = {}
    radius_second_factor = False
    if payload.radius_challenge:
        # The answer to a RADIUS Access-Challenge. The first round proved the
        # password to the RADIUS server; the challenge id (random, two minutes,
        # single use, bound to THIS account) is what carries that proof here.
        pending = radius_auth.take_challenge(payload.radius_challenge, user.id)
        if pending is None:
            method = None
        else:
            try:
                answer = radius_auth.answer_challenge(
                    session, user.organization_id, user.username or user.email,
                    pending, payload.mfa_code or "")
                method = _radius_outcome(session, user, answer, radius_ctx)
                radius_second_factor = method == "radius"
            except radius_auth.RadiusError:
                method = "radius_unavailable"
    else:
        method = _check_credential(session, user, payload.password, radius_ctx)
    if method == "radius_challenge":
        # A challenge, not a failure: the password was right, the server wants
        # its second factor. Nothing is spent from the lockout budget.
        session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={
            "error": "mfa_required", "method": "radius",
            "message": radius_ctx.get("message") or "Enter the code your authentication server asks for",
            "radius_challenge": radius_ctx["challenge"]})
    if method not in {"local", "directory", "radius"}:
        _spend_attempt(user)
        audit.record_auth(session, event="login", success=False, user_id=user.id,
                          organization_id=user.organization_id, email_attempted=identifier,
                          reason=(method if method in ("directory_unavailable", "radius_unavailable")
                                  else "bad_radius_code" if payload.radius_challenge
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

    # When the RADIUS server ran its own second factor (Access-Challenge
    # answered), VEYRS does not ask for a second one of its own.
    credential = method
    if user.mfa_enabled and not radius_second_factor:
        method = user.mfa_method or "totp"
        if not payload.mfa_code:
            # A challenge, not a failure: the client is expected to come back
            # with a code, so this must not spend the lockout budget. For a
            # delivered method the code is sent NOW -- after the password was
            # proved, never before, so nobody can make VEYRS message a person
            # by typing their address.
            challenge = {"error": "mfa_required", "method": method}
            if method in mfa_delivery.DELIVERED:
                try:
                    challenge.update(_send_or_explain(user, method, "login"))
                except HTTPException as exc:
                    audit.record_auth(session, event="login", success=False, user_id=user.id,
                                      organization_id=user.organization_id,
                                      email_attempted=identifier, reason="mfa_delivery_failed",
                                      ip_address=ip, user_agent=user_agent,
                                      correlation_id=correlation_id)
                    session.commit()
                    raise exc
                challenge["error"] = "mfa_required"
            session.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=challenge)
        if method == "totp" and not mfa_delivery.looks_like_recovery(payload.mfa_code):
            try:
                mfa.unseal(user.mfa_secret)
            except mfa.MfaError:
                # Enabled but unusable (key rotated, row corrupt). Fail CLOSED:
                # falling through to password-only would silently downgrade the
                # one account that explicitly asked for a second factor. A
                # recovery code still works -- that is what it is for.
                _spend_attempt(user)
                audit.record_auth(session, event="login", success=False, user_id=user.id,
                                  organization_id=user.organization_id,
                                  email_attempted=identifier, reason="mfa_unusable",
                                  ip_address=ip, user_agent=user_agent,
                                  correlation_id=correlation_id)
                session.commit()
                raise GENERIC_401
        how = _second_factor_ok(user, payload.mfa_code)
        if how is None:
            # Wrong, malformed, expired or replayed. Shares the password budget
            # on purpose: six digits are guessable if attempts are not capped.
            _spend_attempt(user)
            audit.record_auth(session, event="login", success=False, user_id=user.id,
                              organization_id=user.organization_id,
                              email_attempted=identifier, reason="bad_mfa",
                              ip_address=ip, user_agent=user_agent,
                              correlation_id=correlation_id)
            session.commit()
            raise GENERIC_401
        if how == "recovery":
            audit.record(session, action="mfa.recovery_code.used", object_type="user",
                         object_id=user.id, object_label=user.email,
                         organization_id=user.organization_id, actor_id=user.id,
                         actor_label=user.email, correlation_id=correlation_id,
                         ip_address=ip, user_agent=user_agent,
                         changes={"left": len(user.mfa_recovery_codes or [])})

    # `method == "local"` is load-bearing, not a tidy-up. `needs_rehash("")` is
    # True, so without this guard a directory login would fall in here and write
    # `hash_password(payload.password)` onto a row whose whole point is that it
    # has NO local password. The estate would silently acquire a local copy of
    # every domain password typed into it, each one frozen at the moment it was
    # typed -- so a password changed or revoked upstream would keep working here
    # forever, which is the exact failure delegating authentication is meant to
    # remove.
    if credential == "local" and needs_rehash(user.password_hash or ""):
        user.password_hash = hash_password(payload.password)

    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    tokens = _issue(session, user, request)
    audit.record_auth(session, event="login", success=True, user_id=user.id,
                      organization_id=user.organization_id, email_attempted=identifier,
                      reason=f"auth:{credential}" + ("+challenge" if radius_second_factor else ""),
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
# Three steps on purpose. `enroll` picks a method and proves nothing yet: the
# account stays on password-only. `activate` is the proof that the second
# factor actually reaches the person -- the authenticator app produces a code,
# or the e-mail / Telegram message arrived. Enabling in one step is how
# administrators lock themselves out of the console they administer.
#
# Methods: `totp` (authenticator app, security/mfa.py), `email` and `telegram`
# (a code sent to the person, security/mfa_delivery.py). Activation hands out
# ten single-use recovery codes, once.
# ---------------------------------------------------------------------------
def _me(principal, session: Session) -> User:  # noqa: ANN001
    user = session.get(User, principal.user_id) if principal.user_id else None
    if user is None:
        raise GENERIC_401
    return user


def _audit_mfa(session: Session, request: Request, user: User, action: str,
               changes: dict | None = None) -> None:
    ip, user_agent, correlation_id = _client(request)
    audit.record(session, action=action, object_type="user", object_id=user.id,
                 object_label=user.email, organization_id=user.organization_id,
                 actor_id=user.id, actor_label=user.email, correlation_id=correlation_id,
                 ip_address=ip, user_agent=user_agent, changes=changes)


def _second_factor_ok(user: User, code: str | None, *, method: str | None = None) -> str | None:
    """How the code proved the second factor ("totp"/"email"/"telegram"/"recovery"), or None.

    `method` defaults to the account's active method. A recovery code is
    accepted for any method once MFA is enabled; it is consumed here, so the
    caller must commit.
    """
    method = method or user.mfa_method or "totp"
    if user.mfa_enabled and mfa_delivery.looks_like_recovery(code):
        return "recovery" if mfa_delivery.use_recovery_code(user, code) else None
    if method == "totp":
        try:
            secret = mfa.unseal(user.mfa_secret)
        except mfa.MfaError:
            return None
        step = mfa.verify(secret, code, last_step=user.mfa_last_step)
        if step is None:
            return None
        user.mfa_last_step = step
        return "totp"
    try:
        return method if mfa_delivery.check(user, code, method) else None
    except Exception:  # noqa: BLE001 - Redis down: fail CLOSED, never password-only
        return None


def _send_or_explain(user: User, method: str, purpose: str) -> dict:
    """Send a code; turn throttling and transport errors into one HTTP answer."""
    try:
        sent_to = mfa_delivery.issue(user, method, purpose=purpose)
        return {"method": method, "sent_to": sent_to, "expires_in": settings.mfa_code_ttl}
    except mfa_delivery.Throttled as exc:
        # The previous code is still valid: say so rather than failing.
        return {"method": method, "sent_to": mfa_delivery.masked(user, method),
                "throttled": True, "retry_after": exc.retry_after, "detail": str(exc)}
    except mfa_delivery.DeliveryError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail={"error": "mfa_delivery_failed", "method": method,
                                    "message": str(exc)}) from None
    except Exception as exc:  # noqa: BLE001 - Redis or similar: nothing was stored
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail={"error": "mfa_delivery_failed", "method": method,
                                    "message": f"the code store is unavailable ({type(exc).__name__})"}) from None


@router.get("/mfa", summary="My two-factor status and the methods this installation offers")
def mfa_status(principal: CurrentPrincipal, session: DbSession) -> dict:
    user = _me(principal, session)
    method = user.mfa_method or ("totp" if user.mfa_enabled or user.mfa_secret else None)
    return {
        "enabled": bool(user.mfa_enabled),
        "method": method if user.mfa_enabled else None,
        "pending_method": None if user.mfa_enabled else method,
        "destination": mfa_delivery.masked(user, method) if method in mfa_delivery.DELIVERED else None,
        "recovery_codes_left": len(user.mfa_recovery_codes or []) if user.mfa_enabled else 0,
        "available": mfa_delivery.available(),
        "telegram_bot": settings.telegram_bot_username or None,
        "local_password": bool(user.password_hash),
    }


@router.post("/mfa/enroll", summary="Begin MFA enrolment with a method (totp, email or telegram)")
def mfa_enroll(principal: CurrentPrincipal, session: DbSession, request: Request,
               payload: MfaEnrollRequest | None = None) -> dict:
    user = _me(principal, session)
    if user.mfa_enabled:
        # Re-enrolling would silently invalidate the working second factor.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_already_enabled"})
    method = (payload.method if payload else None) or "totp"
    if not mfa_delivery.available().get(method):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_method_unavailable", "method": method,
                                    "message": f"this installation has no {method} delivery configured"})
    if method == "totp":
        secret = mfa.generate_secret()
        user.mfa_secret = mfa.seal(secret)
        user.mfa_last_step = None
        user.mfa_method = "totp"
        _audit_mfa(session, request, user, "mfa.enroll", {"method": "totp"})
        session.commit()
        uri = mfa.provisioning_uri(secret, account=user.email, issuer=settings.app_name)
        return {
            "method": "totp",
            **MfaEnrollResponse(secret=secret, provisioning_uri=uri,
                                digits=mfa.DIGITS, period=mfa.PERIOD).model_dump(),
            "qr_svg": mfa.qr_svg(uri),
        }
    if method == "telegram":
        chat_id = (payload.telegram_chat_id or "").strip() if payload else ""
        if not mfa_delivery.valid_chat_id(chat_id):
            raise HTTPException(status_code=422, detail={"error": "invalid_chat_id",
                                "message": "a Telegram chat id is a number, e.g. 123456789"})
        user.mfa_telegram_chat_id = chat_id
    user.mfa_method = method
    user.mfa_secret = None
    user.mfa_last_step = None
    _audit_mfa(session, request, user, "mfa.enroll", {"method": method})
    session.commit()
    # Proof of delivery is the point of the next step: send the first code now.
    return _send_or_explain(user, method, "enroll")


@router.post("/mfa/send-code", summary="Send a code by my e-mail / Telegram method")
def mfa_send_code(principal: CurrentPrincipal, session: DbSession) -> dict:
    user = _me(principal, session)
    method = user.mfa_method or "totp"
    if method not in mfa_delivery.DELIVERED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_method_not_delivered",
                                    "message": "an authenticator app makes its own codes"})
    return _send_or_explain(user, method, "verify" if user.mfa_enabled else "enroll")


@router.post("/mfa/activate", summary="Confirm enrolment, require MFA at login, get recovery codes")
def mfa_activate(payload: MfaActivate, principal: CurrentPrincipal, session: DbSession,
                 request: Request) -> dict:
    user = _me(principal, session)
    if user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_already_enabled"})
    method = user.mfa_method or ("totp" if user.mfa_secret else None)
    if method is None or (method == "totp" and not user.mfa_secret):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_not_enrolled"})
    if method == "totp":
        try:
            mfa.unseal(user.mfa_secret)
        except mfa.MfaError:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail={"error": "mfa_not_enrolled"})
    if _second_factor_ok(user, payload.code, method=method) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"error": "invalid_code"})
    shown, stored = mfa_delivery.new_recovery_codes()
    user.mfa_enabled = True
    user.mfa_method = method
    user.mfa_recovery_codes = stored
    _audit_mfa(session, request, user, "mfa.activate", {"method": method})
    session.commit()
    return {"enabled": True, "method": method, "recovery_codes": shown,
            "detail": "Store the recovery codes now: they are shown once and each works once."}


@router.post("/mfa/recovery-codes", summary="Replace my recovery codes (password AND a valid code)")
def mfa_recovery_codes(payload: MfaDisable, principal: CurrentPrincipal, session: DbSession,
                       request: Request) -> dict:
    user = _me(principal, session)
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_not_enabled"})
    if not verify_password(payload.password, user.password_hash):
        raise GENERIC_401
    if _second_factor_ok(user, payload.code) is None:
        session.commit()   # a consumed recovery code stays consumed
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"error": "invalid_code"})
    shown, stored = mfa_delivery.new_recovery_codes()
    user.mfa_recovery_codes = stored
    _audit_mfa(session, request, user, "mfa.recovery_codes.replace")
    session.commit()
    return {"recovery_codes": shown}


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
             response_class=Response, summary="Turn MFA off (password AND a valid code)")
def mfa_disable(payload: MfaDisable, principal: CurrentPrincipal, session: DbSession,
                request: Request) -> None:
    user = _me(principal, session)
    if not user.mfa_enabled:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail={"error": "mfa_not_enabled"})
    # Both factors. A stolen access token alone must not be able to strip the
    # second factor off the account it was stolen from.
    if not verify_password(payload.password, user.password_hash):
        raise GENERIC_401
    method = user.mfa_method or "totp"
    unusable = False
    if method == "totp":
        try:
            mfa.unseal(user.mfa_secret)
        except mfa.MfaError:
            # Unusable secret: the password alone is enough to clear the dead
            # state, otherwise a key rotation would brick the account for good.
            unusable = True
    if not unusable and _second_factor_ok(user, payload.code) is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"error": "invalid_code"})

    previous = method
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_last_step = None
    user.mfa_method = None
    user.mfa_telegram_chat_id = None
    user.mfa_recovery_codes = None
    _audit_mfa(session, request, user, "mfa.disable", {"method": previous})
    session.commit()


# ---------------------------------------------------------------------------
# Single sign-on (OpenID Connect) -- services/oidc_auth.py. Off until an
# administrator configures it under Administration -> Single sign-on.
# ---------------------------------------------------------------------------
@router.get("/sso", summary="Is single sign-on offered on this installation?")
def sso_available(session: DbSession) -> dict:
    """A boolean only: listing WHICH organizations use SSO would enumerate tenants."""
    for org in session.execute(select(Organization).where(Organization.is_active.is_(True))).scalars():
        if oidc_auth.is_enabled_cfg(oidc_auth.config(session, org.id)):
            return {"available": True}
    return {"available": False}


@router.get("/oidc/{org_slug}/start", summary="Where to send the browser to sign in with SSO")
def oidc_start(org_slug: str, session: DbSession) -> dict:
    org = session.execute(select(Organization).where(Organization.slug == org_slug.strip().lower(),
                                                     Organization.is_active.is_(True))).scalar_one_or_none()
    try:
        if org is None:
            raise oidc_auth.OidcError("single sign-on is not configured for this organization")
        return {"authorization_url": oidc_auth.start(session, org)}
    except oidc_auth.OidcError as exc:
        # Same answer for "no such organization" and "not configured": no enumeration.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from None


def _sso_back(origin: str, **params: str):
    from urllib.parse import urlencode

    if not origin:
        return HTMLResponse("<p>Single sign-on failed: " + (params.get("error") or "unknown").replace("<", "&lt;")
                            + "</p>", status_code=400)
    return RedirectResponse(origin + "/#/sso?" + urlencode(params), status_code=status.HTTP_303_SEE_OTHER)


@router.get("/oidc/callback", summary="The identity provider sends the browser back here",
            include_in_schema=False)
def oidc_callback(request: Request, session: DbSession, code: str = "", state: str = "",
                  error: str = "") -> Response:
    ip, user_agent, correlation_id = _client(request)
    flow = oidc_auth.take_flow(state)
    if flow is None:
        return _sso_back("", error="this sign-in link expired or was already used; start again")
    org_id = uuid.UUID(flow["org"])
    cfg = oidc_auth.config(session, org_id)
    origin = oidc_auth.console_origin(cfg)

    def refuse(reason: str, message: str, user: User | None = None):
        audit.record_auth(session, event="login", success=False, user_id=user.id if user else None,
                          organization_id=org_id, email_attempted=None, reason=f"sso:{reason}",
                          ip_address=ip, user_agent=user_agent, correlation_id=correlation_id)
        session.commit()
        return _sso_back(origin, error=message)

    if error or not code:
        return refuse("provider_error", f"the identity provider answered: {error[:80] or 'no code'}")
    try:
        claims = oidc_auth.finish(session, flow, code)
    except oidc_auth.OidcError as exc:
        return refuse("bad_token", str(exc))
    email = str(claims.get(cfg.get("email_claim") or "email") or "").strip().lower()
    if not email or claims.get("email_verified") is False:
        return refuse("no_email", "the identity provider sent no verified e-mail address")
    set_tenant(session, org_id)
    user = session.execute(select(User).where(User.organization_id == org_id, User.email == email,
                                              User.deleted_at.is_(None))).scalar_one_or_none()
    if user is None and cfg.get("jit_provisioning"):
        user = User(organization_id=org_id, email=email, password_hash=None,
                    full_name=str(claims.get("name") or email.split("@")[0])[:200])
        session.add(user)
        session.flush()
    if user is None:
        return refuse("unknown_user", f"{email} has no VEYRS account in this organization")
    if user.is_superuser:
        return refuse("superuser", "platform administrators sign in with their local password, never SSO", user)
    if not user.is_active:
        return refuse("inactive", "this account is disabled", user)
    roles = oidc_auth.roles_for(cfg, claims)
    if roles is not None:
        _sync_directory_roles(session, user, roles)
    handoff = oidc_auth.save_handoff(user.id)
    session.commit()
    return _sso_back(origin, h=handoff)


@router.post("/oidc/exchange", response_model=TokenPair, summary="Swap the one-time SSO handoff for tokens")
def oidc_exchange(payload: OidcExchange, request: Request, session: DbSession) -> TokenPair:
    ip, user_agent, correlation_id = _client(request)
    user_id = oidc_auth.take_handoff(payload.handoff)
    user = session.get(User, uuid.UUID(user_id)) if user_id else None
    if user is None or not user.is_active or user.is_superuser:
        raise GENERIC_401
    set_tenant(session, user.organization_id)
    user = session.get(User, user.id)
    user.failed_logins = 0
    user.locked_until = None
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    tokens = _issue(session, user, request)
    audit.record_auth(session, event="login", success=True, user_id=user.id,
                      organization_id=user.organization_id, email_attempted=user.email,
                      reason="auth:sso", ip_address=ip, user_agent=user_agent,
                      correlation_id=correlation_id)
    session.commit()
    return tokens
