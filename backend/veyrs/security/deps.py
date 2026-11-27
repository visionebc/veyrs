"""FastAPI authorization dependencies.

Design rule from the spec (section 22): *every* endpoint authorizes on the
server. There is no "the UI hides the button" path. Concretely:

  * `CurrentPrincipal` resolves a bearer JWT **or** an API key into a Principal
    that always carries an organization_id.
  * `require("asset:write")` returns a dependency that 403s unless the
    principal's expanded permission set contains it.
  * `tenant_session` yields a DB session with `veyrs.current_org` already bound,
    so PostgreSQL RLS is active even if a query forgets its filter.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import uuid
from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_session, set_tenant
from ..models.tenancy import ApiKey, Organization, User
from . import permissions as perms
from . import ratelimit
from . import scope as team_scope
from . import tenant_guard
from .auth import (SCOPE_MFA_ENROLL, AuthError, decode_access_token, split_api_key,
                   verify_api_key_secret)

tenant_guard.install()

bearer_scheme = HTTPBearer(auto_error=False)

UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


@dataclasses.dataclass(frozen=True)
class Principal:
    """Who is making this request, and what may they do."""

    user_id: uuid.UUID | None
    organization_id: uuid.UUID
    label: str
    permissions: frozenset[str]
    is_superuser: bool = False
    kind: str = "user"  # user | apikey
    api_key_id: uuid.UUID | None = None
    # Which teams' assets and findings this principal may see. The default is
    # estate-wide, which is what every existing grant resolves to; see
    # `security.scope`. API keys are never narrowed: an importer that silently
    # stopped seeing two thirds of the estate would close findings it simply
    # could not observe.
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED
    # `mfa_enroll`: signed in with a password under an organization that
    # requires a second factor this account does not have yet. Such a principal
    # holds no permission and reaches only `ENROLLMENT_ROUTES`.
    restriction: str | None = None

    def can(self, permission: str) -> bool:
        return self.is_superuser or permission in self.permissions

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"missing permission: {permission}",
            )


def audit_actor(request: Request, principal: Principal) -> dict:
    """Audit-log context for a request: who, from where, under which trace id.

    The address is `request.client.host` and nothing else. The ASGI server
    resolves it through its trusted-proxy list (`--forwarded-allow-ips`), so it
    is the nearest untrusted hop; the first `X-Forwarded-For` entry is
    whatever the caller sent and must never be recorded as the actor's IP.
    """
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": request.client.host if request.client else None,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


def effective_permissions(session: Session, user: User) -> frozenset[str]:
    """Union of every role granted to the user, wildcards expanded.

    `user_roles` is RLS-forced, so the tenant MUST be bound before the read or
    the policy silently yields an empty grant set (which would look like "this
    user has no permissions" rather than an error). Binding here makes the
    function safe to call from the pre-auth login path too.
    """
    from ..models.tenancy import Role, UserRole  # local import: avoid cycles

    set_tenant(session, user.organization_id)

    rows = session.execute(
        select(Role.permissions)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user.id)
    ).scalars().all()
    granted: list[str] = []
    for permission_list in rows:
        granted.extend(permission_list or [])
    return perms.expand(granted)


def _principal_from_jwt(session: Session, token: str) -> Principal:
    try:
        payload = decode_access_token(token)
    except AuthError:
        raise UNAUTHORIZED from None
    try:
        user_id = uuid.UUID(payload["sub"])
        org_id = uuid.UUID(payload["org"])
    except (KeyError, ValueError):
        raise UNAUTHORIZED from None

    user = session.get(User, user_id)
    if user is None or not user.is_active or user.is_deleted or user.is_locked:
        raise UNAUTHORIZED
    # Logout, password change, MFA reset, deactivation and deletion bump the
    # account's version (`auth.end_sessions`); every access token issued under
    # an older one dies here. The user row is loaded anyway, so this costs
    # nothing. A token from before the column existed has no `tv`: version 0.
    try:
        token_version = int(payload.get("tv", 0))
    except (TypeError, ValueError):
        raise UNAUTHORIZED from None
    if token_version != (user.token_version or 0):
        raise UNAUTHORIZED
    if user.organization_id != org_id and not user.is_superuser:
        # token minted for another tenant: treat as forgery, not as a mismatch
        raise UNAUTHORIZED
    org = session.get(Organization, org_id)
    if org is None or not org.is_active or org.is_deleted:
        raise UNAUTHORIZED

    if payload.get("scp") == SCOPE_MFA_ENROLL:
        return Principal(user_id=user.id, organization_id=org_id, label=user.email,
                         permissions=frozenset(), is_superuser=False, kind="user",
                         restriction=SCOPE_MFA_ENROLL)
    if payload.get("scp"):
        raise UNAUTHORIZED          # a scope this version does not know: refuse, never widen

    # Permissions are re-read from the DB rather than trusted from the token, so
    # a revoked role takes effect immediately instead of at token expiry.
    return Principal(
        user_id=user.id,
        organization_id=org_id,
        label=user.email,
        permissions=effective_permissions(session, user),
        is_superuser=user.is_superuser,
        kind="user",
        scope=team_scope.resolve_for_user(
            session, user.id, org_id, is_superuser=user.is_superuser
        ),
    )


def _principal_from_api_key(session: Session, clear: str) -> Principal:
    try:
        prefix, secret = split_api_key(clear)
    except AuthError:
        raise UNAUTHORIZED from None
    record = session.execute(select(ApiKey).where(ApiKey.prefix == prefix)).scalar_one_or_none()
    if record is None or not record.is_usable:
        raise UNAUTHORIZED
    if not verify_api_key_secret(secret, record.key_hash):
        raise UNAUTHORIZED
    ratelimit.remember_api_key(clear, record.id)   # its own rate-limit bucket from now on
    record.last_used_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return Principal(
        user_id=record.created_by_id,
        organization_id=record.organization_id,
        label=f"apikey:{record.name}",
        permissions=perms.expand(list(record.scopes or [])),
        is_superuser=False,
        kind="apikey",
        api_key_id=record.id,
    )


def get_principal(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> Principal:
    if x_api_key:
        principal = _principal_from_api_key(session, x_api_key)
    elif credentials and credentials.scheme.lower() == "bearer":
        principal = _principal_from_jwt(session, credentials.credentials)
    else:
        raise UNAUTHORIZED
    # Bind RLS for the rest of the request and stash for logging middleware.
    set_tenant(session, principal.organization_id)
    request.state.principal = principal
    if principal.restriction == SCOPE_MFA_ENROLL:
        _refuse_outside_enrollment(request)
    # Refuse, rather than serve unfiltered, on any router that does not yet
    # understand a team scope. Costs nothing for an unrestricted principal.
    team_scope.enforce_route_policy(request, principal.scope)
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]

#: All an enrolment-only token reaches (paths below the API prefix): who am I,
#: the MFA lifecycle up to activation, and sign out.
ENROLLMENT_ROUTES = frozenset({
    "/auth/me", "/auth/mfa", "/auth/mfa/enroll", "/auth/mfa/send-code",
    "/auth/mfa/activate", "/auth/logout",
})


def _refuse_outside_enrollment(request: Request) -> None:
    # The matched route's template, not the raw URL: what was routed is what is checked.
    route = request.scope.get("route")
    path = getattr(route, "path", "") or ""
    prefix = settings.api_prefix
    relative = path[len(prefix):] if path.startswith(prefix) else path
    if relative not in ENROLLMENT_ROUTES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "mfa_enrollment_required",
                    "message": "your organization requires two-factor sign-in: "
                               "set it up before using VEYRS"},
        )


def require(*needed: str) -> Callable[[Principal], Principal]:
    """Dependency factory: `Depends(require("asset:write"))`.

    Unknown permission strings raise at import time, so a typo in a route
    decorator can never silently authorize everyone.
    """
    for permission in needed:
        if not perms.is_valid(permission):
            raise ValueError(f"unknown permission {permission!r}")

    def _dependency(principal: CurrentPrincipal) -> Principal:
        for permission in needed:
            principal.require(permission)
        return principal

    return _dependency


def tenant_session(
    principal: CurrentPrincipal,
    session: Annotated[Session, Depends(get_session)],
) -> Session:
    """A session guaranteed to be bound to the caller's tenant."""
    set_tenant(session, principal.organization_id)
    return session


TenantSession = Annotated[Session, Depends(tenant_session)]
