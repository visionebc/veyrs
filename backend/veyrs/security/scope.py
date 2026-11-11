"""Team-level visibility: the ABAC seam `tenancy.py` promised and never enforced.

Until now RLS answered exactly one question -- *which tenant?* -- and every user
inside a tenant saw the whole estate. `UserRole.team_id` existed, was documented
as "the ABAC seam", and was read by nobody.

**How a principal becomes restricted.** From its grants, not from its team
memberships. If ANY `UserRole` row for the user has `team_id IS NULL`, the grant
is estate-wide and the principal is unrestricted. Only when every grant names a
team is the principal narrowed to the union of those teams. Two consequences,
both deliberate:

* nothing regresses. Every grant that exists today has `team_id NULL`, so every
  user stays unrestricted until an administrator scopes a grant on purpose;
* **joining a team cannot widen what you see.** Membership (`TeamMember`)
  answers "whose queue is this" and is used by `?my_teams=true`; authorization
  comes from grants alone. If membership granted visibility, any user who can
  add themselves to a team would own the authorization decision.

**Unowned rows are invisible by default.** An asset with no team belongs to no
scoped user, the same deny-by-default posture as an agent's `allowed_targets`.
That creates a real blind spot -- work nobody can see is work nobody does -- so
it is *measured*, not assumed away: `coverage()` counts it, `GET /me/scope`
reports it, and `?unowned=true` on both list endpoints finds it. An
administrator who prefers the other trade-off sets
`organization.settings["team_scope"]["unowned_visible"] = true`.

**Everything a restricted principal reads is partial, and says so.** Analytics
carries a `scope` block for exactly this reason: "0 critical findings" under a
team scope means "0 that you can see", and a dashboard that does not say which
one it means is worse than no dashboard.
"""
from __future__ import annotations

import dataclasses
import uuid

from fastapi import HTTPException, Request, status
from sqlalchemy import false as sa_false, func, select
from sqlalchemy.orm import Session

from ..models import Asset, Finding
from ..models.tenancy import Organization, Team, UserRole
from ..services.teams import owning_team, owning_team_for_ticket

# --- which routers understand a team scope --------------------------------
# A restricted principal may only reach routes that filter by team, or routes
# that carry no per-asset tenant data at all. Anything else is refused rather
# than served unfiltered: a control that is only applied where someone
# remembered to apply it is not a control (phase 25, the XXE guard that never
# ran, is the same lesson).
SCOPED_TAGS = frozenset({
    "assets", "vulnerability management", "ticketing", "dashboards & reports",
    # `policies` moved here from EXEMPT_TAGS in v0.17.1. The router is mostly
    # organization configuration -- SLA policies, escalation ladders, assignment
    # rules -- but three of its routes read and write *findings*:
    # `/sla/summary`, `/sla/events` and `/sla/evaluate`. Classifying a router by
    # what most of it does is how a team-restricted identity kept reading
    # estate-wide breach counters after phase 26 shipped. A tag is a claim about
    # every route beneath it, not about the majority of them.
    "policies",
    # `cvss` moved here from EXEMPT_TAGS in v0.21.0, for the same reason
    # `policies` did in v0.17.1. Scoring a vector touches nothing; but
    # `/cvss/assist` reads the tenant's OWN findings and installations to
    # answer "does this bulletin apply to me", and a tag is a claim about
    # every route beneath it rather than about most of them.
    "cvss",
    # `risk register` is SCOPED, not exempt and not refused. A team-scoped
    # identity reads exactly the entries its teams -- or it personally --
    # hold a RACI seat on, which is the whole point of naming somebody: the
    # person named has to be able to see what they were named on. Every
    # WRITE on that router calls `refuse_if_restricted` instead, because
    # adding or closing an organisation-level risk from inside one team is
    # not a narrowed act, it is an unauthorised estate-wide one.
    "risk register",
})
# No asset- or finding-level tenant rows: global intel, own identity, org config.
EXEMPT_TAGS = frozenset({
    "authentication", "intelligence & knowledge", "threat intelligence",
    "operations", "administration",
    # `saved views` stores a QUERY, never a row. Applying one goes through
    # the entity's own list endpoint, which is scoped -- so a shared
    # estate-wide view opened by a restricted operator returns their slice
    # rather than a 403. Enforced by tests/test_phase36_saved_views.py,
    # which reads the router source: this is exactly the claim `policies`
    # made falsely until v0.17.1.
    "saved views",
})
# Estate-wide by nature. A team-scoped identity is a triage and remediation
# identity: it does not enrol scanners, run imports, or answer for the
# organization's compliance posture. Serving these filtered would produce a
# compliance report that silently covers a third of the estate.
# `asset sources` sits here for the same reason `integrations` does: deciding
# where the estate's inventory comes from, and comparing two whole
# inventories against each other, are estate-wide acts. A comparative
# narrowed to one team's slice would read as a complete answer while
# covering a third of the estate -- which is worse than refusing.
REFUSED_TAGS = frozenset({"agents", "ai", "compliance", "engagements",
                          "integrations", "asset sources"})


@dataclasses.dataclass(frozen=True)
class TeamScope:
    """What one principal may see. `restricted=False` is today's behaviour."""

    restricted: bool = False
    team_ids: frozenset[uuid.UUID] = frozenset()
    include_unowned: bool = False
    #: Set when the narrowing came from an explicit `?team_id=` on a dashboard
    #: rather than from the principal's grants -- see `for_team()`.
    view_team_id: uuid.UUID | None = None
    view_team_name: str | None = None
    #: Whether `restricted` states an authorization limit. False means the
    #: caller may see the whole estate and *chose* to look at one team; saying
    #: "your visibility is restricted" there would be a lie, and saying nothing
    #: would let a one-team figure read as an estate figure.
    by_authorization: bool = True

    @property
    def is_empty(self) -> bool:
        """Restricted to no team at all: sees nothing. Fail-closed, on purpose."""
        return self.restricted and not self.team_ids

    def as_dict(self) -> dict:
        out = {
            "restricted": self.restricted,
            "team_ids": sorted(str(t) for t in self.team_ids),
            "include_unowned": self.include_unowned,
        }
        if self.view_team_id is not None:
            out["view_team_id"] = str(self.view_team_id)
            out["view_team_name"] = self.view_team_name
            out["by_authorization"] = self.by_authorization
        return out


UNRESTRICTED = TeamScope()


def for_team(scope: TeamScope, team_id: uuid.UUID,
             team_name: str | None = None) -> TeamScope:
    """Narrow a scope to ONE team for a single read. A view filter, not a grant.

    The point of routing this through `TeamScope` instead of adding a `team_id`
    argument to every analytics function is that it cannot be forgotten: the
    twenty-four tenant predicates in `services.analytics` already go through
    `_scoped*`, so a per-team dashboard is the existing machinery with a smaller
    set -- and a query added tomorrow is filtered without anyone remembering to.

    **It can only ever intersect.** A principal already restricted to teams A
    and B that asks for C gets 404 -- not 403, and not a widened view. 404 is
    the answer the rest of the platform gives for a row outside scope, because
    403 confirms that the team exists.

    `include_unowned` is dropped on purpose: "the platform team's dashboard"
    must not quietly fold in every asset nobody owns. Those rows stay visible
    through the estate-wide view, which is where they can actually be triaged.
    """
    if scope.restricted and team_id not in scope.team_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    return dataclasses.replace(
        scope,
        restricted=True,
        team_ids=frozenset({team_id}),
        include_unowned=False,
        view_team_id=team_id,
        view_team_name=team_name,
        by_authorization=scope.restricted,
    )


def resolve_view(session: Session, scope: TeamScope, organization_id: uuid.UUID,
                 team_id: uuid.UUID | None) -> TeamScope:
    """Resolve an optional `?team_id=` into the scope ONE read runs under.

    `None` leaves the caller's own scope untouched, so the estate view is the
    default and the filter is opt-in.

    This lived privately in the reports router while dashboards were the only
    surface offering the filter. The moment a second router needed the same
    three lines it had to move: two copies are two chances to forget the 404 on
    another tenant's team, or to answer with a bare UUID the console then prints
    as a heading.

    Resolving the row first is what lets the response *name* the team. A
    filtered figure under an unnamed heading is how a one-team screenshot gets
    filed as the estate's.
    """
    if team_id is None:
        return scope
    team = session.get(Team, team_id)
    if team is None or team.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "team not found")
    return for_team(scope, team.id, team.name)


def resolve_for_user(session: Session, user_id: uuid.UUID,
                     organization_id: uuid.UUID, *, is_superuser: bool = False) -> TeamScope:
    """Read the principal's grants and decide the scope.

    Runs on the RLS-bound session for the user's own tenant; `user_roles` is
    FORCEd, so an unbound session would return zero rows and silently restrict
    everyone to nothing. `deps` binds the tenant before calling.
    """
    if is_superuser:
        return UNRESTRICTED
    rows = session.execute(
        select(UserRole.team_id).where(UserRole.user_id == user_id)
    ).scalars().all()
    if not rows:
        # No grants at all. Permission checks will 403 first; restricting to
        # nothing here means that if one ever does not, the answer is empty
        # rather than the estate.
        return TeamScope(restricted=True, team_ids=frozenset())
    if any(team_id is None for team_id in rows):
        return UNRESTRICTED

    organization = session.get(Organization, organization_id)
    settings = (organization.settings or {}) if organization is not None else {}
    include_unowned = bool((settings.get("team_scope") or {}).get("unowned_visible", False))
    return TeamScope(
        restricted=True,
        team_ids=frozenset(t for t in rows if t is not None),
        include_unowned=include_unowned,
    )


def enforce_route_policy(request: Request, scope: TeamScope) -> None:
    """Fail closed on any router that does not yet understand a team scope."""
    if not scope.restricted:
        return
    route = request.scope.get("route")
    tags = frozenset(getattr(route, "tags", None) or ())
    if tags & REFUSED_TAGS:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "this endpoint reports on the whole estate and cannot be narrowed to "
            "a team; it requires an estate-wide role grant",
        )
    if tags and not (tags & (SCOPED_TAGS | EXEMPT_TAGS)):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "endpoint is not team-scope aware; refused rather than served unfiltered",
        )


def refuse_if_restricted(scope: TeamScope, detail: str) -> None:
    """403 an estate-wide *action* attempted by a team-scoped identity.

    The counterpart to the query filters below. Some things cannot be narrowed
    into a smaller correct answer -- they can only be done for everybody or not
    at all: exporting the asset register, or editing the SLA policy the whole
    organization is held to. Serving a narrowed version is worse than refusing,
    because it looks like it worked.

    **403 and not 404 here, deliberately.** The rest of the platform hides rows
    a caller may not see. These rows are readable by the same caller -- a triage
    identity must be able to read the deadline it is judged against -- so there
    is nothing left to conceal, and 403 is the only answer that tells an
    operator what to ask their administrator for.
    """
    if scope.restricted:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail)


# --- query filters --------------------------------------------------------
def _members(column, scope: TeamScope):
    """`column IN scope` plus the unowned bucket when the org allows it."""
    if scope.is_empty:
        return sa_false()
    clause = column.in_(tuple(scope.team_ids))
    if scope.include_unowned:
        clause = clause | column.is_(None)
    return clause


def asset_clause(scope: TeamScope):
    """The bare WHERE predicate, for callers that build their own statements."""
    return _members(Asset.team_id, scope)


def finding_clause(scope: TeamScope):
    return _members(owning_team(), scope)


def ticket_clause(scope: TeamScope):
    return _members(owning_team_for_ticket(), scope)


def assets(stmt, scope: TeamScope):
    """Narrow an `Asset` select to the scope. A no-op when unrestricted."""
    if not scope.restricted:
        return stmt
    return stmt.where(_members(Asset.team_id, scope))


def findings(stmt, scope: TeamScope):
    """Narrow a `Finding` select to the scope, by *effective* owner.

    Uses `services.teams.owning_team()` -- assignment first, asset's team as the
    fallback -- because filtering on `assigned_team_id` alone would hide the
    majority of a team's own work behind a NULL.
    """
    if not scope.restricted:
        return stmt
    return stmt.where(_members(owning_team(), scope))


def tickets(stmt, scope: TeamScope):
    """Narrow a `Ticket` select: own assignment first, else its finding's owner."""
    if not scope.restricted:
        return stmt
    return stmt.where(_members(owning_team_for_ticket(), scope))


def ticket_visible(session: Session, ticket, scope: TeamScope) -> bool:
    if not scope.restricted:
        return True
    team_id = ticket.assigned_team_id
    if team_id is None and ticket.finding_id is not None:
        finding = session.get(Finding, ticket.finding_id)
        if finding is not None:
            return finding_visible(session, finding, scope)
    if team_id is None:
        return scope.include_unowned
    return team_id in scope.team_ids


def asset_visible(asset: Asset, scope: TeamScope) -> bool:
    if not scope.restricted:
        return True
    if asset.team_id is None:
        return scope.include_unowned
    return asset.team_id in scope.team_ids


def finding_visible(session: Session, finding: Finding, scope: TeamScope) -> bool:
    if not scope.restricted:
        return True
    team_id = finding.assigned_team_id
    if team_id is None:
        asset = session.get(Asset, finding.asset_id)
        team_id = asset.team_id if asset is not None else None
    if team_id is None:
        return scope.include_unowned
    return team_id in scope.team_ids


def coverage(session: Session, organization_id: uuid.UUID) -> dict:
    """How much of the estate no team owns -- i.e. what scoping makes invisible.

    Exists so "my dashboard is clean" can be separated from "my dashboard cannot
    see the dirty part". Reported by `GET /me/scope` and by the console banner.
    """
    total_assets, unowned_assets = session.execute(
        select(func.count(Asset.id),
               func.count(Asset.id).filter(Asset.team_id.is_(None)))
        .where(Asset.organization_id == organization_id, Asset.deleted_at.is_(None))
    ).one()
    owner = owning_team()
    total_findings, unowned_findings = session.execute(
        select(func.count(Finding.id), func.count(Finding.id).filter(owner.is_(None)))
        .where(Finding.organization_id == organization_id)
    ).one()
    return {
        "assets": {"total": total_assets or 0, "unowned": unowned_assets or 0},
        "findings": {"total": total_findings or 0, "unowned": unowned_findings or 0},
    }
