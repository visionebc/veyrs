"""Team ownership: name resolution, membership, and the ownership expression.

Three things live here because all three were being reinvented per-endpoint:

  * `resolve_names()` -- batch-resolve team / user / department ids to labels.
    The console was rendering raw UUIDs because every list endpoint would have
    needed its own join; one batched lookup per page is cheaper than a join on
    every row and keeps the ORM query shape untouched.
  * `member_team_ids()` -- the teams a user *belongs to* (TeamMember). This is
    NOT authorization: membership answers "whose queue is this", grants answer
    "what may you see" (see `security.scope`). Conflating them would let anyone
    widen their own visibility by joining a team.
  * `owning_team()` -- the single SQL expression for "which team owns this
    finding": its explicit assignment, falling back to the owning team of its
    asset. Most findings carry no `assigned_team_id` until an AssignmentRule
    fires, so filtering on that column alone answers "almost nothing" and reads
    as "this team has no work".
"""
from __future__ import annotations

import uuid
from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, Finding
from ..models.tenancy import Department, Team, TeamMember, User


def owning_team():
    """`COALESCE(finding.assigned_team_id, asset.team_id)` as an expression.

    Correlated subquery rather than a join: callers compose this into statements
    that may already join `assets` (the `exposure` filter does), and a second
    join would either collide or silently change row counts.

    `.correlate(Finding)` is **mandatory**, not tidiness. Left to auto-correlate,
    SQLAlchemy also correlates `assets` whenever the enclosing statement already
    joins it -- the subquery then has no FROM at all and compilation dies with
    "returned no FROM clauses due to auto-correlation". It only fires on the
    queries that join Asset (internet-exposure counts, `?exposure=`), so it
    looks like an unrelated dashboard bug rather than a bad subquery.
    """
    asset_team = (
        select(Asset.team_id)
        .where(Asset.id == Finding.asset_id)
        .correlate(Finding)
        .scalar_subquery()
    )
    return func.coalesce(Finding.assigned_team_id, asset_team)


def owning_team_for_ticket():
    """Effective owner of a ticket: its own assignment, else its finding's.

    A ticket carries `assigned_team_id` directly, but most are opened *from* a
    finding and inherit their ownership implicitly -- and a ticket that is
    visible while its finding is not (or the reverse) is a segregation hole in
    whichever direction it leaks.
    """
    from ..models import Ticket

    finding_team = (
        select(func.coalesce(
            Finding.assigned_team_id,
            select(Asset.team_id)
            .where(Asset.id == Finding.asset_id)
            .correlate(Finding)
            .scalar_subquery(),
        ))
        .where(Finding.id == Ticket.finding_id)
        .correlate(Ticket)
        .scalar_subquery()
    )
    return func.coalesce(Ticket.assigned_team_id, finding_team)


def member_team_ids(session: Session, user_id: uuid.UUID | None) -> frozenset[uuid.UUID]:
    """Teams the user is a member of. Empty for API keys (`user_id is None`)."""
    if user_id is None:
        return frozenset()
    rows = session.execute(
        select(TeamMember.team_id).where(TeamMember.user_id == user_id)
    ).scalars().all()
    return frozenset(rows)


def resolve_names(
    session: Session,
    *,
    team_ids: Iterable[uuid.UUID | None] = (),
    user_ids: Iterable[uuid.UUID | None] = (),
    department_ids: Iterable[uuid.UUID | None] = (),
) -> dict[str, dict[uuid.UUID, str]]:
    """Batch id -> label for one response page.

    Returns `{"teams": {...}, "users": {...}, "departments": {...}}`. Missing
    ids are simply absent: a team deleted after assignment must not 500 a list.
    """
    def _clean(values) -> list[uuid.UUID]:
        return list({v for v in values if v is not None})

    out: dict[str, dict[uuid.UUID, str]] = {"teams": {}, "users": {}, "departments": {}}

    teams = _clean(team_ids)
    if teams:
        out["teams"] = dict(
            session.execute(select(Team.id, Team.name).where(Team.id.in_(teams))).all()
        )
    users = _clean(user_ids)
    if users:
        out["users"] = dict(
            session.execute(select(User.id, User.full_name).where(User.id.in_(users))).all()
        )
    departments = _clean(department_ids)
    if departments:
        out["departments"] = dict(
            session.execute(
                select(Department.id, Department.name).where(Department.id.in_(departments))
            ).all()
        )
    return out


def validate_team(session: Session, organization_id: uuid.UUID,
                  team_id: uuid.UUID | None) -> Team | None:
    """Return the team or None; raise ValueError if it belongs to another tenant.

    RLS already prevents the cross-tenant read, so this mostly turns a confusing
    "not found" into an explicit rejection -- but it is the check that stops an
    assignment writing an id the tenant does not own.
    """
    if team_id is None:
        return None
    team = session.get(Team, team_id)
    if team is None or team.organization_id != organization_id:
        raise ValueError(f"unknown team {team_id}")
    return team


def validate_user(session: Session, organization_id: uuid.UUID,
                  user_id: uuid.UUID | None) -> User | None:
    if user_id is None:
        return None
    user = session.get(User, user_id)
    if user is None or user.organization_id != organization_id or user.is_deleted:
        raise ValueError(f"unknown user {user_id}")
    return user


def validate_department(session: Session, organization_id: uuid.UUID,
                        department_id: uuid.UUID | None) -> Department | None:
    if department_id is None:
        return None
    row = session.get(Department, department_id)
    if row is None or row.organization_id != organization_id:
        raise ValueError(f"unknown department {department_id}")
    return row
