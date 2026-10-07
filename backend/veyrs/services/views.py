"""Saved views: store a query, replay it, never widen it.

The whole service is the allow-list below plus ownership rules. It is small on
purpose: a saved view must not become a second, weaker way of asking a question
that `/findings` already answers under authorization.

**Why an allow-list and not "store whatever the client sent".** The console
replays `filters` as query parameters. A key this release ignores is a key a
future release might honour -- so an unvalidated blob is a place to park
parameters and wait for the platform to start obeying them. Rejecting unknown
keys at write time means the set of things a saved view can do is the set of
things somebody reviewed.

**Why values are strings.** They are going into a URL. Typing them here would
only move the coercion to the read path, where a bad value would surface as a
422 from an endpoint the operator did not knowingly call.

**What is deliberately NOT here: authorization.** A saved view names a query;
applying it goes through the entity's own list endpoint, which is already team
-scope aware. So a shared estate-wide view opened by a restricted operator
returns their slice, not a 403 and not somebody else's estate. Putting a scope
check here as well would produce two answers to "may I see this", and the one
that runs first would win.
"""
from __future__ import annotations

import uuid
from typing import Any, Iterable

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import SavedView, VIEW_ENTITIES

MAX_VIEWS_PER_USER = 100
MAX_FILTERS = 20
MAX_VALUE_LEN = 200

#: Query parameters a saved view may carry, per entity. Every key here is a
#: real parameter of the corresponding list route -- `tests/test_phase36_*`
#: asserts that by reading the route signatures, so a renamed parameter breaks
#: the test rather than silently producing views that filter nothing.
#:
#: `page` and `size` are absent on purpose: they are paging state, not the
#: question. A view pinned to page 3 is a view that shows nothing the day the
#: queue gets shorter.
ALLOWED_FILTERS: dict[str, frozenset[str]] = {
    "findings": frozenset({
        "q", "state", "open_only", "severity", "risk_level", "min_risk", "kev",
        "min_epss", "exposure", "asset_id", "assigned_team_id", "assigned_user_id",
        "owning_team_id", "my_teams", "mine", "unowned", "sla_breached", "order",
    }),
    "tickets": frozenset({
        "q", "ticket_type", "state", "open_only", "priority", "assigned_team_id",
        "assigned_user_id", "finding_id", "sla_breached",
    }),
    "assets": frozenset({
        "q", "asset_type", "criticality", "exposure", "environment",
        "exclude_exposure", "exclude_environment", "tag", "business_service_id",
        "team_id", "owner_id", "department_id", "unowned", "is_active",
    }),
    "vulnerabilities": frozenset({"q", "severity", "kev", "state", "min_risk"}),
    #: The Issues screen (external ticketing mode). Every name here is a
    #: real query parameter of `integrations.list_links` -- the phase 36
    #: guard reads the signature and fails if that ever stops being true.
    "issues": frozenset({
        "q", "severity", "remote_status", "is_active", "finding_id",
        "asset_id", "connector_id", "object_type",
    }),
}


class SavedViewError(ValueError):
    """Rejected at write time. The API turns this into a 422."""


def normalise_filters(entity: str, filters: dict[str, Any] | None) -> dict[str, str]:
    """Validate and stringify. Raises `SavedViewError` on anything unknown.

    Unknown keys are REJECTED rather than dropped. Silently discarding half a
    filter set returns 201 for a view that answers a different question than
    the one the operator saved -- and they only find out by trusting its count.
    """
    if entity not in VIEW_ENTITIES:
        raise SavedViewError(
            f"unknown entity {entity!r}; expected one of {', '.join(VIEW_ENTITIES)}"
        )
    allowed = ALLOWED_FILTERS[entity]
    raw = filters or {}
    if not isinstance(raw, dict):
        raise SavedViewError("filters must be an object")
    if len(raw) > MAX_FILTERS:
        raise SavedViewError(f"at most {MAX_FILTERS} filters per view")

    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise SavedViewError(
            f"{entity} views accept no filter named {', '.join(unknown)}; "
            f"allowed: {', '.join(sorted(allowed))}"
        )

    out: dict[str, str] = {}
    for key, value in raw.items():
        if value is None or value == "":
            continue                      # an empty filter is not a filter
        if isinstance(value, bool):
            text = "true" if value else "false"
        elif isinstance(value, (int, float, str, uuid.UUID)):
            text = str(value)
        else:
            raise SavedViewError(f"filter {key!r} must be a scalar, not {type(value).__name__}")
        if len(text) > MAX_VALUE_LEN:
            raise SavedViewError(f"filter {key!r} is longer than {MAX_VALUE_LEN} characters")
        out[key] = text
    return out


def visible(
    session: Session,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
    *,
    entity: str | None = None,
) -> list[SavedView]:
    """Mine, plus everything shared in my organization."""
    stmt = select(SavedView).where(SavedView.organization_id == organization_id)
    if user_id is not None:
        stmt = stmt.where(or_(SavedView.owner_id == user_id, SavedView.is_shared.is_(True)))
    else:
        # An API key owns no views. It reads the shared ones and nothing else,
        # rather than the whole table: "mine" for a machine identity is empty.
        stmt = stmt.where(SavedView.is_shared.is_(True))
    if entity:
        stmt = stmt.where(SavedView.entity == entity)
    return list(session.execute(
        stmt.order_by(SavedView.position, SavedView.name)
    ).scalars().all())


def get_owned(
    session: Session, organization_id: uuid.UUID, view_id: uuid.UUID,
    user_id: uuid.UUID | None,
) -> SavedView | None:
    """The row, only if this caller may WRITE it.

    Shared views are readable by everyone and editable by their owner alone.
    Anything else and one operator's morning queue is another's to rename.
    """
    row = session.execute(
        select(SavedView).where(
            SavedView.organization_id == organization_id, SavedView.id == view_id
        )
    ).scalars().first()
    if row is None or user_id is None or row.owner_id != user_id:
        return None
    return row


def create(
    session: Session,
    organization_id: uuid.UUID,
    owner_id: uuid.UUID,
    *,
    entity: str,
    name: str,
    filters: dict[str, Any] | None = None,
    description: str | None = None,
    is_shared: bool = False,
    is_pinned: bool = True,
    position: int = 0,
) -> SavedView:
    name = (name or "").strip()
    if not name:
        raise SavedViewError("a view needs a name")
    count = len([v for v in visible(session, organization_id, owner_id)
                 if v.owner_id == owner_id])
    if count >= MAX_VIEWS_PER_USER:
        raise SavedViewError(f"at most {MAX_VIEWS_PER_USER} saved views per user")
    clash = session.execute(
        select(SavedView).where(
            SavedView.organization_id == organization_id,
            SavedView.owner_id == owner_id,
            SavedView.entity == entity, SavedView.name == name,
        )
    ).scalars().first()
    if clash is not None:
        raise SavedViewError(f"you already have a {entity} view called {name!r}")
    row = SavedView(
        organization_id=organization_id, owner_id=owner_id, entity=entity, name=name[:120],
        description=(description or None), filters=normalise_filters(entity, filters),
        is_shared=is_shared, is_pinned=is_pinned, position=position,
    )
    session.add(row)
    session.flush()
    return row


def update(session: Session, row: SavedView, payload: dict[str, Any]) -> SavedView:
    """Patch in place. `entity` is immutable -- see the module docstring."""
    if "entity" in payload and payload["entity"] not in (None, row.entity):
        raise SavedViewError(
            "a view cannot change entity; its filters mean something different "
            "on another list. Create a new view instead."
        )
    if "name" in payload and payload["name"] is not None:
        name = str(payload["name"]).strip()
        if not name:
            raise SavedViewError("a view needs a name")
        row.name = name[:120]
    if "description" in payload:
        row.description = (payload["description"] or None)
    if "filters" in payload and payload["filters"] is not None:
        row.filters = normalise_filters(row.entity, payload["filters"])
    for flag in ("is_shared", "is_pinned"):
        if payload.get(flag) is not None:
            setattr(row, flag, bool(payload[flag]))
    if payload.get("position") is not None:
        row.position = int(payload["position"])
    session.flush()
    return row


def as_dict(row: SavedView, *, viewer_id: uuid.UUID | None = None) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "entity": row.entity,
        "name": row.name,
        "description": row.description,
        "filters": dict(row.filters or {}),
        "is_shared": row.is_shared,
        "is_pinned": row.is_pinned,
        "position": row.position,
        "owner_id": str(row.owner_id),
        # The console needs this to decide whether to paint Edit/Delete. It is
        # a rendering hint, not the authorization -- `get_owned` is.
        "is_mine": viewer_id is not None and row.owner_id == viewer_id,
    }


def query_string(row: SavedView) -> str:
    """The filters as a URL fragment, for links and for tests."""
    from urllib.parse import urlencode

    return urlencode(sorted((row.filters or {}).items()))


def seed_defaults(
    session: Session, organization_id: uuid.UUID, owner_id: uuid.UUID
) -> list[SavedView]:
    """The three queues a triage operator opens on day one.

    Seeded per user on first visit rather than at bootstrap: an organization
    created before this release has users who would otherwise never see them,
    and a "no views yet" empty state is a worse first run than three that
    explain what a view is by being one.
    """
    wanted: Iterable[tuple[str, str, str, dict[str, Any]]] = (
        ("findings", "Critical, internet-facing",
         "The shortest list that can still ruin a quarter.",
         {"severity": "critical", "exposure": "internet", "order": "risk"}),
        ("findings", "Known exploited (KEV)",
         "CISA has seen these exploited in the wild.",
         {"kev": True, "order": "risk"}),
        ("findings", "Past its SLA",
         "Already late. Ordered by how late.",
         {"sla_breached": True, "order": "sla"}),
    )
    made: list[SavedView] = []
    for entity, name, description, filters in wanted:
        try:
            made.append(create(session, organization_id, owner_id, entity=entity,
                               name=name, description=description, filters=filters,
                               is_pinned=True, position=len(made)))
        except SavedViewError:
            continue                      # already there: seeding is idempotent
    return made
