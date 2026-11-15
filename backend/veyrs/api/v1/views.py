"""Saved views: an operator's own queues.

No permission beyond being authenticated. A saved view is a bookmark: gating it
behind `finding:write` would mean an analyst who can read the queue cannot save
the filter they read it with, and the row itself grants nothing -- applying it
goes through `/findings`, which enforces both permissions and team scope.

The tag is exempt from team scope (`security/scope.py`) because no route here
returns an asset- or finding-level row. That claim is enforced by
`tests/test_phase36_saved_views.py`, which reads this module's source: the
`policies` reclassification in v0.17.1 exists because somebody made the same
claim about a router that had four routes contradicting it.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from ...models import VIEW_ENTITIES
from ...security.deps import CurrentPrincipal, TenantSession
from ...services import audit, views as view_service

router = APIRouter(prefix="/saved-views", tags=["saved views"])


class SavedViewWrite(BaseModel):
    entity: str = Field(..., description=f"one of {', '.join(VIEW_ENTITIES)}")
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=400)
    filters: dict[str, Any] = Field(default_factory=dict)
    is_shared: bool = False
    is_pinned: bool = True
    position: int = 0


class SavedViewPatch(BaseModel):
    #: Declared so that changing it is REFUSED rather than ignored. A field
    #: pydantic drops silently is a request the client believes succeeded:
    #: 200, unchanged entity, filters that now mean something else.
    entity: str | None = None
    name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=400)
    filters: dict[str, Any] | None = None
    is_shared: bool | None = None
    is_pinned: bool | None = None
    position: int | None = None


@router.get("", summary="My saved views, plus everything shared here")
def list_views(
    session: TenantSession,
    principal: CurrentPrincipal,
    entity: str | None = Query(default=None),
    seed: bool = Query(
        default=False,
        description="Install the built-in starter views for this user if they "
                    "have none at all. Idempotent, and never overwrites.",
    ),
) -> dict:
    if entity and entity not in VIEW_ENTITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown entity {entity!r}")
    rows = view_service.visible(session, principal.organization_id,
                                principal.user_id, entity=entity)
    if seed and principal.user_id is not None and not any(
        r.owner_id == principal.user_id for r in rows
    ):
        # Only when the user owns NOTHING, and only what they asked to see.
        # Re-seeding somebody who deleted the starters would be the console
        # arguing with them once a day.
        view_service.seed_defaults(session, principal.organization_id, principal.user_id)
        session.commit()
        rows = view_service.visible(session, principal.organization_id,
                                    principal.user_id, entity=entity)
    return {"items": [view_service.as_dict(r, viewer_id=principal.user_id) for r in rows],
            "entities": list(VIEW_ENTITIES)}


@router.post("", status_code=status.HTTP_201_CREATED, summary="Save a view")
def create_view(payload: SavedViewWrite, session: TenantSession,
                principal: CurrentPrincipal) -> dict:
    if principal.user_id is None:
        # An API key has no morning queue. Refused rather than filed under a
        # NULL owner, which would produce a shared view nobody can edit.
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "saved views belong to a user; an API key cannot own one")
    try:
        row = view_service.create(
            session, principal.organization_id, principal.user_id,
            entity=payload.entity, name=payload.name, filters=payload.filters,
            description=payload.description, is_shared=payload.is_shared,
            is_pinned=payload.is_pinned, position=payload.position,
        )
    except view_service.SavedViewError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="saved_view.create", object_type="saved_view",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"entity": row.entity, "filters": dict(row.filters)})
    session.commit()
    return view_service.as_dict(row, viewer_id=principal.user_id)


@router.patch("/{view_id}", summary="Rename, re-filter or share a view")
def patch_view(view_id: uuid.UUID, payload: SavedViewPatch, session: TenantSession,
               principal: CurrentPrincipal) -> dict:
    row = view_service.get_owned(session, principal.organization_id, view_id,
                                 principal.user_id)
    if row is None:
        # 404 and not 403: a shared view the caller can read but not edit is
        # still not theirs, and confirming "this id exists but is somebody
        # else's" answers a question they did not need answered.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such saved view")
    before = {"name": row.name, "filters": dict(row.filters), "is_shared": row.is_shared}
    try:
        view_service.update(session, row, payload.model_dump(exclude_unset=True))
    except view_service.SavedViewError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    audit.record(session, action="saved_view.update", object_type="saved_view",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=audit.diff(before, {"name": row.name,
                                             "filters": dict(row.filters),
                                             "is_shared": row.is_shared}))
    session.commit()
    return view_service.as_dict(row, viewer_id=principal.user_id)


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a view")
def delete_view(view_id: uuid.UUID, session: TenantSession,
                principal: CurrentPrincipal) -> Response:
    row = view_service.get_owned(session, principal.organization_id, view_id,
                                 principal.user_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such saved view")
    audit.record(session, action="saved_view.delete", object_type="saved_view",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.delete(row)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
