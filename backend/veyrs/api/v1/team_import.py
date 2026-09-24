"""Bringing teams in from NetBox or from the directory.

Separate router rather than more routes on `admin`: the import is the only
place in the product where a WRITE to `teams` is decided by something outside
VEYRS, and keeping it addressable on its own is what makes it auditable and,
if it ever misbehaves, switchable off at the router.

`TenantSession` throughout. `teams` and `team_members` are RLS-FORCED with no
unbound escape, so on a plain session every one of these routes would report
an empty directory-import plan with no error -- a preview that says "0 teams
already exist, all 40 will be created" and then collides on every insert.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...models.cmdb import AssetSource
from ...security.deps import Principal, TenantSession, require
from ...services import team_import

router = APIRouter(prefix="/teams/import", tags=["asset sources"])


class ImportRequest(BaseModel):
    provider: str
    #: netbox only: which source to read through, and which collection of it.
    source_id: uuid.UUID | None = None
    collection: str | None = None
    #: ldap only. Off by default: enumerating every group's membership is one
    #: extra directory search per group, and most imports only want the teams.
    import_members: bool = False
    #: Off by default. An import that renames teams on every run is how a
    #: directory rename nobody announced arrives as "somebody edited our teams".
    update_existing: bool = False


class AssignRequest(BaseModel):
    source_id: uuid.UUID
    dry_run: bool = False
    #: Off by default: an asset a person assigned by hand outranks a label.
    overwrite: bool = False


def _source(session, principal: Principal, source_id: uuid.UUID | None) -> AssetSource | None:
    if source_id is None:
        return None
    source = session.get(AssetSource, source_id)
    if source is None or source.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset source not found")
    return source


def _collect(session, principal: Principal, payload: ImportRequest):
    if payload.provider not in team_import.PROVIDERS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown provider {payload.provider!r}; expected one of "
            f"{list(team_import.PROVIDERS)}")
    source = _source(session, principal, payload.source_id)
    try:
        return team_import.collect(
            session, principal.organization_id, provider=payload.provider,
            source=source, collection=payload.collection,
            with_members=payload.import_members and payload.provider == "ldap",
        )
    except team_import.TeamImportError as exc:
        # 502 and not 500: the fault is in a system VEYRS is talking to, and
        # the operator's next move is to check that system, not this one.
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc


@router.get("/providers", summary="Where teams can be imported from")
def list_providers(
    principal: Annotated[Principal, Depends(require("team:write"))],
    session: TenantSession,
) -> list[dict[str, Any]]:
    return team_import.available(session, principal.organization_id)


@router.post("/preview", summary="What an import would do; writes nothing")
def preview(
    payload: ImportRequest,
    principal: Annotated[Principal, Depends(require("team:write"))],
    session: TenantSession,
) -> dict[str, Any]:
    candidates = _collect(session, principal, payload)
    outcome = team_import.plan(session, principal.organization_id, candidates)
    return {**outcome, "provider": payload.provider,
            "candidates": len(candidates)}


@router.post("", summary="Create the teams this source reports")
def run_import(
    payload: ImportRequest,
    principal: Annotated[Principal, Depends(require("team:write"))],
    session: TenantSession,
) -> dict[str, Any]:
    candidates = _collect(session, principal, payload)
    return team_import.apply(
        session, principal.organization_id, candidates,
        provider=payload.provider, update_existing=payload.update_existing,
        import_members=payload.import_members and payload.provider == "ldap",
        actor_id=principal.user_id, actor_label=principal.label or "unknown",
    )


@router.post("/assign-assets", summary="Point staged assets at their imported team")
def assign_assets(
    payload: AssignRequest,
    principal: Annotated[Principal, Depends(require("team:write"))],
    session: TenantSession,
) -> dict[str, Any]:
    source = _source(session, principal, payload.source_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset source not found")
    return team_import.assign_from_records(
        session, principal.organization_id, source, dry_run=payload.dry_run,
        overwrite=payload.overwrite, actor_id=principal.user_id,
        actor_label=principal.label or "unknown",
    )
