"""Software update: the installation's version, the latest release, and a
request for the root updater to apply it.

Platform administrators only (`is_superuser`). The installed version is a
property of the INSTALLATION, not of a tenant: an organization administrator
of one tenant on a shared node must neither read the host's update logs nor
schedule a restart of everybody's API. API keys never qualify.

`POST /admin/updates/apply` does not update anything. It records the request
in the audit trail and drops one JSON file into the spool; the root
`veyrs-updater.service` does the work and reports back through status files
(`GET /admin/updates` -> `history`). See services/updates.py.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ...security.deps import CurrentPrincipal, Principal, TenantSession
from ...services import audit, updates
from .admin import _actor

router = APIRouter(prefix="/admin/updates", tags=["administration"])


def platform_admin(principal: CurrentPrincipal) -> Principal:
    if not principal.is_superuser or principal.kind != "user":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="software updates concern the whole installation: platform administrators only",
        )
    return principal


class ApplyRequest(BaseModel):
    #: Optional guard: the version the operator saw. Refused if the latest
    #: release moved under them between the page load and the click.
    version: str | None = Field(default=None, max_length=32)


@router.get("", summary="Installed version, latest release and updater history")
def get_updates(
    principal: Annotated[Principal, Depends(platform_admin)],
    refresh: Annotated[bool, Query(description="bypass the one-hour cache")] = False,
) -> dict:
    data = updates.status(force=refresh)
    data["history"] = updates.recent_status()
    return data


@router.post("/apply", status_code=status.HTTP_202_ACCEPTED,
             summary="Queue the latest signed release for the root updater (native installs)")
def apply_update(
    request: Request,
    principal: Annotated[Principal, Depends(platform_admin)],
    session: TenantSession,
    payload: ApplyRequest | None = None,
) -> dict:
    state = updates.status()
    if not state["can_apply"]:
        raise HTTPException(status.HTTP_409_CONFLICT, state["reason"])
    target = state["latest"]
    if payload is not None and payload.version and payload.version.lstrip("v") != target:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"the latest release is {target}, not {payload.version}; reload the page",
        )
    # Audited BEFORE the spool file exists: the updater may start the instant
    # the file appears, and an update nobody can trace is the one outcome this
    # ordering rules out.
    audit.record(
        session,
        action="software.update.requested",
        object_type="installation",
        object_label=f"{state['current']} -> {target}",
        changes={"from_version": state["current"], "to_version": target, "mode": state["mode"]},
        **_actor(request, principal),
    )
    session.commit()
    try:
        queued = updates.request_apply(
            target_version=target, requested_by=principal.label, from_version=state["current"],
        )
    except updates.UpdateRefused as exc:
        audit.record(
            session,
            action="software.update.request_failed",
            object_type="installation",
            object_label=f"{state['current']} -> {target}",
            changes={"reason": str(exc)},
            **_actor(request, principal),
        )
        session.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    return {
        "status": "queued",
        "request": queued,
        "detail": ("the root updater takes it from here: download, signature check, backup, "
                   "install, health check. The API restarts during the install; follow the "
                   "result under history."),
    }
