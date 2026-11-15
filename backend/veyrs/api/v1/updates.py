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

from typing import Annotated, Literal

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
            detail=("this page concerns the whole installation, not one organization: platform "
                    "administrators only (on the host: veyrs platform-admin --email <you>)"),
        )
    return principal


class ApplyRequest(BaseModel):
    #: Optional guard: the version the operator saw. Refused if the latest
    #: release moved under them between the page load and the click. For a
    #: local source it is REQUIRED: it names which local copy to apply.
    version: str | None = Field(default=None, max_length=32)
    #: release (GitHub) | upload (sent through this console) | local (VEYRS_UPDATE_LOCAL_DIR)
    source: Literal["release", "upload", "local"] = "release"


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
    source = payload.source if payload is not None else "release"
    if source == "release":
        if not state["can_apply"]:
            raise HTTPException(status.HTTP_409_CONFLICT, state["reason"])
        target = state["latest"]
        if payload is not None and payload.version and payload.version.lstrip("v") != target:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"the latest release is {target}, not {payload.version}; reload the page",
            )
    else:
        wanted = (payload.version or "").lstrip("v") if payload else ""
        item = next((i for i in state["local"] if i["origin"] == source and i["version"] == wanted), None)
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, f"no {source} copy of release {wanted or '?'}")
        if not item["can_apply"]:
            raise HTTPException(status.HTTP_409_CONFLICT, item["reason"])
        target = item["version"]
    # Audited BEFORE the spool file exists: the updater may start the instant
    # the file appears, and an update nobody can trace is the one outcome this
    # ordering rules out.
    audit.record(
        session,
        action="software.update.requested",
        object_type="installation",
        object_label=f"{state['current']} -> {target}",
        changes={"from_version": state["current"], "to_version": target, "mode": state["mode"],
                 "source": source},
        **_actor(request, principal),
    )
    session.commit()
    try:
        queued = updates.request_apply(
            target_version=target, requested_by=principal.label, from_version=state["current"],
            source=source,
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


# ---------------------------------------------------------------- uploads ---
# A release copied through the browser, in chunks of at most 8 MB: no proxy
# body limit to raise, and an interrupted upload resumes at the offset the
# server reports. The files land in the API's own writable directory and are
# trusted by NOBODY there: the console shows the advisory verification, the
# root updater copies them out and verifies them again before installing.
@router.post("/uploads", status_code=status.HTTP_201_CREATED, summary="Start uploading a release")
def upload_start(principal: Annotated[Principal, Depends(platform_admin)]) -> dict:
    return {"upload_id": updates.upload_start(), "chunk_bytes": updates.CHUNK_MAX_BYTES}


@router.put("/uploads/{upload_id}/{name}", summary="Append one chunk of a release file")
async def upload_chunk(
    upload_id: str, name: str, request: Request,
    principal: Annotated[Principal, Depends(platform_admin)],
    offset: Annotated[int, Query(ge=0)],
    total: Annotated[int, Query(gt=0)],
) -> dict:
    length = int(request.headers.get("content-length") or 0)
    if length > updates.CHUNK_MAX_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "chunks are at most 8 MB")
    data = await request.body()
    try:
        return updates.upload_chunk(upload_id, name, offset, total, data)
    except updates.UploadError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None


@router.post("/uploads/{upload_id}/finish", summary="Finish an upload: stage it under its version")
def upload_finish(
    upload_id: str, request: Request,
    principal: Annotated[Principal, Depends(platform_admin)], session: TenantSession,
) -> dict:
    try:
        item = updates.upload_finish(upload_id)
    except updates.UploadError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    audit.record(
        session, action="software.update.uploaded", object_type="installation",
        object_label=f"release {item.get('version')} uploaded",
        changes={"version": item.get("version"), "verification": item.get("verification"),
                 "files": item.get("files")},
        **_actor(request, principal),
    )
    session.commit()
    return item


@router.delete("/uploads/{version}", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
               summary="Delete an uploaded release copy")
def upload_delete(
    version: str, request: Request,
    principal: Annotated[Principal, Depends(platform_admin)], session: TenantSession,
) -> None:
    if not updates.delete_upload(version):
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no uploaded copy of {version}")
    audit.record(session, action="software.update.upload_deleted", object_type="installation",
                 object_label=f"release {version}", **_actor(request, principal))
    session.commit()
