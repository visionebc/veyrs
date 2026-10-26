"""Report builder API: ad-hoc reports from a curated catalog, plus saved reports.

Authorization, in full:

* **Every route needs `report:read`**, the permission the fixed reports and
  dashboards use. The builder is a reporting surface, so whoever may read
  reports may open it.
* **Running or exporting also needs the entity's own read permission**
  (`finding:read`, `asset:read`, `vulnerability:read`, `ticket:read`,
  `riskregister:read`) -- exactly what that entity's list route requires.
  `report:read` alone must not become a way to read findings through the
  report door; `api/v1/reports.py` made the same rule for the fixed reports.
* **Team scope is applied, not refused.** The fixed exports refuse a scoped
  identity because their titles promise the whole estate. A builder report
  promises nothing but the spec, and its provenance carries a `scope` line, so
  a restricted operator gets their own slice -- rows, group counts and files
  alike -- labelled as such. The tag is `dashboards & reports`, which
  `security/scope.py` classifies as SCOPED.
* **Saving a private report needs only `report:read`**: it is a bookmark that
  grants nothing. **Sharing it with the organization needs `report:write`**:
  a shared report appears in everybody's list under a name somebody chose, and
  publishing to the organization is an editorial act the read-only roles do
  not hold. A shared report still runs under each reader's own permissions.
* **API keys may run and export, not save.** A machine identity has no list of
  reports, and a row filed under the key's creator would be a report that
  person never saved.

Exports are audited as `report.exported`, like the fixed reports; saves,
edits and deletes of saved reports are audited too.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field

from ...security.deps import Principal, TenantSession, require
from ...services import audit, report_builder as builder, reporting

router = APIRouter(prefix="/report-builder", tags=["dashboards & reports"])

Reader = Annotated[Principal, Depends(require("report:read"))]
EXPORT_FORMATS = ("csv", "xlsx", "json")


class QueryWrite(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=400)
    spec: dict[str, Any]
    is_shared: bool = False


class QueryPatch(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=400)
    spec: dict[str, Any] | None = None
    is_shared: bool | None = None


def _unprocessable(exc: Exception) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


def _entity_permission(principal: Principal, spec: Any) -> None:
    """The entity's own read permission. Unknown entities fall through to the 422."""
    entity = builder.CATALOG.get(spec.get("entity")) if isinstance(spec, dict) else None
    if entity is not None:
        principal.require(entity.permission)


def _run(session, principal: Principal, spec: Any, *, limit: int,
         title: str | None = None) -> dict:
    _entity_permission(principal, spec)
    try:
        return builder.run(session, spec, principal.scope, principal.organization_id,
                           user_id=principal.user_id, limit=limit, title=title)
    except builder.ReportBuilderError as exc:
        raise _unprocessable(exc) from exc


def _export(session, principal: Principal, spec: Any, fmt: str, *,
            title: str | None = None, query_id: uuid.UUID | None = None) -> Response:
    if fmt not in EXPORT_FORMATS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown format {fmt!r}; known: {list(EXPORT_FORMATS)}")
    result = _run(session, principal, spec, limit=builder.EXPORT_LIMIT, title=title)
    slug = result["provenance"]["report"]
    report = {"provenance": result["provenance"], "columns": result["columns"],
              "rows": result["rows"]}
    try:
        payload, content_type, filename = reporting.render_document(
            report, builder.tabulate(result), fmt, slug=slug,
            title=result["provenance"]["title"])
    except reporting.ReportError as exc:
        raise _unprocessable(exc) from exc
    # Exports leave the platform: audited like the fixed reports' exports, with
    # the spec, so "who took which slice of the estate home" is answerable.
    audit.record(
        session, action="report.exported", object_type="report",
        object_id=str(query_id) if query_id else slug,
        object_label=result["provenance"]["title"],
        organization_id=principal.organization_id,
        actor_id=principal.user_id, actor_label=principal.label,
        changes={"format": fmt, "bytes": len(payload), "rows": result["row_count"],
                 "truncated": result["truncated"], "scope": result["provenance"]["scope"],
                 "spec": result["spec"]},
    )
    session.commit()
    return Response(content=payload, media_type=content_type,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# ---------------------------------------------------------------------------
# Ad-hoc
# ---------------------------------------------------------------------------
@router.get("/catalog", summary="Entities, fields, operators and limits the builder offers")
def get_catalog(principal: Reader) -> dict:
    body = builder.catalog(principal.can)
    body["formats"] = list(EXPORT_FORMATS)
    body["can_share"] = principal.can("report:write")
    return body


@router.post("/run", summary="Run an ad-hoc report spec")
def run_report(session: TenantSession, principal: Reader,
               spec: Annotated[dict[str, Any], Body()]) -> dict:
    return _run(session, principal, spec, limit=builder.RUN_LIMIT)


@router.post("/export", summary="Export an ad-hoc report spec (csv, xlsx, json)")
def export_report(session: TenantSession, principal: Reader,
                  spec: Annotated[dict[str, Any], Body()],
                  format: str = Query(default="csv")) -> Response:
    return _export(session, principal, spec, format)


# ---------------------------------------------------------------------------
# Saved reports
# ---------------------------------------------------------------------------
def _require_user(principal: Principal) -> uuid.UUID:
    if principal.kind != "user" or principal.user_id is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "saved reports belong to a user; an API key cannot own one")
    return principal.user_id


def _readable(session, principal: Principal, query_id: uuid.UUID):
    row = builder.get_visible(session, principal.organization_id, query_id,
                              principal.user_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such saved report")
    return row


def _stored_spec(row) -> dict:
    """Re-validate a stored spec. A field removed since it was saved is a 422."""
    try:
        return builder.validate(row.spec)
    except builder.ReportBuilderError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"saved report {row.name!r} no longer matches the report catalog: {exc}. "
            "Edit it and save it again.",
        ) from exc


@router.get("/queries", summary="My saved reports, plus everything shared here")
def list_queries(session: TenantSession, principal: Reader) -> dict:
    rows = builder.visible_queries(session, principal.organization_id, principal.user_id)
    return {"items": [builder.query_as_dict(r, viewer_id=principal.user_id) for r in rows]}


@router.post("/queries", status_code=status.HTTP_201_CREATED, summary="Save a report")
def create_query(payload: QueryWrite, session: TenantSession, principal: Reader) -> dict:
    owner = _require_user(principal)
    if payload.is_shared:
        principal.require("report:write")
    try:
        row = builder.create_query(session, principal.organization_id, owner,
                                   name=payload.name, spec=payload.spec,
                                   description=payload.description,
                                   is_shared=payload.is_shared)
    except builder.ReportBuilderError as exc:
        raise _unprocessable(exc) from exc
    audit.record(session, action="report_query.create", object_type="report_query",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"spec": row.spec, "is_shared": row.is_shared})
    session.commit()
    return builder.query_as_dict(row, viewer_id=principal.user_id)


@router.get("/queries/{query_id}", summary="One saved report")
def get_query(query_id: uuid.UUID, session: TenantSession, principal: Reader) -> dict:
    return builder.query_as_dict(_readable(session, principal, query_id),
                                 viewer_id=principal.user_id)


@router.patch("/queries/{query_id}", summary="Rename, re-specify or share a saved report")
def patch_query(query_id: uuid.UUID, payload: QueryPatch, session: TenantSession,
                principal: Reader) -> dict:
    row = builder.get_owned(session, principal.organization_id, query_id,
                            principal.user_id)
    if row is None:
        # 404, not 403, as for saved views: "exists but is somebody else's"
        # answers a question the caller did not need answered.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such saved report")
    if payload.is_shared and not row.is_shared:
        principal.require("report:write")
    before = {"name": row.name, "spec": dict(row.spec), "is_shared": row.is_shared}
    try:
        builder.update_query(session, row, payload.model_dump(exclude_unset=True))
    except builder.ReportBuilderError as exc:
        raise _unprocessable(exc) from exc
    audit.record(session, action="report_query.update", object_type="report_query",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=audit.diff(before, {"name": row.name, "spec": dict(row.spec),
                                             "is_shared": row.is_shared}))
    session.commit()
    return builder.query_as_dict(row, viewer_id=principal.user_id)


@router.delete("/queries/{query_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Delete a saved report")
def delete_query(query_id: uuid.UUID, session: TenantSession, principal: Reader) -> Response:
    row = builder.get_owned(session, principal.organization_id, query_id,
                            principal.user_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such saved report")
    audit.record(session, action="report_query.delete", object_type="report_query",
                 object_id=row.id, object_label=row.name,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.delete(row)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/queries/{query_id}/run", summary="Run a saved report under MY authorization")
def run_query(query_id: uuid.UUID, session: TenantSession, principal: Reader) -> dict:
    row = _readable(session, principal, query_id)
    return _run(session, principal, _stored_spec(row), limit=builder.RUN_LIMIT,
                title=row.name)


@router.post("/queries/{query_id}/export", summary="Export a saved report")
def export_query(query_id: uuid.UUID, session: TenantSession, principal: Reader,
                 format: str = Query(default="csv")) -> Response:
    row = _readable(session, principal, query_id)
    return _export(session, principal, _stored_spec(row), format, title=row.name,
                   query_id=row.id)
