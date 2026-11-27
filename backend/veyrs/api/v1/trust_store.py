"""TLS trust store: the CAs this installation accepts when it connects out.

Platform administrators only (`is_superuser`, user tokens). The store is
installation-wide: one organization adding a CA changes what every
organization's connectors trust, so it is not an organization-admin action.
Every change is audited. See services/trust_store.py for the rules.
"""
from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from ...models.trust import TrustedCa
from ...security.deps import Principal, TenantSession, audit_actor
from ...services import audit
from ...services import trust_store as ts
from .updates import platform_admin

router = APIRouter(prefix="/admin/trust-store", tags=["administration"])

Admin = Annotated[Principal, Depends(platform_admin)]


class TrustCaImport(BaseModel):
    #: One PEM certificate or a pasted chain. The console converts DER uploads to PEM.
    pem: str = Field(min_length=1, max_length=200_000)
    name: str | None = Field(default=None, max_length=180)
    note: str | None = Field(default=None, max_length=500)


class TrustCaUpdate(BaseModel):
    is_enabled: bool | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    note: str | None = Field(default=None, max_length=500)


class TrustProbe(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


def _get(session, ca_id: uuid.UUID) -> TrustedCa:
    row = session.get(TrustedCa, ca_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such certificate authority")
    return row


@router.get("", summary="Trusted certificate authorities, health and chain gaps")
def list_trust_store(_: Admin, session: TenantSession) -> dict:
    return ts.overview(session)


@router.post("", status_code=status.HTTP_201_CREATED,
             summary="Import a CA certificate or chain (PEM)")
def import_ca(request: Request, principal: Admin, session: TenantSession,
              payload: TrustCaImport) -> dict:
    try:
        result = ts.import_pem(session, payload.pem, name_hint=(payload.name or "").strip(),
                               note=(payload.note or "").strip(), actor_id=principal.user_id,
                               actor_label=principal.label)
    except ts.TrustStoreError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    if not result["imported"] and not result["updated"]:
        session.rollback()
        reasons = "; ".join(f"{r['name']}: {r['reason']}" for r in result["rejected"])
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"nothing imported. {reasons}"[:1500])
    audit.record(
        session, action="trust_store.import", object_type="trusted_ca",
        object_label=", ".join(i["name"] for i in result["imported"] + result["updated"])[:255],
        changes={"imported": [i["name"] for i in result["imported"]],
                 "updated": [i["name"] for i in result["updated"]],
                 "rejected": [r["name"] for r in result["rejected"]]},
        **audit_actor(request, principal),
    )
    session.commit()
    ts.invalidate()
    return result


@router.get("/{ca_id}", summary="Decoded content of one trusted CA")
def get_ca(ca_id: uuid.UUID, _: Admin, session: TenantSession) -> dict:
    row = _get(session, ca_id)
    return {**ts.row_out(row), "content": ts.describe(row.pem)}


@router.patch("/{ca_id}", summary="Enable, disable, rename or annotate a trusted CA")
def update_ca(ca_id: uuid.UUID, request: Request, principal: Admin, session: TenantSession,
              payload: TrustCaUpdate) -> dict:
    row = _get(session, ca_id)
    changes: dict = {}
    if payload.is_enabled is not None and payload.is_enabled != row.is_enabled:
        changes["is_enabled"] = [row.is_enabled, payload.is_enabled]
        row.is_enabled = payload.is_enabled
    if payload.name is not None and payload.name.strip() != row.name:
        name = payload.name.strip()
        clash = session.execute(
            select(TrustedCa.id).where(TrustedCa.name == name, TrustedCa.id != row.id)).first()
        if clash:
            raise HTTPException(status.HTTP_409_CONFLICT, f"another CA is already named {name!r}")
        changes["name"] = [row.name, name]
        row.name = name
    if payload.note is not None and payload.note != row.note:
        changes["note"] = True
        row.note = payload.note
    if changes:
        audit.record(session, action="trust_store.update", object_type="trusted_ca",
                     object_id=row.id, object_label=row.name, changes=changes,
                     **audit_actor(request, principal))
        session.commit()
        ts.invalidate()
    return ts.row_out(row)


@router.delete("/{ca_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
               response_class=Response, summary="Remove a CA from the trust store")
def delete_ca(ca_id: uuid.UUID, request: Request, principal: Admin,
              session: TenantSession) -> Response:
    row = _get(session, ca_id)
    audit.record(session, action="trust_store.delete", object_type="trusted_ca",
                 object_id=row.id, object_label=row.name,
                 changes={"fingerprint": row.fingerprint, "subject": row.subject},
                 **audit_actor(request, principal))
    session.delete(row)
    session.commit()
    ts.invalidate()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/probe", summary="Test a server's certificate against the current trust store")
def probe(request: Request, principal: Admin, session: TenantSession,
          payload: TrustProbe) -> dict:
    try:
        result = ts.probe(payload.host, payload.port)
    except ts.TrustStoreError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    # A probe opens a connection from the API node to an address the caller
    # chose: leave a trace of it.
    audit.record(session, action="trust_store.probe", object_type="installation",
                 object_label=f"{result['host']}:{result['port']}"[:255],
                 changes={"verified": result["verified"], "reachable": result["reachable"]},
                 **audit_actor(request, principal))
    session.commit()
    return result
