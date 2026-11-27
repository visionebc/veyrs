"""The certificate VEYRS serves: request (CSR), attach the signed certificate,
install it on every app node, roll back.

Platform administrators only (`is_superuser`, user tokens): the certificate
belongs to the installation, and whoever controls it can impersonate VEYRS to
every user. Every action is audited. The private key is never returned by any
route: it is generated here, sealed, and only the root installer on each node
opens it. See services/web_tls.py.
"""
from __future__ import annotations

import base64
import binascii
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from ...security.deps import Principal, TenantSession, audit_actor
from ...services import audit
from ...services import web_tls as wt
from .updates import platform_admin

router = APIRouter(prefix="/admin/web-certificate", tags=["administration"])

Admin = Annotated[Principal, Depends(platform_admin)]


class WebCertRequestCreate(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    #: More names, one per line or comma-separated (host names or IP addresses).
    extra_names: str | None = Field(default=None, max_length=20_000)
    key_type: str = Field(default=wt.DEFAULT_KEY_TYPE, max_length=16)
    organization: str | None = Field(default=None, max_length=64)
    organizational_unit: str | None = Field(default=None, max_length=64)
    locality: str | None = Field(default=None, max_length=64)
    state: str | None = Field(default=None, max_length=64)
    country: str | None = Field(default=None, max_length=2)
    note: str | None = Field(default=None, max_length=500)


class WebCertAttach(BaseModel):
    #: The signed certificate, PEM (may already include the chain) or base64 DER.
    certificate: str = Field(min_length=1, max_length=400_000)
    chain: str | None = Field(default=None, max_length=400_000)
    #: Optional: which pending request. Without it the key is found by matching.
    request_id: uuid.UUID | None = None


class WebCertImport(BaseModel):
    certificate: str | None = Field(default=None, max_length=400_000)
    private_key: str | None = Field(default=None, max_length=100_000)
    chain: str | None = Field(default=None, max_length=400_000)
    #: A .pfx/.p12 file, base64.
    pkcs12_base64: str | None = Field(default=None, max_length=600_000)
    passphrase: str | None = Field(default=None, max_length=1024)
    note: str | None = Field(default=None, max_length=500)


class WebCertPolicy(BaseModel):
    redirect_http: bool


def _refused(exc: wt.WebTlsError) -> HTTPException:
    detail: dict | str = str(exc)
    if isinstance(exc, wt.CertificateRefused):
        detail = {"message": str(exc), "checks": exc.checks}
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail)


def _get(session, cert_id: uuid.UUID):
    try:
        return wt.get(session, cert_id)
    except LookupError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such certificate") from None


def _der_or_pem(text: str) -> str | bytes:
    if "-----BEGIN" in text:
        return text
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return text


@router.get("", summary="Served certificate, requests, history and what each node serves")
def get_overview(_: Admin, session: TenantSession) -> dict:
    return wt.overview(session)


@router.post("/requests", status_code=status.HTTP_201_CREATED,
             summary="Generate a private key here and a certificate signing request (CSR)")
def create_request(request: Request, principal: Admin, session: TenantSession,
                   payload: WebCertRequestCreate) -> dict:
    try:
        row = wt.create_request(
            session, common_name=payload.common_name, extra_names=payload.extra_names,
            key_type=payload.key_type, note=payload.note or "",
            subject={k: getattr(payload, k) or "" for k in wt.SUBJECT_FIELDS},
            actor_id=principal.user_id, actor_label=principal.label)
    except wt.WebTlsError as exc:
        raise _refused(exc) from None
    audit.record(session, action="web_certificate.request", object_type="web_certificate",
                 object_id=row.id, object_label=row.common_name[:255],
                 changes={"names": row.requested_names, "key_type": row.key_type},
                 **audit_actor(request, principal))
    session.commit()
    return wt.cert_out(row)


@router.get("/{cert_id}/csr", response_class=Response,
            summary="Download the CSR (PEM) to take to the CA")
def download_csr(cert_id: uuid.UUID, _: Admin, session: TenantSession) -> Response:
    row = _get(session, cert_id)
    if not row.csr_pem:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "this certificate was imported: it has no CSR")
    name = "".join(c if c.isalnum() or c in "-." else "_" for c in row.common_name.replace("*", "wildcard"))
    return Response(row.csr_pem, media_type="application/pkcs10",
                    headers={"Content-Disposition": f'attachment; filename="{name}.csr"'})


@router.post("/certificate", summary="Attach the certificate the CA signed to its pending request")
def attach(request: Request, principal: Admin, session: TenantSession, payload: WebCertAttach) -> dict:
    try:
        row, checks = wt.attach_certificate(session, _der_or_pem(payload.certificate),
                                            payload.chain, payload.request_id)
    except wt.WebTlsError as exc:
        session.rollback()
        audit.record(session, action="web_certificate.attach_refused", object_type="web_certificate",
                     object_label=str(exc)[:255], **audit_actor(request, principal))
        session.commit()
        raise _refused(exc) from None
    audit.record(session, action="web_certificate.attach", object_type="web_certificate",
                 object_id=row.id, object_label=(row.subject or row.common_name)[:255],
                 changes={"fingerprint": row.cert_fingerprint, "issuer": row.issuer,
                          "not_after": row.not_after.isoformat() if row.not_after else None,
                          "warnings": [c["check"] for c in checks if c["result"] == "warn"]},
                 **audit_actor(request, principal))
    session.commit()
    return wt.cert_out(row)


@router.post("/import", status_code=status.HTTP_201_CREATED,
             summary="Import a certificate AND its private key issued elsewhere (PEM or PKCS#12)")
def import_pair(request: Request, principal: Admin, session: TenantSession,
                payload: WebCertImport) -> dict:
    p12 = None
    if payload.pkcs12_base64:
        try:
            p12 = base64.b64decode(payload.pkcs12_base64, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "the PKCS#12 data is not valid base64") from None
    try:
        row, checks = wt.import_certificate(
            session, certificate=_der_or_pem(payload.certificate) if payload.certificate else None,
            private_key=payload.private_key, chain=payload.chain, pkcs12_data=p12,
            passphrase=payload.passphrase, note=payload.note or "",
            actor_id=principal.user_id, actor_label=principal.label)
    except wt.WebTlsError as exc:
        session.rollback()
        raise _refused(exc) from None
    audit.record(session, action="web_certificate.import", object_type="web_certificate",
                 object_id=row.id, object_label=(row.subject or row.common_name)[:255],
                 changes={"fingerprint": row.cert_fingerprint, "issuer": row.issuer},
                 **audit_actor(request, principal))
    session.commit()
    return wt.cert_out(row)


@router.post("/{cert_id}/install", summary="Serve this certificate on every app node")
def install(cert_id: uuid.UUID, request: Request, principal: Admin, session: TenantSession) -> dict:
    _get(session, cert_id)
    try:
        row, previous = wt.activate(session, cert_id, principal.label)
    except wt.WebTlsError as exc:
        session.commit()        # keep the refreshed checks on the row
        raise _refused(exc) from None
    audit.record(session, action="web_certificate.install", object_type="web_certificate",
                 object_id=row.id, object_label=(row.subject or row.common_name)[:255],
                 changes={"fingerprint": row.cert_fingerprint,
                          "replaces": previous.cert_fingerprint if previous else None},
                 **audit_actor(request, principal))
    session.commit()
    return wt.overview(session)


@router.post("/uninstall", summary="Stop serving HTTPS from the app nodes")
def uninstall(request: Request, principal: Admin, session: TenantSession) -> dict:
    row = wt.deactivate(session)
    if row is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "no certificate is installed")
    # The redirect goes with it: left on, it would come back by itself the
    # moment someone installs the next certificate.
    if wt.policy(session)["redirect_http"]:
        wt.set_policy(session, redirect_http=False, actor_label=principal.label)
    audit.record(session, action="web_certificate.uninstall", object_type="web_certificate",
                 object_id=row.id, object_label=(row.subject or row.common_name)[:255],
                 changes={"fingerprint": row.cert_fingerprint}, **audit_actor(request, principal))
    session.commit()
    return wt.overview(session)


@router.delete("/{cert_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None,
               response_class=Response, summary="Discard a request or certificate (its key is destroyed)")
def discard(cert_id: uuid.UUID, request: Request, principal: Admin, session: TenantSession) -> Response:
    _get(session, cert_id)
    try:
        row = wt.discard(session, cert_id)
    except wt.WebTlsError as exc:
        raise _refused(exc) from None
    audit.record(session, action="web_certificate.discard", object_type="web_certificate",
                 object_id=row.id, object_label=(row.subject or row.common_name)[:255],
                 changes={"status": row.status, "fingerprint": row.cert_fingerprint},
                 **audit_actor(request, principal))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/policy", summary="Redirect plain HTTP to HTTPS on the app nodes")
def set_policy(request: Request, principal: Admin, session: TenantSession, payload: WebCertPolicy) -> dict:
    before = wt.policy(session)
    if payload.redirect_http and wt.active(session) is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "install a certificate first: redirecting to HTTPS with nothing on 443 "
                            "would lock everyone out")
    after = wt.set_policy(session, redirect_http=payload.redirect_http, actor_label=principal.label)
    audit.record(session, action="web_certificate.policy", object_type="installation",
                 object_label="redirect_http", changes={"before": before, "after": after},
                 **audit_actor(request, principal))
    session.commit()
    return after
