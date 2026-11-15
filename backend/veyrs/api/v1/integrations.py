"""Scanner imports and ITSM connectors (spec sections 14 and 31)."""
from __future__ import annotations

import datetime as dt
import json
import secrets
import uuid
from typing import Annotated, Any

from fastapi import (
    APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, Response,
    UploadFile, status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, nulls_first, or_, select
from sqlalchemy.orm import Session

from ...db import get_session, set_tenant
from ...models import (
    Asset, Finding, ItsmConnector, Organization, ScannerConnector, Ticket,
)
from ...models.integration import ExternalLink, ImportRun, ImportStatus
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...security.secrets import encrypt
from ...services import audit, docs, importers, itsm, itsm_inbound, scanners
from ...services.importers import ImportOptions
from .schemas import Page

router = APIRouter(prefix="/integrations", tags=["integrations"])

MAX_IMPORT_BYTES = 128 * 1024 * 1024
SEVERITIES = ("informational", "low", "medium", "high", "critical")


class ImportRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str
    filename: str | None
    status: str
    records_seen: int
    findings_created: int
    findings_updated: int
    assets_created: int
    records_rejected: int
    reject_reasons: dict
    reject_samples: list
    stale_candidates: int
    findings_marked_absent: int
    findings_closed_absent: int
    endpoints_created: int
    inventory_hosts: int
    inventory_added: int
    inventory_updated: int
    inventory_unmatched: int
    engagement_id: uuid.UUID | None
    test_id: uuid.UUID | None
    dedupe_algorithm: str | None
    error: str | None
    started_at: dt.datetime
    finished_at: dt.datetime | None


class ConnectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    system: str
    base_url: str | None
    is_enabled: bool
    ticket_types: list
    field_mapping: dict
    last_sync_at: dt.datetime | None
    last_error: str | None
    inbound_enabled: bool
    inbound_transitions: dict
    last_inbound_at: dt.datetime | None
    #: True once a secret exists. The secret itself is never serialised - it is
    #: shown exactly once, by the rotate endpoint.
    inbound_secret_set: bool = False
    #: True once credentials exist. Same contract as the directory module's
    #: `bind_password_set`: the console needs to offer "replace the token"
    #: without ever being able to read the one that is stored.
    credentials_set: bool = False


class ConnectorWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    system: str
    base_url: str = Field(min_length=1, max_length=600)
    #: Free-form per system: {"username","password"} | {"email","token"} | {"token"}
    credentials: dict[str, Any] = Field(default_factory=dict)
    ticket_types: list[str] = Field(default_factory=list)
    field_mapping: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    inbound_enabled: bool = False
    inbound_transitions: dict[str, str] = Field(default_factory=dict)


class ConnectorPatch(BaseModel):
    """Everything about a connector EXCEPT `slug` and `system`.

    `system` is not patchable on purpose. The credentials on the row were
    entered for one system, and flipping the discriminator is how a ServiceNow
    password ends up in an `Authorization` header sent to Jira. Deleting and
    recreating is one explicit decision instead of two silent ones.

    `credentials` omitted -- or explicitly null -- leaves the stored secret
    alone, which is what lets the console offer "edit this connector" without
    re-asking for a token it is never allowed to read back.
    """

    name: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, min_length=1, max_length=600)
    credentials: dict[str, Any] | None = None
    ticket_types: list[str] | None = None
    field_mapping: dict[str, Any] | None = None
    is_enabled: bool | None = None
    inbound_enabled: bool | None = None
    inbound_transitions: dict[str, str] | None = None


def _connector_out(connector: ItsmConnector) -> ConnectorOut:
    """`inbound_secret_set` and `credentials_set` are computed, not columns.

    `inbound_secret_set` had been declared on this schema since the inbound leg
    shipped and was never populated, so it answered False for every connector
    -- including every connector that had a secret. A console reading it could
    only ever offer "mint a signing secret", never "you already have one", and
    rotating looked identical to first-time setup.
    """
    out = ConnectorOut.model_validate(connector)
    out.inbound_secret_set = bool(connector.inbound_secret_enc)
    out.credentials_set = bool(connector.credentials_enc)
    return out


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
@router.get("/importers")
def list_importers(
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> dict[str, Any]:
    return {
        "formats": sorted(importers.PARSERS),
        "options": {
            "create_assets": "create assets the scanner reports but VEYRS does not know",
            "dry_run": "parse and report without persisting",
            "min_severity": f"skip records below this severity {list(SEVERITIES)}",
            "target_asset": (
                "asset name for reports with no host of their own (SAST, SCA, "
                "cloud posture). Without it such records are rejected, because "
                "VEYRS never infers which asset a finding belongs to."
            ),
            "engagement_id": "scope this import to an engagement",
            "test_id": "reimport into a specific existing test",
            "reuse_test": (
                "reuse the engagement's test for this scanner (default). False "
                "opens a new test - correct for a pentest, wrong for a nightly sweep."
            ),
            "close_absent": (
                "close findings THIS TEST previously reported and no longer does"
            ),
            "absence_threshold": (
                "consecutive runs a finding may be missing before it counts as "
                "fixed; 0 disables auto-closure"
            ),
            "close_missing": "DEPRECATED alias for close_absent with a threshold of 1",
        },
        "notes": (
            "Findings absent from an export are reported as stale_candidates and "
            "are NOT closed unless close_absent is set: a host that was merely "
            "offline during the scan is not a remediated host. Closure is scoped "
            "to the test that ran - an import can never close a finding on a host "
            "it did not look at."
        ),
        "deduplication": "/api/v1/engagements/dedupe-registry",
    }


@router.post("/imports", response_model=ImportRunOut, status_code=201)
async def create_import(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:write"))],
    file: UploadFile = File(...),
    source: str | None = Form(default=None),
    create_assets: bool = Form(default=False),
    dry_run: bool = Form(default=False),
    close_missing: bool = Form(default=False),
    min_severity: str | None = Form(default=None),
    new_asset_criticality: str = Form(default="medium"),
    new_asset_exposure: str = Form(default="internal"),
    target_asset: str | None = Form(default=None),
    engagement_id: uuid.UUID | None = Form(default=None),
    test_id: uuid.UUID | None = Form(default=None),
    reuse_test: bool = Form(default=True),
    close_absent: bool | None = Form(default=None),
    absence_threshold: int | None = Form(default=None),
    version: str | None = Form(default=None),
    branch_tag: str | None = Form(default=None),
    commit_hash: str | None = Form(default=None),
    build_id: str | None = Form(default=None),
    import_inventory: bool = Form(default=False),
    inventory_from_plugin_output: bool = Form(default=False),
) -> ImportRunOut:
    payload = await file.read()
    if not payload:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "file is empty")
    if len(payload) > MAX_IMPORT_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "file too large")
    if source and source not in importers.PARSERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown source; known: {sorted(importers.PARSERS)}")
    if min_severity and min_severity not in SEVERITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"min_severity must be one of {list(SEVERITIES)}")

    if absence_threshold is not None and not (0 <= absence_threshold <= 30):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "absence_threshold must be between 0 and 30")

    options = ImportOptions(
        create_assets=create_assets, dry_run=dry_run, close_missing=close_missing,
        min_severity=min_severity, new_asset_criticality=new_asset_criticality,
        new_asset_exposure=new_asset_exposure, target_asset=target_asset,
        engagement_id=engagement_id, test_id=test_id, reuse_test=reuse_test,
        close_absent=close_absent, absence_threshold=absence_threshold,
        version=version, branch_tag=branch_tag, commit_hash=commit_hash,
        build_id=build_id, import_inventory=import_inventory,
        inventory_from_plugin_output=inventory_from_plugin_output,
    )
    run = importers.run_import(
        session, principal.organization_id, payload, source=source,
        filename=file.filename or "", options=options, actor_id=principal.user_id,
    )
    audit.record(session, action="import.run", object_type="import_run",
                 object_id=run.id, object_label=run.filename,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"source": run.source, "status": run.status,
                          "created": run.findings_created,
                          "rejected": run.records_rejected,
                          "closed_absent": run.findings_closed_absent,
                          "inventory_added": run.inventory_added,
                          "test_id": str(run.test_id) if run.test_id else None,
                          "dedupe_algorithm": run.dedupe_algorithm})
    if options.dry_run:
        # A preview must leave nothing behind except its own audit record.
        session.rollback()
        run_copy = ImportRunOut.model_validate(run)
        return run_copy
    session.commit()
    return ImportRunOut.model_validate(run)


@router.get("/imports", response_model=Page[ImportRunOut])
def list_imports(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
    source: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[ImportRunOut]:
    statement = select(ImportRun).where(
        ImportRun.organization_id == principal.organization_id
    )
    if source:
        statement = statement.where(ImportRun.source == source)
    total = session.execute(
        select(func.count()).select_from(statement.subquery())
    ).scalar_one()
    rows = session.execute(
        statement.order_by(ImportRun.started_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[ImportRunOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.get("/imports/{run_id}", response_model=ImportRunOut)
def read_import(
    run_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> ImportRunOut:
    run = session.get(ImportRun, run_id)
    if run is None or run.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "import run not found")
    return ImportRunOut.model_validate(run)


# ---------------------------------------------------------------------------
# ITSM connectors
# ---------------------------------------------------------------------------
@router.get("/connectors", response_model=list[ConnectorOut])
def list_connectors(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
    purpose: str | None = Query(None, pattern="^(ticketing|documentation)$"),
) -> list[ConnectorOut]:
    stmt = (
        select(ItsmConnector)
        .where(ItsmConnector.organization_id == principal.organization_id)
        .order_by(ItsmConnector.slug)
    )
    if purpose == "documentation":
        stmt = stmt.where(ItsmConnector.system.in_(tuple(docs.DOCS_SYSTEMS)))
    elif purpose == "ticketing":
        stmt = stmt.where(ItsmConnector.system.notin_(tuple(docs.DOCS_SYSTEMS)))
    rows = session.execute(stmt).scalars().all()
    # `credentials_enc` is absent from ConnectorOut by construction, not by
    # filtering: there is no field to accidentally re-add.
    return [_connector_out(r) for r in rows]


@router.post("/connectors", response_model=ConnectorOut, status_code=201)
def create_connector(
    payload: ConnectorWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> ConnectorOut:
    known = set(itsm.ADAPTERS) | set(docs.DOCS_ADAPTERS)
    if payload.system not in known:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"system must be one of {sorted(known)}")
    exists = session.execute(
        select(ItsmConnector).where(
            ItsmConnector.organization_id == principal.organization_id,
            ItsmConnector.slug == payload.slug)
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"connector {payload.slug!r} already exists")

    connector = ItsmConnector(
        organization_id=principal.organization_id,
        # An EMPTY dict is not a credential. Storing `encrypt("{}")` made
        # `credentials_set` answer True for a connector that has none, and made
        # the "you never saved a token" diagnosis unreachable.
        credentials_enc=(encrypt(json.dumps(payload.credentials))
                         if payload.credentials else None),
        **payload.model_dump(exclude={"credentials"}),
    )
    session.add(connector)
    session.flush()
    audit.record(session, action="itsm.connector.created", object_type="itsm_connector",
                 object_id=connector.id, object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"system": connector.system, "base_url": connector.base_url})
    session.commit()
    return _connector_out(connector)


@router.patch("/connectors/{connector_id}", response_model=ConnectorOut)
def update_connector(
    connector_id: uuid.UUID,
    payload: ConnectorPatch,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> ConnectorOut:
    """Edit a connector in place, including rotating its credential.

    Without this, changing a base URL or replacing an expired API token meant
    deleting the connector -- which cascades `external_links` and throws away
    every recorded correspondence between a VEYRS ticket and its remote twin.
    Rotating a token should not lose the audit trail.
    """
    connector = _connector(session, principal, connector_id)

    # Validated BEFORE anything is mutated, so a refusal leaves the row alone.
    wants_inbound = (connector.inbound_enabled if payload.inbound_enabled is None
                     else payload.inbound_enabled)
    if wants_inbound and not connector.inbound_secret_enc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "inbound cannot be enabled before its signing secret exists: "
            f"POST /integrations/connectors/{connector_id}/inbound-secret first",
        )

    changes: dict[str, Any] = {}
    for key, value in payload.model_dump(exclude_unset=True,
                                         exclude={"credentials"}).items():
        if value is None:
            continue
        if getattr(connector, key) != value:
            changes[key] = value
        setattr(connector, key, value)
    if payload.credentials is not None:
        # Same rule on the rotate path: `credentials: {}` explicitly CLEARS
        # the stored secret rather than storing an empty one. Omitting the key
        # still keeps what is there -- the console's edit form relies on it.
        connector.credentials_enc = (encrypt(json.dumps(payload.credentials))
                                     if payload.credentials else None)
        # THAT it was replaced belongs in the audit trail. The value does not.
        changes["credentials"] = "rotated"

    if not changes:
        return _connector_out(connector)
    audit.record(session, action="itsm.connector.updated",
                 object_type="itsm_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes=changes)
    session.commit()
    return _connector_out(connector)


@router.post("/connectors/{connector_id}/test")
def test_connector(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> dict[str, Any]:
    """Per-step diagnosis of a connector. See services.itsm.test_connector.

    `ticket:admin` rather than `ticket:read` because the response names the
    base URL, the service account and the project -- the same reasoning that
    puts `GET /ldap` behind `settings:admin`.
    """
    connector = _connector(session, principal, connector_id)
    # Dispatched on the connector's own system rather than on a second route.
    # One Test button that knows what it is testing beats two buttons the
    # operator has to choose between correctly.
    result = (docs.test_connector(session, connector)
              if connector.system in docs.DOCS_SYSTEMS
              else itsm.test_connector(session, connector))
    session.commit()
    return result


@router.post("/connectors/{connector_id}/pull")
def pull_connector(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Refresh the remote status of this connector's links.

    `pull_status()` has existed since the ITSM leg shipped and NO route ever
    called it, so the only way to learn that an engineer had closed a Jira
    issue was the inbound webhook -- which requires the remote system to be
    able to REACH VEYRS. A Jira Cloud tenant cannot call into a console that
    is not published on the internet, so for those deployments this is the
    only monitoring leg there is.

    Unchanged safety property: this writes `ExternalLink.remote_status` and
    nothing else. A remote closure is evidence about the work, not proof the
    finding is fixed; moving a VEYRS ticket stays an `inbound_transitions`
    decision the operator has to opt into.

    Bounded, and it reports what it did not reach. Least-recently-pulled
    first, so calling it repeatedly sweeps the whole set instead of re-reading
    the same page -- a silent top-N here would read as "everything is current".
    """
    connector = _connector(session, principal, connector_id)
    query = (
        select(ExternalLink)
        .where(ExternalLink.organization_id == principal.organization_id,
               ExternalLink.connector_id == connector.id,
               ExternalLink.is_active.is_(True))
        .order_by(nulls_first(ExternalLink.last_pulled_at.asc()))
    )
    total = session.execute(
        select(func.count()).select_from(query.subquery())
    ).scalar_one()
    links = list(session.execute(query.limit(limit)).scalars().all())

    changed: list[dict[str, Any]] = []
    refreshed = failed = 0
    for link in links:
        before = link.remote_status
        try:
            after = itsm.pull_status(session, connector, link)
        except itsm.ItsmError as exc:
            link.last_error = str(exc)[:500]
            failed += 1
            continue
        link.last_error = None
        refreshed += 1
        if after != before:
            changed.append({"remote_key": link.remote_key or link.remote_id,
                            "remote_url": link.remote_url,
                            "from": before, "to": after})
    connector.last_error = (f"{failed} of {len(links)} links failed to refresh"
                            if failed else None)
    session.commit()
    return {"links_total": total, "attempted": len(links), "refreshed": refreshed,
            "failed": failed, "not_attempted": max(0, total - len(links)),
            "changed": changed}


@router.delete("/connectors/{connector_id}", status_code=204, response_model=None,
               response_class=Response)
def delete_connector(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> None:
    connector = _connector(session, principal, connector_id)
    audit.record(session, action="itsm.connector.deleted", object_type="itsm_connector",
                 object_id=connector.id, object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.delete(connector)
    session.commit()


@router.post("/connectors/{connector_id}/push/{ticket_id}")
def push_ticket(
    connector_id: uuid.UUID,
    ticket_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> dict[str, Any]:
    connector = _connector(session, principal, connector_id)
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ticket not found")
    try:
        link = itsm.push_ticket(session, connector, ticket)
    except itsm.ItsmError as exc:
        session.commit()  # keep the recorded last_error
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    audit.record(session, action="itsm.ticket.pushed", object_type="ticket",
                 object_id=ticket.id, object_label=ticket.reference,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"connector": connector.slug, "remote_id": link.remote_id})
    session.commit()
    return {"remote_id": link.remote_id, "remote_key": link.remote_key,
            "remote_url": link.remote_url, "remote_status": link.remote_status,
            "last_pushed_at": link.last_pushed_at.isoformat()
                              if link.last_pushed_at else None}


@router.get("/tickets/{ticket_id}/links")
def ticket_links(
    ticket_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
) -> list[dict[str, Any]]:
    ticket = session.get(Ticket, ticket_id)
    if ticket is None or ticket.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ticket not found")
    return [
        {"connector_id": str(link.connector_id), "remote_id": link.remote_id,
         "remote_key": link.remote_key, "remote_url": link.remote_url,
         "remote_status": link.remote_status, "last_error": link.last_error}
        for link in itsm.links_for_ticket(session, ticket)
    ]


def _connector(session, principal: Principal, connector_id: uuid.UUID) -> ItsmConnector:
    connector = session.get(ItsmConnector, connector_id)
    if connector is None or connector.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connector not found")
    return connector


# ---------------------------------------------------------------------------
# ITSM inbound (the remote system pushing back)
#
# `push_ticket` + `pull_status` gave VEYRS an outbound leg and a polling leg.
# Polling answers "did the engineer close this?" minutes late and costs a
# request per link per cycle. These two routes are the push-back.
#
# The safety property, unchanged from `itsm.pull_status`: a remote system does
# not get to close a security finding. An inbound event is ADVISORY unless the
# operator configured `inbound_transitions`, and even then it goes through the
# ticket state machine. See services/itsm_inbound.py.
# ---------------------------------------------------------------------------
@router.post("/connectors/{connector_id}/inbound-secret")
def rotate_inbound_secret(
    connector_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:admin"))],
) -> dict[str, Any]:
    """Mint the HMAC secret the remote system will sign with. Shown once."""
    connector = _connector(session, principal, connector_id)
    secret = secrets.token_urlsafe(40)
    connector.inbound_secret_enc = encrypt(secret)
    organization = session.get(Organization, principal.organization_id)
    audit.record(session, action="itsm.inbound_secret.rotated",
                 object_type="itsm_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.commit()
    path = f"/api/v1/integrations/itsm/{organization.slug}/{connector.slug}/inbound"
    return {
        "secret": secret,
        "webhook_url": str(request.base_url).rstrip("/") + path,
        "signature_header": "X-VEYRS-Signature",
        "timestamp_header": "X-VEYRS-Timestamp",
        "algorithm": "hmac-sha256 over '<timestamp>.' + raw body, hex, prefixed 'sha256='",
        "replay_window_seconds": itsm_inbound.REPLAY_WINDOW_SECONDS,
    }


@router.post("/itsm/{organization_slug}/{connector_slug}/inbound",
             include_in_schema=True, summary="Signed webhook from an ITSM system")
async def itsm_webhook(
    organization_slug: str,
    connector_slug: str,
    request: Request,
    session: Annotated[Any, Depends(get_session)],
    x_veyrs_signature: Annotated[str | None, Header(alias="X-VEYRS-Signature")] = None,
    x_veyrs_timestamp: Annotated[str | None, Header(alias="X-VEYRS-Timestamp")] = None,
) -> dict[str, Any]:
    """Apply one signed remote change.

    No user credential is involved: the HMAC proves the sender, and the tenant
    comes from the path rather than from anything the sender asserts in the
    body. That ordering matters - resolving the tenant from the payload would
    let a signed message for one connector be replayed against another.

    Every failure answers the same shape and, for anything before the signature
    verifies, the same 404/401 regardless of whether the org, the connector or
    the signature was wrong. A webhook endpoint that distinguishes them is an
    enumeration oracle for tenant slugs.
    """
    organization = session.execute(
        select(Organization).where(Organization.slug == organization_slug.lower())
    ).scalars().first()
    if organization is None or not organization.is_active:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown webhook endpoint")
    set_tenant(session, organization.id)

    connector = session.execute(
        select(ItsmConnector).where(
            ItsmConnector.organization_id == organization.id,
            ItsmConnector.slug == connector_slug,
        )
    ).scalars().first()
    if connector is None or not connector.inbound_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown webhook endpoint")

    body = await request.body()
    try:
        itsm_inbound.verify_signature(
            connector, body=body, signature=x_veyrs_signature,
            timestamp=x_veyrs_timestamp,
        )
    except itsm_inbound.SignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    except itsm_inbound.InboundError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    try:
        event = itsm_inbound.parse_inbound(connector, body)
        outcome = itsm_inbound.handle_inbound(session, connector, event)
    except itsm_inbound.InboundError as exc:
        # The sender is authenticated from here on, so it gets a real reason:
        # a misconfigured business rule is fixed by reading the error.
        connector.last_error = str(exc)[:500]
        session.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    audit.record(session, action="itsm.inbound", object_type="itsm_connector",
                 object_id=connector.id, object_label=connector.slug,
                 organization_id=organization.id,
                 actor_label=f"{connector.system}:webhook",
                 changes=outcome)
    session.commit()
    return outcome


# ---------------------------------------------------------------------------
# Scanner connectors (pull)
# ---------------------------------------------------------------------------
# The push path above receives a file. These routes go and fetch one. They sit
# in this router, and therefore inherit `integrations` being in
# `security.scope.REFUSED_TAGS`: enrolling a scanner is an estate-wide act, and
# a team-scoped identity is refused rather than served a narrowed version.
#
# Permissions reuse the existing `importer:*` resource rather than inventing a
# `scanner:*` one. Pulling an export IS an import; a separate resource would
# have to be added to every built-in role, and the first role someone forgot
# would silently lose the ability to do something it already could.
class ScannerConnectorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    driver: str
    base_url: str | None
    is_enabled: bool
    verify_tls: bool
    allowed_scans: list
    engagement_id: uuid.UUID | None
    create_assets: bool
    close_absent: bool
    absence_threshold: int
    min_severity: str | None
    import_inventory: bool
    inventory_from_plugin_output: bool
    last_sync_at: dt.datetime | None
    last_error: str | None
    last_run_id: uuid.UUID | None
    #: True once credentials exist. As with ITSM connectors, the ciphertext has
    #: no field on this schema at all -- it cannot be re-added by accident.
    credentials_set: bool = False
    #: Reported so the console can say "inert" instead of drawing an enabled
    #: connector that will refuse every sync.
    is_inert: bool = False


class ScannerConnectorWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    driver: str
    base_url: str = Field(default="", max_length=600)
    credentials: dict[str, Any] = Field(default_factory=dict)
    #: Defaults to False. A connector is enrolled first and switched on second.
    is_enabled: bool = False
    verify_tls: bool = True
    allowed_scans: list[str] = Field(default_factory=list)
    engagement_id: uuid.UUID | None = None
    create_assets: bool = False
    close_absent: bool = False
    absence_threshold: int = Field(default=0, ge=0, le=30)
    min_severity: str | None = None
    #: True by default -- the connector exists to keep VEYRS fed, and the host
    #: inventory is already sitting in the export it downloads.
    import_inventory: bool = True
    inventory_from_plugin_output: bool = False


class ScannerConnectorPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, max_length=600)
    #: Omitted leaves the stored credentials untouched; an operator editing the
    #: allowed-scan list must not have to re-type a secret to do it.
    credentials: dict[str, Any] | None = None
    is_enabled: bool | None = None
    verify_tls: bool | None = None
    allowed_scans: list[str] | None = None
    engagement_id: uuid.UUID | None = None
    create_assets: bool | None = None
    close_absent: bool | None = None
    absence_threshold: int | None = Field(default=None, ge=0, le=30)
    min_severity: str | None = None
    import_inventory: bool | None = None
    inventory_from_plugin_output: bool | None = None


class ScannerSyncRequest(BaseModel):
    #: None = every allowed scan. A scan outside `allowed_scans` is rejected,
    #: never filtered out -- see services.scanners.sync().
    scan_ids: list[str] | None = None
    #: Re-import an export byte-identical to the last one.
    force: bool = False
    dry_run: bool = False


def _scanner_out(connector: ScannerConnector) -> ScannerConnectorOut:
    out = ScannerConnectorOut.model_validate(connector)
    out.credentials_set = bool(connector.credentials_enc)
    out.is_inert = not connector.allowed_scans
    return out


def _scanner(session, principal: Principal, connector_id: uuid.UUID) -> ScannerConnector:
    connector = session.get(ScannerConnector, connector_id)
    if connector is None or connector.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scanner connector not found")
    return connector


@router.get("/scanner-drivers")
def list_scanner_drivers(
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> dict[str, Any]:
    return {
        "drivers": scanners.describe_drivers(),
        "notes": (
            "A pulled export is parsed by the same parser as an uploaded one, "
            "so a connector cannot introduce a second deduplication rule. A "
            "connector with no allowed scans is inert, and close_absent "
            "requires an engagement."
        ),
    }


@router.get("/scanners", response_model=list[ScannerConnectorOut])
def list_scanner_connectors(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> list[ScannerConnectorOut]:
    rows = session.execute(
        select(ScannerConnector)
        .where(ScannerConnector.organization_id == principal.organization_id)
        .order_by(ScannerConnector.slug)
    ).scalars().all()
    return [_scanner_out(r) for r in rows]


@router.post("/scanners", response_model=ScannerConnectorOut, status_code=201)
def create_scanner_connector(
    payload: ScannerConnectorWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> ScannerConnectorOut:
    if payload.driver not in scanners.DRIVERS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"driver must be one of {sorted(scanners.DRIVERS)}")
    if payload.min_severity and payload.min_severity not in SEVERITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"min_severity must be one of {list(SEVERITIES)}")
    if payload.close_absent and payload.engagement_id is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "close_absent requires an engagement: absence-based closure outside "
            "a scope marks hosts the scan never looked at as remediated",
        )
    default_base = getattr(scanners.DRIVERS[payload.driver], "default_base_url", "")
    if not payload.base_url.strip() and not default_base:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "base_url is required for this driver")
    exists = session.execute(
        select(ScannerConnector).where(
            ScannerConnector.organization_id == principal.organization_id,
            ScannerConnector.slug == payload.slug)
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"scanner connector {payload.slug!r} already exists")

    connector = ScannerConnector(
        organization_id=principal.organization_id,
        credentials_enc=encrypt(json.dumps(payload.credentials))
                        if payload.credentials else None,
        **payload.model_dump(exclude={"credentials"}),
    )
    session.add(connector)
    session.flush()
    audit.record(session, action="scanner.connector.created",
                 object_type="scanner_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"driver": connector.driver, "base_url": connector.base_url,
                          "is_enabled": connector.is_enabled,
                          "allowed_scans": connector.allowed_scans})
    session.commit()
    return _scanner_out(connector)


@router.patch("/scanners/{connector_id}", response_model=ScannerConnectorOut)
def update_scanner_connector(
    connector_id: uuid.UUID,
    payload: ScannerConnectorPatch,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> ScannerConnectorOut:
    connector = _scanner(session, principal, connector_id)
    fields = payload.model_dump(exclude_unset=True)
    credentials = fields.pop("credentials", None)

    if fields.get("min_severity") and fields["min_severity"] not in SEVERITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"min_severity must be one of {list(SEVERITIES)}")
    for field, value in fields.items():
        setattr(connector, field, value)
    # Validated against the RESULTING row, not against the patch: enabling
    # close_absent in one request and clearing the engagement in the next would
    # otherwise slip past a check that only reads what changed.
    if connector.close_absent and connector.engagement_id is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "close_absent requires an engagement",
        )
    if credentials is not None:
        connector.credentials_enc = (encrypt(json.dumps(credentials))
                                     if credentials else None)
    session.flush()
    audit.record(session, action="scanner.connector.updated",
                 object_type="scanner_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={**{k: str(v) for k, v in fields.items()},
                          "credentials": "rotated" if credentials is not None else None})
    session.commit()
    return _scanner_out(connector)


@router.delete("/scanners/{connector_id}", status_code=204, response_model=None,
               response_class=Response)
def delete_scanner_connector(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> None:
    connector = _scanner(session, principal, connector_id)
    audit.record(session, action="scanner.connector.deleted",
                 object_type="scanner_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.delete(connector)
    session.commit()


@router.get("/scanners/{connector_id}/scans")
def list_scanner_scans(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:read"))],
) -> dict[str, Any]:
    """What the remote console holds. Read-only, and it writes no finding.

    Deliberately available without `importer:admin`: choosing which scans a
    connector may pull is the decision that bounds every later sync, and an
    operator who cannot see the list would be picking ids out of the air.
    """
    connector = _scanner(session, principal, connector_id)
    try:
        remote = scanners.list_remote_scans(connector)
    except scanners.ScannerError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    allowed = set(connector.allowed_scans or [])
    return {
        "connector": connector.slug,
        "scans": [{**s.as_dict(), "allowed": s.id in allowed} for s in remote],
        "allowed_scans": sorted(allowed),
    }


@router.post("/scanners/{connector_id}/test")
def test_scanner_connector(
    connector_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:admin"))],
) -> dict[str, Any]:
    """Prove the credentials work, without importing anything.

    The result is persisted to `last_error` even on success (as a clear), so
    the connector list reflects the last thing that actually happened rather
    than the last thing an operator remembers doing.
    """
    connector = _scanner(session, principal, connector_id)
    try:
        remote = scanners.list_remote_scans(connector)
    except scanners.ScannerError as exc:
        connector.last_error = str(exc)[:2000]
        session.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc
    connector.last_error = None
    audit.record(session, action="scanner.connector.tested",
                 object_type="scanner_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"scans_visible": len(remote)})
    session.commit()
    return {"ok": True, "scans_visible": len(remote),
            "driver": connector.driver,
            "inert": not connector.allowed_scans}


@router.post("/scanners/{connector_id}/sync")
def sync_scanner_connector(
    connector_id: uuid.UUID,
    payload: ScannerSyncRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("importer:write"))],
) -> dict[str, Any]:
    """Pull the allowed scans and ingest each one as its own ImportRun."""
    connector = _scanner(session, principal, connector_id)
    try:
        outcomes = scanners.sync(
            session, connector, actor_id=principal.user_id,
            scan_ids=payload.scan_ids, force=payload.force, dry_run=payload.dry_run,
        )
    except scanners.ScannerError as exc:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    audit.record(session, action="scanner.sync",
                 object_type="scanner_connector", object_id=connector.id,
                 object_label=connector.slug,
                 organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={"imported": sum(1 for o in outcomes if o.status == "imported"),
                          "skipped": sum(1 for o in outcomes if o.status == "skipped"),
                          "failed": sum(1 for o in outcomes if o.status == "failed"),
                          "dry_run": payload.dry_run})
    if payload.dry_run:
        # A preview leaves nothing behind but its audit record, exactly as the
        # upload path does.
        results = [o.as_dict() for o in outcomes]
        session.rollback()
        return {"connector": connector.slug, "dry_run": True, "results": results}
    session.commit()
    return {"connector": connector.slug, "dry_run": False,
            "results": [o.as_dict() for o in outcomes]}


# ---------------------------------------------------------------------------
# The relation (phase 45): external issue <-> finding, device, dates
# ---------------------------------------------------------------------------
def _link_out(session: Session, link: ExternalLink) -> dict[str, Any]:
    """One row of the screen that REPLACES the Tickets section in external mode.

    Every field an operator used to read off a VEYRS ticket -- what, where, how
    bad, by when, what state -- is answered from this row alone. It calls
    nothing remote: a list view that fans out one Jira request per row is a
    list view that times out at 200 findings and gets blamed on VEYRS.
    """
    asset = session.get(Asset, link.asset_id) if link.asset_id else None
    finding = session.get(Finding, link.finding_id) if link.finding_id else None
    connector = session.get(ItsmConnector, link.connector_id)
    return {
        "id": str(link.id),
        "object_type": link.object_type,
        "object_id": link.object_id,
        "system": connector.system if connector is not None else None,
        "connector_id": str(link.connector_id),
        "connector_name": connector.name if connector is not None else None,
        # --- the external issue
        "remote_id": link.remote_id,
        "remote_key": link.remote_key,
        "remote_url": link.remote_url,
        "remote_status": link.remote_status,
        "remote_priority": link.remote_priority,
        "remote_type": link.remote_type,
        "remote_assignee": link.remote_assignee,
        "remote_created_at": link.remote_created_at,
        "remote_updated_at": link.remote_updated_at,
        # --- what it is about
        "summary": link.summary,
        "cve_id": link.cve_id,
        "severity": link.severity,
        "risk_score": link.risk_score,
        "finding_id": str(link.finding_id) if link.finding_id else None,
        "vulnerability_id": str(link.vulnerability_id) if link.vulnerability_id else None,
        # --- the device
        "asset_id": str(link.asset_id) if link.asset_id else None,
        "asset_name": asset.name if asset is not None else None,
        "asset_environment": asset.environment if asset is not None else None,
        # --- the dates
        "due_at": link.due_at,
        "created_at": link.created_at,
        "last_pushed_at": link.last_pushed_at,
        "last_pulled_at": link.last_pulled_at,
        # --- honesty about the VEYRS side
        #: The finding's CURRENT state, next to the snapshot the issue was
        #: raised from. A finding that VEYRS has since verified as fixed while
        #: the Jira issue is still open is the single most useful disagreement
        #: this screen can show, and it only exists if both are printed.
        "finding_state": finding.state if finding is not None else None,
        "finding_severity": finding.severity if finding is not None else None,
        "is_active": link.is_active,
        "last_error": link.last_error,
    }


@router.get("/links", summary="External issues and what they are about")
def list_links(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:read"))],
    finding_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    connector_id: uuid.UUID | None = None,
    object_type: str | None = Query(None, pattern="^(ticket|finding)$"),
    remote_status: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    is_active: bool | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
) -> dict[str, Any]:
    """The list the console shows where Tickets used to be.

    Filtering happens in SQL and not in the browser, for the reason phase 31
    settled: a client-side overlay over one page of results silently answers a
    different question than the one the operator asked.
    """
    stmt = select(ExternalLink).where(
        ExternalLink.organization_id == principal.organization_id
    )
    if finding_id is not None:
        stmt = stmt.where(ExternalLink.finding_id == finding_id)
    if asset_id is not None:
        stmt = stmt.where(ExternalLink.asset_id == asset_id)
    if connector_id is not None:
        stmt = stmt.where(ExternalLink.connector_id == connector_id)
    if object_type:
        stmt = stmt.where(ExternalLink.object_type == object_type)
    if remote_status:
        stmt = stmt.where(ExternalLink.remote_status == remote_status)
    if severity:
        stmt = stmt.where(ExternalLink.severity == severity.lower())
    if is_active is not None:
        stmt = stmt.where(ExternalLink.is_active.is_(is_active))
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            ExternalLink.summary.ilike(needle),
            ExternalLink.remote_key.ilike(needle),
            ExternalLink.cve_id.ilike(needle),
        ))

    total = session.execute(
        select(func.count()).select_from(stmt.subquery())
    ).scalar_one()
    rows = session.execute(
        stmt.order_by(ExternalLink.created_at.desc())
        .offset((page - 1) * size).limit(size)
    ).scalars().all()
    return {
        "items": [_link_out(session, link) for link in rows],
        "total": total, "limit": size, "offset": (page - 1) * size, "page": page,
    }


@router.post("/links/{link_id}/refresh", summary="Re-read one issue's remote status")
def refresh_link(
    link_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> dict[str, Any]:
    """Never raises for a remote failure -- it records it on the row.

    A refresh button that 500s when Jira is down is a button that makes an
    outage look like a VEYRS bug. The error lands in `last_error`, where the
    list view already prints it.
    """
    link = session.get(ExternalLink, link_id)
    if link is None or link.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    connector = session.get(ItsmConnector, link.connector_id)
    if connector is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "connector not found")
    try:
        itsm.pull_status(session, connector, link)
        link.last_error = None
    except itsm.ItsmError as exc:
        link.last_error = str(exc)[:500]
    except Exception as exc:  # noqa: BLE001
        link.last_error = f"unexpected {exc.__class__.__name__}"
    session.commit()
    session.refresh(link)
    return _link_out(session, link)


@router.post("/links/{link_id}/unlink", summary="Detach a relation without touching the remote")
def unlink_link(
    link_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
) -> dict[str, Any]:
    """Marks the relation inactive. It does NOT close or delete the remote issue.

    VEYRS is the system of record for the finding, never for somebody else's
    queue -- deleting a Jira issue from a security console is a destructive act
    on a system whose other users did not consent to it. Unlinking frees the
    finding to be raised again, which is the only reason to press this.
    """
    link = session.get(ExternalLink, link_id)
    if link is None or link.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    link.is_active = False
    audit.record(
        session, organization_id=principal.organization_id,
        actor_id=principal.user_id, actor_label=principal.label,
        ip_address=(request.client.host if request.client else None),
        action="external_link.unlinked", object_type="external_link",
        object_id=str(link.id), object_label=link.remote_key or link.remote_id,
        changes={"is_active": [True, False]},
    )
    session.commit()
    session.refresh(link)
    return _link_out(session, link)
