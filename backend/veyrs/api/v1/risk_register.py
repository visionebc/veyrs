"""Risk register API: risks that are not findings, and who answers for them.

Tagged `risk register`, which `security/scope.py` classifies as SCOPED: a
team-restricted identity reads the entries its teams (or it personally) hold a
seat on, and **is refused every write**. The register is an estate-level record
-- one team quietly adding or closing organisation-wide risks is the failure
this refusal exists to prevent -- while the read must still work, because the
whole point of RACI is that the person named can see what they were named on.

Every write also passes `risk_register_mode.require_enabled`. Hiding the section
in the console while the API keeps accepting writes is the defect class
`services/scanning` and `services/ticketing_mode` were written around, and it
would land here the same way: an operator turns the register off, an automation
keeps filling it, and the rows are discovered a year later in an audit.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import nulls_last, or_, select

from ...models.risk_register import (
    PARTY_TYPES,
    RACI_LABELS,
    RACI_ROLES,
    RISK_BANDS,
    RISK_CATEGORIES,
    RISK_LINK_TYPES,
    RISK_SOURCES,
    RISK_STATUSES,
    RISK_TREATMENTS,
    OPEN_RISK_STATUSES,
    RiskEntry,
    RiskLink,
    risk_band,
)
from ...models.tenancy import Team, TeamMember
from ...security import scope as team_scope
from ...security.deps import Principal, TenantSession, require
from ...services import audit
from ...services import risk_register as service
from ...services import risk_register_mode as mode
from .schemas import Page

router = APIRouter(prefix="/risks", tags=["risk register"])


# --- payloads -------------------------------------------------------------


class RaciSeat(BaseModel):
    """One seat. A team, or a person -- optionally a person *inside* a team."""

    raci: str = Field(..., description=", ".join(f"{k} = {v}" for k, v in RACI_LABELS.items()))
    party_type: str = Field(..., description="|".join(PARTY_TYPES))
    team_id: uuid.UUID | None = None
    user_id: uuid.UUID | None = None
    note: str | None = Field(default=None, max_length=400)


class RiskWrite(BaseModel):
    #: Same `forbid` as RiskPatch, for the same reason.
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=300)
    description: str | None = None
    category: str | None = Field(default=None, max_length=60)
    source: str | None = Field(default=None, max_length=40)
    status: str = "identified"
    treatment: str = "pending"
    treatment_plan: str | None = None
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    residual_likelihood: int | None = Field(default=None, ge=1, le=5)
    residual_impact: int | None = Field(default=None, ge=1, le=5)
    identified_at: dt.date | None = None
    review_due_at: dt.date | None = None
    closure_note: str | None = None
    tags: list[str] = Field(default_factory=list)
    external_ref: str | None = Field(default=None, max_length=300)
    #: Set the matrix in the same call that creates the risk. A register entry
    #: created with nobody accountable is the row that sits untouched for a
    #: year, so the console always sends this -- but it is not mandatory here:
    #: refusing to store a risk somebody just identified because they do not yet
    #: know who owns it is how risks stay in spreadsheets.
    raci: list[RaciSeat] = Field(default_factory=list)


class RiskPatch(BaseModel):
    """Every field optional, and an unknown one is a 422 rather than a no-op.

    `extra="forbid"` is the half that matters. Pydantic's default is to DROP an
    undeclared key, so `{"score": 3}` would answer 200 with the score unchanged
    -- a caller that believes it set a value the platform derives, and no error
    anywhere to find later. `score`, `residual_score`, `code`, `closed_at` and
    the `*_by_id` columns are all platform-written, so all of them land here.
    """

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=300)
    description: str | None = None
    category: str | None = Field(default=None, max_length=60)
    source: str | None = Field(default=None, max_length=40)
    status: str | None = None
    treatment: str | None = None
    treatment_plan: str | None = None
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    residual_likelihood: int | None = Field(default=None, ge=1, le=5)
    residual_impact: int | None = Field(default=None, ge=1, le=5)
    identified_at: dt.date | None = None
    review_due_at: dt.date | None = None
    closure_note: str | None = None
    tags: list[str] | None = None
    external_ref: str | None = Field(default=None, max_length=300)


class RaciWrite(BaseModel):
    """The WHOLE matrix, replaced in one call. See `services.risk_register.set_raci`."""

    raci: list[RaciSeat] = Field(default_factory=list)


class LinkWrite(BaseModel):
    object_type: str = Field(..., description="|".join(RISK_LINK_TYPES))
    object_id: uuid.UUID
    note: str | None = Field(default=None, max_length=400)


# --- helpers --------------------------------------------------------------


def _actor(request: Request, principal: Principal) -> dict:
    ip = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": ip,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


def _guard_write(session, principal: Principal, what: str) -> None:
    """The two refusals every write shares, in the order that reads best."""
    team_scope.refuse_if_restricted(
        principal.scope,
        "the risk register records organization-level risk and cannot be "
        f"written by a team-scoped identity; {what} requires an estate-wide "
        "role grant. You can still read the risks your teams are named on",
    )
    try:
        mode.require_enabled(session, principal.organization_id, what)
    except mode.RiskRegisterDisabled as exc:
        # 409 and not 403: the caller holds the permission; the tenant is in a
        # state where the request does not apply. A 403 sends somebody hunting
        # for a role that is not missing.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


def _visible_ids(session, principal: Principal) -> set[uuid.UUID] | None:
    """None = the whole register. A set = exactly what a scoped identity sees."""
    if not principal.scope.restricted:
        return None
    return service.for_party(
        session, principal.organization_id,
        user_id=principal.user_id, team_ids=principal.scope.team_ids,
    )


def _fetch(session, principal: Principal, risk_id: uuid.UUID) -> RiskEntry:
    risk = service.get(session, principal.organization_id, risk_id)
    if risk is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such risk")
    visible = _visible_ids(session, principal)
    if visible is not None and risk.id not in visible:
        # 404, not 403: confirming "this risk exists but is somebody else's"
        # answers a question a scoped identity did not need answered.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such risk")
    return risk


def _bad_request(exc: service.RiskRegisterError) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


# --- vocabulary and summary ----------------------------------------------
# Declared BEFORE `/{risk_id}`: FastAPI matches in declaration order, and a
# literal path registered after a UUID parameter is unreachable.


@router.get("/meta", summary="Vocabularies the register uses")
def meta(
    principal: Annotated[Principal, Depends(require("riskregister:read"))],
    session: TenantSession,
) -> dict:
    """Served rather than hardcoded in the console.

    A picker built from a copy of these tuples goes stale the day one gains a
    value, and the symptom is an option that exists in the API and cannot be
    chosen anywhere.
    """
    return {
        "statuses": list(RISK_STATUSES),
        "open_statuses": list(OPEN_RISK_STATUSES),
        "treatments": list(RISK_TREATMENTS),
        "categories": list(RISK_CATEGORIES),
        "sources": list(RISK_SOURCES),
        "bands": list(RISK_BANDS),
        "raci": [{"key": k, "label": v} for k, v in RACI_LABELS.items()],
        "party_types": list(PARTY_TYPES),
        "link_types": list(RISK_LINK_TYPES),
        "enabled": mode.is_enabled(session, principal.organization_id),
        #: So the console can render the 5x5 heat map without inventing its own
        #: thresholds -- two different band boundaries is two different registers.
        "band_of": {str(n): risk_band(n) for n in range(1, 26)},
    }


@router.get("/summary", summary="Counts for the register header")
def summary(
    principal: Annotated[Principal, Depends(require("riskregister:read"))],
    session: TenantSession,
) -> dict:
    out = service.summary(session, principal.organization_id)
    out["enabled"] = mode.is_enabled(session, principal.organization_id)
    return out


# --- list / read ----------------------------------------------------------


@router.get("", response_model=Page[dict], summary="The risk register")
def list_risks(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:read"))],
    q: str | None = Query(default=None, description="substring of code or title"),
    status_: str | None = Query(default=None, alias="status"),
    band: str | None = None,
    category: str | None = None,
    treatment: str | None = None,
    tag: str | None = None,
    open_only: bool = False,
    review_overdue: bool = False,
    unassigned: bool = Query(default=False, description="open risks with no Accountable"),
    mine: bool = Query(default=False, description="risks I or my teams hold a seat on"),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[dict]:
    stmt = select(RiskEntry).where(
        RiskEntry.organization_id == principal.organization_id,
        RiskEntry.deleted_at.is_(None),
    )
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(RiskEntry.title.ilike(like), RiskEntry.code.ilike(like)))
    if status_:
        stmt = stmt.where(RiskEntry.status == status_.strip().lower())
    if category:
        stmt = stmt.where(RiskEntry.category == category.strip())
    if treatment:
        stmt = stmt.where(RiskEntry.treatment == treatment.strip().lower())
    if tag:
        stmt = stmt.where(RiskEntry.tags.contains([tag]))
    if open_only:
        stmt = stmt.where(RiskEntry.status.in_(tuple(OPEN_RISK_STATUSES)))

    rows = list(session.execute(
        # Highest inherent score first, then oldest review date: the two orders
        # an operator opening this screen is actually looking for. NULLs last so
        # an unscored risk does not sit at the top pretending to be the worst.
        stmt.order_by(nulls_last(RiskEntry.score.desc()), RiskEntry.code)
    ).scalars().all())

    visible = _visible_ids(session, principal)
    if visible is not None:
        rows = [r for r in rows if r.id in visible]
    if mine:
        teams_of_me = []
        if principal.user_id:
            teams_of_me = list(session.execute(
                select(TeamMember.team_id).where(TeamMember.user_id == principal.user_id)
            ).scalars().all())
        seats = service.for_party(session, principal.organization_id,
                                  user_id=principal.user_id, team_ids=teams_of_me)
        rows = [r for r in rows if r.id in seats]

    # Filters computed from derived values are applied after the query rather
    # than in SQL: `band` and "has an Accountable" are properties of the object,
    # and duplicating their definition in a WHERE clause is how the list stops
    # agreeing with the detail page.
    teams, users = service.party_labels(session, principal.organization_id)
    items = [service.as_dict(session, r, teams=teams, users=users) for r in rows]
    if band:
        items = [i for i in items if i["band"] == band.strip().lower()]
    if review_overdue:
        items = [i for i in items if i["review_overdue"]]
    if unassigned:
        items = [i for i in items if i["is_open"] and not i["accountable"]]

    start = (page - 1) * size
    return Page.of(items[start:start + size], len(items), page, size)


@router.get("/{risk_id}", summary="One risk, with its RACI, links and history")
def get_risk(
    risk_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:read"))],
) -> dict:
    risk = _fetch(session, principal, risk_id)
    return service.as_dict(session, risk, with_detail=True)


# --- write ----------------------------------------------------------------


@router.post("", status_code=status.HTTP_201_CREATED, summary="Add a risk")
def create_risk(
    payload: RiskWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:write"))],
) -> dict:
    _guard_write(session, principal, "adding a risk")
    data = payload.model_dump(exclude={"raci"}, exclude_unset=True)
    try:
        risk = service.create(session, principal.organization_id, data,
                              actor_id=principal.user_id, actor_label=principal.label)
        if payload.raci:
            service.set_raci(session, risk,
                             [s.model_dump() for s in payload.raci],
                             actor_id=principal.user_id, actor_label=principal.label)
    except service.RiskRegisterError as exc:
        raise _bad_request(exc) from exc
    audit.record(session, action="risk_register.create", object_type="risk",
                 object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                 changes={"status": risk.status, "score": risk.score},
                 **_actor(request, principal))
    session.commit()
    return service.as_dict(session, risk, with_detail=True)


@router.patch("/{risk_id}", summary="Update a risk")
def patch_risk(
    risk_id: uuid.UUID,
    payload: RiskPatch,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:write"))],
) -> dict:
    _guard_write(session, principal, "changing a risk")
    risk = _fetch(session, principal, risk_id)
    try:
        changes = service.update(session, risk, payload.model_dump(exclude_unset=True),
                                 actor_id=principal.user_id, actor_label=principal.label)
    except service.RiskRegisterError as exc:
        raise _bad_request(exc) from exc
    if changes:
        audit.record(session, action="risk_register.update", object_type="risk",
                     object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                     changes=changes, **_actor(request, principal))
    session.commit()
    return service.as_dict(session, risk, with_detail=True)


@router.put("/{risk_id}/raci", summary="Set who is Responsible, Accountable, Consulted, Informed")
def set_raci(
    risk_id: uuid.UUID,
    payload: RaciWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:write"))],
) -> dict:
    """Replaces the whole matrix.

    One call, because a RACI is read as a single statement: swapping the
    Accountable through two requests leaves a window in which the register says
    nobody is accountable, and a failure between them makes that window
    permanent.
    """
    _guard_write(session, principal, "changing a risk's RACI")
    risk = _fetch(session, principal, risk_id)
    before = service.summarise_raci(session, risk)
    try:
        service.set_raci(session, risk, [s.model_dump() for s in payload.raci],
                         actor_id=principal.user_id, actor_label=principal.label)
    except service.RiskRegisterError as exc:
        raise _bad_request(exc) from exc
    audit.record(session, action="risk_register.raci_changed", object_type="risk",
                 object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                 changes={"raci": [before, service.summarise_raci(session, risk)]},
                 **_actor(request, principal))
    session.commit()
    return service.as_dict(session, risk, with_detail=True)


@router.post("/{risk_id}/links", status_code=status.HTTP_201_CREATED,
             summary="Link this risk to an asset, finding, vulnerability or control")
def add_link(
    risk_id: uuid.UUID,
    payload: LinkWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:write"))],
) -> dict:
    """Optional and additive. A risk with no link at all is the ordinary case --
    that is the reason this module exists."""
    _guard_write(session, principal, "linking a risk")
    risk = _fetch(session, principal, risk_id)
    try:
        service.add_link(session, risk, payload.object_type, payload.object_id,
                         note=payload.note, actor_id=principal.user_id,
                         actor_label=principal.label)
    except service.RiskRegisterError as exc:
        raise _bad_request(exc) from exc
    audit.record(session, action="risk_register.linked", object_type="risk",
                 object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                 changes={"object_type": payload.object_type,
                          "object_id": str(payload.object_id)},
                 **_actor(request, principal))
    session.commit()
    return service.as_dict(session, risk, with_detail=True)


@router.delete("/{risk_id}/links/{link_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Remove a link")
def remove_link(
    risk_id: uuid.UUID,
    link_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:write"))],
) -> Response:
    _guard_write(session, principal, "unlinking a risk")
    risk = _fetch(session, principal, risk_id)
    link = session.execute(
        select(RiskLink).where(RiskLink.id == link_id, RiskLink.risk_id == risk.id)
    ).scalars().first()
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such link on this risk")
    service.remove_link(session, risk, link, actor_id=principal.user_id,
                        actor_label=principal.label)
    audit.record(session, action="risk_register.unlinked", object_type="risk",
                 object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                 changes={"link_id": str(link_id)}, **_actor(request, principal))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{risk_id}", status_code=status.HTTP_204_NO_CONTENT,
               summary="Remove a risk from the register")
def delete_risk(
    risk_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("riskregister:delete"))],
) -> Response:
    """SOFT delete, like assets and users.

    A risk that was on the register and is not any more is itself a fact an
    auditor asks about; a hard delete makes "was this ever raised?" unanswerable.
    Closing with a note is the ordinary way to retire a risk -- this is for the
    duplicate and the typo.
    """
    _guard_write(session, principal, "removing a risk")
    risk = _fetch(session, principal, risk_id)
    risk.deleted_at = dt.datetime.now(dt.timezone.utc)
    service.record_event(session, risk, "deleted", actor_id=principal.user_id,
                         actor_label=principal.label)
    audit.record(session, action="risk_register.delete", object_type="risk",
                 object_id=risk.id, object_label=f"{risk.code} {risk.title}"[:200],
                 changes={"deleted_at": risk.deleted_at.isoformat()},
                 **_actor(request, principal))
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
