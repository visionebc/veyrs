"""Domain service for the risk register. Every write goes through here.

The invariants live in this module rather than in the router because there are
already three callers in sight (the API, the console's bulk assign, and the
importer that will eventually read somebody's spreadsheet) and an invariant
enforced at one of three doors is not enforced.

What it refuses, and why each refusal exists:

* **Two Accountables.** Capped in the database by a partial unique index and
  here with a sentence that names the seat. RACI without a single A is a list.
* **A team as Accountable.** A team cannot be called into a room. R, C and I
  take teams happily.
* **A person seated under a team they do not belong to.** A matrix that names
  somebody under a team they left is worse than an empty one: it looks
  answered. Membership is checked, not trusted.
* **A party from another tenant.** RLS already makes that row invisible, so the
  lookup returns nothing and the caller gets a 422 that says which id was not
  found -- rather than a foreign key error five layers down.
* **Closing without a reason.** `closure_note` is required to reach `closed`.
  "Why is this risk no longer on the register" is the question an auditor asks
  first, and the answer is unrecoverable a year later.
* **A score the caller computed.** `score` and `residual_score` are derived from
  likelihood x impact here. A stored score that disagrees with its own factors
  is a number two people read differently.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.assets import Asset
from ..models.compliance import ComplianceControl
from ..models.risk_register import (
    OPEN_RISK_STATUSES,
    PARTY_TYPES,
    RACI_LABELS,
    RACI_ROLES,
    RISK_LINK_TYPES,
    RISK_STATUSES,
    RISK_TREATMENTS,
    RiskEntry,
    RiskEvent,
    RiskLink,
    RiskRaci,
    risk_band,
    risk_score,
)
from ..models.tenancy import Team, TeamMember, User
from ..models.ticketing import TicketCounter
from ..models.vulnerability import Finding, Vulnerability

#: Reference prefix. Allocated from `ticket_counters`, which is a per-tenant
#: named sequence with row locking that already exists and is already RLS
#: covered -- the table is named after its first caller, not after a constraint
#: on who may use it. A fifth table whose only column is an integer would be
#: more code and one more thing to keep isolated.
COUNTER_KEY = "risk_register"


class RiskRegisterError(ValueError):
    """A register write the caller can fix by changing the request."""


# --- references -----------------------------------------------------------


def next_code(session: Session, organization_id: uuid.UUID) -> str:
    counter = session.execute(
        select(TicketCounter).where(
            TicketCounter.organization_id == organization_id,
            TicketCounter.ticket_type == COUNTER_KEY,
        ).with_for_update()
    ).scalars().first()
    if counter is None:
        counter = TicketCounter(
            organization_id=organization_id, ticket_type=COUNTER_KEY, last_value=0
        )
        session.add(counter)
        session.flush()
    counter.last_value += 1
    session.flush()
    return f"RISK-{counter.last_value:06d}"


# --- validation helpers ---------------------------------------------------


def _level(value: Any, field: str) -> int | None:
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise RiskRegisterError(f"{field} must be a whole number from 1 to 5") from exc
    if not 1 <= number <= 5:
        raise RiskRegisterError(f"{field} must be from 1 (lowest) to 5 (highest); got {number}")
    return number


def _one_of(value: Any, allowed: tuple[str, ...], field: str) -> str:
    text = str(value or "").strip().lower()
    if text not in allowed:
        raise RiskRegisterError(
            f"{field} must be one of {', '.join(allowed)}; got {text!r}"
        )
    return text


def _apply_scores(risk: RiskEntry) -> None:
    """Derived, never accepted from the wire."""
    risk.score = risk_score(risk.likelihood, risk.impact)
    risk.residual_score = risk_score(risk.residual_likelihood, risk.residual_impact)


# --- events ---------------------------------------------------------------


def record_event(
    session: Session,
    risk: RiskEntry,
    event: str,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    details: dict | None = None,
    note: str | None = None,
) -> RiskEvent:
    row = RiskEvent(
        organization_id=risk.organization_id, risk_id=risk.id, event=event,
        actor_id=actor_id, actor_label=actor_label or "system",
        details=details or {}, note=note,
    )
    session.add(row)
    return row


# --- create / update ------------------------------------------------------

#: Everything a caller may set directly. `code`, `score`, `residual_score`,
#: `closed_at` and the `*_by_id` columns are deliberately absent: they are the
#: platform's to write, and accepting them from the wire is how a register ends
#: up with two entries called RISK-000004.
WRITABLE_FIELDS = (
    "title", "description", "category", "source", "status", "treatment",
    "treatment_plan", "likelihood", "impact", "residual_likelihood",
    "residual_impact", "identified_at", "review_due_at", "closure_note",
    "tags", "external_ref",
)


def _assign(risk: RiskEntry, data: dict[str, Any]) -> dict[str, Any]:
    """Validate and apply. Returns {field: [before, after]} for the changed ones."""
    changes: dict[str, Any] = {}
    for field in WRITABLE_FIELDS:
        if field not in data:
            continue
        value = data[field]
        if field in ("likelihood", "impact", "residual_likelihood", "residual_impact"):
            value = _level(value, field)
        elif field == "status":
            value = _one_of(value, RISK_STATUSES, "status")
        elif field == "treatment":
            value = _one_of(value, RISK_TREATMENTS, "treatment")
        elif field == "tags":
            value = sorted({str(t).strip() for t in (value or []) if str(t).strip()})
        elif isinstance(value, str):
            value = value.strip() or None
        before = getattr(risk, field)
        if before != value:
            changes[field] = [
                before.isoformat() if isinstance(before, (dt.date, dt.datetime)) else before,
                value.isoformat() if isinstance(value, (dt.date, dt.datetime)) else value,
            ]
            setattr(risk, field, value)

    if not (risk.title or "").strip():
        raise RiskRegisterError("a risk needs a title: name the thing that could go wrong")

    if risk.status == "closed":
        if not (risk.closure_note or "").strip():
            # Refused rather than closed with an empty note. See the module
            # docstring: this is the first question asked about a closed risk.
            raise RiskRegisterError(
                "closing a risk needs a closure note saying why it is no longer "
                "on the register (fixed, accepted, no longer applicable, ...)"
            )
        if risk.closed_at is None:
            risk.closed_at = dt.datetime.now(dt.timezone.utc)
    else:
        # Reopening clears the timestamp; leaving it behind produces a risk that
        # is open and was closed at the same time, which no report can render.
        risk.closed_at = None

    _apply_scores(risk)
    return changes


def create(
    session: Session,
    organization_id: uuid.UUID,
    data: dict[str, Any],
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
) -> RiskEntry:
    risk = RiskEntry(
        organization_id=organization_id,
        code=next_code(session, organization_id),
        title="",
        created_by_id=actor_id,
        updated_by_id=actor_id,
        identified_at=dt.date.today(),
    )
    _assign(risk, {**data})
    session.add(risk)
    session.flush()
    record_event(session, risk, "created", actor_id=actor_id, actor_label=actor_label,
                 details={"status": risk.status, "score": risk.score})
    return risk


def update(
    session: Session,
    risk: RiskEntry,
    data: dict[str, Any],
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
) -> dict[str, Any]:
    before_status = risk.status
    changes = _assign(risk, data)
    if changes:
        risk.updated_by_id = actor_id
        record_event(session, risk, "updated", actor_id=actor_id,
                     actor_label=actor_label, details=changes)
    if "status" in changes:
        record_event(
            session, risk, "status_changed", actor_id=actor_id, actor_label=actor_label,
            details={"from": before_status, "to": risk.status},
            note=risk.closure_note if risk.status == "closed" else None,
        )
    session.flush()
    return changes


# --- RACI -----------------------------------------------------------------


def _resolve_party(
    session: Session, organization_id: uuid.UUID, seat: dict[str, Any]
) -> dict[str, Any]:
    raci = str(seat.get("raci") or "").strip().upper()
    if raci not in RACI_ROLES:
        raise RiskRegisterError(
            f"raci must be one of {', '.join(RACI_ROLES)} "
            f"({', '.join(f'{k}={v}' for k, v in RACI_LABELS.items())}); got {raci!r}"
        )
    party_type = _one_of(seat.get("party_type"), PARTY_TYPES, "party_type")
    team_id = seat.get("team_id")
    user_id = seat.get("user_id")

    team = None
    if team_id:
        team = session.execute(
            select(Team).where(Team.id == uuid.UUID(str(team_id)),
                               Team.organization_id == organization_id)
        ).scalars().first()
        if team is None:
            raise RiskRegisterError(f"team {team_id} not found in this organization")

    if party_type == "team":
        if team is None:
            raise RiskRegisterError("a team seat needs team_id")
        if user_id:
            raise RiskRegisterError(
                "a seat names a team or a person, not both. To name a person "
                "inside a team, use party_type='user' with that team in team_id"
            )
        if raci == "A":
            # The invariant this module was written around.
            raise RiskRegisterError(
                "Accountable must be one named person, not a team: a team cannot "
                "be called into a room, and a seat everybody holds is a seat "
                "nobody holds. Name the individual; the team can be Responsible"
            )
        return {"raci": raci, "party_type": "team", "team_id": team.id, "user_id": None,
                "note": (seat.get("note") or None)}

    if not user_id:
        raise RiskRegisterError("a person seat needs user_id")
    user = session.execute(
        select(User).where(User.id == uuid.UUID(str(user_id)),
                           User.organization_id == organization_id,
                           User.deleted_at.is_(None))
    ).scalars().first()
    if user is None:
        raise RiskRegisterError(f"user {user_id} not found in this organization")
    if team is not None:
        member = session.execute(
            select(TeamMember.id).where(TeamMember.team_id == team.id,
                                        TeamMember.user_id == user.id)
        ).scalars().first()
        if member is None:
            # Checked, not trusted. See the module docstring.
            raise RiskRegisterError(
                f"{user.full_name or user.email} is not a member of {team.name}; "
                "add them to the team first, or leave team_id empty to name them "
                "directly"
            )
    return {"raci": raci, "party_type": "user",
            "team_id": team.id if team is not None else None, "user_id": user.id,
            "note": (seat.get("note") or None)}


def set_raci(
    session: Session,
    risk: RiskEntry,
    seats: Iterable[dict[str, Any]],
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
) -> list[RiskRaci]:
    """Replace the whole matrix in one call.

    Whole-matrix replacement rather than seat-by-seat editing because a RACI is
    read as one statement: a client that removed the Accountable and added the
    new one in two requests would leave a window where the register says nobody
    is accountable, and any failure between the two makes that window permanent.
    """
    resolved = [_resolve_party(session, risk.organization_id, dict(s)) for s in seats]

    accountable = [s for s in resolved if s["raci"] == "A"]
    if len(accountable) > 1:
        raise RiskRegisterError(
            "a risk has exactly one Accountable. Two people accountable for the "
            "same risk is the state RACI exists to prevent; the second belongs "
            "in Responsible or Consulted"
        )

    seen: set[tuple] = set()
    for seat in resolved:
        key = (seat["raci"], seat["team_id"], seat["user_id"])
        if key in seen:
            raise RiskRegisterError(
                f"the same party is listed twice as {RACI_LABELS[seat['raci']]}"
            )
        seen.add(key)

    before = summarise_raci(session, risk)
    for row in session.execute(
        select(RiskRaci).where(RiskRaci.risk_id == risk.id)
    ).scalars().all():
        session.delete(row)
    session.flush()

    rows = []
    for seat in resolved:
        row = RiskRaci(organization_id=risk.organization_id, risk_id=risk.id, **seat)
        session.add(row)
        rows.append(row)
    session.flush()

    after = summarise_raci(session, risk)
    if before != after:
        record_event(session, risk, "raci_changed", actor_id=actor_id,
                     actor_label=actor_label, details={"from": before, "to": after})
    return rows


def summarise_raci(session: Session, risk: RiskEntry) -> dict[str, list[str]]:
    """A comparable, human-readable snapshot for the event log."""
    out: dict[str, list[str]] = {r: [] for r in RACI_ROLES}
    for row in raci_rows(session, risk.id):
        out[row.raci].append(f"{row.party_type}:{row.user_id or row.team_id}")
    return {k: sorted(v) for k, v in out.items() if v}


def raci_rows(session: Session, risk_id: uuid.UUID) -> list[RiskRaci]:
    return list(session.execute(
        select(RiskRaci).where(RiskRaci.risk_id == risk_id)
    ).scalars().all())


# --- links ----------------------------------------------------------------

def _link_target(
    session: Session, organization_id: uuid.UUID, object_type: str, object_id: uuid.UUID
) -> str:
    """Confirm the target exists here and return the label to snapshot."""
    if object_type == "asset":
        row = session.execute(
            select(Asset).where(Asset.id == object_id,
                                Asset.organization_id == organization_id)
        ).scalars().first()
        return row.name if row else ""
    if object_type == "finding":
        row = session.execute(
            select(Finding).where(Finding.id == object_id,
                                  Finding.organization_id == organization_id)
        ).scalars().first()
        return row.title if row else ""
    if object_type == "vulnerability":
        row = session.execute(
            select(Vulnerability).where(Vulnerability.id == object_id,
                                        Vulnerability.organization_id == organization_id)
        ).scalars().first()
        return row.title if row else ""
    # Compliance controls are a GLOBAL catalogue (models/base.GLOBAL_TABLES):
    # there is no tenant column to filter on, and that is not a leak -- the
    # framework library is public reference data.
    row = session.execute(
        select(ComplianceControl).where(ComplianceControl.id == object_id)
    ).scalars().first()
    return row.title if row else ""


def add_link(
    session: Session,
    risk: RiskEntry,
    object_type: str,
    object_id: uuid.UUID,
    *,
    note: str | None = None,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
) -> RiskLink:
    kind = _one_of(object_type, RISK_LINK_TYPES, "object_type")
    label = _link_target(session, risk.organization_id, kind, object_id)
    if not label:
        raise RiskRegisterError(f"no {kind} {object_id} in this organization")
    existing = session.execute(
        select(RiskLink).where(RiskLink.risk_id == risk.id,
                               RiskLink.object_type == kind,
                               RiskLink.object_id == object_id)
    ).scalars().first()
    if existing is not None:
        # Idempotent rather than a 409: linking the same asset twice is a
        # double-click, not an error worth teaching somebody about.
        return existing
    row = RiskLink(organization_id=risk.organization_id, risk_id=risk.id,
                   object_type=kind, object_id=object_id, label=label[:300], note=note)
    session.add(row)
    session.flush()
    record_event(session, risk, "linked", actor_id=actor_id, actor_label=actor_label,
                 details={"object_type": kind, "object_id": str(object_id),
                          "label": label[:300]})
    return row


def remove_link(
    session: Session,
    risk: RiskEntry,
    link: RiskLink,
    *,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
) -> None:
    details = {"object_type": link.object_type, "object_id": str(link.object_id),
               "label": link.label}
    session.delete(link)
    session.flush()
    record_event(session, risk, "unlinked", actor_id=actor_id, actor_label=actor_label,
                 details=details)


# --- read -----------------------------------------------------------------


def party_labels(session: Session, organization_id: uuid.UUID) -> tuple[dict, dict]:
    """Team and user display names for one tenant, fetched once per list page.

    Public because the list endpoint renders a page of risks and resolving the
    names per row would be two queries per risk -- the N+1 that made the first
    findings list unusable at 400 rows.
    """
    teams = {
        t.id: t.name for t in session.execute(
            select(Team).where(Team.organization_id == organization_id)
        ).scalars().all()
    }
    users = {
        u.id: (u.full_name or u.email) for u in session.execute(
            select(User).where(User.organization_id == organization_id)
        ).scalars().all()
    }
    return teams, users


def as_dict(
    session: Session,
    risk: RiskEntry,
    *,
    with_detail: bool = False,
    teams: dict | None = None,
    users: dict | None = None,
) -> dict[str, Any]:
    if teams is None or users is None:
        teams, users = party_labels(session, risk.organization_id)

    seats = []
    for row in raci_rows(session, risk.id):
        seats.append({
            "id": str(row.id),
            "raci": row.raci,
            "raci_label": RACI_LABELS[row.raci],
            "party_type": row.party_type,
            "team_id": str(row.team_id) if row.team_id else None,
            "team_name": teams.get(row.team_id),
            "user_id": str(row.user_id) if row.user_id else None,
            "user_name": users.get(row.user_id),
            "note": row.note,
        })

    out = {
        "id": str(risk.id),
        "code": risk.code,
        "title": risk.title,
        "description": risk.description,
        "category": risk.category,
        "source": risk.source,
        "status": risk.status,
        "is_open": risk.is_open,
        "treatment": risk.treatment,
        "treatment_plan": risk.treatment_plan,
        "likelihood": risk.likelihood,
        "impact": risk.impact,
        "score": risk.score,
        "band": risk.band,
        "residual_likelihood": risk.residual_likelihood,
        "residual_impact": risk.residual_impact,
        "residual_score": risk.residual_score,
        "residual_band": risk.residual_band,
        "identified_at": risk.identified_at.isoformat() if risk.identified_at else None,
        "review_due_at": risk.review_due_at.isoformat() if risk.review_due_at else None,
        "review_overdue": bool(
            risk.review_due_at and risk.is_open and risk.review_due_at < dt.date.today()
        ),
        "closed_at": risk.closed_at.isoformat() if risk.closed_at else None,
        "closure_note": risk.closure_note,
        "tags": list(risk.tags or []),
        "external_ref": risk.external_ref,
        "created_at": risk.created_at.isoformat() if risk.created_at else None,
        "updated_at": risk.updated_at.isoformat() if risk.updated_at else None,
        "raci": seats,
        #: Surfaced on every row, not only the detail page. A register whose
        #: list view does not say who is accountable is a list of worries.
        "accountable": next(
            (s["user_name"] or s["team_name"] for s in seats if s["raci"] == "A"), None
        ),
        "responsible": [
            s["user_name"] or s["team_name"] for s in seats if s["raci"] == "R"
        ],
    }

    if with_detail:
        out["links"] = [
            {"id": str(l.id), "object_type": l.object_type,
             "object_id": str(l.object_id), "label": l.label, "note": l.note}
            for l in session.execute(
                select(RiskLink).where(RiskLink.risk_id == risk.id)
                .order_by(RiskLink.created_at)
            ).scalars().all()
        ]
        out["events"] = [
            {"id": str(e.id), "event": e.event, "actor_label": e.actor_label,
             "details": e.details, "note": e.note,
             "created_at": e.created_at.isoformat() if e.created_at else None}
            for e in session.execute(
                select(RiskEvent).where(RiskEvent.risk_id == risk.id)
                .order_by(RiskEvent.created_at.desc()).limit(200)
            ).scalars().all()
        ]
    return out


def summary(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """Counts for the register header and the switch screen."""
    base = select(RiskEntry).where(RiskEntry.organization_id == organization_id,
                                   RiskEntry.deleted_at.is_(None))
    rows = list(session.execute(base).scalars().all())
    today = dt.date.today()
    by_band: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for row in rows:
        by_status[row.status] = by_status.get(row.status, 0) + 1
        band = row.band
        if band:
            by_band[band] = by_band.get(band, 0) + 1
    accountable_ids = {
        r.risk_id for r in session.execute(
            select(RiskRaci).where(RiskRaci.organization_id == organization_id,
                                   RiskRaci.raci == "A")
        ).scalars().all()
    }
    open_rows = [r for r in rows if r.status in OPEN_RISK_STATUSES]
    return {
        "total": len(rows),
        "open": len(open_rows),
        "by_status": by_status,
        "by_band": by_band,
        "review_overdue": len([
            r for r in open_rows if r.review_due_at and r.review_due_at < today
        ]),
        #: The number that makes the register honest. An open risk with nobody
        #: accountable is the one the next incident review will find.
        "unassigned": len([r for r in open_rows if r.id not in accountable_ids]),
        "unscored": len([r for r in open_rows if r.score is None]),
    }


def get(session: Session, organization_id: uuid.UUID, risk_id: uuid.UUID) -> RiskEntry | None:
    return session.execute(
        select(RiskEntry).where(RiskEntry.id == risk_id,
                                RiskEntry.organization_id == organization_id,
                                RiskEntry.deleted_at.is_(None))
    ).scalars().first()


def for_party(
    session: Session,
    organization_id: uuid.UUID,
    *,
    user_id: uuid.UUID | None = None,
    team_ids: Iterable[uuid.UUID] = (),
    roles: tuple[str, ...] = RACI_ROLES,
) -> set[uuid.UUID]:
    """Risk ids where this person, or one of these teams, holds a seat.

    Used by `?mine=true`. A person's own seats and their teams' seats are one
    question -- "what is on my plate" -- and answering it with two filters the
    operator has to combine by hand is how the second one gets forgotten.
    """
    stmt = select(RiskRaci.risk_id).where(
        RiskRaci.organization_id == organization_id,
        RiskRaci.raci.in_(tuple(roles)),
    )
    team_ids = list(team_ids)
    if user_id and team_ids:
        stmt = stmt.where((RiskRaci.user_id == user_id) | (RiskRaci.team_id.in_(team_ids)))
    elif user_id:
        stmt = stmt.where(RiskRaci.user_id == user_id)
    elif team_ids:
        stmt = stmt.where(RiskRaci.team_id.in_(team_ids))
    else:
        return set()
    return set(session.execute(stmt).scalars().all())


__all__ = [
    "RiskRegisterError", "COUNTER_KEY", "WRITABLE_FIELDS",
    "next_code", "create", "update", "set_raci", "raci_rows", "summarise_raci",
    "add_link", "remove_link", "as_dict", "summary", "get", "for_party", "party_labels",
    "record_event",
]
