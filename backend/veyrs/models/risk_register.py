"""The risk register: risks that are not findings, and the RACI that owns them.

VEYRS derives risk from the estate -- a CVE on an asset, scored by exposure and
business criticality. That machinery answers *what is wrong with the machines*.
It cannot hold the other half of a security programme: the supplier with no exit
plan, the process nobody has documented, the one person who knows how the
payment batch is released, the data-protection gap a lawyer found. Those risks
have no asset, no CVE and no scanner that will ever report them, so today they
live in somebody's spreadsheet -- which is where risks go to be forgotten.

This module is that register. Four boundaries, each of them deliberate:

**A register entry is never derived.** Nothing here is computed from findings. A
row exists because a person wrote it down, and only a person changes it. If the
register could be written by the correlation engine, an operator could never
tell an accepted business decision from a side effect of last night's scan.

**Linking to the estate is optional and additive.** `risk_register_links` may
point a risk at an asset, a finding, a vulnerability or a compliance control,
and a risk with no link at all is completely ordinary -- that is the entire
reason this module exists. The link enriches the record; it never owns it, and
deleting the asset does not delete the risk.

**There is no `owner_team_id` column, and that is the point.** The Accountable
row in `risk_register_raci` IS the owner. A denormalised owner column would be a
second authority over the same question, and the day the two disagree the
register stops being evidence of anything -- the same duplicate-authority defect
that made `ticketing_mode` necessary. RACI is the assignment model; the platform
keeps no shadow copy of it.

**Accountable is exactly one named person.** `raci = 'A'` is capped at one row
per risk by a partial unique index, and the service refuses a team in that seat.
"The security team is accountable" is the sentence that turns a risk register
into a list nobody acts on: a team cannot be called into a room, and a seat
everybody holds is a seat nobody holds. Responsible, Consulted and Informed take
teams *or* people, in any number -- those are the seats where a group is the
honest answer.

Assigning a person *within* a team is a first-class case (`party_type='user'`
with `team_id` set as context), and the service verifies the membership rather
than trusting the caller: a RACI matrix that names somebody under a team they
left is worse than one that names nobody, because it looks answered.

Scoring is the ordinary 5x5 -- likelihood x impact, inherent and residual -- with
the band DERIVED from the product rather than typed in, so two risks written by
two people six months apart are still comparable.
"""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, SoftDeleteMixin, TenantMixin, TimestampMixin, uuid_pk

# --- vocabularies ---------------------------------------------------------
# Plain tuples of strings, and String columns rather than native PostgreSQL
# enums, for the same reason every other state column in VEYRS is one: adding a
# value to a pg enum is a migration, and `sync-schema` does not write those.

#: ISO 31000 shaped. `closed` is the only terminal one.
RISK_STATUSES = ("identified", "assessed", "treatment", "monitoring", "closed")
OPEN_RISK_STATUSES = ("identified", "assessed", "treatment", "monitoring")

#: `pending` is the honest default: a risk that has been written down but whose
#: treatment nobody has decided yet is the normal state of a new entry, and
#: defaulting to `mitigate` would put a decision in somebody's mouth.
RISK_TREATMENTS = ("pending", "mitigate", "accept", "transfer", "avoid")

RACI_ROLES = ("R", "A", "C", "I")
RACI_LABELS = {
    "R": "Responsible",
    "A": "Accountable",
    "C": "Consulted",
    "I": "Informed",
}
PARTY_TYPES = ("team", "user")

#: What a risk may be linked to. `control` is a compliance control, which is why
#: the register is useful to an auditor: "which risk is this control mitigating"
#: and "which control covers this risk" become the same row read twice.
RISK_LINK_TYPES = ("asset", "finding", "vulnerability", "control")

#: Suggested, NOT enforced. A register that refuses an operator's own taxonomy
#: is a register they keep a spreadsheet beside.
RISK_CATEGORIES = (
    "cyber", "operational", "third-party", "compliance", "privacy",
    "physical", "financial", "strategic", "people", "continuity",
)
RISK_SOURCES = (
    "assessment", "audit", "incident", "workshop", "third-party",
    "threat-intel", "penetration-test", "other",
)

#: 5x5. The bands are the common ones; they are computed, never stored as text.
RISK_BANDS = ("low", "medium", "high", "critical")


def risk_band(score: int | None) -> str | None:
    """Map a 1-25 product onto the four bands the rest of VEYRS speaks."""
    if score is None:
        return None
    if score >= 15:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def risk_score(likelihood: int | None, impact: int | None) -> int | None:
    if likelihood is None or impact is None:
        return None
    return int(likelihood) * int(impact)


class RiskEntry(Base, TenantMixin, TimestampMixin, SoftDeleteMixin):
    """One risk in the register. Written by a person, owned through RACI."""

    __tablename__ = "risk_register"
    __table_args__ = (
        UniqueConstraint("organization_id", "code"),
        Index("ix_risk_register_org_status", "organization_id", "status"),
        Index("ix_risk_register_org_review", "organization_id", "review_due_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: Human reference, `RISK-000001`, allocated per tenant. People cite these
    #: in board minutes; a UUID is not a thing anybody reads aloud.
    code: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)
    category: Mapped[str | None] = mapped_column(String(60), default=None, index=True)
    source: Mapped[str | None] = mapped_column(String(40), default=None)

    status: Mapped[str] = mapped_column(String(30), default="identified", nullable=False)
    treatment: Mapped[str] = mapped_column(String(30), default="pending", nullable=False)
    treatment_plan: Mapped[str | None] = mapped_column(Text, default=None)

    #: Inherent: before the controls you are counting on. 1-5 each.
    likelihood: Mapped[int | None] = mapped_column(Integer, default=None)
    impact: Mapped[int | None] = mapped_column(Integer, default=None)
    #: Stored so the database can sort and filter on it. Always written through
    #: `services.risk_register`, never by a caller -- a score that disagrees
    #: with its own factors is a number two people will read differently.
    score: Mapped[int | None] = mapped_column(Integer, default=None, index=True)

    #: Residual: what is left once the treatment is actually in place. NULL
    #: until somebody has assessed it, and deliberately not defaulted to the
    #: inherent values -- "we have not looked yet" and "the controls changed
    #: nothing" are different answers and must not render identically.
    residual_likelihood: Mapped[int | None] = mapped_column(Integer, default=None)
    residual_impact: Mapped[int | None] = mapped_column(Integer, default=None)
    residual_score: Mapped[int | None] = mapped_column(Integer, default=None, index=True)

    identified_at: Mapped[dt.date | None] = mapped_column(Date, default=None)
    #: When this must be looked at again. The one date that makes a register
    #: alive rather than an archive: `GET /risks?overdue_review=true`.
    review_due_at: Mapped[dt.date | None] = mapped_column(Date, default=None)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    #: Required to close. A risk that left the register without a sentence
    #: saying why is the one the next auditor will ask about.
    closure_note: Mapped[str | None] = mapped_column(Text, default=None)

    tags: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Free-text pointer into whatever GRC tool or board pack this also lives
    #: in. Not a connector: the register does not pretend to synchronise.
    external_ref: Mapped[str | None] = mapped_column(String(300), default=None)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    @property
    def band(self) -> str | None:
        return risk_band(self.score)

    @property
    def residual_band(self) -> str | None:
        return risk_band(self.residual_score)

    @property
    def is_open(self) -> bool:
        return self.status in OPEN_RISK_STATUSES


class RiskRaci(Base, TenantMixin, TimestampMixin):
    """One seat in one risk's RACI matrix: a team, or a person, never both.

    `party_type='user'` with `team_id` set means *this person, in this team* --
    which is what "assign it to somebody inside the team" actually means, and
    the service refuses it unless the membership exists.
    """

    __tablename__ = "risk_register_raci"
    __table_args__ = (
        # Blocks the same party being added twice in the same seat. Postgres
        # treats NULLs as distinct, which is exactly right here: a team row
        # (user_id NULL) and a user row (team_id NULL) are different parties.
        UniqueConstraint("risk_id", "raci", "team_id", "user_id"),
        # ONE Accountable. Enforced in the database and not only in the service
        # because a second writer -- an import, a script, a future workflow
        # action -- would otherwise be able to create the committee this module
        # exists to prevent.
        Index(
            "uq_risk_register_one_accountable",
            "risk_id",
            unique=True,
            postgresql_where=text("raci = 'A'"),
        ),
        Index("ix_risk_register_raci_user", "user_id"),
        Index("ix_risk_register_raci_team", "team_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    risk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_register.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    raci: Mapped[str] = mapped_column(String(1), nullable=False)
    party_type: Mapped[str] = mapped_column(String(10), nullable=False)
    team_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("teams.id", ondelete="CASCADE"), default=None
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), default=None
    )
    #: Why this seat exists -- "signs off the DPIA", "runs the quarterly
    #: restore test". The difference between a matrix and a name list.
    note: Mapped[str | None] = mapped_column(String(400), default=None)


class RiskLink(Base, TenantMixin, TimestampMixin):
    """Optional pointer from a register entry into the estate.

    Additive by construction: no register entry requires one, and the target is
    stored as (type, id) rather than four nullable foreign keys so adding a
    fifth linkable thing is not a schema change to every existing row.
    """

    __tablename__ = "risk_register_links"
    __table_args__ = (
        UniqueConstraint("risk_id", "object_type", "object_id"),
        Index("ix_risk_register_links_object", "object_type", "object_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    risk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_register.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    object_type: Mapped[str] = mapped_column(String(30), nullable=False)
    object_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    #: Snapshot of what the target was called when it was linked. Kept so the
    #: register still reads as a sentence after the asset is decommissioned --
    #: the link is evidence of a decision made at a time, not a live join.
    label: Mapped[str | None] = mapped_column(String(300), default=None)
    note: Mapped[str | None] = mapped_column(String(400), default=None)


class RiskEvent(Base, TenantMixin):
    """Append-only history of one risk. Never updated, never deleted.

    The global `audit_log` records that a risk changed; this records what the
    register looked like as it changed, next to the risk itself, so the story of
    a risk is readable without an auditor's permission on the audit trail.
    """

    __tablename__ = "risk_register_events"
    __table_args__ = (Index("ix_risk_register_events_risk", "risk_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    risk_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("risk_register.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    event: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    actor_label: Mapped[str] = mapped_column(String(200), default="system", nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, default=None)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: dt.datetime.now(dt.timezone.utc),
        nullable=False, index=True,
    )


__all__ = [
    "RISK_STATUSES", "OPEN_RISK_STATUSES", "RISK_TREATMENTS", "RACI_ROLES",
    "RACI_LABELS", "PARTY_TYPES", "RISK_LINK_TYPES", "RISK_CATEGORIES",
    "RISK_SOURCES", "RISK_BANDS", "risk_band", "risk_score",
    "RiskEntry", "RiskRaci", "RiskLink", "RiskEvent",
]
