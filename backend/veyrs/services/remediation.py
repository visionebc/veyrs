"""One entry point for "somebody must fix this finding", whichever queue owns it.

Before this module there were three ways remediation work was created --
`autoticket.consider`, the workflow engine's `create_ticket` action, and
`POST /tickets` -- and every one of them called `ticketing.ticket_for_finding`
directly. Adding an external-ticketing mode by patching the console would have
left all three still writing internal rows: the switch would have looked
enforced and would not have been, which is the exact defect class phase 24's
MFA check and phase 41's missing UNIQUE constraint belong to.

So the dispatch lives here, in ONE function, and the three callers were changed
to use it. A fourth creation path added later that forgets this module is a bug
with a name and a test (`test_no_caller_bypasses_the_dispatcher`), not a silent
regression discovered by an operator wondering why Jira is empty.

`RemediationRecord` is the shape both branches return, so callers do not have
to know which mode they are in. It is deliberately NOT a `Ticket` subclass or a
duck-typed stand-in: code that wants a real internal ticket should say so and
get `None`, rather than receive an object that answers `.reference` and blows up
on `.comments`.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.integration import ExternalLink
from ..models.ticketing import ItsmConnector, Ticket
from ..models.vulnerability import Finding
from . import ticketing, ticketing_mode

log = logging.getLogger("veyrs.remediation")


@dataclasses.dataclass(slots=True)
class RemediationRecord:
    """Where the work to fix one finding actually lives."""

    #: "internal" (a VEYRS ticket) or "external" (an issue in Jira/ServiceNow).
    kind: str
    #: The id an operator can look the work up by, in whichever system owns it.
    id: str
    #: Human-facing key: VEYRS-REM-000123, or SEC-4412.
    reference: str
    url: str | None = None
    state: str | None = None
    #: Present only in internal mode. See the module docstring.
    ticket: Ticket | None = None
    #: Present only in external mode.
    link: ExternalLink | None = None

    def as_dict(self) -> dict:
        return {
            "kind": self.kind, "id": self.id, "reference": self.reference,
            "url": self.url, "state": self.state,
        }


def _from_ticket(ticket: Ticket) -> RemediationRecord:
    return RemediationRecord(
        kind="internal", id=str(ticket.id), reference=ticket.reference,
        url=f"/tickets/{ticket.id}", state=ticket.state, ticket=ticket,
    )


def _from_link(link: ExternalLink) -> RemediationRecord:
    return RemediationRecord(
        kind="external", id=str(link.id),
        reference=link.remote_key or link.remote_id,
        url=link.remote_url, state=link.remote_status, link=link,
    )


def open_link_for_finding(
    session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID
) -> ExternalLink | None:
    """The live external issue for a finding, if one was already raised.

    Scoped by `is_active` rather than by remote status on purpose: a Jira issue
    an engineer moved to Done is still THE issue for that finding, and treating
    it as absent would raise a duplicate every night for a finding whose fix is
    waiting on verification. Closing the relation is `is_active = false`, which
    only a human or an explicit unlink does.
    """
    return session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == organization_id,
            ExternalLink.object_type == "finding",
            ExternalLink.object_id == str(finding_id),
            ExternalLink.is_active.is_(True),
        ).order_by(ExternalLink.created_at.desc())
    ).scalars().first()


def existing_for_finding(
    session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID
) -> RemediationRecord | None:
    """Is there already work open for this finding, in whichever queue owns it?

    This is the dedupe check. It follows the CURRENT mode, which is the
    behaviour an operator expects after a flip: work raised in Jira from now on,
    even for a finding that carries a closed internal ticket from before.

    It deliberately does NOT fall back to the other mode's record. A tenant that
    flipped to external and still has an open internal ticket for a finding will
    get a Jira issue raised for it -- and that is correct, because the internal
    ticket is no longer a queue anyone works from. The count of those tickets is
    reported by `ticketing_mode.state()` before the flip, so it is a decision
    rather than a surprise.
    """
    if ticketing_mode.is_external(session, organization_id):
        link = open_link_for_finding(session, organization_id, finding_id)
        return _from_link(link) if link is not None else None
    ticket = ticketing.open_ticket_for_finding(session, finding_id)
    return _from_ticket(ticket) if ticket is not None else None


def open_for_finding(
    session: Session,
    finding: Finding,
    *,
    ticket_type: str = "remediation",
    actor_label: str = "system",
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
) -> tuple[RemediationRecord, bool]:
    """Raise (or return) the remediation work for a finding. Idempotent.

    Returns `(record, created)` exactly like `ticketing.ticket_for_finding`, so
    the three call sites read the same as they did before the mode existed.
    """
    org_id = finding.organization_id
    if not ticketing_mode.is_external(session, org_id):
        ticket, created = ticketing.ticket_for_finding(
            session, finding, ticket_type=ticket_type, actor_label=actor_label,
            assigned_team_id=assigned_team_id, assigned_user_id=assigned_user_id,
        )
        return _from_ticket(ticket), created

    # --- external -----------------------------------------------------------
    existing = open_link_for_finding(session, org_id, finding.id)
    if existing is not None:
        return _from_link(existing), False

    connector = ticketing_mode.active_connector(session, org_id)
    if connector is None:
        # Not a silent no-op. `state()["usable"]` is already False and the
        # console says so, but a caller that got here anyway is asking for work
        # to be created and must be told it was not.
        raise ticketing_mode.TicketingModeError(
            "external ticketing is selected but its connector is missing or was "
            "deleted; no issue was raised. Fix it in Administration -> Ticketing."
        )

    from . import correlation, itsm  # local: itsm imports models, avoid a cycle

    link = itsm.push_finding(
        session, connector, finding,
        ticket_type=ticket_type,
        assigned_team_id=assigned_team_id or finding.assigned_team_id,
        assigned_user_id=assigned_user_id or finding.assigned_user_id,
    )
    correlation.record_event(
        session, finding, "external_issue_created",
        actor_label=actor_label,
        details={
            "system": connector.system,
            "connector": connector.slug,
            "issue": link.remote_key or link.remote_id,
            "url": link.remote_url,
        },
    )
    session.flush()
    return _from_link(link), True


def refresh(session: Session, link: ExternalLink) -> ExternalLink:
    """Re-read one external issue's status and stamp the relation."""
    from . import itsm

    connector = session.get(ItsmConnector, link.connector_id)
    if connector is None:
        raise ticketing_mode.TicketingModeError("the connector for this link is gone")
    status = itsm.pull_status(session, connector, link)
    if status is not None:
        link.remote_status = status
    link.last_pulled_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return link


__all__ = [
    "RemediationRecord", "open_for_finding", "existing_for_finding",
    "open_link_for_finding", "refresh",
]
