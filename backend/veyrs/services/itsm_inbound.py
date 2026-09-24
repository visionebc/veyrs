"""Inbound ITSM events: the return leg of the sync (spec section 34).

VEYRS could already push a ticket to ServiceNow/Jira and poll it back
(`itsm.pull_status`). Polling is the wrong shape for the question "did the
engineer close this?": it is minutes late, it costs a request per link per
cycle, and it silently stops mattering the moment there are ten thousand links.
This module is the push-back: the remote system tells VEYRS, signed, when
something changed.

**The policy this module does NOT relax.** `pull_status()` deliberately refuses
to map a remote closure onto a VEYRS state, on the grounds that an external
system must not be able to close a security finding. That reasoning survives
intact here, and the design follows from it:

* By default an inbound event is **advisory**: it updates `remote_status`,
  `remote_key`, `remote_url` and imports comments. Nothing in VEYRS moves.
* An operator may opt in to state changes per connector
  (`inbound_transitions`), and even then the mapping is applied through
  `ticketing.transition_ticket()`, so the ticket state machine still governs
  what is legal.
* `RESOLUTION_ADVANCES_FINDING` is where a resolved ticket touches its finding,
  and that path stays exactly as it was: reachable, but only via a transition
  the operator explicitly configured. There is no route from "Jira says Done"
  to "the vulnerability is closed" that a human did not switch on.

**Authentication is an HMAC, not a bearer token.** The remote system holds a
shared secret; the request carries `X-VEYRS-Signature: sha256=<hex>` over
`timestamp.body`, and the timestamp must be inside a five-minute window. A
bearer token in a webhook config is a credential sitting in a third party's
database that grants API access; a shared secret used only to sign proves the
sender without granting anything.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ExternalLink, ItsmConnector, Ticket
from ..security.secrets import decrypt
from . import ticketing

log = logging.getLogger("veyrs.itsm.inbound")

#: How far a signed timestamp may be from now. Five minutes is the de-facto
#: standard for webhook replay windows (Stripe, GitHub) and is comfortably
#: wider than any legitimate clock skew.
REPLAY_WINDOW_SECONDS = 300
MAX_INBOUND_BYTES = 1024 * 1024


class InboundError(ValueError):
    """Any refusal of an inbound event. The API maps it to 400/401/404."""


class SignatureError(InboundError):
    """The request did not prove it came from the configured system."""


@dataclasses.dataclass
class InboundEvent:
    """One remote change, normalised out of whatever the vendor posted."""

    remote_id: str
    status: str | None = None
    remote_key: str | None = None
    url: str | None = None
    actor: str | None = None
    comments: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    event: str | None = None
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------
def signing_secret(connector: ItsmConnector) -> str:
    secret = decrypt(connector.inbound_secret_enc)
    if not secret:
        raise InboundError(
            f"connector {connector.slug} has no inbound secret; "
            "rotate one before pointing a webhook at it"
        )
    return secret


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The canonical signature. Exposed so tests and docs cannot drift from it."""
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_signature(
    connector: ItsmConnector, *, body: bytes, signature: str | None,
    timestamp: str | None, now: float | None = None,
) -> None:
    if len(body) > MAX_INBOUND_BYTES:
        raise InboundError("inbound payload too large")
    if not signature or not timestamp:
        raise SignatureError("missing signature or timestamp header")
    try:
        sent_at = float(timestamp)
    except (TypeError, ValueError) as exc:
        raise SignatureError("timestamp header is not a unix timestamp") from exc
    if abs((now if now is not None else time.time()) - sent_at) > REPLAY_WINDOW_SECONDS:
        # Without this the signature alone would make every captured request
        # replayable forever.
        raise SignatureError("timestamp outside the replay window")
    expected = sign(signing_secret(connector), timestamp, body)
    if not hmac.compare_digest(expected, signature):
        raise SignatureError("signature mismatch")


# ---------------------------------------------------------------------------
# Vendor payloads -> InboundEvent
# ---------------------------------------------------------------------------
def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def parse_jira(body: dict) -> InboundEvent:
    issue = body.get("issue") or {}
    fields = issue.get("fields") or {}
    comment = body.get("comment") or {}
    comments = []
    if comment.get("body"):
        author = (comment.get("author") or {}).get("displayName")
        comments.append({"body": str(comment["body"])[:8000],
                         "author": _text(author) or "jira"})
    return InboundEvent(
        remote_id=str(issue.get("id") or ""),
        status=_text(((fields.get("status") or {}).get("name"))),
        remote_key=_text(issue.get("key")),
        url=_text(issue.get("self")),
        actor=_text(((body.get("user") or {}).get("displayName"))),
        comments=comments,
        event=_text(body.get("webhookEvent")),
        raw=body,
    )


def parse_servicenow(body: dict) -> InboundEvent:
    """ServiceNow business rules post whatever the author wrote.

    Both the flat shape (`{"sys_id": ..., "state": ...}`) and the REST-ish
    `{"result": {...}}` wrapper are accepted, because both are what real
    instances send.
    """
    record = body.get("result") if isinstance(body.get("result"), dict) else body
    comments = []
    if _text(record.get("comments")):
        comments.append({"body": str(record["comments"])[:8000], "author": "servicenow"})
    return InboundEvent(
        remote_id=str(record.get("sys_id") or record.get("number") or ""),
        status=_text(record.get("state")) or _text(record.get("incident_state")),
        remote_key=_text(record.get("number")),
        url=_text(record.get("url")),
        actor=_text(record.get("sys_updated_by")),
        comments=comments,
        event=_text(body.get("event")),
        raw=body,
    )


def parse_generic(body: dict) -> InboundEvent:
    """VEYRS' own canonical shape, for anything with a scripting hook."""
    comments = []
    for entry in body.get("comments") or []:
        if isinstance(entry, dict) and _text(entry.get("body")):
            comments.append({"body": str(entry["body"])[:8000],
                             "author": _text(entry.get("author")) or "webhook"})
        elif _text(entry):
            comments.append({"body": str(entry)[:8000], "author": "webhook"})
    return InboundEvent(
        remote_id=str(body.get("remote_id") or body.get("id") or ""),
        status=_text(body.get("status")),
        remote_key=_text(body.get("key")),
        url=_text(body.get("url")),
        actor=_text(body.get("actor")),
        comments=comments,
        event=_text(body.get("event")),
        raw=body,
    )


PARSERS = {"jira": parse_jira, "servicenow": parse_servicenow, "webhook": parse_generic}


def parse_inbound(connector: ItsmConnector, body: bytes) -> InboundEvent:
    try:
        decoded = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InboundError(f"inbound body is not JSON: {exc}") from exc
    if not isinstance(decoded, dict):
        raise InboundError("inbound body must be a JSON object")
    parser = PARSERS.get(connector.system, parse_generic)
    event = parser(decoded)
    if not event.remote_id:
        raise InboundError(
            f"could not find a remote id in this {connector.system} payload"
        )
    return event


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
def _normalise(status: str) -> str:
    return " ".join(status.strip().lower().replace("_", " ").split())


def mapped_state(connector: ItsmConnector, status: str | None) -> str | None:
    """Which VEYRS ticket state, if any, this remote status means HERE.

    Returns None unless the operator configured the mapping. That is the whole
    safety property: an unmapped "Done" is recorded and ignored, never guessed.
    """
    if not status:
        return None
    mapping = {
        _normalise(str(k)): str(v)
        for k, v in (connector.inbound_transitions or {}).items()
    }
    return mapping.get(_normalise(status))


def handle_inbound(
    session: Session, connector: ItsmConnector, event: InboundEvent
) -> dict[str, Any]:
    """Apply one verified event. Idempotent: replaying it changes nothing."""
    if not connector.inbound_enabled:
        raise InboundError(f"connector {connector.slug} does not accept inbound events")

    link = session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == connector.organization_id,
            ExternalLink.connector_id == connector.id,
            ExternalLink.remote_id == event.remote_id,
        )
    ).scalars().first()
    if link is None:
        # Not an error the sender can fix by retrying, and not something to
        # create: VEYRS only tracks twins it pushed itself. Recorded and 404ed
        # so a misconfigured webhook is visible rather than silently swallowed.
        raise InboundError(
            f"no VEYRS object is linked to {connector.system} record {event.remote_id}"
        )

    now = dt.datetime.now(dt.timezone.utc)
    outcome: dict[str, Any] = {
        "connector": connector.slug, "remote_id": event.remote_id,
        "status": event.status, "state_changed": False, "comments_added": 0,
        "advisory_only": True,
    }

    previous_status = link.remote_status
    if event.status:
        link.remote_status = event.status[:60]
    if event.remote_key:
        link.remote_key = event.remote_key[:120]
    if event.url:
        link.remote_url = event.url[:1000]
    link.last_pulled_at = now
    link.last_error = None
    connector.last_inbound_at = now
    connector.last_error = None

    ticket = None
    if link.object_type == "ticket":
        try:
            ticket = session.get(Ticket, uuid.UUID(link.object_id))
        except ValueError:
            ticket = None
    if ticket is None or ticket.organization_id != connector.organization_id:
        session.flush()
        outcome["note"] = "link is not a ticket in this organization; status recorded only"
        return outcome

    actor_label = f"{connector.system}:{event.actor}" if event.actor else connector.system

    for comment in event.comments:
        ticketing.add_comment(
            session, ticket, comment["body"],
            author_label=f"{connector.system}:{comment.get('author') or 'remote'}"[:120],
            is_internal=False,
        )
        outcome["comments_added"] += 1

    target = mapped_state(connector, event.status)
    if target is None:
        if event.status and event.status != previous_status:
            # Visible, not silent: an unmapped status that keeps arriving is
            # how an operator discovers the mapping they meant to configure.
            ticketing.record_event(
                session, ticket, "remote_status_changed", actor_label=actor_label,
                details={"connector": connector.slug, "from": previous_status,
                         "to": event.status, "applied": False,
                         "reason": "no inbound_transitions mapping for this status"},
            )
        session.flush()
        return outcome

    outcome["advisory_only"] = False
    if ticket.state == target:
        session.flush()
        return outcome
    try:
        ticketing.transition_ticket(
            session, ticket, target, actor_label=actor_label,
            note=f"{connector.system} reported status {event.status!r}",
        )
        outcome["state_changed"] = True
        outcome["new_state"] = target
    except ticketing.TicketError as exc:
        # The remote system moved somewhere VEYRS' own state machine does not
        # allow from here. Record it; do not force it.
        ticketing.record_event(
            session, ticket, "remote_transition_refused", actor_label=actor_label,
            details={"connector": connector.slug, "target": target,
                     "current": ticket.state, "error": str(exc)},
        )
        outcome["refused"] = str(exc)
    session.flush()
    return outcome
