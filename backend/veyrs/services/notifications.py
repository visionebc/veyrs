"""Notification dispatch: in-app, email, webhook (spec section 30).

Two rules shape this module:

1. **Nothing is fire-and-forget.** Every message is a `Notification` row before
   any transport is attempted, so "was the CISO actually told about the breach?"
   has an answer during the post-incident review.
2. **Escalation notices cannot be muted.** Per-user preferences apply to routine
   traffic; an SLA breach or an escalation step ignores them. A product whose
   alerts can be silently switched off is worse than no product.

Transport is pluggable and defaults to a recording no-op ("queued") so tests and
air-gapped installs never depend on an SMTP server being reachable.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import logging
import smtplib
import uuid
from email.message import EmailMessage
from typing import Any, Callable, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    Notification, NotificationPreference, NotificationTemplate, Team, TeamMember, User,
    WebhookEndpoint,
)

log = logging.getLogger("veyrs.notifications")

SUPPORTED_LOCALES = ("en", "es", "de", "fr", "it")

#: Events that ignore per-user opt-outs.
UNMUTABLE_EVENTS = {"sla.breached", "sla.escalated", "finding.kev_detected"}

#: Built-in templates. `{placeholders}` are filled from the event context; a
#: missing key renders as an empty string rather than raising, because a
#: template typo must never stop a breach notice from going out.
BUILTIN_TEMPLATES: dict[str, dict[str, dict[str, str]]] = {
    "finding.created": {
        "en": {"subject": "[VEYRS] New {risk_level} finding: {title}",
               "body": "A new finding was detected.\n\n{title}\nAsset: {asset}\n"
                       "Risk: {risk_score} ({risk_level})\nDue: {due_at}\n\n{link}"},
        "es": {"subject": "[VEYRS] Nuevo hallazgo {risk_level}: {title}",
               "body": "Se ha detectado un nuevo hallazgo.\n\n{title}\nActivo: {asset}\n"
                       "Riesgo: {risk_score} ({risk_level})\nVence: {due_at}\n\n{link}"},
        "de": {"subject": "[VEYRS] Neuer Befund ({risk_level}): {title}",
               "body": "Ein neuer Befund wurde erkannt.\n\n{title}\nAsset: {asset}\n"
                       "Risiko: {risk_score} ({risk_level})\nFaellig: {due_at}\n\n{link}"},
        "fr": {"subject": "[VEYRS] Nouvelle vulnerabilite ({risk_level}) : {title}",
               "body": "Une nouvelle vulnerabilite a ete detectee.\n\n{title}\n"
                       "Actif : {asset}\nRisque : {risk_score} ({risk_level})\n"
                       "Echeance : {due_at}\n\n{link}"},
        "it": {"subject": "[VEYRS] Nuova vulnerabilita ({risk_level}): {title}",
               "body": "Rilevata una nuova vulnerabilita.\n\n{title}\nAsset: {asset}\n"
                       "Rischio: {risk_score} ({risk_level})\nScadenza: {due_at}\n\n{link}"},
    },
    "finding.assigned": {
        "en": {"subject": "[VEYRS] Assigned to you: {title}",
               "body": "You have been assigned a finding.\n\n{title}\nAsset: {asset}\n"
                       "Risk: {risk_score} ({risk_level})\nDue: {due_at}\n\n{link}"},
        "es": {"subject": "[VEYRS] Asignado a ti: {title}",
               "body": "Se te ha asignado un hallazgo.\n\n{title}\nActivo: {asset}\n"
                       "Riesgo: {risk_score} ({risk_level})\nVence: {due_at}\n\n{link}"},
    },
    "sla.warned": {
        "en": {"subject": "[VEYRS] SLA warning ({percent_used}% used): {title}",
               "body": "This finding is approaching its SLA deadline.\n\n{title}\n"
                       "Asset: {asset}\nDue: {due_at}\n\n{link}"},
        "es": {"subject": "[VEYRS] Aviso de SLA ({percent_used}% consumido): {title}",
               "body": "Este hallazgo se acerca a su fecha limite.\n\n{title}\n"
                       "Activo: {asset}\nVence: {due_at}\n\n{link}"},
    },
    "sla.breached": {
        "en": {"subject": "[VEYRS] SLA BREACHED: {title}",
               "body": "The remediation deadline has passed.\n\n{title}\nAsset: {asset}\n"
                       "Was due: {due_at}\nOverdue: {overdue_hours} h\n\n{link}"},
        "es": {"subject": "[VEYRS] SLA INCUMPLIDO: {title}",
               "body": "La fecha limite de remediacion ha pasado.\n\n{title}\n"
                       "Activo: {asset}\nVencia: {due_at}\nRetraso: {overdue_hours} h\n\n{link}"},
    },
    "sla.escalated": {
        "en": {"subject": "[VEYRS] Escalation level {level}: {title}",
               "body": "This finding has escalated to level {level} ({notify}).\n\n"
                       "{title}\nAsset: {asset}\nDue: {due_at}\n\n{link}"},
        "es": {"subject": "[VEYRS] Escalado a nivel {level}: {title}",
               "body": "Este hallazgo ha escalado al nivel {level} ({notify}).\n\n"
                       "{title}\nActivo: {asset}\nVence: {due_at}\n\n{link}"},
    },
    "ticket.created": {
        "en": {"subject": "[VEYRS] {reference}: {title}",
               "body": "A ticket has been created.\n\n{reference} - {title}\n"
                       "Priority: {priority}\nDue: {due_at}\n\n{link}"},
        "es": {"subject": "[VEYRS] {reference}: {title}",
               "body": "Se ha creado un ticket.\n\n{reference} - {title}\n"
                       "Prioridad: {priority}\nVence: {due_at}\n\n{link}"},
    },
    # The digest arrives pre-rendered: `services/digest.render_body` builds
    # the whole message so that the preview endpoint and the sent mail come
    # from one function. The template exists so a tenant can still put its own
    # wrapper around it, not so it can reassemble the content.
    "digest.daily": {
        "en": {"subject": "[VEYRS] Daily digest - {subject_counts}",
               "body": "{body}"},
        "es": {"subject": "[VEYRS] Resumen diario - {subject_counts}",
               "body": "{body}"},
    },
    "ticket.state_changed": {
        "en": {"subject": "[VEYRS] {reference} is now {state}",
               "body": "{reference} - {title}\nState: {previous_state} -> {state}\n\n{link}"},
        "es": {"subject": "[VEYRS] {reference} ahora esta en {state}",
               "body": "{reference} - {title}\nEstado: {previous_state} -> {state}\n\n{link}"},
    },
}


class _SafeDict(dict):
    """`str.format_map` helper: unknown placeholders render empty, not KeyError."""

    def __missing__(self, key: str) -> str:  # noqa: D105
        return ""


def render(event: str, locale: str, context: dict[str, Any],
           session: Session | None = None,
           organization_id: uuid.UUID | None = None) -> tuple[str, str]:
    """Resolve a template (tenant override first, then built-in, then fallback)."""
    locale = (locale or settings.default_locale or "en")[:2].lower()
    if session is not None and organization_id is not None:
        row = session.execute(
            select(NotificationTemplate).where(
                NotificationTemplate.organization_id == organization_id,
                NotificationTemplate.slug == event,
                NotificationTemplate.locale == locale,
            )
        ).scalars().first()
        if row is not None:
            return (row.subject.format_map(_SafeDict(context)),
                    row.body.format_map(_SafeDict(context)))

    per_locale = BUILTIN_TEMPLATES.get(event, {})
    template = per_locale.get(locale) or per_locale.get("en")
    if template is None:
        # Unknown event: still deliver something actionable rather than nothing.
        return (f"[VEYRS] {event}", json.dumps(context, default=str, indent=2))
    return (template["subject"].format_map(_SafeDict(context)),
            template["body"].format_map(_SafeDict(context)))


def _muted(session: Session, user: User, event: str, channel: str) -> bool:
    if event in UNMUTABLE_EVENTS:
        return False
    pref = session.execute(
        select(NotificationPreference).where(
            NotificationPreference.user_id == user.id,
            NotificationPreference.event == event,
        )
    ).scalars().first()
    if pref is None:
        return False
    return not (pref.email if channel == "email" else pref.in_app)


def team_members(session: Session, team_id: uuid.UUID) -> list[User]:
    return session.execute(
        select(User).join(TeamMember, TeamMember.user_id == User.id)
        .where(TeamMember.team_id == team_id, User.is_active.is_(True))
    ).scalars().all()


def queue(
    session: Session,
    organization_id: uuid.UUID,
    event: str,
    context: dict[str, Any],
    *,
    users: Iterable[User] | None = None,
    team_id: uuid.UUID | None = None,
    addresses: Iterable[str] | None = None,
    channels: tuple[str, ...] = ("in_app", "email"),
    finding_id: uuid.UUID | None = None,
    ticket_id: uuid.UUID | None = None,
) -> list[Notification]:
    """Create Notification rows for every resolved recipient/channel pair."""
    recipients: list[User] = list(users or [])
    if team_id is not None:
        recipients.extend(team_members(session, team_id))
    # De-duplicate: a user on two notified teams gets one message, not two.
    unique: dict[uuid.UUID, User] = {u.id: u for u in recipients}

    created: list[Notification] = []
    for user in unique.values():
        locale = getattr(user, "locale", None) or settings.default_locale
        subject, body = render(event, locale, context, session, organization_id)
        for channel in channels:
            if _muted(session, user, event, channel):
                continue
            row = Notification(
                organization_id=organization_id, channel=channel, event=event,
                subject=subject[:300], body=body, locale=locale[:5],
                recipient_user_id=user.id,
                recipient_address=user.email if channel == "email" else None,
                finding_id=finding_id, ticket_id=ticket_id, payload=context,
            )
            session.add(row)
            created.append(row)

    for address in addresses or []:
        subject, body = render(event, settings.default_locale, context,
                               session, organization_id)
        row = Notification(
            organization_id=organization_id, channel="email", event=event,
            subject=subject[:300], body=body, recipient_address=address,
            finding_id=finding_id, ticket_id=ticket_id, payload=context,
        )
        session.add(row)
        created.append(row)

    if team_id is not None and not unique:
        # A team with no members is a routing hole, not a silent success.
        log.warning("notification %s targeted team %s which has no active members",
                    event, team_id)
    session.flush()
    return created


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------


def _send_email(notification: Notification) -> None:
    if not settings.smtp_host:
        raise RuntimeError("SMTP is not configured (VEYRS_SMTP_HOST)")
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = notification.recipient_address
    message["Subject"] = notification.subject
    message.set_content(notification.body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password or "")
        smtp.send_message(message)


TRANSPORTS: dict[str, Callable[[Notification], None]] = {
    # In-app messages are "delivered" the moment the row exists.
    "in_app": lambda notification: None,
    "email": _send_email,
}


def dispatch(
    session: Session,
    organization_id: uuid.UUID,
    *,
    limit: int = 200,
    max_attempts: int = 5,
) -> dict[str, int]:
    """Attempt delivery of pending notifications. Safe to call repeatedly."""
    rows = session.execute(
        select(Notification).where(
            Notification.organization_id == organization_id,
            Notification.status == "pending",
            Notification.attempts < max_attempts,
        ).order_by(Notification.created_at).limit(limit)
    ).scalars().all()

    stats = {"attempted": 0, "sent": 0, "failed": 0, "skipped": 0}
    for row in rows:
        transport = TRANSPORTS.get(row.channel)
        if transport is None:
            row.status = "failed"
            row.error = f"no transport for channel {row.channel}"
            stats["skipped"] += 1
            continue
        stats["attempted"] += 1
        row.attempts += 1
        try:
            transport(row)
        except Exception as exc:  # noqa: BLE001 - recorded on the row, not raised
            row.error = f"{type(exc).__name__}: {exc}"[:2000]
            # Give up permanently only after max_attempts, so a transient SMTP
            # outage does not silently drop a breach notice.
            row.status = "failed" if row.attempts >= max_attempts else "pending"
            stats["failed"] += 1
            continue
        row.status = "sent"
        row.sent_at = dt.datetime.now(dt.timezone.utc)
        row.error = None
        stats["sent"] += 1
    session.flush()
    return stats


def sign_webhook(secret: str, body: bytes, timestamp: str) -> str:
    """HMAC-SHA256 over `timestamp.body`, the standard replay-safe scheme."""
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode() + body, hashlib.sha256)
    return f"t={timestamp},v1={mac.hexdigest()}"


def webhook_targets(
    session: Session, organization_id: uuid.UUID, event: str
) -> list[WebhookEndpoint]:
    rows = session.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.organization_id == organization_id,
            WebhookEndpoint.is_enabled.is_(True),
        )
    ).scalars().all()
    # An endpoint with an empty event list subscribes to everything.
    return [r for r in rows if not r.events or event in r.events]


def unread_count(session: Session, user_id: uuid.UUID) -> int:
    rows = session.execute(
        select(Notification).where(
            Notification.recipient_user_id == user_id,
            Notification.channel == "in_app",
            Notification.read_at.is_(None),
        )
    ).scalars().all()
    return len(rows)


__all__ = [
    "BUILTIN_TEMPLATES", "SUPPORTED_LOCALES", "UNMUTABLE_EVENTS", "render", "queue",
    "dispatch", "sign_webhook", "webhook_targets", "team_members", "unread_count",
    "TRANSPORTS",
]
