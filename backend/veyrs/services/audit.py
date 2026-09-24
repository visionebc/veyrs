"""Audit-trail writer.

Every mutating service calls `record()`. It never raises into the caller: losing
an audit row must not roll back a legitimate business transaction, but it MUST
be visible, so failures are logged at ERROR with the payload digest.
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

from sqlalchemy.orm import Session

from ..models.audit import AiAuditLog, AuditLog, AuthEvent

log = logging.getLogger("veyrs.audit")

REDACT_KEYS = {
    "password", "password_hash", "secret", "token", "key_hash", "mfa_secret",
    "api_key", "authorization", "smtp_password", "private_key",
}


#: Types psycopg can put in a JSONB column without help. Anything else has to
#: be rendered, because the failure is not a warning: it is a 500 at
#: `session.commit()`, AFTER the business change has already been flushed, so
#: the operation is lost and the audit entry that was supposed to record it is
#: what killed it.
_JSON_NATIVE = (str, int, float, bool, type(None))


def _renderable(value: Any) -> Any:
    """Make one value safe for JSONB, recursively.

    A `uuid.UUID` is the case that bit: every ownership column in this schema is
    one, so `audit.diff({"team_id": <UUID>}, ...)` -- the obvious thing for a
    caller to write -- raised *Object of type UUID is not JSON serializable*
    inside the commit. Fixed here rather than at the call site: there are dozens
    of `audit.record` callers and the next one to hand over an id would hit the
    identical wall.

    Datetimes go to ISO-8601 and everything else to `str()`. Rendering beats
    dropping: an audit entry that quietly omits the field that changed is worse
    than one that spells it slightly differently.
    """
    if isinstance(value, _JSON_NATIVE):
        return value
    if isinstance(value, dict):
        return {str(k): _renderable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_renderable(v) for v in value]
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    return str(value)


def scrub(payload: dict[str, Any]) -> dict[str, Any]:
    """Strip anything that looks like a credential, and render the rest."""
    out: dict[str, Any] = {}
    for key, value in (payload or {}).items():
        if key.lower() in REDACT_KEYS or any(r in key.lower() for r in ("password", "secret", "token")):
            out[key] = "[redacted]"
        elif isinstance(value, dict):
            out[key] = scrub(value)
        else:
            out[key] = _renderable(value)
    return out


def diff(before: dict[str, Any] | None, after: dict[str, Any] | None) -> dict[str, Any]:
    """Field-level change set, ready for the `changes` column."""
    before, after = scrub(before or {}), scrub(after or {})
    changes: dict[str, Any] = {}
    for key in set(before) | set(after):
        old, new = before.get(key), after.get(key)
        if old != new:
            changes[key] = {"from": old, "to": new}
    return changes


def record(
    session: Session,
    *,
    action: str,
    object_type: str,
    object_id: Any = None,
    object_label: str | None = None,
    organization_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    actor_label: str = "system",
    changes: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> None:
    try:
        session.add(
            AuditLog(
                organization_id=organization_id,
                actor_id=actor_id,
                actor_label=actor_label,
                action=action,
                object_type=object_type,
                object_id=str(object_id) if object_id is not None else None,
                object_label=object_label,
                changes=scrub(changes or {}),
                correlation_id=correlation_id,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        session.flush()
    except Exception:  # noqa: BLE001 - audit must not break the request
        log.exception("audit write failed action=%s object=%s", action, object_type)


def record_auth(
    session: Session,
    *,
    event: str,
    success: bool,
    email_attempted: str | None = None,
    user_id: uuid.UUID | None = None,
    organization_id: uuid.UUID | None = None,
    reason: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    correlation_id: str | None = None,
) -> None:
    try:
        session.add(
            AuthEvent(
                event=event, success=success, email_attempted=email_attempted,
                user_id=user_id, organization_id=organization_id, reason=reason,
                ip_address=ip_address, user_agent=user_agent, correlation_id=correlation_id,
            )
        )
        session.flush()
    except Exception:  # noqa: BLE001
        log.exception("auth audit write failed event=%s", event)


def record_ai(session: Session, **kwargs: Any) -> None:
    try:
        session.add(AiAuditLog(**kwargs))
        session.flush()
    except Exception:  # noqa: BLE001
        log.exception("ai audit write failed")
