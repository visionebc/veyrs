---
title: Notifications and digest
purpose: Document in-app and e-mail notifications, per-user preferences and the periodic digest.
scope: The `/notifications` routes and the notification and digest services; workflow `notify` actions are in ticketing-itsm.md.
version: 0.41.0
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/tickets.py, backend/veyrs/services/notifications.py, backend/veyrs/services/digest.py]
related: [functional/ticketing-itsm.md, functional/sla-escalation.md, api/reference/ticketing.md]
---

# Notifications and digest

## Notifications

Every message is a `Notification` row before any transport runs. Transports are `in_app` and `email` only (`services/notifications.py`). Locales: en, es, de, fr, it are accepted; built-in templates exist in all five only for `finding.created`, every other built-in event has en and es (`BUILTIN_TEMPLATES`, `services/notifications.py:46`). Delivery retries up to 5 attempts; e-mail is held while `notify_email_enabled` is false. `UNMUTABLE_EVENTS` (`sla.breached`, `sla.escalated`, `finding.kev_detected`) ignore user mute preferences.

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| My notifications | `GET /notifications` | authenticated | `tickets.py:673` | Verified |
| Mark read | `POST /notifications/{notification_id}/read` | authenticated | `:710` | Implemented |
| Dispatch pending | `POST /notifications/dispatch` | `notification:admin` | `:724` | Implemented |
| Read preferences | `GET /notifications/preferences` | authenticated | `:773` | Implemented |
| Write preferences | `PUT /notifications/preferences` | authenticated | `:797` | Implemented |

Data: `notifications`, notification preferences. Errors: 404 unknown notification; 422 unknown event or channel.

Defect: `webhook_targets` and `sign_webhook` (`services/notifications.py:311-327`) are called nowhere, so webhook delivery does not exist. Live: 7,819 notifications unread.

## Digest

A periodic summary per recipient, built under that recipient's own team scope (`services/digest.py`). Off by default; default hour 07 UTC, window 24 h, minimum severity high; empty digests are not sent. The hourly timer asks `due_now`, with a 12 h double-fire guard that is now backed by a lock: `veyrs digest` takes a PostgreSQL advisory lock per organization (`pg_try_advisory_xact_lock`), re-reads `last_run_at` under it and skips the organization if another run holds the lock or has just sent, so two nodes running the timer cannot both send. Queued e-mail of every kind is dispatched by the hourly tick, not only by the digest (see [Notifications](../integrations/notifications.md)).

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| Read config | `GET /notifications/digest` | `notification:read` | `tickets.py:834` | Verified |
| Update config | `PUT /notifications/digest` | `notification:admin` | `:845` | Implemented |
| Preview | `POST /notifications/digest/preview` | `finding:read` | `:873` | Implemented |
| Send | `POST /notifications/digest/send` | `notification:admin` | `:890` | Implemented |

`send` defaults to `dry_run=true`. Live: digest enabled, in-app channel only, 2 recipients.
