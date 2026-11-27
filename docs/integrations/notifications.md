---
title: Notifications, digest and AI providers
purpose: Document how VEYRS tells people things (in-app, e-mail, digest, Telegram codes), which locales exist, how delivery actually happens, and how AI providers and the AI gateway are configured.
scope: Covers the notification queue, channels, templates and locales, the daily digest and its timer, outbound webhook and Slack status, and AI provider kinds, policy and gateway order. AI threat modelling is in AI_SECURITY.md.
version: 0.41.0
verified: 2026-11-17
status: Partial
sources: [backend/veyrs/services/notifications.py, backend/veyrs/services/digest.py, backend/veyrs/security/mfa_delivery.py, backend/veyrs/api/v1/tickets.py, backend/veyrs/models/workflow.py, backend/veyrs/services/ai/gateway.py, backend/veyrs/services/ai/providers.py, backend/veyrs/models/ai.py, backend/veyrs/api/v1/ai.py, backend/veyrs/config.py, infrastructure/systemd/veyrs-digest.timer, infrastructure/systemd/veyrs-digest.service, scripts/send-digest.sh]
related: [integrations/README.md, integrations/automation.md, AI_SECURITY.md, ADRs/0003-ai-gateway.md, reference/configuration.md, INTEGRATIONS.md]
---

# Notifications, digest and AI providers

## Channels

| Channel | Transport | Status |
|---|---|---|
| `in_app` | The `notifications` row is the message; "delivered" the moment it exists | Verified |
| `email` | SMTP, `smtplib`, 15 s timeout, optional STARTTLS and login | Implemented |
| `webhook`, `slack` | **None.** Offered as choices by the workflow builder, but `TRANSPORTS` has only `in_app` and `email` | Planned |
| Telegram | Only for MFA sign-in codes (see [Telegram](#telegram)); not a notification channel | Partial |

### How a notification is produced and delivered

Nothing is fire-and-forget: every message is a `Notification` row (`status` `pending`, then `sent` or `failed`) before any transport is tried.

1. **Produced** by `notifications.queue(event, context, users|team|addresses, channels)`. Callers are the workflow `notify` action ([Automation](automation.md#actions)) and the digest. Recipients are de-duplicated (a user on two notified teams gets one message). A team with no active members is logged as a routing hole.
2. **Template** resolved per recipient: a tenant override row in `notification_templates` (`slug` = event, `locale`), else the built-in template for the user's locale, else the English built-in, else a generic `[VEYRS] <event>` plus the JSON context. Placeholders are filled with `format_map`; a missing key renders empty so a template typo never stops a breach notice.
3. **Muting**: per-user preferences (`PUT /notifications/preferences`, per event and channel) apply to routine events. `sla.breached`, `sla.escalated` and `finding.kev_detected` are in `UNMUTABLE_EVENTS` and ignore them.
4. **Delivered** by `notifications.dispatch(session, organization_id, limit=200, max_attempts=5)`: for each pending row the transport is called; success sets `sent`; failure records `error`, keeps `pending` until the fifth attempt, then `failed`. A channel with no transport is marked `failed` immediately (`no transport for channel webhook`).

**Dispatch runs on the hourly tick** (since 0.41.0). `scripts/sync-intel.sh` ends with `veyrs maintenance`, whose first step calls `dispatch` for every active organization, so SLA breach, escalation and workflow e-mails leave within about an hour whether or not the digest is enabled. Other callers: `veyrs digest` (right after queuing its own rows) and the two operator routes `POST /notifications/dispatch` and `POST /notifications/digest/send`.

- **No double send.** The batch is selected `FOR UPDATE SKIP LOCKED`, so a tick and a digest run (or two nodes) that overlap never pick the same row; the lock lasts until the caller commits, by which time the row is `sent`.
- **E-mail is held, not burned, while it cannot go out.** The tick passes `hold_email` when `VEYRS_SMTP_HOST` is empty, and `VEYRS_NOTIFY_EMAIL_ENABLED=false` holds e-mail everywhere: the rows stay `pending` with `attempts` untouched, instead of failing five times in five hours. Set the relay (or re-enable) and the backlog drains on the next tick, up to 200 rows per organization per tick.
- In-app notifications are readable immediately (the list route reads rows regardless of `status`); dispatch marks them `sent`.
- Delivery is at-least-once: a process that dies after the relay accepted a message and before the commit sends it again on the next tick.

`VEYRS_NOTIFY_EMAIL_ENABLED=false` holds all e-mail **notifications** (the tick respects it) in the queue (they stay `pending`, attempts untouched) while SMTP still carries sign-in codes. Links in templates are relative paths (`/findings/<id>`, `/tickets/<id>`); `VEYRS_PUBLIC_BASE_URL` is validated as HTTPS but is not used to build them.

### E-mail

Settings (see [Configuration reference](../reference/configuration.md)): `VEYRS_SMTP_HOST` (empty means e-mail is not configured and every send raises), `VEYRS_SMTP_PORT` (25), `VEYRS_SMTP_USER`, `VEYRS_SMTP_PASSWORD`, `VEYRS_SMTP_FROM`, `VEYRS_SMTP_STARTTLS` (true). The transport is plain `smtplib.SMTP` with `STARTTLS`; implicit TLS on port 465 (`SMTP_SSL`) is not supported. The relay is shared with MFA code delivery.

```bash
# Flush the pending notification queue now (also the way to test the SMTP relay end to end).
# Prerequisite: a token holding notification:admin. Returns {attempted, sent, failed, skipped}.
curl -sS -X POST "https://veyrs.example.com/api/v1/notifications/dispatch" -H "Authorization: Bearer $TOKEN"
```

### Telegram

`VEYRS_TELEGRAM_BOT_TOKEN`, `VEYRS_TELEGRAM_API_URL` (default `https://api.telegram.org`) and `VEYRS_TELEGRAM_BOT_USERNAME` configure a bot that sends **MFA sign-in codes** to a chat id the user registered and proved at enrolment (`security/mfa_delivery.py`: `POST {api}/bot<token>/sendMessage`, 10 s timeout). The code is sent only after the password verified, is single-use, lives in Redis for `VEYRS_MFA_CODE_TTL` seconds (default 300, 60 to 900), and sending is throttled to one message per 30 s and six per 15 minutes per account. There is no Telegram transport for notifications or the digest. Detail belongs to the security documentation.

### Outbound webhooks and Slack

**Status: Partial, effectively not usable.** The code contains `WebhookEndpoint` (`webhook_endpoints`: `url`, `events`, encrypted `secret_enc`, `last_status`), `notifications.sign_webhook` (HMAC-SHA256 over `<timestamp>.<body>`, header value `t=<ts>,v1=<hex>`) and `webhook_targets()` (enabled endpoints whose `events` is empty or contains the event). But no route creates or edits an endpoint, no transport sends to one, and nothing calls `webhook_targets` or `sign_webhook` (a unit test, `test_webhook_signature_is_stable_and_replay_scoped`, exercises only the signer). The generic ITSM `webhook` connector is a different mechanism: it pushes tickets with an optional bearer token, **not** an HMAC signature ([ITSM](itsm-and-webhooks.md)). The workflow builder's `webhook` and `slack` channel options queue rows that `dispatch` then marks `failed`.

## Locales

Five locales: `en`, `es`, `de`, `fr`, `it` (`SUPPORTED_LOCALES`; `VEYRS_DEFAULT_LOCALE`, organization `default_locale`, per-user `locale`). The locale is chosen per recipient, and the AI gateway adds a matching "answer in ..." instruction.

Built-in **template coverage is not five-locale across the board**:

| Event | Locales with a built-in template |
|---|---|
| `finding.created` | en, es, de, fr, it |
| `finding.assigned`, `sla.warned`, `sla.breached`, `sla.escalated`, `ticket.created`, `ticket.state_changed`, `digest.daily` | en, es |

A recipient whose locale has no template for an event receives the English one. A tenant can override any (event, locale) pair with a `notification_templates` row, but **there is no API route to manage those rows**; they can only be written to the database. The digest body itself (`render_body`) is English only; only its subject line is localised, and only for `en` and `es`.

Built-in event keys: `finding.created`, `finding.assigned`, `sla.warned`, `sla.breached`, `sla.escalated`, `ticket.created`, `ticket.state_changed`, `digest.daily`. `finding.assigned` and `finding.kev_detected` are defined for templates and muting but no code emits them; a workflow `notify` step can name them as its `event`.

## Daily digest

`services/digest.py`: VEYRS goes and finds the operator. **Off by default, per organization.**

| Setting (`organizations.settings.digest`) | Default | Range |
|---|---|---|
| `enabled` | false | |
| `hour` | 7 | 0 to 23, **UTC** |
| `window_hours` | 24 | 1 to 168 |
| `min_severity` | `high` | `critical`, `high`, `medium`, `low`, `info`, `none` |
| `channels` | `["in_app","email"]` | each must have a transport; not empty |
| `include_sla`, `include_unassigned` | true | |

Behaviour:

- **Recipients** are active users who hold `finding:read` (or are superusers), computed from permissions and not from team membership.
- **Each digest is built under the recipient's own team scope**, and says so when restricted ("These figures cover your teams only").
- **An empty digest is not sent** (every count zero), except under `force`.
- Content: counts of new findings at or above `min_severity` in the window, past-SLA, open KEV, never-triaged and open tickets, plus the top 8 new and top 8 breached findings. Plain text.
- **Due logic** (`due_now`): enabled, the current UTC hour equals `hour`, and the last run was at least 12 hours ago.

```text
veyrs-digest.timer (OnCalendar=hourly, RandomizedDelaySec=300, Persistent=true)
  -> veyrs-digest.service (oneshot, TimeoutStartSec=600, OOMPolicy=continue)
    -> scripts/send-digest.sh -> python -m veyrs digest
```

The timer is a tick, not a schedule: pinning `OnCalendar` to one hour would make the console setting decorative. The service exits 0 when nothing was due. Containers run it as service `digest` (`docker/tick.sh digest 3600 300`, profile `workers`).

```bash
# On an app node, as root. Build every digest and report; send nothing.
cd /opt/veyrs/backend && set -a && . ../.env && set +a
PYTHONPATH=. ../venv/bin/python -m veyrs digest --dry-run
# --force ignores the enabled flag and the hour (an operator asking now). Per-user mutes still apply.
```

| Route | Permission | Notes |
|---|---|---|
| `GET /notifications/digest`, `PUT /notifications/digest` | `notification:read`, `notification:admin` | The policy. |
| `POST /notifications/digest/preview` | `finding:read` | Built by the same function as the sender, under the caller's scope. |
| `POST /notifications/digest/send?dry_run=true` | `notification:admin` | `dry_run` defaults to **true**; refused to team-scoped identities. A real send also dispatches and is audited as `digest.send`. |
| `GET /notifications`, `POST /notifications/{id}/read`, `GET`/`PUT /notifications/preferences` | any signed-in user | The caller's own. |

Verified node: digest enabled, hour 7, channel `in_app` only, last run `2026-11-16T07:02Z`, 2 recipients.

## AI providers

All model use passes through one door, `services/ai/gateway.invoke()` ([ADR 0003](../ADRs/0003-ai-gateway.md)). No other code calls a provider.

### Provider kinds

| `kind` | Endpoint | Auth | External? |
|---|---|---|---|
| `deterministic` | none; re-presents the VEYRS facts block, no model | none | never; the fallback for every failure |
| `ollama` | `POST {base}/api/chat`, `stream:false`, **`think:false`**, `temperature`, `num_predict` | none | operator's choice (`is_external`); default base `http://127.0.0.1:11434` |
| `openai_compatible` | `POST {base}/v1/chat/completions` | `Authorization: Bearer` | operator's choice (a self-hosted gateway may be internal) |
| `openai` | same, default base `https://api.openai.com` | Bearer | always external |
| `anthropic` | `POST {base}/v1/messages`, header `anthropic-version: 2023-06-01`, `x-api-key` | key | always external |
| `gemini` | `POST {base}/v1beta/models/{model}:generateContent`, `x-goog-api-key` | key | always external |

`think:false` matters: reasoning models otherwise return their thinking in a separate field and an empty `content`, which reads as "the model returned nothing". Reasoning blocks (`<think>`, `<thinking>`, `<reasoning>`) are also stripped from replies. The gateway treats `openai`, `anthropic` and `gemini` as external whatever `is_external` says (`INHERENTLY_EXTERNAL`); the create route requires `is_external` explicitly. API keys are stored encrypted (`api_key_enc`) and the list route returns only a masked form.

Provider settings per row: `slug`, `name`, `kind`, `model`, `base_url`, `is_external`, `is_enabled`, `is_default`, `capabilities` (empty means all), `timeout_seconds` (1 to 600, default 60), `temperature` (0 to 2, default 0.1), `max_output_tokens` (64 to 32,000, default 1,500).

### Gateway order

1. Capability known and not in `disabled_capabilities`. There are 13 capabilities: `cve_analysis, advisory_analysis, document_analysis, risk_explanation, remediation_advice, ticket_draft, article_draft, threat_summary, nl_search, classify_vulnerability, classify_product, suggest_team, assistant`.
2. The **caller already holds** the permission the capability maps to (`cve:read`, `intel:read`, `document:read`, `risk:read`, `finding:read`, `ticket:write`, `knowledge:write`, `ai:read`, `vulnerability:read`, `product:read`). The model never grants access.
3. Budget: prompt at most `max_prompt_chars` (default 24,000) and fewer than `daily_call_limit` (default 2,000, a rolling 24 hours, blocked calls not counted).
4. Sanitise: secrets and PII stripped per policy; injection signals scored, and the call is blocked when signals are detected and `block_on_injection` is on.
5. Provider selection: enabled providers ordered default first, then internal before external, then creation order; the first whose policy permits the data classification wins.
6. Call. On `ProviderError` the gateway **degrades** to `deterministic` instead of failing. With no eligible provider it also answers deterministically (decision `degraded`).
7. Output guard scans the reply for secrets.
8. An `ai_audit_log` row is written for allowed, degraded and blocked calls alike (`GET /ai/audit`, `audit:read`).

External payloads additionally have internal (RFC 1918) addresses redacted on the way out.

### Policy (`ai_policies`, one row per organization)

The absent-row defaults are restrictive:

| Field | Default |
|---|---|
| `allow_external` | `VEYRS_AI_ALLOW_EXTERNAL` (false) |
| `allow_local` | `VEYRS_AI_ALLOW_LOCAL` (true) |
| `max_external_classification` | `public` |
| `max_local_classification` | `VEYRS_AI_MAX_DATA_CLASSIFICATION` (`internal`) |
| `allowed_providers`, `allowed_models`, `disabled_capabilities` | empty (no restriction) |
| `redact_secrets`, `redact_pii`, `block_on_injection` | true |
| `max_prompt_chars`, `daily_call_limit` | 24,000; 2,000 |

Classification ladder: `public` < `internal` < `confidential` < `restricted`. `PUT /ai/policy` and provider create or delete need `ai:admin`; reads need `ai:read`. Routes: `/ai/policy`, `/ai/providers`, `/ai/capabilities`, `/ai/ask`, `/ai/search` (+ `/ai/search/grammar`), `/ai/cve/{id}/analysis`, `/ai/findings/{id}/explain|remediation|ticket-draft|suggest-team`, `/ai/threat-summary`, `/ai/conversations`, `/ai/audit`, `/ai/scan`. See [AI API](../api/reference/ai.md) and [AI security](../AI_SECURITY.md).

Verified node: four `ollama` providers, all internal, one default; external providers disallowed by the deployment setting.

## Sources

- Queue, templates, dispatch: `services/notifications.py` (`BUILTIN_TEMPLATES`, `UNMUTABLE_EVENTS`, `dispatch`).
- Digest: `services/digest.py`; routes `api/v1/tickets.py:834-905`.
- Webhook helpers: `services/notifications.py:311-330`, `models/workflow.py:152`.
- AI: `services/ai/gateway.py`, `services/ai/providers.py:369-390`, `models/ai.py`.
