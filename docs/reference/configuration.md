---
title: Configuration reference
purpose: Every environment variable the VEYRS process reads, generated from `Settings`.
scope: Names, types, defaults and the modules that read each value. How to choose values is in the deployment and system manuals.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/config.py]
related: [SYSTEM_MANUAL.md, DEPLOYMENT.md, DOCKER_COMPOSE_MANUAL.md]
---

# Configuration reference

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


**74 settings.** Each is read from the environment as `VEYRS_<NAME>` (case-insensitive) or from a `.env` file in the working directory; unknown variables are ignored (`extra="ignore"`). Secret-like defaults are shown as *(redacted)*. "Read by" lists the backend modules that reference the setting by name (a static scan: a value read through another name is missed).

> [!WARNING]
> `VEYRS_SECRET_KEY` and `VEYRS_ENCRYPTION_KEY` have no usable default: production refuses to start without them, and losing the encryption key makes stored third-party credentials unreadable.

## Identity

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_APP_NAME` | `str` | `VEYRS` | - | `veyrs/api/v1/auth.py`, `veyrs/main.py`, `veyrs/security/auth.py`, `veyrs/services/reporting.py` |
| `VEYRS_VERSION` | `str` | the release version (kept equal to `pyproject.toml`) | - | `veyrs/__init__.py`, `veyrs/cli.py`, `veyrs/intel/feeds.py`, `veyrs/main.py`, `veyrs/observability.py`, `veyrs/services/reporting.py`, `veyrs/services/software_inventory.py`, `veyrs/services/updates.py` |
| `VEYRS_ENVIRONMENT` | `Literal['development', 'staging', 'production']` | `development` | - | `veyrs/cli.py`, `veyrs/main.py`, `veyrs/observability.py` |
| `VEYRS_DEBUG` | `bool` | `False` | - | `veyrs/main.py`, `veyrs/security/tenant_guard.py` |

## Crypto / sessions

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_SECRET_KEY` | `str` | empty | - | `veyrs/security/auth.py`, `veyrs/security/secrets.py` |
| `VEYRS_ENCRYPTION_KEY` | `str` | empty | Fernet key for reversible secrets at rest (see security/secrets.py). Empty => derived from secret_key, which is fine for dev and refused in prod. | - |
| `VEYRS_ENCRYPTION_KEY_PREVIOUS` | `str` | empty | Earlier `VEYRS_ENCRYPTION_KEY` values, comma-separated, used to DECRYPT only. Set it while rotating the key so rows sealed under the old key stay readable until `veyrs secrets rekey --apply` has re-sealed them under `encryption_key`; then remove it. Never used to encrypt. | - |
| `VEYRS_SECRET_BACKEND` | `Literal['local', 'mirror', 'vault']` | `local` | Where reversible secrets live (security/secret_vault.py). `local` keeps them in the database under the Fernet key above and never contacts a vault; `mirror` writes both and reads the vault first; `vault` keeps the vault as the only copy. The vault's own settings below are deliberately environment-only: storing them in the database, encrypted by the very key this exists to take off the host, would protect nothing. | `veyrs/services/network_requirements.py` |
| `VEYRS_VAULT_ADDR` | `str` | empty | - | `veyrs/security/secret_vault.py`, `veyrs/services/network_requirements.py` |
| `VEYRS_VAULT_MOUNT` | `str` | `veyrs` | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_AUTH` | `Literal['approle', 'token']` | `approle` | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_ROLE_ID` | `str` | empty | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_SECRET_ID_FILE` | `str` | empty | Paths to 0600 files, never the values: an environment variable is readable in /proc/<pid>/environ and in every `docker inspect`. | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_TOKEN_FILE` | `str` | empty | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_CA_FILE` | `str` | empty | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_NAMESPACE` | `str` | empty | - | `veyrs/security/secret_vault.py` |
| `VEYRS_VAULT_TIMEOUT` | `float` | `5.0` | - | `veyrs/security/secret_vault.py` |
| `VEYRS_ACCESS_TOKEN_MINUTES` | `int` | `30` | - | `veyrs/security/auth.py` |
| `VEYRS_REFRESH_TOKEN_DAYS` | `int` | `14` | - | `veyrs/security/auth.py` |
| `VEYRS_JWT_ALGORITHM` | `Literal['HS256', 'HS384', 'HS512']` | `HS256` | - | `veyrs/security/auth.py` |
| `VEYRS_PASSWORD_MIN_LENGTH` | `int` | `12` | - | `veyrs/cli.py`, `veyrs/security/auth.py` |
| `VEYRS_LOCKOUT_EXEMPT_NETWORKS` | `str` | empty | Comma-separated CIDR networks (e.g. an office or a jump host) whose sign-ins are never refused by the ACCOUNT-wide lock that a distributed guessing attack can trigger (security/lockout.py). The per-source back-off still applies to them. Empty = no exemption. | `veyrs/security/lockout.py` |

## API surface / outbound network

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_EXPOSE_OPENAPI` | `bool` | `False` | Serve /docs, /redoc and the OpenAPI schema in production. Off by default: the schema is a map of every route. Always served in development. | `veyrs/main.py` |
| `VEYRS_OUTBOUND_ALLOW_PRIVATE` | `bool` | `True` | Allow outbound connectors (CMDB, ITSM, scanners, Confluence, AI providers, webhooks) to reach private/RFC1918 addresses. On-premise deployments need it (NetBox, Jira on the LAN); set false for a cloud deployment that should only reach public services. Link-local and cloud metadata addresses are refused regardless. | `veyrs/services/net_guard.py` |
| `VEYRS_OUTBOUND_ALLOW_LOOPBACK` | `bool` | `False` | Also allow loopback (127.0.0.0/8, ::1). Off: a connector pointed at the VEYRS host itself is almost always a mistake or an SSRF probe. | `veyrs/services/net_guard.py` |

## Storage

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_DATABASE_URL` | `str` | *(redacted)* | - | `veyrs/db.py`, `veyrs/services/network_requirements.py`, `veyrs/services/software_inventory.py`, `veyrs/services/updates.py` |
| `VEYRS_REDIS_URL` | `str` | *(redacted)* | - | `veyrs/cli.py`, `veyrs/main.py`, `veyrs/security/mfa_delivery.py`, `veyrs/security/ratelimit.py`, `veyrs/services/network_requirements.py`, `veyrs/services/software_inventory.py` |
| `VEYRS_DB_POOL_SIZE` | `int` | `8` | Per-worker SQLAlchemy pool. The ceiling is workers x (pool_size + max_overflow): 4 x (8 + 12) = 80, under PostgreSQL's default max_connections of 100 with headroom for the CLI, timers and the agent. | `veyrs/db.py` |
| `VEYRS_DB_MAX_OVERFLOW` | `int` | `12` | - | `veyrs/db.py` |

## Api surface

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_API_PREFIX` | `str` | `/api/v1` | - | `veyrs/api/v1/auth.py`, `veyrs/main.py`, `veyrs/security/deps.py` |
| `VEYRS_CORS_ORIGINS` | `str` | empty | Browser origins allowed to call the API cross-origin. Empty = none, which is right whenever the console is served from the API's own host. | - |
| `VEYRS_RATE_LIMIT_PER_MINUTE` | `int` | `240` | - | `veyrs/security/ratelimit.py` |
| `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | `int` | `10` | Strict budget for /auth/* , keyed per source IP. Deliberately separate: this is credential-stuffing defence and must bite long before the general limit. Raise it for offices that egress behind one NAT address, where 50 analysts signing in at 09:00 legitimately exceed the default. | `veyrs/security/ratelimit.py` |
| `VEYRS_METRICS_TOKEN` | `str` | empty | Bearer token required to read /metrics. Unset means the endpoint is open in development and refused outright in production - the exposition maps the whole API surface, so it is not public data. | `veyrs/main.py` |

## Intelligence feeds (all optional; the platform degrades, never breaks)

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_NVD_API_KEY` | `str` | empty | - | `veyrs/intel/feeds.py` |
| `VEYRS_NVD_API_URL` | `str` | *(redacted)* | - | `veyrs/intel/feeds.py` |
| `VEYRS_EPSS_CSV_URL` | `str` | *(redacted)* | - | `veyrs/intel/feeds.py` |
| `VEYRS_KEV_JSON_URL` | `str` | *(redacted)* | - | `veyrs/intel/feeds.py` |
| `VEYRS_CWE_CATALOG_URL` | `str` | *(redacted)* | - | `veyrs/intel/feeds.py` |
| `VEYRS_FEED_HTTP_TIMEOUT` | `int` | `60` | - | `veyrs/intel/feeds.py` |
| `VEYRS_EPSS_HISTORY_DAYS` | `int` | `365` | Days of daily EPSS snapshots kept in `epss_history`, counted back from the newest scored day (not from today). A scored day is ~370,000 rows, about 80 MB: unpruned, the table grew ~30 GB a year. 0 keeps everything. | `veyrs/cli.py`, `veyrs/intel/feeds.py` |

## Retention (`veyrs prune`, run by the hourly tick). 0 keeps everything.

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_RETENTION_AUDIT_DAYS` | `int` | `400` | audit_log, ai_audit_log and auth_events. A row younger than this is never deleted. | - |
| `VEYRS_RETENTION_TOKENS_DAYS` | `int` | `30` | refresh_tokens: deleted this many days after they expired or were revoked. | - |
| `VEYRS_RETENTION_NOTIFICATIONS_DAYS` | `int` | `90` | notifications: read ones, and delivered/failed e-mail/webhook rows. | - |
| `VEYRS_RETENTION_RUNS_DAYS` | `int` | `180` | workflow_runs, feed_runs, import_runs, asset_source_runs, finished agent_job_events. | - |
| `VEYRS_RETENTION_EVENTS_DAYS` | `int` | `730` | finding_events, sla_events, risk_score_history of findings that are no longer open. | - |
| `VEYRS_RETENTION_ARTICLES_DAYS` | `int` | `365` | threat_articles (by publication date). | - |
| `VEYRS_TICK_STALE_MINUTES` | `int` | `180` | Minutes without a successful hourly tick after which /intel/health reports it stale. | `veyrs/services/tick.py` |

## AI gateway

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_AI_ALLOW_EXTERNAL` | `bool` | `False` | - | `veyrs/services/ai/gateway.py`, `veyrs/services/network_requirements.py` |
| `VEYRS_AI_ALLOW_LOCAL` | `bool` | `True` | - | `veyrs/services/ai/gateway.py` |
| `VEYRS_AI_MAX_DATA_CLASSIFICATION` | `Literal['public', 'internal', 'confidential', 'restricted']` | `internal` | - | `veyrs/services/ai/gateway.py` |

## Notifications

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_SMTP_HOST` | `str` | empty | - | `veyrs/security/mfa_delivery.py`, `veyrs/services/network_requirements.py`, `veyrs/services/notifications.py`, `veyrs/services/tick.py` |
| `VEYRS_SMTP_PORT` | `int` | `25` | - | `veyrs/security/mfa_delivery.py`, `veyrs/services/network_requirements.py`, `veyrs/services/notifications.py` |
| `VEYRS_SMTP_USER` | `str` | empty | - | `veyrs/security/mfa_delivery.py`, `veyrs/services/notifications.py` |
| `VEYRS_SMTP_PASSWORD` | `str` | empty | - | `veyrs/security/mfa_delivery.py`, `veyrs/services/notifications.py` |
| `VEYRS_SMTP_FROM` | `str` | empty | Required in production whenever smtp_host is set. | `veyrs/security/mfa_delivery.py`, `veyrs/services/notifications.py` |
| `VEYRS_SMTP_STARTTLS` | `bool` | `True` | - | `veyrs/security/mfa_delivery.py`, `veyrs/services/notifications.py` |
| `VEYRS_PUBLIC_BASE_URL` | `str` | empty | The console's public URL (links in notifications). Required, https, in production. | `veyrs/services/digest.py` |
| `VEYRS_NOTIFY_EMAIL_ENABLED` | `bool` | `True` | False holds every e-mail NOTIFICATION in the queue (it stays `pending`) while SMTP still carries two-factor codes. For turning on sign-in codes without releasing a backlog of old notifications in the same minute. | `veyrs/services/network_requirements.py`, `veyrs/services/notifications.py`, `veyrs/services/tick.py` |
| `VEYRS_NOTIFY_EMAIL_MAX_AGE_HOURS` | `int` | `48` | A notification e-mail still queued this many hours after it was created is not sent but marked `expired` (0 = no limit). After a dispatch outage (or an upgrade that starts dispatching, 0.41.0) a backlog of stale SLA and escalation mail must not reach people in one burst; the in-app copy of each event is unaffected. | `veyrs/services/notifications.py` |

## Two-factor delivery (security/mfa_delivery.py)

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_TELEGRAM_BOT_TOKEN` | `str` | empty | A Telegram bot token (from @BotFather). Empty = Telegram codes are not offered. | `veyrs/security/mfa_delivery.py`, `veyrs/services/network_requirements.py` |
| `VEYRS_TELEGRAM_API_URL` | `str` | *(redacted)* | - | `veyrs/security/mfa_delivery.py` |
| `VEYRS_TELEGRAM_BOT_USERNAME` | `str` | empty | Shown in the console so people know which bot to open (e.g. VeyrsBot). | `veyrs/api/v1/auth.py` |
| `VEYRS_MFA_CODE_TTL` | `int` | `300` | Lifetime of an e-mail / Telegram code, in seconds. | `veyrs/api/v1/auth.py`, `veyrs/security/mfa_delivery.py` |

## I18n

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_DEFAULT_LOCALE` | `Literal['en', 'es', 'de', 'fr', 'it']` | `en` | - | `veyrs/services/notifications.py` |

## Software updates (services/updates.py, scripts/veyrs-updater.sh)

| Variable | Type | Default | Description | Read by |
|---|---|---|---|---|
| `VEYRS_UPDATE_URL` | `str` | *(redacted)* | Where the "is there a newer release?" check asks. EMPTY disables every network check -- the setting for an air-gapped installation. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_DOWNLOAD_BASE` | `str` | `https://github.com/visionebc/veyrs/releases/download` | Base the root updater downloads release assets from (`<base>/v<X.Y.Z>/<asset>`). | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_SPOOL` | `str` | `/var/lib/veyrs/update-requests` | The API only WRITES a request here; the root `veyrs-updater.path` unit acts on it. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_LOCAL_DIR` | `str` | empty | A directory the root updater may install a release FROM (a USB disk, an NFS share): <dir>/v<X.Y.Z>/, <dir>/veyrs-<X.Y.Z>/ or the files in <dir>/. Empty = off. Not under /home or /root: the API cannot read those. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_UPLOAD_DIR` | `str` | empty | Where console uploads are staged. Empty = <install>/var/update-uploads, the one directory the API may write. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_STATUS_DIR` | `str` | `/var/lib/veyrs/update-status` | Where the updater leaves one JSON per run (steps, outcome) for the console. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_PRE_HOOK` | `str` | empty | Command the updater runs before touching anything (e.g. scripts/backup.sh). Without it, or `update_skip_backup`, the updater refuses to update. | `veyrs/services/updates.py` |
| `VEYRS_UPDATE_SKIP_BACKUP` | `bool` | `False` | - | `veyrs/services/updates.py` |
| `VEYRS_INSTALL_MODE` | `str` | empty | `git` \| `docker` \| `native`; empty = detected. A `.git` in the install root always wins: that tree is managed by a git deploy, never self-updated. | `veyrs/services/updates.py` |
