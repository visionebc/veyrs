---
title: Architecture overview
purpose: Explain how VEYRS is layered, which processes run, and which architectural patterns hold the design together, so an engineer can predict where a change belongs.
scope: The backend, the console, the background processes and the static sites as of 0.39.1; deployment topology is in deployment.md and diagrams are in c4.md.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/main.py, backend/veyrs/db.py, backend/veyrs/api/v1/__init__.py, backend/veyrs/security/deps.py, backend/veyrs/observability.py, backend/veyrs/cli.py, infrastructure/systemd/veyrs-api.service, integrations/systemd/veyrs-intel-sync.timer, scripts/sync-intel.sh]
related: [architecture/c4.md, architecture/dependencies.md, architecture/data-flows.md, architecture/sequences.md, architecture/deployment.md, ARCHITECTURE.md, reference/glossary.md]
---

# Architecture overview

VEYRS is a single Python application (FastAPI, SQLAlchemy 2, PostgreSQL 15 with row level security, Redis) plus a static JavaScript console, a handful of systemd timers or container loops that call its command line, an optional scan agent, and two static-site generators. There is no message broker and no task queue: background work is a command-line invocation on an hourly tick, and the one queue (scan jobs) is a database table.

Terms are defined in the [glossary](../reference/glossary.md). Counts below come from the machine-generated extracts of the 0.39.0 code, whose backend 0.39.1 leaves unchanged apart from the version string: 89 tables, 336 routes (330 documented operations over 266 paths), 116 permissions, 60 settings.

## 1. Layers

The backend package is `backend/veyrs/`. Requests flow top to bottom.

| Layer | Path | Responsibility | Size |
|---|---|---|---|
| Composition root | `main.py` | Builds the ASGI app: middleware, error handlers, `/healthz`, `/readyz`, `/metrics`, mounts the v1 router. No business logic. | 185 lines |
| HTTP | `api/v1/*.py` | Routers: path, validation (Pydantic), authorization (`require("perm")`), call into services, shape the response. 24 routers assembled in `api/v1/__init__.py`. | 27 files |
| Security | `security/*.py` | Principal resolution (JWT or API key), permission expansion, team scope, rate limiting, MFA, secrets, agent authentication. | 11 files |
| Services | `services/*.py`, `services/ai/`, `services/importers/` | Business logic, one module per context. Own the transaction semantics of their callers. | 50 top-level modules |
| Engines | `engines/risk.py`, `engines/cvss/` | The risk formula and the CVSS v2/v3/v4 calculators. | 2 + 6 files |
| Intel | `intel/feeds.py` | Outbound collection of NVD, EPSS, CISA KEV and MITRE CWE. Hands results to `services/intelligence.py`. | 1 file |
| Models | `models/*.py` | SQLAlchemy declarative classes: 89 tables in 19 table modules. | 21 files |
| Core | `config.py`, `db.py`, `observability.py` | Settings, engine and tenant binding, logging and metrics. | 3 files |
| Entry points | `cli.py`, `__main__.py` | `python -m veyrs <command>` (20 top-level commands) used by installers and timers. | 838 lines |

### 1.1 Real import direction

The legacy diagram says `engines/` never imports `services/`. The code is slightly different. The matrix below counts `import` statements (module-level and function-local) between layers, extracted by parsing every file under `backend/veyrs` with Python's `ast` module (method in [dependencies](dependencies.md)).

| From \ To | api | services | security | engines | intel | models | config/db |
|---|---|---|---|---|---|---|---|
| `api` | - | 48 | 42 | 2 | 0 | 30 | 5 |
| `services` | 0 | (internal) | 24 | 2 | 0 | 105 | 13 |
| `security` | 0 | 2 | (internal) | 0 | 0 | 5 | 7 |
| `engines` | 0 | 1 | 0 | (internal) | 0 | 2 | 1 |
| `intel` | 0 | 1 | 0 | 0 | - | 0 | 2 |
| `models` | 0 | 0 | 0 | 0 | 0 | (internal) | 0 |

What holds, and is worth keeping:

- Nothing outside `main.py` and `cli.py` imports `api`. Services never depend on HTTP objects.
- `models` imports nothing from the other layers.
- The CVSS calculators (`engines/cvss/`) import only each other. That is why they can be validated against the official vector corpus without a database (`tests/test_cvss_official.py`).

What the legacy rule gets wrong:

- `engines/risk.py` imports weight constants from `models/assets.py` at module level, and its `run_cli()` imports `db`, `models` and `services.risk` inside the function. The scoring functions (`evaluate`, `technical_risk`, and so on) take a plain `RiskInput` dataclass and touch no database; the CLI wrapper in the same file does. Treat "engine = pure" as true of `evaluate()`, not of the file.
- `security/scope.py` imports `services.teams`, and `security/agent_auth.py` imports `services.agents`. Security is therefore not strictly below services.
- `intel/feeds.py` imports three services (`intel_pipeline`, `intelligence`, `xmlsafe`). It is a collection layer above the ingest services, not an engine.

`services` modules also import each other, and several use function-local imports to break cycles (for example `correlation` imports `autoticket` and `workflow` late because `workflow` → `ticketing` → `correlation` would be circular, `services/correlation.py:598-606`).

### 1.2 Router assembly

`api/v1/__init__.py` includes routers in a deliberate order: `attribution` before `findings` so `/findings/changes` is not captured by `/findings/{id}`. Each router declares its OpenAPI tag, and the tag drives two cross-cutting policies: [team scope](#46-server-side-authorization-and-team-scope) and the API reference grouping (`../api/reference/<tag-slug>.md`).

## 2. Request lifecycle

Outermost first (Starlette runs middleware in reverse order of registration, `main.py:75-86`):

1. **CORS** (`CORSMiddleware`) with origins from `VEYRS_CORS_ORIGINS`.
2. **RequestContextMiddleware** (`observability.py`): takes or generates `X-Correlation-ID`, times the request, increments `veyrs_requests_total` labelled by the matched route template, adds the security headers, writes one JSON log line.
3. **RateLimitMiddleware** (`security/ratelimit.py`): a strict per-IP budget for `/auth/login`, `/auth/refresh`, `/auth/mfa`, `/auth/password` (default 10 per minute) and a per-credential budget elsewhere (default 240 per minute). Probes and `/metrics` are exempt. Redis-backed; falls back to per-process windows and fails open if Redis is unreachable.
4. **Routing and dependencies**: `get_principal` resolves `Authorization: Bearer` or `X-API-Key`, binds the tenant with `set_tenant`, applies the team-scope route policy; `require(...)` checks permissions; handlers receive a tenant-bound `Session`.
5. **Service call**, commit, audit row, response.

Handlers are mostly synchronous `def` functions (run in Starlette's thread pool); a few are `async` because they stream a request body (scanner upload, agent result). Throughput comes from processes: `--workers 4` in the systemd unit and `VEYRS_WORKERS` (default 4) in the container. Each worker has its own SQLAlchemy pool (`pool_size=10`, `max_overflow=20`) and per-connection `statement_timeout = 30s` and `idle_in_transaction_session_timeout = 60s` (`db.py`).

Errors: validation errors return field paths without submitted values; database errors return a correlation id and a generic body; an unreadable stored secret returns 503 `secret_storage_unavailable` (`main.py:141-186`).

Probes: `/healthz` is liveness and answers 200 even if the database is gone; `/readyz` runs `SELECT 1` and a Redis `PING` and answers 503 if either fails. `/metrics` is Prometheus text, returns 404 unless the bearer matches `VEYRS_METRICS_TOKEN` (or, outside production with no token, is open). Metrics are per worker process.

## 3. Process model

| Process | Started by | Count | Role |
|---|---|---|---|
| `veyrs-api` (uvicorn, `veyrs.main:app`) | systemd `veyrs-api.service`, or container `api` | 4 workers per node | The HTTP API. Binds 127.0.0.1:8000 (native) or the container network (8000, not published). |
| nginx | system package, or container `console` | 1 per node | Serves the console and static files, proxies `/api/`, `/healthz`, `/readyz` to uvicorn. TLS is terminated upstream of it. |
| `veyrs-intel-sync` | `veyrs-intel-sync.timer` (hourly, 600 s jitter), or container `intel` loop | 1 per installation | Runs `scripts/sync-intel.sh`: asks `veyrs intel-due`, runs due feeds in fixed order CWE, NVD, EPSS, KEV, then **always** runs `veyrs run-sla`. |
| `veyrs-digest` | `veyrs-digest.timer` (hourly, 300 s jitter), or container `digest` loop | 1 per installation | Runs `veyrs digest`; each organization is processed only if its configured hour has arrived. |
| `veyrs-agent` | `veyrs-agent.service`, or container `agent` (profile `agent`) | 1 per scan location | Polls `/api/v1/agents/self/*`, runs a scanner, returns output. Standard library only. |
| `veyrs-updater` | `veyrs-updater.path` when the API drops a request file in the spool | on demand | Root-privileged half of the in-product update: verifies the signed release, backs up, installs, health-checks. |
| Backup timers | `veyrs-pgdump.timer` (02:15 daily), `veyrs-pgverify.timer` (Sunday 04:30), `veyrs-replcheck.timer` (15 min) | database node | Logical dump, weekly restore proof, replication check. See [deployment](deployment.md). |
| CLI | operator, installer, timers | ad hoc | `python -m veyrs <command>`; see [CLI](#5-command-line-surface). |
| Static builders | release process | ad hoc | `site/build.py` (Docs Center) and `site/web/build_web.py` (product site). Output is plain HTML. |

The intel and digest processes are **ticks, not schedules**: the unit fires hourly and the application decides whether anything is due from settings stored per organization (`organizations.settings.intel_schedule`, `.digest`). Changing a cadence is a console edit, not a unit-file edit (`integrations/systemd/veyrs-intel-sync.timer` comments; `services/intel_schedule.py`).

Where background work is **not** done: there is no `veyrs-worker`, no Celery (not in `requirements.txt`; guarded by `tests/test_docs_are_current.py`). SLA evaluation runs inside the intel tick, so without that tick (for example the container `workers` profile off) deadlines stop elapsing and no warning or breach events are produced. Stale agent leases are requeued only when someone calls `POST /api/v1/agents/maintenance/reap`; no shipped timer calls it (see [data flows](data-flows.md#4-agent-job-lifecycle)).

## 4. Patterns

Each pattern lists where it lives, the decision record, and what it costs.

| Pattern | Implementation | Decision | What it gives up |
|---|---|---|---|
| Two-layer multi-tenancy | `TenantSession`/`set_tenant` in the app, `FORCE ROW LEVEL SECURITY` in 73 tables | [ADR 0001](../ADRs/0001-postgres-rls.md) | A forgotten `WHERE` returns zero rows, not leakage; but the application role must be neither superuser nor `BYPASSRLS`, and `pg_dump` as that role writes a truncated archive. |
| Stateless application nodes | Uploads held in memory then persisted, sessions are `refresh_tokens` rows, JWT secret shared, rate limits in shared Redis | [ADR 0007](../ADRs/0007-stateless-app-nodes.md) | The database node is a single point of failure; promotion of a standby is manual. |
| One AI gateway | `services/ai/gateway.invoke()` is the only caller of a provider | [ADR 0003](../ADRs/0003-ai-gateway.md) | No streaming; refusals are results the caller must handle. |
| Closed query grammar | Model emits JSON, `nlquery.validate()` checks fields/operators/values, VEYRS compiles and appends the tenant predicate | [ADR 0004](../ADRs/0004-closed-query-grammar.md) | Cannot express anything outside the grammar. |
| Algorithms from the specification | `engines/cvss/` implemented from FIRST's published algorithms | [ADR 0002](../ADRs/0002-cvss-from-spec.md) | Maintenance burden when FIRST publishes a new version. |
| Partial catalogues, stated | `is_partial` derived from imported vs official control count | [ADR 0005](../ADRs/0005-partial-catalogues.md) | Full catalogues need a licensed import. |
| Absence is not proof | Reconciliation scoped to one scan test, threshold by engagement type | [ADR 0006](../ADRs/0006-no-autoclose-on-absence.md) (partly superseded, see ADR) | Larger, more honest queues. |
| Per-scanner deduplication | Four algorithms selected per scanner; `legacy` stays the default so existing findings are not re-keyed | `services/dedupe.py` | Switching algorithm requires a deliberate re-hash. |
| Closed workflow vocabulary | `ACTIONS` registry of six functions; `ACTION_SCHEMA` must have the same keys (asserted at import) | `services/workflow.py:266,410` | No tenant-defined logic. |
| Two credential types | `Principal` (user, API key) versus `ExecAgent`; different headers, different dependencies, different token schemes | `security/agent_auth.py` | Two code paths to maintain. |
| Database as the queue | Agent jobs claimed with `FOR UPDATE SKIP LOCKED`, lease token, expiry sweep | `services/agents.py:665` | Throughput bounded by the database; needs an external trigger for lease reaping. |
| Tick, not schedule | Hourly timer asks the application what is due | `scripts/sync-intel.sh` | One scheduling concept in the database instead of in systemd; a stopped tick is invisible in the console. |
| Additive schema reconciliation | `Base.metadata.create_all` then `sync_columns()`; no Alembic | `cli.py:67-140`, `migrations/README.md` | Destructive changes (drop, rename, narrow) are manual. |
| Envelope secrets with optional vault | Fernet under `VEYRS_ENCRYPTION_KEY`; `local`, `mirror` or `vault` backend | `security/secrets.py`, `security/secret_vault.py` | Losing the key loses every stored third-party credential. |
| Dependency-light observability | JSON logs, in-process counters, bounded label space; no prometheus_client or OpenTelemetry | `observability.py` | Metrics are per worker; a scrape samples whichever worker answers. |

### 4.1 Multi-tenant RLS in the application

Every request binds `veyrs.current_org` through `get_principal` and again through `tenant_session` (`security/deps.py:169-216`). `set_config(..., true)` is transaction-local, so a pooled connection cannot carry one request's tenant into the next. A commit ends the transaction, so `db._rebind_tenant` re-applies the remembered tenant on every `after_begin`. Background jobs that walk all tenants (`services/intel_pipeline.py`) rebind per tenant and restore the previous binding on exit. Sequence: [sequences](sequences.md#3-tenant-session-binding-rls).

Policy shapes (`cli.py:58-64`): strict `organization_id::text = NULLIF(current_setting('veyrs.current_org', true), '')`, and for the four credential-keyed tables a permissive-when-unbound variant so login can find a user by e-mail before any tenant is bound. Seventeen tables are not under RLS: 13 global reference tables, `organizations`, `roles`, `auth_events`, and `feed_runs`.

### 4.2 Stateless nodes

The only filesystem writes in the backend are the self-update staging area (`<install>/var/update-uploads`, `services/updates.py:338`) and the update spool and status directories under `/var/lib/veyrs` (`config.py:132-141`). Uploaded documents are parsed in memory and only their extracted text, hash and metadata are stored in PostgreSQL (`Document.text_content`; the `Document.storage_key` column for an object store is never written by any code), and reports are rendered into memory per request (`services/reporting.py`). Everything else a node holds is its `.env` and its installed tree. That is what lets two application nodes run behind one proxy with no sticky sessions and no shared file system ([ADR 0007](../ADRs/0007-stateless-app-nodes.md)). The in-product update is node-local by nature, so it must be run on each node.

### 4.3 AI gateway

Steps in `invoke()` (`services/ai/gateway.py:231-352`): capability enabled for the tenant; caller holds the capability's permission; prompt size and daily budget; sanitise (secrets, PII, injection check); select provider by data classification ceiling; redact infrastructure addresses if the provider is external; call or degrade to the deterministic provider; scan the output; write `ai_audit_log`. Only `gateway.py` imports `get_provider`; `capabilities.py` imports `providers` solely for `ProviderError` and `parse_json_object`.

### 4.4 Imports and deduplication

`bytes → parser → ScanRecord[] → base.ingest() → Finding[]`, wrapped in an `ImportRun`. A record whose asset cannot be identified inside the tenant is rejected with a reason; VEYRS never attaches it to a neighbour. Identity is resolved by `services/dedupe.py` (`resolve_identity`, `find_existing`). Details in [data flows](data-flows.md#1-scan-import-to-verified-closure).

### 4.5 Time and watermarks

Feeds are incremental. NVD is walked by `lastModified` in windows of at most 120 days; the watermark is the boundary requested, not the run time. A feed that fetches nothing is not recorded as a successful run, because freshness in `/intel/health` derives from successful runs (`intel/feeds.py` header).

### 4.6 Server-side authorization and team scope

`require(*perms)` validates permission strings at import time, so a typo cannot silently authorize everyone. `get_principal` then calls `team_scope.enforce_route_policy`: routers tagged `agents`, `ai`, `compliance`, `engagements`, `integrations`, `asset sources` refuse a team-restricted principal; `assets`, `vulnerability management`, `ticketing`, `dashboards & reports`, `policies`, `cvss`, `risk register` serve it filtered; `authentication`, `intelligence & knowledge`, `threat intelligence`, `operations`, `administration`, `saved views` are exempt (`security/scope.py:60-100`). A new router tag that is in none of the three sets is therefore an architectural decision to make explicitly.

## 5. Command-line surface

`python -m veyrs <command>` is how installers, timers and operators reach the application without HTTP. Commands (from `cli.py:675-790` and `services/mfa_admin.py`): `init-db`, `sync-schema`, `check`, `keygen`, `bootstrap`, `platform-admin`, `sync-kev`, `sync-epss`, `sync-nvd`, `sync-cwe`, `recompute-risk`, `run-sla`, `digest`, `prune-epss-history`, `intel-due`, `import-inventory`, `secrets` (`status`, `migrate`, `rekey`, `gc`), plus the two-factor administration commands registered by `mfa_admin`. Operator usage is in the system manual; this document only places the CLI in the architecture: it is a second entry point into the services layer, with no HTTP and no principal.

## 6. Frontend and static sites

- **Console** (`frontend/console/`): `index.html`, `console.css` and one 9,507-line `app.js`. Plain JavaScript, hash routing (`#/path`), no bundler, no package manager. Served by nginx with a strict CSP (`script-src 'self'`). It calls the same `/api/v1` as any other client; authorization is always server-side.
- **Docs Center** (`site/build.py`) and **product site** (`site/web/build_web.py`): Python standard-library generators. The product-site builder imports the Docs Center's Markdown renderer so the two cannot render the same file differently (`docs/ARCHITECTURE.md`, "Public surfaces").

## 7. Decisions index

| ADR | Decision | Status against 0.39.1 |
|---|---|---|
| [0001](../ADRs/0001-postgres-rls.md) | PostgreSQL RLS as a second tenant barrier | Accepted; implemented. Pre-auth tables are four, not three. |
| [0002](../ADRs/0002-cvss-from-spec.md) | CVSS from the published algorithms | Accepted; implemented; corpus test present. |
| [0003](../ADRs/0003-ai-gateway.md) | One AI gateway | Accepted; implemented. |
| [0004](../ADRs/0004-closed-query-grammar.md) | AI emits validated JSON, never SQL | Accepted; implemented. |
| [0005](../ADRs/0005-partial-catalogues.md) | Partial catalogues, stated | Accepted; implemented. |
| [0006](../ADRs/0006-no-autoclose-on-absence.md) | Never close on absence | Accepted in principle; mechanism superseded by scoped, threshold-based reconciliation. |
| [0007](../ADRs/0007-stateless-app-nodes.md) | Stateless app nodes | Accepted; routing changed from active/active to primary/backup. |
| [0008](../ADRs/0008-state-off-host-and-proven-backups.md) | State off the app host, proven backups | Accepted; the standby does not currently sit on a separate physical host. |

## Sources

- `backend/veyrs/main.py`, `db.py`, `config.py`, `observability.py`, `cli.py`
- `backend/veyrs/security/deps.py`, `ratelimit.py`, `scope.py`, `agent_auth.py`
- `backend/veyrs/services/ai/gateway.py`, `services/agents.py`, `services/correlation.py`, `services/workflow.py`
- `scripts/sync-intel.sh`, `integrations/systemd/*`, `infrastructure/systemd/*`
